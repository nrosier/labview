package access

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nrosier/labview/internal/payload"
)

// The gate (§19): one request hook, one response hook, and the decision that sits between them.
//
// Three rules govern everything below, and each is written at the line that keeps it:
//
//   - **The gate never consults scanned data** (I8). Nothing in this file imports the scan, reads the
//     build cache or waits on anything. A login screen that waits on a fleet scan is a login screen
//     that times out at the moment an operator most needs it — when the fleet is broken.
//   - **A reply says less than the log.** The client gets `401 {"error":"authentication required"}`
//     and nothing else; the reason goes to the log, with the username sanitised.
//   - **The public-path test is an exact-match allowlist** over a normalised path. A prefix test would
//     open `/api/healthz/../overview`.

// The public API paths, exactly (§19).
//
// Four, and each for a stated reason: healthz so a container probe works without a credential, session
// so the UI can ask whether it needs to show a login form, and login and logout because a gate that
// required a session in order to get one would be closed to everybody.
//
// A map rather than a slice with a loop, so *exact match* is the only thing the lookup can do.
var publicPaths = map[string]bool{
	"/api/healthz": true,
	"/api/session": true,
	"/api/login":   true,
	"/api/logout":  true,
}

// PublicPaths lists the allowlist in sorted order, for a test and for documentation.
func PublicPaths() []string {
	return []string{"/api/healthz", "/api/login", "/api/logout", "/api/session"}
}

// Public reports whether an already-normalised path is in the allowlist.
//
// It takes a normalised path and does not normalise one itself, because a function that did both could
// be called with a raw path by mistake and would silently answer a question about the wrong string.
// Normalise returns the value this expects.
func Public(normalised string) bool { return publicPaths[normalised] }

// Normalise reduces a request path to the string the allowlist is checked against, and reports whether
// it is acceptable at all (§19).
//
// Query and fragment are already absent from r.URL.Path, and are stripped here anyway because this
// function is also called on strings that came from somewhere else. Duplicate slashes collapse, because
// `//api//healthz` reaches the same handler and must reach the same decision. **Any `..` is refused
// rather than resolved** — resolving it would mean this program contains a path-traversal resolver, and
// the only reason to write one is to be wrong about it once. Nothing that needs `..` is a legitimate
// request to LabView.
func Normalise(path string) (string, bool) {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}

	// Percent-decoded before the `..` test, because `/api/healthz/%2e%2e/overview` is the same request
	// as the literal form and a test that ran before decoding would not see it. A path that will not
	// decode is refused rather than passed through.
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return "", false
	}
	path = decoded

	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		// A relative path in a request line is not something to interpret.
		return "", false
	}

	var out strings.Builder
	out.Grow(len(path))
	for i := 0; i < len(path); i++ {
		if path[i] == '/' && out.Len() > 0 && path[i-1] == '/' {
			continue
		}
		out.WriteByte(path[i])
	}
	path = out.String()

	for _, segment := range strings.Split(path, "/") {
		if segment == ".." {
			return "", false
		}
	}

	// A trailing slash is removed, so `/api/session/` and `/api/session` are one path. Not removed from
	// the root, which is the only path that *is* a slash.
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return path, true
}

// APIPath reports whether a normalised path is part of the API, which is what `Cache-Control: no-store`
// attaches to while enforcing (§19).
func APIPath(normalised string) bool {
	return normalised == "/api" || strings.HasPrefix(normalised, "/api/")
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

// Rejection is one refused request, for the log. It is never serialised to a client.
type Rejection struct {
	// Path is the normalised path, which is a string this program produced rather than one a client
	// chose — so it is safe to log.
	Path string

	// Reason is the sentence for the operator.
	Reason string

	// Username is already sanitised (§16): `?` unless it satisfied the pattern.
	Username string

	// Kind is the session rejection when there was one — `malformed`, `signature`, `expired` or
	// `revoked` (§4.7). Empty when the request carried no session at all.
	Kind payload.SessionRejection

	// Status is what the client was told.
	Status int
}

// Gate holds everything the request hook consults, and nothing else.
type Gate struct {
	// Postures is the 5000 ms-cached posture. Required.
	Postures *Postures

	// Signer verifies sessions. Required.
	Signer *Signer

	// Cookies reads the session cookie.
	Cookies Cookies

	// Throttle counts failed password attempts. Nil throttles nothing.
	Throttle *Throttle

	// Now is the injected clock. Nil is time.Now.
	Now func() time.Time

	// Rejected is called for every refused request. Nil means nobody is listening.
	Rejected func(Rejection)
}

// Wrap composes the response hook around the request hook.
//
// The order is not a preference. The headers have to be on the 401 the request hook itself writes, and
// a middleware cannot add a header after a handler has written one — so headers go outside. Stated here
// because the two hooks read as independent and are not.
func (g *Gate) Wrap(next http.Handler) http.Handler {
	return g.Headers(g.Guard(next))
}

// Headers is the response hook (§19).
//
// Three headers unconditionally, plus `Cache-Control: no-store` on `/api/*` while enforcing:
//
//   - `X-Content-Type-Options: nosniff` — a JSON payload a browser decided to treat as HTML is a JSON
//     payload that can carry script, and LabView serves strings that came from a scanned fleet.
//   - `Referrer-Policy: same-origin` — a URL carries a service slug and a filter, which is a
//     description of somebody's fleet, and there is no reason to send it to whatever they click next.
//   - `X-Frame-Options: DENY` — nothing embeds LabView, and a dashboard in an invisible frame is the
//     setup for a clickjacked Rescan.
//
// **No CSP** (§19). The UI is self-contained, framing is already forbidden, and a policy that has to
// enumerate what a self-contained page may load is a policy that will one day silently break a panel
// nobody tested. That is a decision, not an omission.
func (g *Gate) Headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")

		normalised, ok := Normalise(r.URL.Path)
		if ok && APIPath(normalised) && g.posture().Enforced() {
			// While enforcing only, because a cached API response is a convenience on an open
			// dashboard and a leak on a gated one — a shared browser's back button should not
			// re-render a fleet after a sign-out.
			h.Set("Cache-Control", "no-store")
		}

		next.ServeHTTP(w, r)
	})
}

// Guard is the request hook.
func (g *Gate) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		normalised, ok := Normalise(r.URL.Path)
		if !ok {
			// A path this program refuses to interpret is refused as a request. 400 rather than 404,
			// because the path is not wrong about what exists — it is not a path.
			g.refuse(w, r, http.StatusBadRequest, Rejection{
				Path:     "(unparseable)",
				Reason:   "the request path could not be normalised",
				Username: UnknownUsername,
				Status:   http.StatusBadRequest,
			})
			return
		}

		posture := g.posture()

		// **Open unless configured** (§19). With nothing enforced there is no check at all — but the
		// session is still resolved, so a dashboard that was gated a moment ago still shows who is
		// signed in rather than appearing to sign them out.
		if !posture.Enforced() {
			next.ServeHTTP(w, g.with(r, g.resolve(r)))
			return
		}

		// **CSRF before the session check** (§19). Before, because an unauthenticated cross-site POST
		// must be refused on the grounds that it is cross-site, not on the grounds that it had no
		// session — and because a check that ran after would have already looked at the cookie the
		// attacker was hoping to have used.
		if r.Method == http.MethodPost {
			if origin, allowed := checkOrigin(r); !allowed {
				g.refuse(w, r, http.StatusForbidden, Rejection{
					Path:     normalised,
					Reason:   "a POST arrived from another origin: " + origin,
					Username: UnknownUsername,
					Status:   http.StatusForbidden,
				})
				return
			}
		}

		viewer := g.resolve(r)

		// **Gate the data, not the shell** (§19). Only the API is gated, and within it only the paths
		// outside the allowlist.
		//
		// Both halves matter. The UI assets carry no fleet data, and gating them would answer a reader
		// with a JSON 401 where a login form belongs — so `/`, `/index.html` and every bundle stay
		// reachable. The OIDC routes sit outside `/api` for the same reason and one more: a sign-in that
		// required a session in order to start would be a sign-in nobody could reach. That is why the
		// allowlist has four entries rather than six — it is about the API, and `/auth/oidc/*` was never
		// in the API's scope.
		if !APIPath(normalised) || Public(normalised) {
			next.ServeHTTP(w, g.with(r, viewer))
			return
		}

		if viewer.User == nil {
			reason := "no session"
			if viewer.Kind != "" {
				reason = "session " + string(viewer.Kind)
			}
			g.refuse(w, r, http.StatusUnauthorized, Rejection{
				Path:     normalised,
				Reason:   reason,
				Username: viewer.Name,
				Kind:     viewer.Kind,
				Status:   http.StatusUnauthorized,
			})
			return
		}

		next.ServeHTTP(w, g.with(r, viewer))
	})
}

// refuse writes the short reply and hands the long one to the log (§19).
//
// **No Set-Cookie on a refusal.** §19 requires it for the CSRF case and it is right for all of them: a
// refused request has established nothing, and clearing a cookie here would let a cross-site POST sign
// somebody out — a CSRF defence that performed the attack it was defending against.
func (g *Gate) refuse(w http.ResponseWriter, r *http.Request, status int, entry Rejection) {
	if g.Rejected != nil {
		g.Rejected(entry)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	// One body for every refusal, with no reason in it. A client that could tell `expired` from
	// `signature` from `revoked` could tell a forged token from a stale one, which is a probe oracle;
	// and the UI's response to all three is identical — show the login form.
	switch status {
	case http.StatusUnauthorized:
		_, _ = w.Write([]byte(`{"error":"authentication required"}`))
	case http.StatusForbidden:
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	default:
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}
}

// ---------------------------------------------------------------------------
// The session on a request
// ---------------------------------------------------------------------------

// Viewer is what a request's session amounts to.
type Viewer struct {
	// User is who is signed in, or nil.
	User *payload.SessionUser

	// Name is the sanitised username for the log — present even when User is nil, because a rejected
	// token's claims are worth logging and are not worth trusting.
	Name string

	// Kind is why a session was refused, empty when none was presented.
	Kind payload.SessionRejection
}

// Resolve reads and verifies the session on a request. Exported because the session route needs it on a
// path the guard let through without checking.
func (g *Gate) Resolve(r *http.Request) Viewer { return g.resolve(r) }

func (g *Gate) resolve(r *http.Request) Viewer {
	token, err := g.Cookies.Token(r)
	if err != nil {
		return Viewer{Name: UnknownUsername}
	}

	claims, kind, err := g.Signer.Verify(token, g.clock()())
	if err != nil {
		// The claims are returned for the expired and revoked cases, where the token was ours and the
		// name in it is therefore a name we signed. Sanitised regardless: a name that was valid when
		// signed is still passed through the sanitiser, because the code that signs it and the code
		// that logs it should not have to agree about who checked.
		return Viewer{Name: Username(claims.U), Kind: kind}
	}

	user := claims.User()
	return Viewer{User: &user, Name: user.Name}
}

// viewerKey is the context key. An unexported struct type, so no other package can collide with it and
// no string constant can be guessed.
type viewerKey struct{}

func (g *Gate) with(r *http.Request, v Viewer) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), viewerKey{}, v))
}

// From reads the viewer a request was guarded with.
//
// A handler that was reached through the gate always has one. A handler that was not gets the zero
// value, which reports nobody signed in — the safe answer, since a route that forgot to be wrapped
// should behave as though it has no idea who is calling rather than as though everybody is trusted.
func From(ctx context.Context) Viewer {
	if v, ok := ctx.Value(viewerKey{}).(Viewer); ok {
		return v
	}
	return Viewer{Name: UnknownUsername}
}

// ---------------------------------------------------------------------------
// The Origin check
// ---------------------------------------------------------------------------

// checkOrigin is the other half of the CSRF defence, `SameSite=Lax` being the first (§19).
//
// **A missing `Origin` passes.** Browsers send it on every cross-origin request and on every POST, so
// its absence means the caller is not a browser — curl, a script, a container's health check — and none
// of those is subject to CSRF, because none of them has a cookie jar somebody else's page can borrow.
// Refusing them would break every non-browser client to defend against an attack they cannot carry.
//
// It returns the origin it saw, so the log can say what arrived; the value is bounded and sanitised on
// the way out, since it came off the wire.
func checkOrigin(r *http.Request) (string, bool) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return "", true
	}
	// Some browsers send `null` for an opaque origin — a sandboxed frame or a `file://` page. That is
	// not this origin, and treating it as absent would be reading a hostile value as *no value*.
	if origin == "null" {
		return "null", false
	}

	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "(unparseable)", false
	}

	if u.Scheme != EffectiveScheme(r) {
		// A POST from `http://host` to the https deployment of the same host is still cross-origin, and
		// it is the shape a stripped-TLS attack takes.
		return safeOrigin(u.Scheme + "://" + u.Host), false
	}
	for _, host := range hosts(r) {
		if host != "" && strings.EqualFold(u.Host, host) {
			return safeOrigin(u.Scheme + "://" + u.Host), true
		}
	}
	return safeOrigin(u.Scheme + "://" + u.Host), false
}

// hosts is what this request may legitimately have come from.
//
// `Host` first, which every proxy in ordinary use passes through unchanged. `X-Forwarded-Host` is also
// accepted, because a proxy configured to rewrite Host would otherwise make every POST look
// cross-origin — and a browser cannot set that header on a cross-site form POST or on a simple fetch,
// so accepting it does not hand an attacker a way past the check.
func hosts(r *http.Request) []string {
	out := []string{r.Host}
	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		first := forwarded
		if i := strings.Index(first, ","); i >= 0 {
			first = first[:i]
		}
		out = append(out, strings.TrimSpace(first))
	}
	return out
}

// safeOrigin bounds an origin for a log line. It came off the wire, so it is truncated and stripped of
// anything that could forge a line — the same reasoning as the username sanitiser (§16).
func safeOrigin(s string) string {
	const max = 128
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == '"' {
			continue
		}
		b.WriteByte(c)
	}
	if b.Len() == 0 {
		return "(unprintable)"
	}
	return b.String()
}

func (g *Gate) posture() Posture {
	if g.Postures == nil {
		return Posture{}
	}
	return g.Postures.Current()
}

func (g *Gate) clock() func() time.Time {
	if g.Now == nil {
		return time.Now
	}
	return g.Now
}
