package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/payload"
)

// gated builds a gate holding one account — `ada`, password `one` — and reports the posture it will use.
// enforce says whether the passwd method is enabled, which is what decides enforcement.
func gated(t *testing.T, enforce bool) (*Gate, Posture) {
	t.Helper()

	now := at(0)
	cfg := config.AuthConfig{}
	if enforce {
		cfg.Passwd = config.PasswdConfig{Enabled: true, File: "/p"}
	}

	postures := &Postures{
		Config: func() config.AuthConfig { return cfg },
		Passwd: &PasswdReader{FS: &memFS{files: map[string]*memFile{
			"/p": {content: []byte("ada:" + hash(t, "one") + "\n"), mtime: now},
		}}},
		Now: func() time.Time { return now },
	}

	g := &Gate{
		Postures: postures,
		Signer:   NewSigner("a test signing secret that is long enough", time.Hour),
		Throttle: &Throttle{Max: 3, Window: 60 * time.Second},
		Now:      func() time.Time { return now },
	}
	return g, postures.Current()
}

// reached is a handler that records that it was called and with which viewer.
func reached(seen *Viewer, called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		*seen = From(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func signedIn(t *testing.T, g *Gate, r *http.Request, user string) {
	t.Helper()
	token, _, err := g.Signer.Mint(user, payload.MethodPasswd, at(0))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: token})
}

// ---------------------------------------------------------------------------
// Normalise
// ---------------------------------------------------------------------------

func TestNormaliseReducesAPathToTheStringTheAllowlistIsCheckedAgainst(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"/api/session", "/api/session", true},
		{"/api/session/", "/api/session", true},
		{"//api//session", "/api/session", true},
		{"///api///session///", "/api/session", true},
		{"/", "/", true},
		{"//", "/", true},
		{"", "/", true},
		{"/api/session?filter=down", "/api/session", true},
		{"/api/session#panel", "/api/session", true},
		// Percent-decoded, so an encoded spelling of an allowlisted path is the same request.
		{"/api/sess%69on", "/api/session", true},
		{"/api/session%2f", "/api/session", true},
	} {
		got, ok := Normalise(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("Normalise(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// §19: **any `..` is refused rather than resolved.** Resolving it would mean this program contains a
// path-traversal resolver, and a prefix allowlist plus a resolver is how `/api/healthz/../overview`
// becomes public.
func TestEveryFormOfDotDotIsRefusedRatherThanResolved(t *testing.T) {
	for _, path := range []string{
		"/api/healthz/../overview",
		"/api/healthz/%2e%2e/overview",
		"/api/healthz/%2E%2E/overview",
		"/api/../api/overview",
		"/..",
		"/../",
		"//..//",
		"/api/healthz/..%2foverview",
	} {
		if got, ok := Normalise(path); ok {
			t.Fatalf("Normalise(%q) = %q, accepted; §19 requires a refusal", path, got)
		}
	}
}

func TestAPathThatIsNotAPathIsRefused(t *testing.T) {
	for _, path := range []string{
		"relative/path",
		"api/overview",
		"%2e%2e/api",
		"/api/%zz",
		"http://elsewhere.example.com/api/overview",
	} {
		if got, ok := Normalise(path); ok {
			t.Fatalf("Normalise(%q) = %q, accepted", path, got)
		}
	}
}

// §19: the public-path test is an **exact-match allowlist**.
func TestThePublicPathTestIsExactMatchAndNothingElse(t *testing.T) {
	for _, path := range PublicPaths() {
		if !Public(path) {
			t.Fatalf("%q is in the documented list and is not public", path)
		}
	}

	for _, path := range []string{
		"/api/healthz/",
		"/api/healthz/x",
		"/api/healthzz",
		"/api/healthz.json",
		"/api/HEALTHZ",
		"/api",
		"/api/overview",
		"/api/session/../overview",
		"",
		"/",
	} {
		if Public(path) {
			t.Fatalf("%q is treated as public", path)
		}
	}
}

// The documented list and the map the lookup uses are two statements of one fact, so they are checked
// against each other: a path added to the map and not the list would be public and undocumented.
func TestTheDocumentedAllowlistAndTheLookupAgree(t *testing.T) {
	listed := PublicPaths()
	if len(listed) != len(publicPaths) {
		t.Fatalf("PublicPaths lists %d paths, the lookup holds %d", len(listed), len(publicPaths))
	}
	for _, path := range listed {
		if !publicPaths[path] {
			t.Fatalf("%q is documented as public and is not in the lookup", path)
		}
		if normalised, ok := Normalise(path); !ok || normalised != path {
			t.Fatalf("%q is not its own normalised form (%q, %v), so it could never match", path, normalised, ok)
		}
	}
}

func TestAPIPathCoversTheAPIAndNothingAboveIt(t *testing.T) {
	for path, want := range map[string]bool{
		"/api":                true,
		"/api/overview":       true,
		"/api/healthz":        true,
		"/":                   false,
		"/apish":              false,
		"/assets/x.js":        false,
		"/auth/oidc/callback": false,
	} {
		if got := APIPath(path); got != want {
			t.Fatalf("APIPath(%q) = %v, want %v", path, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// The response hook
// ---------------------------------------------------------------------------

// §19: three headers unconditionally, plus `Cache-Control: no-store` on `/api/*` while enforcing, and
// **no CSP**.
func TestTheThreeHeadersAreSetWhateverElseHappens(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		for _, path := range []string{"/", "/api/overview", "/assets/app.js", "/api/healthz/../x"} {
			g, _ := gated(t, enforce)
			rec := httptest.NewRecorder()

			g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
				ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			for header, want := range map[string]string{
				"X-Content-Type-Options": "nosniff",
				"Referrer-Policy":        "same-origin",
				"X-Frame-Options":        "DENY",
			} {
				if got := rec.Header().Get(header); got != want {
					t.Fatalf("enforce=%v %s: %s is %q, want %q", enforce, path, header, got, want)
				}
			}
		}
	}
}

func TestNoStoreIsSetOnTheAPIOnlyWhileEnforcing(t *testing.T) {
	for _, tc := range []struct {
		enforce bool
		path    string
		want    string
	}{
		{true, "/api/overview", "no-store"},
		{true, "/api", "no-store"},
		{true, "/api/session/", "no-store"},
		{true, "/", ""},
		{true, "/assets/app.js", ""},
		{false, "/api/overview", ""},
		{false, "/", ""},
	} {
		g, _ := gated(t, tc.enforce)
		rec := httptest.NewRecorder()

		g.Headers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))

		if got := rec.Header().Get("Cache-Control"); got != tc.want {
			t.Fatalf("enforce=%v %s: Cache-Control is %q, want %q", tc.enforce, tc.path, got, tc.want)
		}
	}
}

// §19 states *no CSP* as a decision. Asserted, so adding one is a deliberate change to a test rather
// than a quiet addition that breaks a panel nobody re-opened.
func TestNoContentSecurityPolicyIsSent(t *testing.T) {
	g, _ := gated(t, true)
	rec := httptest.NewRecorder()

	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	for _, header := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		if got := rec.Header().Get(header); got != "" {
			t.Fatalf("%s is set to %q; §19 states no CSP", header, got)
		}
	}
}

// The headers have to be outside the guard, because the guard writes the 401 itself and no middleware
// can add a header after a body has been written.
func TestTheHeadersAreOnTheGuardsOwnRefusal(t *testing.T) {
	g, _ := gated(t, true)
	rec := httptest.NewRecorder()

	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("the handler was reached on an unauthenticated request")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("the guard's own 401 carries none of the response hook's headers")
	}
}

// ---------------------------------------------------------------------------
// The request hook
// ---------------------------------------------------------------------------

// §19's headline again, at the gate this time: *open unless configured*.
func TestWithNothingEnforcedEveryRequestPassesAndTheSessionIsStillResolved(t *testing.T) {
	g, _ := gated(t, false)

	var seen Viewer
	called := false
	r := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	signedIn(t, g, r, "ada")

	rec := httptest.NewRecorder()
	g.Guard(reached(&seen, &called)).ServeHTTP(rec, r)

	if !called {
		t.Fatalf("an open gate refused a request with %d", rec.Code)
	}
	if seen.User == nil || seen.User.Name != "ada" {
		t.Fatal("an open gate did not resolve the session, so a dashboard would appear to sign the user out")
	}
}

func TestWhileEnforcingAnUnauthenticatedRequestIsRefusedWithOneSentenceAndNoCookie(t *testing.T) {
	g, _ := gated(t, true)

	var entry Rejection
	g.Rejected = func(got Rejection) { entry = got }

	rec := httptest.NewRecorder()
	g.Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("the handler was reached")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"authentication required"}` {
		t.Fatalf("body is %q; §19 fixes the reply at one sentence", body)
	}
	// §19: **no Set-Cookie on a refusal** — clearing one here would let a cross-site request sign
	// somebody out.
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("a refusal carried Set-Cookie: %v", got)
	}
	if entry.Path != "/api/overview" || entry.Status != http.StatusUnauthorized || entry.Username != UnknownUsername {
		t.Fatalf("the log entry does not describe the refusal: %+v", entry)
	}
}

func TestWhileEnforcingTheAllowlistedPathsAreStillReachable(t *testing.T) {
	for _, path := range PublicPaths() {
		g, _ := gated(t, true)

		var seen Viewer
		called := false
		rec := httptest.NewRecorder()
		g.Guard(reached(&seen, &called)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if !called {
			t.Fatalf("%s was refused with %d while enforcing; a gate that required a session to get one would be closed to everybody", path, rec.Code)
		}
		if seen.User != nil {
			t.Fatalf("%s was reached with a signed-in viewer on an anonymous request", path)
		}
	}
}

// §19: *gate the data, not the shell.* The UI assets carry no fleet data and a JSON 401 where a login
// form belongs is the one failure mode this rule exists to prevent, so every path outside `/api` is
// reachable with no session — including the two OIDC routes, which is why the allowlist stays at four.
func TestWhileEnforcingEverythingOutsideTheAPIIsStillReachable(t *testing.T) {
	for _, path := range []string{
		"/",
		"/index.html",
		"/assets/app-4f2c.js",
		"/favicon.ico",
		"/auth/oidc/start",
		"/auth/oidc/callback",
	} {
		g, _ := gated(t, true)

		var seen Viewer
		called := false
		rec := httptest.NewRecorder()
		g.Guard(reached(&seen, &called)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if !called {
			t.Fatalf("%s was refused with %d while enforcing; §19 gates the data, not the shell", path, rec.Code)
		}
		if seen.User != nil {
			t.Fatalf("%s was reached with a signed-in viewer on an anonymous request", path)
		}
	}
}

// The other half of the same rule: everything under `/api` that is not allowlisted *is* gated. Stated
// as its own test over a path that does not exist, because the refusal must not depend on a route
// having been registered — the gate runs before the router, and a 404 for an unauthenticated caller
// would say which API paths exist.
func TestWhileEnforcingEveryOtherAPIPathIsGatedIncludingOnesThatDoNotExist(t *testing.T) {
	for _, path := range []string{"/api", "/api/overview", "/api/rescan", "/api/nothing-here"} {
		g, _ := gated(t, true)

		rec := httptest.NewRecorder()
		g.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatalf("%s reached the handler with no session", path)
		})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s answered %d, want 401", path, rec.Code)
		}
	}
}

func TestWhileEnforcingAValidSessionReachesTheHandler(t *testing.T) {
	g, _ := gated(t, true)

	var seen Viewer
	called := false
	r := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	signedIn(t, g, r, "ada")

	rec := httptest.NewRecorder()
	g.Guard(reached(&seen, &called)).ServeHTTP(rec, r)

	if !called {
		t.Fatalf("a signed-in request was refused with %d", rec.Code)
	}
	if seen.User == nil || seen.User.Name != "ada" || seen.User.Via != payload.MethodPasswd {
		t.Fatalf("the handler was reached with %+v", seen)
	}
}

func TestEachSessionRejectionReachesTheLogWithoutReachingTheClient(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token func(g *Gate) string
		want  payload.SessionRejection
	}{
		{
			name:  "malformed",
			token: func(*Gate) string { return "not-a-token" },
			want:  payload.RejectMalformed,
		},
		{
			name: "signature",
			token: func(*Gate) string {
				token, _, _ := NewSigner("a completely different secret value", time.Hour).
					Mint("ada", payload.MethodPasswd, at(0))
				return token
			},
			want: payload.RejectSignature,
		},
		{
			name: "expired",
			token: func(g *Gate) string {
				token, _, _ := g.Signer.Mint("ada", payload.MethodPasswd, at(0).Add(-2*time.Hour))
				return token
			},
			want: payload.RejectExpired,
		},
		{
			name: "revoked",
			token: func(g *Gate) string {
				token, claims, _ := g.Signer.Mint("ada", payload.MethodPasswd, at(0))
				g.Signer.Revoke(claims, at(0))
				return token
			},
			want: payload.RejectRevoked,
		},
	} {
		g, _ := gated(t, true)
		var entry Rejection
		g.Rejected = func(got Rejection) { entry = got }

		r := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
		r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: tc.token(g)})

		rec := httptest.NewRecorder()
		g.Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("%s: the handler was reached", tc.name)
		})).ServeHTTP(rec, r)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", tc.name, rec.Code)
		}
		if entry.Kind != tc.want {
			t.Fatalf("%s: the log records kind %q, want %q", tc.name, entry.Kind, tc.want)
		}
		// The client is told the same thing every time, so it cannot tell a forged token from a stale one.
		if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"authentication required"}` {
			t.Fatalf("%s: the reply distinguishes the reason: %q", tc.name, body)
		}
	}
}

func TestAnUnparseablePathIsRefusedAsABadRequest(t *testing.T) {
	g, _ := gated(t, true)
	var entry Rejection
	g.Rejected = func(got Rejection) { entry = got }

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.URL.Path = "/api/healthz/../overview"

	rec := httptest.NewRecorder()
	g.Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("the handler was reached")
	})).ServeHTTP(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"bad request"}` {
		t.Fatalf("body is %q", body)
	}
	// The path is not echoed: it is a string a client chose.
	if strings.Contains(entry.Path, "..") {
		t.Fatalf("the log entry echoed the client's path: %q", entry.Path)
	}
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

// §19: the Origin check runs **before the session check**. Before, because a cross-site POST must be
// refused for being cross-site — and because a check that ran after would already have consulted the very
// cookie the attacker was hoping to borrow.
func TestACrossOriginPostIsRefusedBeforeTheSessionIsEvenConsulted(t *testing.T) {
	g, _ := gated(t, true)
	var entry Rejection
	g.Rejected = func(got Rejection) { entry = got }

	// A perfectly valid session, which is exactly the case CSRF exploits.
	r := httptest.NewRequest(http.MethodPost, "/api/rescan", nil)
	signedIn(t, g, r, "ada")
	r.Header.Set("Origin", "https://attacker.example.com")

	rec := httptest.NewRecorder()
	g.Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("a cross-origin POST reached the handler")
	})).ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 — a valid session must not rescue a cross-origin POST", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"forbidden"}` {
		t.Fatalf("body is %q", body)
	}
	if entry.Kind != "" {
		t.Fatalf("the refusal reports a session rejection (%q), so the session was consulted first", entry.Kind)
	}
	if !strings.Contains(entry.Reason, "attacker.example.com") {
		t.Fatalf("the log does not say where the POST came from: %q", entry.Reason)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("the CSRF refusal carried Set-Cookie (%v), which would let the attack sign the user out", got)
	}
}

// A public path is public for GET; it is not an exemption from the Origin check, because `/api/login` is
// the POST an attacker would most like to forge.
func TestTheOriginCheckAppliesToTheAllowlistedPostsToo(t *testing.T) {
	g, _ := gated(t, true)
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.Header.Set("Origin", "https://attacker.example.com")

	rec := httptest.NewRecorder()
	g.Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("a cross-origin POST to a public path reached the handler")
	})).ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

func TestASameOriginPostPasses(t *testing.T) {
	g, _ := gated(t, true)

	var seen Viewer
	called := false
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.Header.Set("Origin", "http://"+r.Host)

	rec := httptest.NewRecorder()
	g.Guard(reached(&seen, &called)).ServeHTTP(rec, r)

	if !called {
		t.Fatalf("a same-origin POST was refused with %d", rec.Code)
	}
}

// A GET is not checked, because the check is about a state-changing request and a browser sends Origin on
// plenty of harmless navigations.
func TestAGetIsNotSubjectToTheOriginCheck(t *testing.T) {
	g, _ := gated(t, true)

	var seen Viewer
	called := false
	r := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	r.Header.Set("Origin", "https://attacker.example.com")

	rec := httptest.NewRecorder()
	g.Guard(reached(&seen, &called)).ServeHTTP(rec, r)

	if !called {
		t.Fatalf("a cross-origin GET to a public path was refused with %d", rec.Code)
	}
}

// §19: **a missing `Origin` passes.** Its absence means the caller is not a browser, and nothing without
// a cookie jar somebody else's page can borrow is subject to CSRF.
func TestTheOriginCheckIsExactlyWhatNineteenStates(t *testing.T) {
	for _, tc := range []struct {
		name      string
		origin    string
		host      string
		forwarded map[string]string
		allowed   bool
	}{
		{name: "absent", origin: "", allowed: true},
		{name: "the same origin", origin: "http://lab.example.com", host: "lab.example.com", allowed: true},
		{name: "the same host, different case", origin: "http://LAB.example.com", host: "lab.example.com", allowed: true},
		{name: "another host", origin: "http://attacker.example.com", host: "lab.example.com"},
		{name: "opaque", origin: "null", host: "lab.example.com"},
		{name: "unparseable", origin: "://", host: "lab.example.com"},
		{name: "no host in the origin", origin: "https://", host: "lab.example.com"},
		{
			name: "the wrong scheme for the same host", origin: "http://lab.example.com", host: "lab.example.com",
			forwarded: map[string]string{"X-Forwarded-Proto": "https"},
		},
		{
			name: "the right scheme behind a proxy", origin: "https://lab.example.com", host: "lab.example.com",
			forwarded: map[string]string{"X-Forwarded-Proto": "https"}, allowed: true,
		},
		{
			name: "a proxy that rewrote Host", origin: "http://lab.example.com", host: "127.0.0.1:8080",
			forwarded: map[string]string{"X-Forwarded-Host": "lab.example.com"}, allowed: true,
		},
		{
			name: "a chain of proxies", origin: "http://lab.example.com", host: "127.0.0.1:8080",
			forwarded: map[string]string{"X-Forwarded-Host": "lab.example.com, inner.internal"}, allowed: true,
		},
		{name: "a port that does not match", origin: "http://lab.example.com:9000", host: "lab.example.com"},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/rescan", nil)
		if tc.host != "" {
			r.Host = tc.host
		}
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		for name, value := range tc.forwarded {
			r.Header.Set(name, value)
		}

		_, allowed := checkOrigin(r)
		if allowed != tc.allowed {
			t.Fatalf("%s: allowed=%v, want %v", tc.name, allowed, tc.allowed)
		}
	}
}

func TestTheLoggedOriginIsBoundedAndCannotForgeALogLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http://host\nada signed in", "http://hostada signed in"},
		{"http://ho\"st", "http://host"},
		{"\x00\x01\x02", "(unprintable)"},
	} {
		if got := safeOrigin(tc.in); got != tc.want {
			t.Fatalf("safeOrigin(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	long := safeOrigin("https://" + strings.Repeat("a", 500))
	if len(long) != 128 {
		t.Fatalf("a 500-character origin logged as %d characters", len(long))
	}
}

// ---------------------------------------------------------------------------
// The viewer
// ---------------------------------------------------------------------------

// A handler reached without the gate must behave as though it has no idea who is calling, rather than as
// though everybody is trusted.
func TestAHandlerThatWasNeverGuardedSeesNobody(t *testing.T) {
	got := From(httptest.NewRequest(http.MethodGet, "/", nil).Context())

	if got.User != nil {
		t.Fatal("an unguarded context reported a signed-in user")
	}
	if got.Name != UnknownUsername {
		t.Fatalf("the name is %q, want the unknown marker", got.Name)
	}
}

func TestResolveReportsARejectedTokensNameForTheLogWithoutTrustingIt(t *testing.T) {
	g, _ := gated(t, true)
	token, _, _ := g.Signer.Mint("ada", payload.MethodPasswd, at(0).Add(-2*time.Hour))

	r := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: token})

	got := g.Resolve(r)

	if got.User != nil {
		t.Fatal("an expired token resolved to a signed-in user")
	}
	if got.Kind != payload.RejectExpired {
		t.Fatalf("kind is %q, want expired", got.Kind)
	}
	if got.Name != "ada" {
		t.Fatalf("the name for the log is %q, want the one that was signed", got.Name)
	}
}

// ---------------------------------------------------------------------------
// The login decision (§19's ordering)
// ---------------------------------------------------------------------------

func TestTheRightPasswordMintsASessionThatVerifies(t *testing.T) {
	g, posture := gated(t, true)

	got := g.Attempt(posture, "ada", "one", at(0))

	if !got.OK || got.Status != http.StatusOK {
		t.Fatalf("the right password was refused: %+v", got)
	}
	if _, _, err := g.Signer.Verify(got.Token, at(1)); err != nil {
		t.Fatalf("the minted token does not verify: %v", err)
	}
	if got.Claims.Via != payload.MethodPasswd || got.Username != "ada" {
		t.Fatalf("the outcome does not describe the sign-in: %+v", got)
	}
}

func TestAWrongPasswordAndAnUnknownNameAreAnsweredIdentically(t *testing.T) {
	g, posture := gated(t, true)

	wrong := g.Attempt(posture, "ada", "two", at(0))
	unknown := g.Attempt(posture, "grace", "two", at(0))

	for _, got := range []Login{wrong, unknown} {
		if got.OK || got.Status != http.StatusUnauthorized || got.Reason != payload.FailCredentials {
			t.Fatalf("expected 401 credentials, got %+v", got)
		}
		if got.Token != "" {
			t.Fatal("a failed attempt produced a token")
		}
	}
	if wrong.Reason != unknown.Reason || wrong.Status != unknown.Status {
		t.Fatal("a wrong password and an unknown name are distinguishable, which enumerates accounts")
	}
}

// §19: the lock is **checked before the password, so it holds regardless of whether the password was
// right**. A lock that opened for the correct password would not be a lock — and since the ordering is
// what makes that true, reverting the order is exactly what this must catch.
func TestALockedNameIsRefusedEvenWhenThePasswordIsCorrect(t *testing.T) {
	g, posture := gated(t, true)

	for i := 0; i < 3; i++ {
		g.Attempt(posture, "ada", "wrong", at(i))
	}

	got := g.Attempt(posture, "ada", "one", at(4))

	if got.OK {
		t.Fatal("the correct password opened a locked name; the throttle must be consulted before the password")
	}
	if got.Status != http.StatusTooManyRequests || got.Reason != payload.FailThrottled {
		t.Fatalf("expected 429 throttled, got %+v", got)
	}
	if got.RetryAfter <= 0 {
		t.Fatalf("retry-after is %v", got.RetryAfter)
	}
	if got.Token != "" {
		t.Fatal("a throttled attempt produced a token")
	}
}

// The attempt that reaches the limit is answered as throttled rather than as a bad password, so the person
// who mistyped learns to wait rather than typing again.
func TestTheAttemptThatReachesTheLimitCarriesTheRetryAfter(t *testing.T) {
	g, posture := gated(t, true)

	g.Attempt(posture, "ada", "wrong", at(0))
	g.Attempt(posture, "ada", "wrong", at(1))
	got := g.Attempt(posture, "ada", "wrong", at(2))

	if got.Status != http.StatusTooManyRequests || got.Reason != payload.FailThrottled {
		t.Fatalf("expected the third failure to be reported as throttled, got %+v", got)
	}
	if got.RetryAfter <= 0 {
		t.Fatalf("retry-after is %v", got.RetryAfter)
	}
}

func TestASuccessfulSignInClearsTheCountSoTheNextTypoDoesNotLock(t *testing.T) {
	g, posture := gated(t, true)

	g.Attempt(posture, "ada", "wrong", at(0))
	g.Attempt(posture, "ada", "wrong", at(1))
	if got := g.Attempt(posture, "ada", "one", at(2)); !got.OK {
		t.Fatalf("the right password after two failures was refused: %+v", got)
	}

	if got := g.Attempt(posture, "ada", "wrong", at(3)); got.Reason != payload.FailCredentials {
		t.Fatalf("the count survived a success: %+v", got)
	}
}

// §19: an attempt against a method that is not available is **not a failed attempt** — 503, and nothing
// counted.
func TestAnAttemptAgainstADeadMethodIsNotJudgedAndNotCounted(t *testing.T) {
	g, posture := gated(t, false)

	for i := 0; i < 10; i++ {
		got := g.Attempt(posture, "ada", "one", at(i))

		if got.Status != http.StatusServiceUnavailable || got.Reason != payload.FailMethodUnavailable {
			t.Fatalf("expected 503 method-unavailable, got %+v", got)
		}
	}
	if g.Throttle.Tracked() != 0 {
		t.Fatalf("%d names were counted against an unavailable method", g.Throttle.Tracked())
	}
}

func TestTheOutcomeCarriesASanitisedNameAndNeverThePassword(t *testing.T) {
	g, posture := gated(t, true)

	got := g.Attempt(posture, "ada\nsigned in: root", "hunter2", at(0))

	if got.Username != UnknownUsername {
		t.Fatalf("the log name is %q; §16 requires it sanitised", got.Username)
	}
	if strings.Contains(got.Detail, "hunter2") {
		t.Fatalf("the detail carries the password: %q", got.Detail)
	}
}

// §19: the provider path does not touch the password throttle. A name locked at the passwd file has proved
// nothing to the provider, and a provider sign-in has proved nothing about the password.
func TestAcceptNeitherConsultsNorResetsThePasswordThrottle(t *testing.T) {
	g, _ := gated(t, true)
	posture := Resolve(config.AuthConfig{
		Passwd: config.PasswdConfig{Enabled: true, File: "/p"},
		OIDC:   config.OIDCConfig{Enabled: true, Issuer: "https://idp.example.com", ClientID: "labview"},
	}, ParsePasswd([]byte("ada:"+hash(t, "one")+"\n")))

	// Lock the name at the passwd file.
	for i := 0; i < 3; i++ {
		g.Attempt(posture, "ada", "wrong", at(i))
	}

	got := g.Accept(posture, "ada", payload.MethodOIDC, at(4))
	if !got.OK {
		t.Fatalf("a provider sign-in was refused because the password was locked: %+v", got)
	}
	if got.Claims.Via != payload.MethodOIDC {
		t.Fatalf("the session says it came from %q", got.Claims.Via)
	}

	// And the lock is still there afterwards.
	if attempt := g.Attempt(posture, "ada", "one", at(5)); attempt.OK {
		t.Fatal("a provider sign-in cleared the password lock")
	}
}

func TestAcceptRefusesAMethodThatIsNotLive(t *testing.T) {
	g, posture := gated(t, true)

	got := g.Accept(posture, "ada", payload.MethodOIDC, at(0))

	if got.OK || got.Status != http.StatusServiceUnavailable {
		t.Fatalf("a session was minted for a method that is not live: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

func TestLogoutRevokesTheSessionAndClearsTheCookie(t *testing.T) {
	g, posture := gated(t, true)
	minted := g.Attempt(posture, "ada", "one", at(0))

	r := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: minted.Token})

	cookie := g.Logout(r)

	if cookie == nil || cookie.MaxAge != -1 {
		t.Fatalf("the clearing cookie is %+v", cookie)
	}
	if _, kind, err := g.Signer.Verify(minted.Token, at(1)); err == nil || kind != payload.RejectRevoked {
		t.Fatalf("the token still verifies after a logout (kind %q, err %v)", kind, err)
	}
}

// §19's revocation cap has a public trigger, so the set must only ever grow for a session that was
// actually ours: an unauthenticated caller filling it would evict real revocations, which is a sign-out
// that silently un-signs-out.
func TestAnUnauthenticatedLogoutRevokesNothing(t *testing.T) {
	g, _ := gated(t, true)

	for i := 0; i < 50; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
		if i%2 == 0 {
			r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: "v1.forged" + itoa(i) + ".signature"})
		}

		if cookie := g.Logout(r); cookie == nil {
			t.Fatal("a logout with no session did not return the clearing cookie")
		}
	}

	if g.Signer.Revocations() != 0 {
		t.Fatalf("%d identifiers were revoked by unauthenticated callers", g.Signer.Revocations())
	}
}

// ---------------------------------------------------------------------------
// The session endpoint's payload
// ---------------------------------------------------------------------------

func TestSessionInfoDescribesThePostureThatGatesTheRequest(t *testing.T) {
	g, _ := gated(t, true)

	r := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	signedIn(t, g, r, "ada")

	got := g.SessionInfo(r)

	if !got.AccessMode.Enforced {
		t.Fatal("the session endpoint says nothing is enforced while the gate enforces")
	}
	if got.User == nil || got.User.Name != "ada" {
		t.Fatalf("the signed-in user is %+v", got.User)
	}
}

// A UI that renders *a label exists, show the button* must not be handed a label for a sign-in that would
// fail.
func TestTheProviderLabelIsWithheldWhenTheMethodIsNotLive(t *testing.T) {
	g, _ := gated(t, true)

	got := g.SessionInfo(httptest.NewRequest(http.MethodGet, "/api/session", nil))

	if got.OIDCLabel != "" {
		t.Fatalf("a provider label (%q) was served with the method not live", got.OIDCLabel)
	}
	if got.User != nil {
		t.Fatalf("an anonymous request was reported as signed in: %+v", got.User)
	}
}

// The viewer the guard already resolved is preferred, so a public route and a gated one agree about who is
// calling rather than each verifying the token separately.
func TestSessionInfoPrefersTheViewerTheGuardResolved(t *testing.T) {
	g, _ := gated(t, true)

	var got payload.SessionInfo
	r := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	signedIn(t, g, r, "ada")

	g.Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = g.SessionInfo(r)
	})).ServeHTTP(httptest.NewRecorder(), r)

	if got.User == nil || got.User.Name != "ada" {
		t.Fatalf("the guarded viewer did not reach the session payload: %+v", got.User)
	}
}

// A gate configured without a throttle is weaker, not broken (I4) — and several goroutines sharing the
// default must not race.
func TestAGateWithNoThrottleStillSignsPeopleIn(t *testing.T) {
	g, posture := gated(t, true)
	g.Throttle = nil

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for n := 0; n < 20; n++ {
				g.Attempt(posture, "ada", "wrong", at(n))
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}

	if got := g.Attempt(posture, "ada", "one", at(0)); !got.OK {
		t.Fatalf("160 failures against a gate with no throttle locked the name anyway: %+v", got)
	}
}
