package httpapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/access"
	"github.com/nrosier/labview/internal/config"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// ---------------------------------------------------------------------------
// GET /api/session
// ---------------------------------------------------------------------------

// §18: the route is public, and what it answers is the posture. The UI has to know whether to render a
// login form before it has a session, so this is asserted while enforcing and with no cookie — the case
// where a gated route would refuse.
func TestTheSessionRouteAnswersThePostureWithoutASession(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	rec := l.do(get("/api/session"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the session route answered %d while enforcing: %s", rec.Code, rec.Body.String())
	}

	var info payload.SessionInfo
	decode(t, rec, &info)

	if !info.Enforced || len(info.Methods) != 1 || info.Methods[0] != payload.MethodPasswd {
		t.Fatalf("the posture is %+v, want passwd enforced", info.AccessMode)
	}
	if !info.Consistent() {
		t.Fatalf("the posture contradicts itself: %+v", info.AccessMode)
	}
	if info.User != nil {
		t.Fatalf("a request with no cookie was told it is signed in as %+v", info.User)
	}
}

func TestTheSessionRouteNamesWhoeverIsSignedIn(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	r := get("/api/session")
	l.signIn(t, r, "ada")

	var info payload.SessionInfo
	decode(t, l.do(r), &info)

	if info.User == nil || info.User.Name != "ada" || info.User.Via != payload.MethodPasswd {
		t.Fatalf("the session route reports %+v, want ada via passwd", info.User)
	}
}

// With nothing configured the posture is open, and the route says so rather than saying nothing: a UI
// that could not distinguish *no authentication* from *not asked yet* would render a login form on an
// open dashboard.
func TestWithNothingConfiguredTheSessionRouteReportsAnOpenPosture(t *testing.T) {
	l := newLab(t, labOptions{})

	var info payload.SessionInfo
	decode(t, l.do(get("/api/session")), &info)

	if info.Enforced || len(info.Methods) != 0 {
		t.Fatalf("the posture is %+v, want open with no methods", info.AccessMode)
	}
	if len(info.Notes) != 0 {
		t.Fatalf("an install that never configured authentication was given notes: %q", info.Notes)
	}
}

// ---------------------------------------------------------------------------
// POST /api/login
// ---------------------------------------------------------------------------

func login(t *testing.T, l *lab, name, secret string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(credentials{Username: name, Password: secret})
	if err != nil {
		t.Fatalf("encoding the credentials: %v", err)
	}
	return l.do(post("/api/login", string(body)))
}

// The right password mints a session, and the cookie it sets is one the gate accepts on a data route —
// which is the only assertion that says the two halves are the same session.
func TestTheRightPasswordMintsASessionThatOpensTheDataRoutes(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	rec := login(t, l, "ada", "one")
	if rec.Code != http.StatusOK {
		t.Fatalf("a correct password answered %d: %s", rec.Code, rec.Body.String())
	}

	var reply loginReply
	decode(t, rec, &reply)
	if !reply.OK || reply.User == nil || reply.User.Name != "ada" || reply.User.Via != payload.MethodPasswd {
		t.Fatalf("the reply is %+v, want ada via passwd", reply)
	}
	if reply.Error != "" || reply.Reason != "" {
		t.Fatalf("a successful sign-in carried a failure: %+v", reply)
	}

	cookie := cookieNamed(rec, access.DefaultCookieName)
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}
	if !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("the session cookie is %+v; §19 requires HttpOnly, path / and SameSite=Lax", cookie)
	}

	// The half that matters: it works.
	r := get("/api/overview")
	r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	if got := overviewOf(t, l.do(r)); got.Stats.Stacks != 1 {
		t.Fatalf("the minted session read build %d", got.Stats.Stacks)
	}
}

// A rejected attempt: the code, the sentence, and **no cookie**. The reply is the same for a wrong
// password as for a name that does not exist, because a reply that distinguished them would enumerate
// accounts (§19).
func TestAWrongPasswordAndAnUnknownNameAreRefusedIdentically(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	wrong := login(t, l, "ada", "two")
	unknown := login(t, l, "grace", "two")

	for what, rec := range map[string]*httptest.ResponseRecorder{"a wrong password": wrong, "an unknown name": unknown} {
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s answered %d, want 401", what, rec.Code)
		}
		if cookieNamed(rec, access.DefaultCookieName) != nil {
			t.Fatalf("%s set a session cookie", what)
		}
		var reply loginReply
		decode(t, rec, &reply)
		if reply.OK || reply.User != nil {
			t.Fatalf("%s answered %+v", what, reply)
		}
		if reply.Reason != payload.FailCredentials {
			t.Fatalf("%s was refused as %q, want %q", what, reply.Reason, payload.FailCredentials)
		}
		if reply.Error != sentences[payload.FailCredentials] {
			t.Fatalf("%s rendered as %q", what, reply.Error)
		}
	}

	if wrong.Body.String() != unknown.Body.String() {
		t.Fatalf("the two refusals differ:\n  wrong password: %s\n  unknown name:   %s",
			wrong.Body.String(), unknown.Body.String())
	}
}

// §19: the throttle is per username, with the lockout as the Retry-After. Rounded up — a header that
// rounded down would invite the client back a fraction of a second before the lock lifts and be answered
// with another 429.
func TestAFourthFailedAttemptIsThrottledWithARetryAfterThatDoesNotRoundDown(t *testing.T) {
	clock := at(0)
	l := newLab(t, labOptions{enforce: true, now: func() time.Time { return clock }})

	// Two of the three the throttle allows, so the next one is the attempt that *reaches* the limit —
	// which §19 answers with the lock rather than telling that caller their password was wrong and the
	// next one that they are locked out.
	for i := 0; i < 2; i++ {
		if rec := login(t, l, "ada", "two"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d answered %d, want 401", i+1, rec.Code)
		}
	}

	// Half a second into the window, so the remaining 59.5 seconds is a value that rounding down would
	// report as 59.
	clock = at(0).Add(500 * time.Millisecond)

	rec := login(t, l, "ada", "two")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the attempt that reached the limit answered %d, want 429", rec.Code)
	}

	var reply loginReply
	decode(t, rec, &reply)
	if reply.Reason != payload.FailThrottled {
		t.Fatalf("the attempt that reached the limit was refused as %q", reply.Reason)
	}

	header := rec.Header().Get("Retry-After")
	seconds, err := strconv.Atoi(header)
	if err != nil {
		t.Fatalf("Retry-After is %q, which is not a whole number of seconds", header)
	}
	if seconds != 60 {
		t.Fatalf("Retry-After is %d, want 60 — 59.5 seconds of lockout must not be reported as 59", seconds)
	}

	// The lock is on the name, not on the caller: a correct password for a different name still works.
	if rec := login(t, l, "ada", "one"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a locked-out name was judged on its password (%d)", rec.Code)
	}
}

// I6: the password reaches neither the reply nor the log. Asserted with a distinctive one, so a match is
// the password and not a substring of something else.
func TestThePasswordReachesNeitherTheReplyNorTheLog(t *testing.T) {
	const secret = "hunter-two-correct-horse-battery"

	l := newLab(t, labOptions{enforce: true})
	rec := login(t, l, "ada", secret)

	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("the reply carried the password: %s", rec.Body.String())
	}
	if strings.Contains(strings.Join(rec.Header().Values("Retry-After"), " "), secret) {
		t.Fatal("the headers carried the password")
	}

	event := l.last(t, EventLogin)
	rendered, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("rendering the event: %v", err)
	}
	if strings.Contains(string(rendered), secret) {
		t.Fatalf("the log line carried the password: %s", rendered)
	}
	if event.Username != "ada" || event.OK {
		t.Fatalf("the log line is %+v, want a failed attempt naming ada", event)
	}
}

// A body that is not a JSON object is refused **without being judged**: an attempt that was never
// judged must not be reported as one that failed, and must not spend an attempt against the throttle.
func TestALoginBodyThatIsNotAJSONObjectIsRefusedWithoutBeingJudged(t *testing.T) {
	for _, body := range []string{`[]`, `"ada"`, `{"username":`, `42`} {
		l := newLab(t, labOptions{enforce: true})
		rec := l.do(post("/api/login", body))

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s answered %d, want 400", body, rec.Code)
		}
		var reply errorReply
		decode(t, rec, &reply)
		if reply.Reason != "" {
			t.Fatalf("%s was answered with the login failure code %q; it was never judged", body, reply.Reason)
		}

		l.mu.Lock()
		events := len(l.events)
		l.mu.Unlock()
		if events != 0 {
			t.Fatalf("%s produced %d log events", body, events)
		}
	}
}

func TestAnOversizedLoginBodyIsRefusedRatherThanRead(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	rec := l.do(post("/api/login", `{"username":"ada","password":"`+strings.Repeat("x", MaxBodyBytes)+`"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an oversized body answered %d, want 400", rec.Code)
	}
	var reply errorReply
	decode(t, rec, &reply)
	if !strings.Contains(reply.Error, "body") {
		t.Fatalf("the refusal is %q; it must name the body rather than the credentials", reply.Error)
	}
}

// With no method live there is nothing to judge an attempt against, and the code says so rather than
// reporting the credentials as wrong (§19).
func TestALoginAttemptWithNothingConfiguredIsMethodUnavailable(t *testing.T) {
	l := newLab(t, labOptions{})

	rec := login(t, l, "ada", "one")

	var reply loginReply
	decode(t, rec, &reply)
	if reply.Reason != payload.FailMethodUnavailable {
		t.Fatalf("the attempt was refused as %q, want %q", reply.Reason, payload.FailMethodUnavailable)
	}
	if cookieNamed(rec, access.DefaultCookieName) != nil {
		t.Fatal("a sign-in with no method configured minted a session")
	}
}

// ---------------------------------------------------------------------------
// POST /api/logout
// ---------------------------------------------------------------------------

// Clearing the cookie is not enough: the token is revoked, so a copy of it taken before the logout does
// not still open the data routes (§19).
func TestLogoutClearsTheCookieAndRevokesTheTokenItCleared(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	minted := cookieNamed(login(t, l, "ada", "one"), access.DefaultCookieName)
	if minted == nil {
		t.Fatal("no session to log out of")
	}
	held := &http.Cookie{Name: minted.Name, Value: minted.Value}

	signedIn := get("/api/overview")
	signedIn.AddCookie(held)
	if rec := l.do(signedIn); rec.Code != http.StatusOK {
		t.Fatalf("the session did not open the overview: %d", rec.Code)
	}

	out := post("/api/logout", "")
	out.AddCookie(held)
	rec := l.do(out)

	if rec.Code != http.StatusOK {
		t.Fatalf("logout answered %d: %s", rec.Code, rec.Body.String())
	}
	var reply okReply
	decode(t, rec, &reply)
	if !reply.OK {
		t.Fatalf("logout answered %+v", reply)
	}

	cleared := cookieNamed(rec, access.DefaultCookieName)
	if cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Fatalf("logout set %+v, want the cookie cleared", cleared)
	}

	replay := get("/api/overview")
	replay.AddCookie(held)
	if rec := l.do(replay); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a token taken before the logout still answered %d; clearing a cookie is not revoking a session", rec.Code)
	}

	if got := l.last(t, EventLogout).Username; got != "ada" {
		t.Fatalf("the logout was logged as %q, want the subject of the session it ended", got)
	}
}

// A logout with no session answers the same 200. One that reported *you were not signed in* would be a
// way to ask whether a token is still valid without holding one.
func TestALogoutWithNoSessionAnswersTheSame(t *testing.T) {
	l := newLab(t, labOptions{enforce: true})

	rec := l.do(post("/api/logout", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("a logout with no session answered %d", rec.Code)
	}
	var reply okReply
	decode(t, rec, &reply)
	if !reply.OK {
		t.Fatalf("answered %+v", reply)
	}
}

// ---------------------------------------------------------------------------
// The eight sentences
// ---------------------------------------------------------------------------

// §4.7 fixes eight codes. The table is total over them, because a code with no sentence is an empty
// string a browser renders as nothing.
func TestEveryFailureCodeRendersAsItsOwnSentence(t *testing.T) {
	all := []payload.LoginFailureReason{
		payload.FailCredentials,
		payload.FailThrottled,
		payload.FailMethodUnavailable,
		payload.FailSessionExpired,
		payload.FailOIDCState,
		payload.FailOIDCProvider,
		payload.FailOIDCToken,
		payload.FailOIDCIdentity,
	}

	if len(sentences) != len(all) {
		t.Fatalf("there are %d sentences for %d codes", len(sentences), len(all))
	}

	seen := map[string]payload.LoginFailureReason{}
	for _, reason := range all {
		got := Sentence(reason)
		if got == "" {
			t.Fatalf("%q renders as nothing", reason)
		}
		if strings.Contains(got, string(reason)) && reason != payload.FailCredentials {
			t.Fatalf("%q renders as its own code (%q) rather than as a sentence", reason, got)
		}
		if first, ok := seen[got]; ok {
			t.Fatalf("%q and %q render identically as %q", first, reason, got)
		}
		seen[got] = reason
	}
}

// A code from outside the closed set renders as the generic sentence rather than as itself: a value that
// arrived from somewhere unexpected is not one to reflect back into a response body.
func TestAnUnknownFailureCodeRendersGenerically(t *testing.T) {
	got := Sentence(payload.LoginFailureReason("<script>alert(1)</script>"))

	if got != "the sign-in did not succeed" {
		t.Fatalf("an unknown code rendered as %q", got)
	}
}

// ---------------------------------------------------------------------------
// The provider handshake
// ---------------------------------------------------------------------------

// The two routes stay registered when no provider is configured, and answer with a code the UI can
// render — because a browser that still has a sign-in button must not be sent the UI shell where a
// redirect was expected (§18).
func TestTheOIDCRoutesRedirectWithMethodUnavailableWhenNoProviderIsConfigured(t *testing.T) {
	l := newLab(t, labOptions{})

	for _, path := range []string{"/auth/oidc/start", "/auth/oidc/callback"} {
		rec := l.do(get(path))

		if rec.Code != http.StatusFound {
			t.Fatalf("%s answered %d, want 302", path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "/?login_error=method-unavailable" {
			t.Fatalf("%s redirected to %q", path, got)
		}
		if cookieNamed(rec, access.DefaultCookieName) != nil {
			t.Fatalf("%s minted a session with no provider configured", path)
		}
	}
}

// The whole handshake, driven the way a browser drives it: start, read the redirect, hand the provider's
// answer back to the callback. What is asserted is the wiring §18 specifies — the transient cookie, the
// two redirects, and a session that opens the data routes.
func TestACompletedHandshakeMintsASessionAndSendsTheBrowserToTheDashboard(t *testing.T) {
	idp := newIDP()
	l := newLab(t, labOptions{oidc: idp.provider(), oidcConfig: idp.config()})

	started := l.do(get("/auth/oidc/start"))
	if started.Code != http.StatusFound {
		t.Fatalf("start answered %d: %s", started.Code, started.Body.String())
	}

	target, err := url.Parse(started.Header().Get("Location"))
	if err != nil {
		t.Fatalf("the authorize URL is not a URL: %v", err)
	}
	if target.Scheme != "https" || target.Host != "idp.example.com" {
		t.Fatalf("the browser was sent to %q", target)
	}
	query := target.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("the authorization request carried no PKCE challenge: %v", query)
	}

	handshake := cookieNamed(started, access.TransientCookieName)
	if handshake == nil || handshake.Value == "" {
		t.Fatal("start set no handshake cookie, so no callback could ever be checked")
	}
	if !handshake.HttpOnly || handshake.Path != "/auth/oidc/callback" {
		t.Fatalf("the handshake cookie is %+v; §19 scopes it to the callback path", handshake)
	}

	// The provider mints its ID token for the nonce this handshake committed to.
	idp.issue(t, query.Get("nonce"), "grace")

	back := get("/auth/oidc/callback?code=an-authorization-code&state=" + url.QueryEscape(query.Get("state")))
	back.AddCookie(&http.Cookie{Name: handshake.Name, Value: handshake.Value})
	rec := l.do(back)

	if rec.Code != http.StatusFound {
		t.Fatalf("the callback answered %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("a completed sign-in redirected to %q, want the dashboard", got)
	}

	session := cookieNamed(rec, access.DefaultCookieName)
	if session == nil || session.Value == "" {
		t.Fatal("the callback minted no session")
	}

	// Cleared on the way through, so the state and nonce cannot be replayed.
	if cleared := cookieNamed(rec, access.TransientCookieName); cleared == nil || cleared.Value != "" {
		t.Fatalf("the handshake cookie was left as %+v", cleared)
	}

	r := get("/api/overview")
	r.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	if rec := l.do(r); rec.Code != http.StatusOK {
		t.Fatalf("the provider session did not open the overview: %d %s", rec.Code, rec.Body.String())
	}

	var info payload.SessionInfo
	whoami := get("/api/session")
	whoami.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	decode(t, l.do(whoami), &info)
	if info.User == nil || info.User.Name != "grace" || info.User.Via != payload.MethodOIDC {
		t.Fatalf("the session is %+v, want grace via oidc", info.User)
	}

	if event := l.last(t, EventOIDCCallback); !event.OK || event.Username != "grace" || event.Via != payload.MethodOIDC {
		t.Fatalf("the callback was logged as %+v", event)
	}
}

// The same callback twice. The second one arrives with the cookie the first was answered with — which is
// none, because the transient cookie is cleared on the way through — so the replay is refused.
func TestTheHandshakeCookieCannotBeReplayed(t *testing.T) {
	idp := newIDP()
	l := newLab(t, labOptions{oidc: idp.provider(), oidcConfig: idp.config()})

	started := l.do(get("/auth/oidc/start"))
	query := mustURL(t, started.Header().Get("Location")).Query()
	idp.issue(t, query.Get("nonce"), "grace")

	callback := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		r := get("/auth/oidc/callback?code=an-authorization-code&state=" + url.QueryEscape(query.Get("state")))
		if cookie != nil {
			r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
		return l.do(r)
	}

	handshake := cookieNamed(started, access.TransientCookieName)
	if rec := callback(handshake); cookieNamed(rec, access.DefaultCookieName) == nil {
		t.Fatalf("the first callback did not complete: %d %s", rec.Code, rec.Body.String())
	}

	// The browser's copy is gone, so this is what a replay actually looks like.
	rec := callback(nil)
	if got := rec.Header().Get("Location"); got != "/?login_error=oidc-state" {
		t.Fatalf("a replayed callback redirected to %q", got)
	}
	if cookieNamed(rec, access.DefaultCookieName) != nil {
		t.Fatal("a callback with no handshake minted a session")
	}
}

// Every way the handshake can fail ends the same way: a 302 to the dashboard with a code, no session,
// and the handshake cookie cleared. The browser is not left holding a spent state and the reader is not
// left on a blank page.
func TestAFailedHandshakeRedirectsWithACodeAndClearsTheHandshake(t *testing.T) {
	for _, tc := range []struct {
		name     string
		query    string
		withIDP  func(*idp)
		wantCode payload.LoginFailureReason
	}{
		{
			name:     "the provider refused the authorization request",
			query:    "?error=access_denied",
			wantCode: payload.FailOIDCProvider,
		},
		{
			name:     "no authorization code",
			query:    "?state=whatever",
			wantCode: payload.FailOIDCState,
		},
		{
			name:     "a state that does not match",
			query:    "?code=a-code&state=not-the-one-this-browser-started-with",
			wantCode: payload.FailOIDCState,
		},
		{
			name:     "the token endpoint refuses the exchange",
			query:    "?code=a-code",
			withIDP:  func(p *idp) { p.refuse("invalid_grant") },
			wantCode: payload.FailOIDCProvider,
		},
		{
			name:     "the token response carries no id_token",
			query:    "?code=a-code",
			withIDP:  func(p *idp) { p.silent() },
			wantCode: payload.FailOIDCToken,
		},
		{
			name:     "the id token is signed by somebody else",
			query:    "?code=a-code",
			withIDP:  func(p *idp) { p.forge() },
			wantCode: payload.FailOIDCToken,
		},
		{
			name:     "the id token names nobody",
			query:    "?code=a-code",
			withIDP:  func(p *idp) { p.anonymous() },
			wantCode: payload.FailOIDCIdentity,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newIDP()
			l := newLab(t, labOptions{oidc: idp.provider(), oidcConfig: idp.config()})

			started := l.do(get("/auth/oidc/start"))
			query := mustURL(t, started.Header().Get("Location")).Query()
			idp.issue(t, query.Get("nonce"), "grace")
			if tc.withIDP != nil {
				tc.withIDP(idp)
			}

			// The started state, so only the case that means to break it does.
			target := "/auth/oidc/callback" + tc.query
			if strings.Contains(tc.query, "state=whatever") {
				target = "/auth/oidc/callback?state=" + url.QueryEscape(query.Get("state"))
			} else if strings.Contains(tc.query, "code=a-code") && !strings.Contains(tc.query, "state=") {
				target += "&state=" + url.QueryEscape(query.Get("state"))
			}

			r := get(target)
			if handshake := cookieNamed(started, access.TransientCookieName); handshake != nil {
				r.AddCookie(&http.Cookie{Name: handshake.Name, Value: handshake.Value})
			}
			rec := l.do(r)

			if rec.Code != http.StatusFound {
				t.Fatalf("answered %d, want 302: %s", rec.Code, rec.Body.String())
			}
			want := "/?login_error=" + url.QueryEscape(string(tc.wantCode))
			if got := rec.Header().Get("Location"); got != want {
				t.Fatalf("redirected to %q, want %q", got, want)
			}
			if cookieNamed(rec, access.DefaultCookieName) != nil {
				t.Fatal("a failed handshake minted a session")
			}
			if cleared := cookieNamed(rec, access.TransientCookieName); cleared == nil || cleared.Value != "" {
				t.Fatalf("the handshake cookie was left as %+v; a failed handshake must not stay replayable", cleared)
			}

			// The log gets the reason; the browser got the code. The reason is the half a client is not
			// told, so it must be there and must say more than the code.
			event := l.last(t, EventOIDCCallback)
			if event.Reason != tc.wantCode {
				t.Fatalf("logged as %q, want %q", event.Reason, tc.wantCode)
			}
			if event.Detail == "" {
				t.Fatal("the log line carries no reason, so the operator has only the code the browser got")
			}
		})
	}
}

// The failure a reader can cause with no provider reachable at all. The report is what §15 requires of a
// failed read, and it belongs in the log rather than in the redirect.
func TestAProviderThatCannotBeReadIsReportedToTheLogAndNotToTheBrowser(t *testing.T) {
	idp := newIDP()
	idp.unreachable()
	l := newLab(t, labOptions{oidc: idp.provider(), oidcConfig: idp.config()})

	rec := l.do(get("/auth/oidc/start"))

	if got := rec.Header().Get("Location"); got != "/?login_error=oidc-provider" {
		t.Fatalf("start redirected to %q", got)
	}
	if strings.Contains(rec.Header().Get("Location"), "idp.example.com") {
		t.Fatal("the redirect names the provider's endpoint")
	}

	event := l.last(t, EventOIDCStart)
	if event.Report == nil {
		t.Fatal("a failed provider read reached the log with no connection report")
	}
	if event.Report.OK {
		t.Fatalf("the report says the read succeeded: %+v", event.Report)
	}
}

// ---------------------------------------------------------------------------
// A canned identity provider
// ---------------------------------------------------------------------------

const (
	idpIssuer   = "https://idp.example.com"
	idpClientID = "labview-test-client"
	idpKeyID    = "test-1"
)

// idpKey is the provider's signing key, generated once. Key generation is the expensive part of this
// file and every test wants the same provider.
var idpKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("generating the test provider's key: " + err.Error())
	}
	return key
})

// otherKey is a second key nobody published, for the token signed by somebody else.
var otherKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("generating a second key: " + err.Error())
	}
	return key
})

// idp is a provider that answers over the transport chokepoint rather than over a socket, so the
// handshake is exercised end to end with no listener and no wall-clock timeouts.
type idp struct {
	mu        sync.Mutex
	token     string // the id_token the token endpoint returns
	refusal   string // an OAuth error code, instead of a token
	reachable bool
}

func newIDP() *idp { return &idp{reachable: true} }

func (p *idp) config() config.OIDCConfig {
	return config.OIDCConfig{
		Enabled:       true,
		Issuer:        idpIssuer,
		ClientID:      idpClientID,
		RedirectURI:   "https://labview.example.com/auth/oidc/callback",
		Scopes:        []string{"openid", "profile"},
		UsernameClaim: "preferred_username",
		Label:         "Sign in with the test provider",
	}
}

func (p *idp) provider() *access.Provider {
	cfg := p.config()
	return &access.Provider{
		Config: func() access.OIDCSettings {
			return access.OIDCSettings{
				Issuer:        cfg.Issuer,
				ClientID:      cfg.ClientID,
				RedirectURI:   cfg.RedirectURI,
				Scopes:        cfg.Scopes,
				UsernameClaim: cfg.UsernameClaim,
			}
		},
		HTTP:   p,
		Signer: access.NewSigner("a test signing secret that is long enough", time.Hour),
		Now:    func() time.Time { return at(0) },
	}
}

// issue installs the ID token this provider will return, minted for one nonce.
func (p *idp) issue(t *testing.T, nonce, username string) {
	t.Helper()
	p.set(p.mint(t, idpKey(), nonce, map[string]any{"preferred_username": username}))
}

// forge installs a token signed by a key the provider never published.
func (p *idp) forge() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = signJWT(otherKey(), map[string]any{
		"iss": idpIssuer, "aud": idpClientID, "sub": "s-1",
		"exp": at(300).Unix(), "iat": at(0).Unix(),
		"nonce": "whatever", "preferred_username": "grace",
	})
}

// anonymous installs a token that verifies and names nobody usable.
//
// Every claim in §19's chain is either absent or unusable — a `sub` with spaces in it is what a provider
// configured to issue display names produces, and it is not a username.
func (p *idp) anonymous() {
	p.mu.Lock()
	token := p.token
	p.mu.Unlock()

	// The nonce this handshake committed to, taken from the token already minted for it, so only the
	// username claim differs.
	nonce := ""
	if claims := claimsOf(token); claims != nil {
		nonce, _ = claims["nonce"].(string)
	}
	p.set(signJWT(idpKey(), map[string]any{
		"iss": idpIssuer, "aud": idpClientID, "sub": "Grace Hopper (she/her)",
		"exp": at(300).Unix(), "iat": at(0).Unix(), "nonce": nonce,
	}))
}

// silent makes the token endpoint answer without an id_token, which is what an OAuth flow that lost
// `openid` from its scopes looks like.
func (p *idp) silent() { p.set("") }

// refuse makes the token endpoint refuse the exchange.
func (p *idp) refuse(code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refusal = code
}

// unreachable makes every read of this provider fail at the connection.
func (p *idp) unreachable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reachable = false
}

func (p *idp) set(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = token
}

func (p *idp) mint(t *testing.T, key *rsa.PrivateKey, nonce string, extra map[string]any) string {
	t.Helper()
	if nonce == "" {
		t.Fatal("no nonce to mint an id token for; the authorize URL carried none")
	}
	claims := map[string]any{
		"iss": idpIssuer, "aud": idpClientID, "sub": "s-1",
		"exp": at(300).Unix(), "iat": at(0).Unix(), "nonce": nonce,
	}
	for k, v := range extra {
		claims[k] = v
	}
	return signJWT(key, claims)
}

// Do is the access.Doer this provider is reached through.
func (p *idp) Do(_ context.Context, req transport.Request) transport.Result {
	p.mu.Lock()
	token, refusal, reachable := p.token, p.refusal, p.reachable
	p.mu.Unlock()

	if !reachable {
		return transport.Result{
			Phase:    payload.PhaseConnect,
			Endpoint: req.URL,
			Err:      errUnreachable,
		}
	}

	switch req.URL {
	case idpIssuer + "/.well-known/openid-configuration":
		return answered(req.URL, map[string]any{
			"issuer":                 idpIssuer,
			"authorization_endpoint": idpIssuer + "/authorize",
			"token_endpoint":         idpIssuer + "/token",
			"jwks_uri":               idpIssuer + "/keys",
		})

	case idpIssuer + "/keys":
		key := idpKey().PublicKey
		return answered(req.URL, map[string]any{"keys": []map[string]any{{
			"kty": "RSA",
			"kid": idpKeyID,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})

	case idpIssuer + "/token":
		if refusal != "" {
			return answered(req.URL, map[string]any{"error": refusal})
		}
		return answered(req.URL, map[string]any{"token_type": "Bearer", "id_token": token})
	}

	return transport.Result{Phase: payload.PhaseNotFound, Endpoint: req.URL, Status: http.StatusNotFound}
}

var errUnreachable = &unreachableError{}

type unreachableError struct{}

func (*unreachableError) Error() string { return "connection refused" }

// answered is a 200 carrying a JSON document.
func answered(endpoint string, body map[string]any) transport.Result {
	encoded, err := json.Marshal(body)
	if err != nil {
		panic("encoding a canned provider reply: " + err.Error())
	}
	return transport.Result{
		Phase:    payload.PhaseConnected,
		Status:   http.StatusOK,
		Header:   http.Header{"Content-Type": []string{"application/json"}},
		Body:     encoded,
		Endpoint: endpoint,
	}
}

// signJWT is the provider's side of RS256: base64url header and claims, signed as one string.
func signJWT(key *rsa.PrivateKey, claims map[string]any) string {
	header := segment(map[string]any{"alg": "RS256", "typ": "JWT", "kid": idpKeyID})
	body := segment(claims)

	signed := header + "." + body
	sum := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic("signing a test id token: " + err.Error())
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func segment(v map[string]any) string {
	encoded, err := json.Marshal(v)
	if err != nil {
		panic("encoding a token segment: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// claimsOf reads a token's claims without verifying it, for the helpers that need the nonce back.
func claimsOf(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("%q is not a URL: %v", s, err)
	}
	return u
}

// §16, and the reason Normalize exists: `methods` and `notes` are **required** lists in Appendix A, so
// they go out as `[]` and never as `null`.
//
// The open case is the one that gets this wrong, because it is the one where the list is empty: a
// posture with nothing live builds no methods at all, and Go writes `null` for a nil slice. A consumer
// would then have to treat *no methods* differently from *an empty method list*, which is exactly the
// distinction Appendix A reserves for the fields it marks optional — and the UI decides whether to draw
// a login form off this payload.
func TestTheSessionRouteNeverAnswersWithANullList(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		name := "open"
		if enforce {
			name = "enforcing"
		}
		t.Run(name, func(t *testing.T) {
			l := newLab(t, labOptions{enforce: enforce})

			rec := l.do(get("/api/session"))
			if rec.Code != http.StatusOK {
				t.Fatalf("the session route answered %d: %s", rec.Code, rec.Body.String())
			}

			// Asserted on the bytes rather than on the decoded struct, because `null` and `[]` both
			// decode to a nil-or-empty slice in Go and only one of them is on the wire.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatalf("the session payload does not parse: %v", err)
			}
			for _, field := range []string{"methods", "notes"} {
				held, ok := raw[field]
				if !ok {
					t.Fatalf("%q is absent from the session payload, and it is required: %s", field, rec.Body.String())
				}
				if string(held) == "null" {
					t.Fatalf("%q went out as null rather than as a list: %s", field, rec.Body.String())
				}
			}
		})
	}
}
