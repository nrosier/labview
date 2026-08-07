package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// ---------------------------------------------------------------------------
// A provider that answers from a fixture rather than from a network
// ---------------------------------------------------------------------------

// canned is the HTTP chokepoint, replaced. It records every request, so a test can assert what was sent
// as well as what came back — which is how the client secret's placement and the one-refetch bound are
// checked at all.
type canned struct {
	mu     sync.Mutex
	routes map[string]func(transport.Request) transport.Result
	calls  []transport.Request
}

func newCanned() *canned {
	return &canned{routes: map[string]func(transport.Request) transport.Result{}}
}

func (c *canned) Do(_ context.Context, req transport.Request) transport.Result {
	c.mu.Lock()
	reply, ok := c.routes[req.URL]
	c.calls = append(c.calls, req)
	c.mu.Unlock()

	if !ok {
		// A request the fixture does not describe is a bug in the test, not a provider that is down —
		// so it comes back as a phase rather than silently as an empty success.
		return transport.Result{Phase: payload.PhaseResolve, Code: "no route in the fixture", Endpoint: req.URL}
	}
	return reply(req)
}

func (c *canned) route(target string, reply func(transport.Request) transport.Result) *canned {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.routes[target] = reply
	return c
}

// serves answers a URL with a JSON document and a full read.
func (c *canned) serves(target string, document any) *canned {
	body, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return c.raw(target, string(body))
}

func (c *canned) raw(target, body string) *canned {
	return c.route(target, func(transport.Request) transport.Result {
		return transport.Result{
			Phase:    payload.PhaseConnected,
			Status:   http.StatusOK,
			Body:     []byte(body),
			Endpoint: target,
		}
	})
}

// broken answers a URL with a transport failure already classified, as the real chokepoint would.
func (c *canned) broken(target string, phase payload.ConnectionPhase, code string) *canned {
	return c.route(target, func(transport.Request) transport.Result {
		return transport.Result{Phase: phase, Code: code, Endpoint: target}
	})
}

func (c *canned) count(target string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0
	for _, req := range c.calls {
		if req.URL == target {
			n++
		}
	}
	return n
}

func (c *canned) requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

// last is the most recent request to a URL, so a test can read what was sent.
func (c *canned) last(t *testing.T, target string) transport.Request {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := len(c.calls) - 1; i >= 0; i-- {
		if c.calls[i].URL == target {
			return c.calls[i]
		}
	}
	t.Fatalf("nothing was ever sent to %s", target)
	return transport.Request{}
}

const (
	discoveryURL = testIssuer + "/.well-known/openid-configuration"
	authorizeURL = testIssuer + "/authorize"
	tokenURL     = testIssuer + "/token"
	jwksURL      = testIssuer + "/jwks"
	redirectURI  = "https://lab.example.com/auth/oidc/callback"
)

// document is what a conforming provider publishes.
func document() Discovery {
	return Discovery{
		Issuer:                testIssuer,
		AuthorizationEndpoint: authorizeURL,
		TokenEndpoint:         tokenURL,
		JWKSURI:               jwksURL,
	}
}

func oidcSettings() OIDCSettings {
	return OIDCSettings{
		Issuer:       testIssuer,
		ClientID:     testClientID,
		ClientSecret: testSecret,
		RedirectURI:  redirectURI,
		Scopes:       []string{"profile", "email"},
	}
}

// conforming is a fixture whose discovery and key set are both good. The token endpoint is left to the
// test, because what it returns depends on the nonce the handshake generated.
func conforming() *canned {
	return newCanned().
		serves(discoveryURL, document()).
		serves(jwksURL, JWKS{Keys: providerKeys()})
}

// oidcProvider builds a provider over a fixture. The clock is the one from posture_test.go, so a test
// can move time without waiting for it.
func oidcProvider(t *testing.T, http Doer, cfg OIDCSettings, clock *postureClock) *Provider {
	t.Helper()
	if clock == nil {
		clock = &postureClock{at: at(0)}
	}
	return &Provider{
		Config: func() OIDCSettings { return cfg },
		HTTP:   http,
		Signer: signer(t),
		Now:    clock.now,
	}
}

// started runs Start and hands back the handshake the browser was given, unsealed.
func started(t *testing.T, p *Provider) (string, Handshake, *http.Cookie) {
	t.Helper()

	target, cookie, err := p.Start(context.Background(), httptest.NewRequest(http.MethodGet, "/api/login/oidc", nil))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	raw, err := p.unseal(cookie.Value)
	if err != nil {
		t.Fatalf("the cookie this program just sealed does not unseal: %v", err)
	}
	var held Handshake
	if err := json.Unmarshal(raw, &held); err != nil {
		t.Fatalf("unmarshalling our own handshake: %v", err)
	}
	return target, held, cookie
}

// callback builds the request a provider's redirect produces.
func callback(code, state string, cookie *http.Cookie) *http.Request {
	q := url.Values{}
	if code != "" {
		q.Set("code", code)
	}
	if state != "" {
		q.Set("state", state)
	}
	r := httptest.NewRequest(http.MethodGet, DefaultCallbackPath+"?"+q.Encode(), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

// tokenResponse makes the token endpoint return a conforming ID token for a handshake's nonce.
func tokenResponse(t *testing.T, fixture *canned, nonce string) {
	t.Helper()
	fixture.serves(tokenURL, map[string]any{
		"token_type":   "Bearer",
		"access_token": "an access token this program has no use for",
		"id_token": sign(t, "RS256", "k1", provider(), idClaims(at(0), map[string]any{
			"nonce": nonce, "preferred_username": "ada",
		})),
	})
}

// asFailure asserts an error is a handshake Failure carrying a code.
func asFailure(t *testing.T, err error, want payload.LoginFailureReason) Failure {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %s failure, got success", want)
	}
	got, ok := err.(Failure)
	if !ok {
		t.Fatalf("error is %T (%v), want a Failure so the browser can be redirected", err, err)
	}
	if got.Code != want {
		t.Fatalf("code is %q, want %q (reason: %s)", got.Code, want, got.Reason)
	}
	return got
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

func TestStartSendsTheBrowserToTheProviderWithEverythingTheHandshakeNeeds(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)

	target, held, _ := started(t, p)

	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("the authorization URL does not parse: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != authorizeURL {
		t.Fatalf("the browser is sent to %q, not to the discovered authorization endpoint", target)
	}

	q := u.Query()
	for name, want := range map[string]string{
		"response_type":         "code",
		"client_id":             testClientID,
		"redirect_uri":          redirectURI,
		"state":                 held.State,
		"nonce":                 held.Nonce,
		"code_challenge":        challenge(held.Verifier),
		"code_challenge_method": "S256",
	} {
		if got := q.Get(name); got != want {
			t.Fatalf("%s is %q, want %q", name, got, want)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("scope is %q and does not request openid", q.Get("scope"))
	}
}

// §19: **S256, never `plain`.** A `plain` challenge *is* the verifier, so anybody who saw the
// authorization request would hold everything needed to redeem the code — the mechanism would be present
// and worthless.
func TestThePKCEChallengeIsTheHashAndTheVerifierNeverLeavesThisProgram(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)

	target, held, _ := started(t, p)
	q, _ := url.ParseQuery(strings.SplitN(target, "?", 2)[1])

	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("the challenge method is %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == held.Verifier {
		t.Fatal("the challenge is the verifier itself, which is `plain` under an S256 label")
	}
	if q.Get("code_challenge") != challenge(held.Verifier) {
		t.Fatal("the challenge is not the hash of the verifier, so the provider's check would refuse the redemption")
	}
	if strings.Contains(target, held.Verifier) {
		t.Fatal("the verifier appears in the authorization URL, which defeats PKCE entirely")
	}
}

// §19: `openid` is **always** requested. Without it a provider runs a plain OAuth flow and returns no ID
// token — a handshake that completes and identifies nobody.
func TestOpenidIsAlwaysRequestedWhateverIsConfigured(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured []string
		want       []string
	}{
		{"nothing configured", nil, []string{"openid"}},
		{"the usual pair", []string{"profile", "email"}, []string{"openid", "profile", "email"}},
		{"openid configured too", []string{"openid", "profile"}, []string{"openid", "profile"}},
		{"a duplicate", []string{"profile", "profile"}, []string{"openid", "profile"}},
		{"padding", []string{" openid ", " profile "}, []string{"openid", "profile"}},
		{"an empty entry", []string{"", "profile"}, []string{"openid", "profile"}},
	} {
		got := scopes(tc.configured)

		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: scopes are %v, want %v", tc.name, got, tc.want)
		}
	}
}

// §19: the handshake cookie is **scoped to the callback path**. A cookie on `/` would travel on every
// request to every route including the API — a handshake secret in flight constantly, for one route.
func TestTheHandshakeCookieIsScopedToTheCallbackAndUnreadableByScript(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)

	_, _, cookie := started(t, p)

	if cookie.Name != TransientCookieName {
		t.Fatalf("name is %q", cookie.Name)
	}
	if cookie.Name == DefaultCookieName {
		t.Fatal("the handshake cookie shares the session cookie's name, so a browser could not hold both")
	}
	if cookie.Path != "/auth/oidc/callback" {
		t.Fatalf("path is %q, want the callback's own path", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Fatal("the handshake cookie is readable by script")
	}
	// Lax rather than Strict: the callback arrives as a top-level navigation from the provider, and
	// Strict would not send the cookie on it, so no handshake could ever complete.
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite is %v, want Lax", cookie.SameSite)
	}
	if cookie.MaxAge != int(HandshakeWindow.Seconds()) || cookie.MaxAge != 300 {
		t.Fatalf("Max-Age is %d, want 300", cookie.MaxAge)
	}
}

func TestTheCallbackPathIsTakenFromTheRedirectURIAndDefaultedWhenItNamesNone(t *testing.T) {
	for _, tc := range []struct{ redirect, want string }{
		{"https://lab.example.com/auth/oidc/callback", "/auth/oidc/callback"},
		{"https://lab.example.com/behind/a/prefix/callback", "/behind/a/prefix/callback"},
		{"https://lab.example.com", DefaultCallbackPath},
		{"https://lab.example.com/", DefaultCallbackPath},
		{"", DefaultCallbackPath},
		{"://", DefaultCallbackPath},
	} {
		if got := callbackPath(tc.redirect); got != tc.want {
			t.Fatalf("callbackPath(%q) = %q, want %q", tc.redirect, got, tc.want)
		}
	}

	// §19 puts the default outside `/api`, so the API's allowlist stays a statement about the API.
	if strings.HasPrefix(DefaultCallbackPath, "/api") {
		t.Fatalf("the default callback path is %q, inside the API surface", DefaultCallbackPath)
	}
	if Public(DefaultCallbackPath) {
		t.Fatal("the callback path is in the API's public allowlist, which it has no business being in")
	}
}

func TestTheHandshakeCookieIsSecureBehindAProxyTerminatingTLS(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)

	plain := httptest.NewRequest(http.MethodGet, "/api/login/oidc", nil)
	behind := httptest.NewRequest(http.MethodGet, "/api/login/oidc", nil)
	behind.Header.Set("X-Forwarded-Proto", "https")

	_, over, err := p.Start(context.Background(), plain)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, secured, err := p.Start(context.Background(), behind)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if over.Secure {
		t.Fatal("the cookie is Secure on plain http, so a browser would never send it back")
	}
	if !secured.Secure {
		t.Fatal("the cookie is not Secure behind a proxy that terminated TLS")
	}
}

// A provider whose authorization endpoint already carries a query keeps it: some publish a tenant or
// realm there, and overwriting it would send the browser to the wrong realm.
func TestAnAuthorizationEndpointThatAlreadyCarriesAQueryKeepsIt(t *testing.T) {
	fixture := newCanned().
		serves(discoveryURL, Discovery{
			Issuer:                testIssuer,
			AuthorizationEndpoint: authorizeURL + "?realm=lab",
			TokenEndpoint:         tokenURL,
			JWKSURI:               jwksURL,
		}).
		serves(jwksURL, JWKS{Keys: providerKeys()})
	p := oidcProvider(t, fixture, oidcSettings(), nil)

	target, _, _ := started(t, p)

	if strings.Count(target, "?") != 1 {
		t.Fatalf("the authorization URL has %d question marks: %s", strings.Count(target, "?"), target)
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Query().Get("realm") != "lab" {
		t.Fatalf("the provider's own query parameter was dropped: %s", target)
	}
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("our own parameters were dropped instead: %s", target)
	}
}

func TestStartRefusesWithoutAskingTheProviderAnythingWhenTheMethodIsNotConfigured(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  OIDCSettings
	}{
		{"no issuer", OIDCSettings{ClientID: testClientID}},
		{"no client id", OIDCSettings{Issuer: testIssuer}},
		{"neither", OIDCSettings{}},
		{"a blank issuer", OIDCSettings{Issuer: "   ", ClientID: testClientID}},
	} {
		fixture := conforming()
		p := oidcProvider(t, fixture, tc.cfg, nil)

		_, _, err := p.Start(context.Background(), httptest.NewRequest(http.MethodGet, "/api/login/oidc", nil))

		asFailure(t, err, payload.FailMethodUnavailable)
		if fixture.requests() != 0 {
			t.Fatalf("%s: %d requests were sent to an unconfigured provider", tc.name, fixture.requests())
		}
	}
}

func TestTwoSignInsNeverShareAHandshakeValue(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)
	seen := map[string]bool{}

	for i := 0; i < 20; i++ {
		_, held, _ := started(t, p)

		for _, value := range []string{held.State, held.Nonce, held.Verifier} {
			if value == "" {
				t.Fatal("a handshake value is empty")
			}
			if seen[value] {
				t.Fatal("two handshakes share a value; all three are worthless if guessable")
			}
			seen[value] = true
		}
	}
}

// ---------------------------------------------------------------------------
// The seal on the handshake cookie
// ---------------------------------------------------------------------------

func TestAHandshakeCookieThisProgramDidNotSignIsRefused(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	forger := oidcProvider(t, fixture, oidcSettings(), nil)
	forger.Signer = NewSigner("a secret that is not this program's own", time.Hour)

	_, held, cookie := started(t, forger)
	tokenResponse(t, fixture, held.Nonce)

	_, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))

	asFailure(t, err, payload.FailOIDCState)
	if fixture.count(tokenURL) != 0 {
		t.Fatal("a code was redeemed against a handshake this program never started")
	}
}

// §19's domain separation, both ways. Both cookies are signed with one secret, so without a label a
// token minted as one could be presented as the other.
func TestASessionTokenAndAHandshakeCookieCannotBeSwappedForEachOther(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)

	session, _, err := p.Signer.Mint("ada", payload.MethodPasswd, at(0))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := p.unseal(session); err == nil {
		t.Fatal("a session token unsealed as a handshake cookie")
	}

	_, _, cookie := started(t, p)
	if _, kind, err := p.Signer.Verify(cookie.Value, at(0)); err == nil {
		t.Fatalf("a handshake cookie verified as a session (kind %q)", kind)
	}

	// And the label is what does it: the same payload signed without it does not unseal.
	body, _ := json.Marshal(Handshake{State: "s", Nonce: "n", Verifier: "v", Exp: at(60).Unix()})
	encoded := enc(body)
	unlabelled := encoded + "." + enc(p.Signer.mac([]byte(encoded)))
	if _, err := p.unseal(unlabelled); err == nil {
		t.Fatal("a payload signed without the domain label unsealed as a handshake")
	}
}

// §19: **the window is re-checked from the payload.** `Max-Age` is advice to a browser; a client that
// ignores it would otherwise present a state from last week, and the signature would verify because a
// signature says nothing about time.
func TestTheHandshakeWindowIsReCheckedFromThePayloadAndNotFromTheCookie(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)

	for _, tc := range []struct {
		name string
		exp  int64
		when time.Time
	}{
		{"a window that closed", at(0).Add(HandshakeWindow).Unix(), at(0).Add(HandshakeWindow + time.Second)},
		{"the instant it closes", at(0).Add(HandshakeWindow).Unix(), at(0).Add(HandshakeWindow)},
		{"a state from last week", at(-7 * 24 * 3600).Unix(), at(0)},
		{"no window at all", 0, at(0)},
	} {
		sealed, err := p.seal(Handshake{State: "s", Nonce: "n", Verifier: "v", Exp: tc.exp})
		if err != nil {
			t.Fatalf("%s: seal: %v", tc.name, err)
		}

		r := callback("a-code", "s", &http.Cookie{Name: TransientCookieName, Value: sealed})
		_, err = p.openTransient(r, tc.when)

		asFailure(t, err, payload.FailOIDCState)
	}

	// A handshake inside the window opens, so the check is a window and not a refusal.
	sealed, _ := p.seal(Handshake{State: "s", Nonce: "n", Verifier: "v", Exp: at(0).Add(HandshakeWindow).Unix()})
	if _, err := p.openTransient(callback("a-code", "s", &http.Cookie{Name: TransientCookieName, Value: sealed}), at(1)); err != nil {
		t.Fatalf("a handshake one second old was refused: %v", err)
	}
}

func TestAHandshakeMissingAValueIsRefusedRatherThanCompletedWithABlankOne(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)

	for _, held := range []Handshake{
		{Nonce: "n", Verifier: "v", Exp: at(60).Unix()},
		{State: "s", Verifier: "v", Exp: at(60).Unix()},
		{State: "s", Nonce: "n", Exp: at(60).Unix()},
		{Exp: at(60).Unix()},
	} {
		sealed, _ := p.seal(held)
		r := callback("a-code", held.State, &http.Cookie{Name: TransientCookieName, Value: sealed})

		_, err := p.openTransient(r, at(0))

		asFailure(t, err, payload.FailOIDCState)
	}
}

func TestAHandshakeCookieIsBoundedBeforeAnythingIsHashed(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)

	for _, value := range []string{
		strings.Repeat("a", MaxTokenBytes+1),
		"nodot",
		".mac",
		"body.",
		"body.!!!not-base64!!!",
	} {
		if _, err := p.unseal(value); err == nil {
			t.Fatalf("%.20q unsealed", value)
		}
	}
}

func TestTheClearingCookieMatchesTheHandshakeCookieItClears(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)
	r := httptest.NewRequest(http.MethodGet, DefaultCallbackPath, nil)

	_, set, err := p.Start(context.Background(), r)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	clear := p.ClearTransient(r)

	if clear.Name != set.Name || clear.Path != set.Path || clear.HttpOnly != set.HttpOnly ||
		clear.SameSite != set.SameSite || clear.Secure != set.Secure {
		t.Fatalf("the clearing cookie differs in an attribute, so the handshake would survive:\nset   %+v\nclear %+v", set, clear)
	}
	if clear.MaxAge != -1 || clear.Value != "" {
		t.Fatalf("the clearing cookie is %+v", clear)
	}
}

// ---------------------------------------------------------------------------
// Callback
// ---------------------------------------------------------------------------

func TestAWholeHandshakeSignsSomebodyIn(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)

	_, held, cookie := started(t, p)
	tokenResponse(t, fixture, held.Nonce)

	got, err := p.Callback(context.Background(), callback("an-authorization-code", held.State, cookie))
	if err != nil {
		t.Fatalf("a conforming handshake did not complete: %v", err)
	}

	if got.Username != "ada" {
		t.Fatalf("username is %q", got.Username)
	}
	if got.Claims.Iss != testIssuer || got.Claims.Nonce != held.Nonce {
		t.Fatalf("the claims do not describe this handshake: %+v", got.Claims)
	}
}

// A user who pressed Cancel produces `error=access_denied` and no code. Reporting that as a state failure
// would send an operator looking for a cookie problem that does not exist.
func TestTheProvidersOwnRefusalIsReportedAsItsOwnAndNotAsAStateProblem(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	_, _, cookie := started(t, p)

	r := httptest.NewRequest(http.MethodGet, DefaultCallbackPath+"?error=access_denied", nil)
	r.AddCookie(cookie)

	_, err := p.Callback(context.Background(), r)

	got := asFailure(t, err, payload.FailOIDCProvider)
	if !strings.Contains(got.Reason, "access_denied") {
		t.Fatalf("the log does not say what the provider said: %q", got.Reason)
	}
	if fixture.count(tokenURL) != 0 {
		t.Fatal("a code was redeemed after the provider said there was none")
	}
}

// The error parameter is a string a provider — or anybody who can aim a browser at the callback — chose,
// and it reaches a log.
func TestTheProvidersErrorStringCannotForgeALogLine(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)
	_, _, cookie := started(t, p)

	r := httptest.NewRequest(http.MethodGet, DefaultCallbackPath+"?"+url.Values{
		"error": {"access_denied\nlabview: ada signed in"},
	}.Encode(), nil)
	r.AddCookie(cookie)

	_, err := p.Callback(context.Background(), r)

	got := asFailure(t, err, payload.FailOIDCProvider)
	if strings.ContainsAny(got.Reason, "\n\r") {
		t.Fatalf("a newline from the provider reached the log line: %q", got.Reason)
	}
}

func TestACallbackWithNoCodeAndOneWithNoCookieAreBothRefused(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	_, held, cookie := started(t, p)
	tokenResponse(t, fixture, held.Nonce)

	// No code: nothing to redeem.
	_, err := p.Callback(context.Background(), callback("", held.State, cookie))
	asFailure(t, err, payload.FailOIDCState)

	// No cookie: indistinguishable from a forged callback, which is why the cookie is required rather
	// than merely preferred.
	_, err = p.Callback(context.Background(), callback("a-code", held.State, nil))
	asFailure(t, err, payload.FailOIDCState)

	if fixture.count(tokenURL) != 0 {
		t.Fatal("a code was redeemed without a handshake to redeem it against")
	}
}

// The state comparison hashes both sides, for §19's reason: the two values are attacker-influenced, and a
// length-sensitive comparison would distinguish *truncated* from *wrong*.
func TestTheStateMustMatchTheOneThisBrowserStartedWith(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	_, held, cookie := started(t, p)
	tokenResponse(t, fixture, held.Nonce)

	for _, tc := range []struct{ name, state string }{
		{"another handshake's state", "a-state-from-somewhere-else"},
		{"none at all", ""},
		{"truncated", held.State[:len(held.State)-1]},
		{"one character over", held.State + "x"},
		{"a different case", strings.ToUpper(held.State)},
	} {
		_, err := p.Callback(context.Background(), callback("a-code", tc.state, cookie))

		asFailure(t, err, payload.FailOIDCState)
		if fixture.count(tokenURL) != 0 {
			t.Fatalf("%s: a code was redeemed against a state that did not match", tc.name)
		}
	}
}

// §19: the secret goes in the **body**, not a Basic header. Both are legal; the body keeps it out of
// anything that logs request headers — and this program's own transport reports the names of the headers
// it sent (I6), so a header is exactly where a secret should not be.
func TestTheCodeIsRedeemedWithTheVerifierAndTheSecretInTheBody(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	_, held, cookie := started(t, p)
	tokenResponse(t, fixture, held.Nonce)

	if _, err := p.Callback(context.Background(), callback("an-authorization-code", held.State, cookie)); err != nil {
		t.Fatalf("Callback: %v", err)
	}

	sent := fixture.last(t, tokenURL)
	if sent.Method != http.MethodPost {
		t.Fatalf("the exchange was a %s", sent.Method)
	}
	if got := sent.Header["Content-Type"]; got != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type is %q", got)
	}
	for name := range sent.Header {
		if strings.EqualFold(name, "Authorization") {
			t.Fatal("the client secret was sent as a header; §19 puts it in the body")
		}
	}

	form, err := url.ParseQuery(string(sent.Body))
	if err != nil {
		t.Fatalf("the body is not a form: %v", err)
	}
	for name, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "an-authorization-code",
		"redirect_uri":  redirectURI,
		"client_id":     testClientID,
		"code_verifier": held.Verifier,
		"client_secret": testSecret,
	} {
		if got := form.Get(name); got != want {
			t.Fatalf("%s is %q, want %q", name, got, want)
		}
	}
}

// A public client has no secret, and sending an empty one is not the same request as sending none: some
// providers refuse a blank `client_secret` outright.
func TestNoSecretIsSentWhenNoneIsConfigured(t *testing.T) {
	fixture := conforming()
	cfg := oidcSettings()
	cfg.ClientSecret = ""
	p := oidcProvider(t, fixture, cfg, nil)

	_, held, cookie := started(t, p)
	tokenResponse(t, fixture, held.Nonce)

	if _, err := p.Callback(context.Background(), callback("a-code", held.State, cookie)); err != nil {
		t.Fatalf("a public client could not sign in: %v", err)
	}

	form, _ := url.ParseQuery(string(fixture.last(t, tokenURL).Body))
	if _, present := form["client_secret"]; present {
		t.Fatal("a client_secret was sent by a client that has none")
	}
	if form.Get("code_verifier") == "" {
		t.Fatal("a public client sent no verifier, which is the only thing authenticating it")
	}
}

// §19, I5, I6: the access token is **discarded**. LabView calls no provider API, so keeping one would be
// holding a credential with no use — and the guarantee is structural, so it is asserted structurally: there
// is nowhere for it to go.
func TestTheAccessTokenIsDiscardedRatherThanKept(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Identity{}), reflect.TypeOf(IDClaims{}), reflect.TypeOf(Claims{})} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, forbidden := range []string{"access", "bearer", "refresh"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s.%s holds a provider credential this program has no use for",
						typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}

	// And it does not arrive by the back door either: nothing the handshake returns carries the value the
	// token endpoint sent.
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	_, held, cookie := started(t, p)
	tokenResponse(t, fixture, held.Nonce)

	got, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	rendered, _ := json.Marshal(got)
	if strings.Contains(string(rendered), "an access token") {
		t.Fatalf("the access token survived the handshake: %s", rendered)
	}
}

func TestATokenEndpointThatRefusesTheExchangeIsReportedAsAProviderFailure(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	_, held, cookie := started(t, p)
	fixture.serves(tokenURL, map[string]any{"error": "invalid_grant"})

	_, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))

	got := asFailure(t, err, payload.FailOIDCProvider)
	if !strings.Contains(got.Reason, "invalid_grant") {
		t.Fatalf("the log does not say why the exchange was refused: %q", got.Reason)
	}
}

// A flow that returned an access token and no ID token is an OAuth flow, not an OIDC one — usually
// because `openid` was dropped somewhere. It must not complete as an anonymous sign-in.
func TestAResponseWithNoIDTokenIsRefusedEvenThoughItCarriesAnAccessToken(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	_, held, cookie := started(t, p)
	fixture.serves(tokenURL, map[string]any{"token_type": "Bearer", "access_token": "a-token"})

	_, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))

	asFailure(t, err, payload.FailOIDCToken)
}

func TestAProviderThatAnswersWithSomethingOtherThanJSONCarriesAProtocolReport(t *testing.T) {
	for _, tc := range []struct {
		name   string
		build  func(*canned)
		detail string
	}{
		{
			name:   "the discovery document",
			build:  func(c *canned) { c.raw(discoveryURL, "<html><body>Sign in</body></html>") },
			detail: "discovery",
		},
		{
			name:   "the key set",
			build:  func(c *canned) { c.raw(jwksURL, "not json") },
			detail: "key set",
		},
		{
			name:   "the token endpoint",
			build:  func(c *canned) { c.raw(tokenURL, "<html>gateway error</html>") },
			detail: "token endpoint",
		},
	} {
		fixture := conforming()
		p := oidcProvider(t, fixture, oidcSettings(), nil)
		_, held, cookie := started(t, p)
		fixture.serves(tokenURL, map[string]any{
			"id_token": sign(t, "RS256", "k1", provider(), idClaims(at(0), map[string]any{"nonce": held.Nonce})),
		})
		tc.build(fixture)

		// Discovery was already cached by Start, so that case needs a provider that has not discovered yet.
		if tc.detail == "discovery" {
			p = oidcProvider(t, fixture, oidcSettings(), nil)
		}

		_, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))

		got := asFailure(t, err, payload.FailOIDCProvider)
		if got.Report == nil {
			t.Fatalf("%s: no connection report, so no panel can say what happened", tc.name)
		}
		if got.Report.Phase != payload.PhaseProtocol {
			t.Fatalf("%s: phase is %q, want protocol — it answered, just not as this API", tc.name, got.Report.Phase)
		}
		if got.Report.Target != "oidc" {
			t.Fatalf("%s: the report names target %q", tc.name, got.Report.Target)
		}
	}
}

// §15, §19: a provider that will not answer reports the same phases as a Docker socket that will not,
// because both go through one chokepoint and one classification.
func TestATransportFailureCarriesTheSamePhaseVocabularyAsEveryOtherTarget(t *testing.T) {
	for _, phase := range []payload.ConnectionPhase{
		payload.PhaseResolve,
		payload.PhaseConnect,
		payload.PhaseTLS,
		payload.PhaseTimeout,
		payload.PhaseStatus,
		payload.PhaseAuthenticate,
	} {
		fixture := conforming().broken(discoveryURL, phase, "the code the transport classified")
		p := oidcProvider(t, fixture, oidcSettings(), nil)

		_, _, err := p.Start(context.Background(), httptest.NewRequest(http.MethodGet, "/api/login/oidc", nil))

		got := asFailure(t, err, payload.FailOIDCProvider)
		if got.Report == nil {
			t.Fatalf("%s: no connection report", phase)
		}
		if got.Report.Phase != phase {
			t.Fatalf("report phase is %q, want the transport's %q", got.Report.Phase, phase)
		}
		if got.Report.OK {
			t.Fatalf("%s: the report says the read was ok", phase)
		}
		if !strings.Contains(got.Reason, "the code the transport classified") {
			t.Fatalf("%s: the log drops the transport's code: %q", phase, got.Reason)
		}
	}
}

// ---------------------------------------------------------------------------
// The key set
// ---------------------------------------------------------------------------

// §19: **exactly one** refetch on an unknown key id. The one legitimate cause is a rotation since the
// cache was filled; an unbounded refetch would let anybody with a made-up `kid` aim this program at the
// provider's JWKS endpoint as fast as they can post callbacks.
func TestAKeyRotationIsPickedUpByExactlyOneRefetch(t *testing.T) {
	fixture := conforming().serves(jwksURL, JWKS{Keys: []JWK{rsaJWK(&stranger().PublicKey, "the-old-key")}})
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	_, held, cookie := started(t, p)
	tokenResponse(t, fixture, held.Nonce)

	// The cache is filled with the old set, and then the provider rotates.
	if _, err := p.jwks(context.Background(), document(), at(0), false); err != nil {
		t.Fatalf("filling the cache: %v", err)
	}
	before := fixture.count(jwksURL)
	fixture.serves(jwksURL, JWKS{Keys: providerKeys()})

	got, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))
	if err != nil {
		t.Fatalf("a token signed with a rotated key was refused: %v", err)
	}
	if got.Username != "ada" {
		t.Fatalf("username is %q", got.Username)
	}
	if n := fixture.count(jwksURL) - before; n != 1 {
		t.Fatalf("the rotation cost %d fetches, want exactly 1", n)
	}
}

func TestAForgedKeyIdCostsOneProviderRequestAndThenNoMore(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)
	_, held, cookie := started(t, p)

	// A token naming a key the provider does not publish, presented five times.
	fixture.serves(tokenURL, map[string]any{
		"id_token": sign(t, "RS256", "a-key-id-nobody-published", provider(),
			idClaims(at(0), map[string]any{"nonce": held.Nonce})),
	})

	for i := 0; i < 5; i++ {
		_, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))
		asFailure(t, err, payload.FailOIDCToken)
	}

	// One fetch to fill the cache, then one forced refetch per callback. Never two per callback, and
	// never a retry loop.
	if got := fixture.count(jwksURL); got != 6 {
		t.Fatalf("five forged callbacks caused %d key-set fetches, want 6 (one fill, one refetch each)", got)
	}
}

func TestTheKeySetIsCachedForTenMinutes(t *testing.T) {
	clock := &postureClock{at: at(0)}
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), clock)

	if _, err := p.jwks(context.Background(), document(), clock.now(), false); err != nil {
		t.Fatalf("jwks: %v", err)
	}
	if got := fixture.count(jwksURL); got != 1 {
		t.Fatalf("%d fetches for the first read", got)
	}

	clock.add(DiscoveryTTL - time.Second)
	if _, err := p.jwks(context.Background(), document(), clock.now(), false); err != nil {
		t.Fatalf("jwks: %v", err)
	}
	if got := fixture.count(jwksURL); got != 1 {
		t.Fatalf("the key set was re-fetched inside the window (%d fetches)", got)
	}

	clock.add(2 * time.Second)
	if _, err := p.jwks(context.Background(), document(), clock.now(), false); err != nil {
		t.Fatalf("jwks: %v", err)
	}
	if got := fixture.count(jwksURL); got != 2 {
		t.Fatalf("the key set was not re-fetched after the window closed (%d fetches)", got)
	}
}

// A rotation published at a new URI must not be answered from the old URI's cache.
func TestAKeySetAtANewURIIsNotAnsweredFromTheOldOnesCache(t *testing.T) {
	moved := testIssuer + "/keys/v2"
	fixture := conforming().serves(moved, JWKS{Keys: providerKeys()})
	p := oidcProvider(t, fixture, oidcSettings(), nil)

	if _, err := p.jwks(context.Background(), document(), at(0), false); err != nil {
		t.Fatalf("jwks: %v", err)
	}

	relocated := document()
	relocated.JWKSURI = moved
	if _, err := p.jwks(context.Background(), relocated, at(1), false); err != nil {
		t.Fatalf("jwks at the new URI: %v", err)
	}

	if got := fixture.count(moved); got != 1 {
		t.Fatalf("the new URI was fetched %d times; the cache answered for a URI it was not filled from", got)
	}
}

// A key set with nothing usable in it is a provider failure, not a pass. The dangerous reading of an
// empty candidate list is "no key said no".
func TestAKeySetWithNothingUsableIsAProviderFailureAndNeverAPass(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  JWKS
	}{
		{"empty", JWKS{}},
		{"only symmetric keys", JWKS{Keys: []JWK{{Kty: "oct", Kid: "k1", Alg: "HS256"}}}},
		{"only encryption keys", JWKS{Keys: []JWK{{Kty: "RSA", Kid: "k1", Use: "enc", N: "AQAB", E: "AQAB"}}}},
		{"an unknown key type", JWKS{Keys: []JWK{{Kty: "OKP", Kid: "k1", Crv: "Ed25519", X: "AQAB"}}}},
	} {
		fixture := conforming().serves(jwksURL, tc.set)
		p := oidcProvider(t, fixture, oidcSettings(), nil)

		_, err := p.jwks(context.Background(), document(), at(0), false)

		got := asFailure(t, err, payload.FailOIDCProvider)
		if !strings.Contains(got.Reason, "usable") {
			t.Fatalf("%s: the reason does not say the set was unusable: %q", tc.name, got.Reason)
		}
	}
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func TestTheDiscoveryTargetIsTheWellKnownPathWithNoDoubledSlash(t *testing.T) {
	for _, issuer := range []string{testIssuer, testIssuer + "/"} {
		fixture := conforming()
		cfg := oidcSettings()
		cfg.Issuer = issuer
		p := oidcProvider(t, fixture, cfg, nil)

		if _, err := p.Discover(context.Background()); err != nil {
			t.Fatalf("issuer %q: %v", issuer, err)
		}
		if got := fixture.count(discoveryURL); got != 1 {
			t.Fatalf("issuer %q produced %d requests to the well-known path", issuer, got)
		}
	}
}

func TestDiscoveryIsCachedForTenMinutes(t *testing.T) {
	clock := &postureClock{at: at(0)}
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), clock)

	if _, err := p.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	clock.add(DiscoveryTTL - time.Second)
	if _, err := p.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if got := fixture.count(discoveryURL); got != 1 {
		t.Fatalf("%d fetches inside the window, want 1 — a login form should not cost the provider a request per page load", got)
	}

	clock.add(2 * time.Second)
	if _, err := p.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if got := fixture.count(discoveryURL); got != 2 {
		t.Fatalf("%d fetches after the window closed, want 2 — a reconfigured provider must be picked up", got)
	}
}

// §19: **the document's own issuer MUST equal the configured one.** This is the check that makes discovery
// safe at all: without it a mistyped or hijacked issuer URL could hand back a document pointing every
// endpoint at somebody else's provider, and the sign-in would complete against an identity provider
// nobody chose.
func TestTheDocumentsIssuerMustEqualTheConfiguredOneWithOnlySlashesForgiven(t *testing.T) {
	for _, tc := range []struct {
		name       string
		declared   string
		configured string
		ok         bool
	}{
		{"exactly equal", testIssuer, testIssuer, true},
		{"a trailing slash in the document", testIssuer + "/", testIssuer, true},
		{"a trailing slash in the configuration", testIssuer, testIssuer + "/", true},
		{"padding", " " + testIssuer + " ", testIssuer, true},
		{"another provider entirely", "https://idp.attacker.example.com", testIssuer, false},
		{"a subdomain", "https://sso.idp.example.com", testIssuer, false},
		{"a suffix", testIssuer + ".attacker.example.com", testIssuer, false},
		{"a different case", "https://IDP.example.com", testIssuer, false},
		{"http against https", "http://idp.example.com", testIssuer, false},
		{"an added path", testIssuer + "/realms/lab", testIssuer, false},
		{"a doubled slash", "https://idp.example.com//", testIssuer, false},
		{"nothing declared", "", testIssuer, false},
	} {
		d := document()
		d.Issuer = tc.declared

		err := CheckDiscovery(d, tc.configured)

		if (err == nil) != tc.ok {
			t.Fatalf("%s: declared %q against configured %q gave %v", tc.name, tc.declared, tc.configured, err)
		}
	}
}

// And the check is actually reached, rather than being a pure function nobody calls.
func TestADocumentDeclaringAnotherIssuerIsRefusedByDiscovery(t *testing.T) {
	hijacked := document()
	hijacked.Issuer = "https://idp.attacker.example.com"
	hijacked.AuthorizationEndpoint = "https://idp.attacker.example.com/authorize"
	fixture := conforming().serves(discoveryURL, hijacked)
	p := oidcProvider(t, fixture, oidcSettings(), nil)

	_, _, err := p.Start(context.Background(), httptest.NewRequest(http.MethodGet, "/api/login/oidc", nil))

	got := asFailure(t, err, payload.FailOIDCProvider)
	if !strings.Contains(got.Reason, "issuer") {
		t.Fatalf("the reason does not name the problem: %q", got.Reason)
	}
}

// §19: **https, loopback excepted.** A client secret and an authorization code both travel to the token
// endpoint, so plain HTTP there is handing them to the network.
func TestEveryProviderEndpointMustBeHTTPSUnlessItIsLoopback(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		ok       bool
	}{
		{"https://idp.example.com/token", true},
		{"http://localhost:9000/token", true},
		{"http://127.0.0.1:9000/token", true},
		{"http://127.0.0.2/token", true},
		{"http://[::1]:9000/token", true},
		{"http://idp.example.com/token", false},
		{"http://192.0.2.10/token", false},
		{"ftp://idp.example.com/token", false},
		{"/token", false},
		{"", false},
		{"idp.example.com/token", false},
		// A name that merely *resolves* to loopback is not loopback: resolution happens later and
		// elsewhere, and trusting DNS here would let whoever controls DNS switch the https rule off.
		{"http://localhost.attacker.example.com/token", false},
		{"http://127.0.0.1.attacker.example.com/token", false},
		{"http://localhost.localdomain/token", false},
	} {
		err := requireHTTPS(tc.endpoint)

		if (err == nil) != tc.ok {
			t.Fatalf("requireHTTPS(%q) = %v, want ok=%v", tc.endpoint, err, tc.ok)
		}
	}
}

func TestLoopbackIsDecidedByNameOrLiteralAndNeverByResolution(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":                      true,
		"127.0.0.1":                      true,
		"127.1.2.3":                      true,
		"::1":                            true,
		"LOCALHOST":                      false, // a hostname is compared exactly; the literal spelling is what §19 excepts
		"localhost.attacker.example.com": false,
		"192.0.2.10":                     false,
		"idp.example.com":                false,
		"":                               false,
	} {
		if got := loopback(host); got != want {
			t.Fatalf("loopback(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestADocumentMissingAnEndpointIsRefusedNamingWhichOne(t *testing.T) {
	for name, blank := range map[string]func(*Discovery){
		"authorization endpoint": func(d *Discovery) { d.AuthorizationEndpoint = "" },
		"token endpoint":         func(d *Discovery) { d.TokenEndpoint = "" },
		"jwks uri":               func(d *Discovery) { d.JWKSURI = "   " },
	} {
		d := document()
		blank(&d)

		err := CheckDiscovery(d, testIssuer)

		if err == nil {
			t.Fatalf("a document with no %s was accepted", name)
		}
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("the error does not say which endpoint was missing: %q", err)
		}
	}
}

func TestADocumentWhoseTokenEndpointIsPlainHTTPIsRefused(t *testing.T) {
	insecure := document()
	insecure.TokenEndpoint = "http://idp.example.com/token"
	fixture := conforming().serves(discoveryURL, insecure)
	p := oidcProvider(t, fixture, oidcSettings(), nil)

	_, _, err := p.Start(context.Background(), httptest.NewRequest(http.MethodGet, "/api/login/oidc", nil))

	got := asFailure(t, err, payload.FailOIDCProvider)
	if !strings.Contains(got.Reason, "token endpoint") {
		t.Fatalf("the reason does not name the endpoint: %q", got.Reason)
	}
}

// ---------------------------------------------------------------------------
// What a failure says, and to whom
// ---------------------------------------------------------------------------

// §19: **a reply says less than the log.** The browser gets one of eight codes — enough to render a
// sentence, not enough to describe the provider's configuration to whoever is holding the browser.
func TestEveryFailureRedirectsWithACodeAndNothingElse(t *testing.T) {
	for _, code := range payload.LoginFailureReasons {
		f := Failure{Code: code, Reason: "the token endpoint at https://idp.internal:8443 refused the exchange"}

		u, err := url.Parse(f.Redirect())
		if err != nil {
			t.Fatalf("%s: the redirect does not parse: %v", code, err)
		}
		if u.Path != "/" {
			t.Fatalf("%s: the browser is sent to %q", code, u.Path)
		}
		if got := u.Query().Get("login_error"); got != string(code) {
			t.Fatalf("%s: login_error is %q", code, got)
		}
		if len(u.Query()) != 1 {
			t.Fatalf("%s: the redirect carries more than the code: %v", code, u.Query())
		}
		if strings.Contains(f.Redirect(), "idp.internal") {
			t.Fatalf("%s: the reason reached the browser: %s", code, f.Redirect())
		}
		// The log gets the whole thing, which is the other half of the rule.
		if !strings.Contains(f.Error(), "idp.internal") {
			t.Fatalf("%s: the log does not carry the reason: %q", code, f.Error())
		}
	}
}

// The code is one of a closed set, and it is escaped anyway: a value that arrived from somewhere
// unexpected must not be able to break out of the query string.
func TestACodeFromSomewhereUnexpectedCannotBreakOutOfTheQueryString(t *testing.T) {
	f := Failure{Code: payload.LoginFailureReason("oidc-token&admin=1#")}

	u, err := url.Parse(f.Redirect())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(u.Query()) != 1 {
		t.Fatalf("a hostile code produced %d parameters: %v", len(u.Query()), u.Query())
	}
	if u.Fragment != "" {
		t.Fatalf("a hostile code produced a fragment: %q", u.Fragment)
	}
}

// The identity failure is its own code, because it is the one failure an operator fixes in LabView's
// configuration rather than in the provider's.
func TestATokenThatIdentifiesNobodyIsAnIdentityFailureAndNotATokenOne(t *testing.T) {
	fixture := conforming()
	p := oidcProvider(t, fixture, oidcSettings(), nil)

	_, held, cookie := started(t, p)
	// A token that verifies perfectly and holds no name matching the pattern anywhere in the chain.
	fixture.serves(tokenURL, map[string]any{
		"id_token": sign(t, "RS256", "k1", provider(), idClaims(at(0), map[string]any{
			"nonce": held.Nonce, "sub": "a subject with spaces in it",
		})),
	})

	_, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))

	got := asFailure(t, err, payload.FailOIDCIdentity)
	// §19: a value that fails the pattern is **not** turned into the unknown marker. A session for `?`
	// would be a session for everybody else who also failed the pattern.
	if strings.Contains(got.Reason, "a subject with spaces") {
		t.Fatalf("the reason echoes the claim value a provider chose: %q", got.Reason)
	}
	if !strings.Contains(got.Reason, UsernamePattern) {
		t.Fatalf("the reason does not say what the name had to look like: %q", got.Reason)
	}
}

// A configured claim the provider does not send is a weaker reading, not a refusal (I4): the chain
// continues, so a typo in `usernameClaim` does not lock everybody out.
func TestAConfiguredClaimThatIsAbsentFallsThroughTheChainRatherThanFailing(t *testing.T) {
	fixture := conforming()
	cfg := oidcSettings()
	cfg.UsernameClaim = "a_claim_this_provider_does_not_send"
	p := oidcProvider(t, fixture, cfg, nil)

	_, held, cookie := started(t, p)
	tokenResponse(t, fixture, held.Nonce)

	got, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))
	if err != nil {
		t.Fatalf("a typo in the configured claim locked everybody out: %v", err)
	}
	if got.Username != "ada" {
		t.Fatalf("username is %q, want the one from preferred_username", got.Username)
	}
}

// And a configured claim the provider *does* send is preferred over the rest of the chain, which is the
// whole point of the setting.
func TestTheConfiguredClaimIsPreferredOverTheRestOfTheChain(t *testing.T) {
	fixture := conforming()
	cfg := oidcSettings()
	cfg.UsernameClaim = "labview_name"
	p := oidcProvider(t, fixture, cfg, nil)

	_, held, cookie := started(t, p)
	fixture.serves(tokenURL, map[string]any{
		"id_token": sign(t, "RS256", "k1", provider(), idClaims(at(0), map[string]any{
			"nonce": held.Nonce, "preferred_username": "ada", "labview_name": "grace",
		})),
	})

	got, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if got.Username != "grace" {
		t.Fatalf("username is %q, want the configured claim's value", got.Username)
	}
}

// A token that fails verification is a token failure, whichever way it failed — the browser learns that
// much and no more, and the log carries the reason.
func TestAnUnverifiableTokenIsATokenFailure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(*testing.T, Handshake) string
	}{
		{
			name: "signed by a stranger",
			build: func(t *testing.T, h Handshake) string {
				return sign(t, "RS256", "k1", stranger(), idClaims(at(0), map[string]any{"nonce": h.Nonce}))
			},
		},
		{
			name: "from another handshake",
			build: func(t *testing.T, h Handshake) string {
				return sign(t, "RS256", "k1", provider(), idClaims(at(0), map[string]any{"nonce": "a-nonce-from-another-sign-in"}))
			},
		},
		{
			name: "expired",
			build: func(t *testing.T, h Handshake) string {
				return sign(t, "RS256", "k1", provider(), idClaims(at(-7200), map[string]any{"nonce": h.Nonce}))
			},
		},
		{
			name: "for another client",
			build: func(t *testing.T, h Handshake) string {
				return sign(t, "RS256", "k1", provider(), idClaims(at(0), map[string]any{"aud": "somebody-else", "nonce": h.Nonce}))
			},
		},
		{
			name: "unsigned",
			build: func(t *testing.T, h Handshake) string {
				return sign(t, "none", "", nil, idClaims(at(0), map[string]any{"nonce": h.Nonce}))
			},
		},
		{
			name: "signed with the client secret",
			build: func(t *testing.T, h Handshake) string {
				return sign(t, "HS256", "k1", []byte(testSecret), idClaims(at(0), map[string]any{"nonce": h.Nonce}))
			},
		},
		{
			name:  "not a token at all",
			build: func(*testing.T, Handshake) string { return "not.a.token" },
		},
	} {
		fixture := conforming()
		p := oidcProvider(t, fixture, oidcSettings(), nil)
		_, held, cookie := started(t, p)
		fixture.serves(tokenURL, map[string]any{"id_token": tc.build(t, held)})

		_, err := p.Callback(context.Background(), callback("a-code", held.State, cookie))

		got := asFailure(t, err, payload.FailOIDCToken)
		if got.Reason == "" {
			t.Fatalf("%s: nothing was written to the log", tc.name)
		}
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// Two people signing in at once share one provider, one discovery cache and one key cache — and each
// must come back with their own handshake's token rather than the other's.
func TestConcurrentSignInsDoNotRaceOverTheCaches(t *testing.T) {
	fixture := conforming()

	// The token endpoint answers each redemption with a token minted for that code's own nonce, which is
	// what a real provider does and what makes the nonce check meaningful under concurrency.
	var mu sync.Mutex
	nonces := map[string]string{}
	fixture.route(tokenURL, func(req transport.Request) transport.Result {
		form, err := url.ParseQuery(string(req.Body))
		if err != nil {
			return transport.Result{Phase: payload.PhaseProtocol, Endpoint: tokenURL}
		}
		mu.Lock()
		nonce := nonces[form.Get("code")]
		mu.Unlock()

		body, _ := json.Marshal(map[string]any{
			"id_token": sign(t, "RS256", "k1", provider(), idClaims(at(0), map[string]any{
				"nonce": nonce, "preferred_username": "ada",
			})),
		})
		return transport.Result{Phase: payload.PhaseConnected, Status: http.StatusOK, Body: body, Endpoint: tokenURL}
	})

	p := oidcProvider(t, fixture, oidcSettings(), nil)

	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			_, held, cookie := started(t, p)

			code := "code-" + itoa(i)
			mu.Lock()
			nonces[code] = held.Nonce
			mu.Unlock()

			_, err := p.Callback(context.Background(), callback(code, held.State, cookie))
			done <- err
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent sign-in: %v", err)
		}
	}
}

// §3.2: `LABVIEW_OIDC_REDIRECT_URI` **empty derives it from the request**, honouring
// `X-Forwarded-Proto` and `X-Forwarded-Host`. That is what lets the ordinary deployment — one
// container behind the reverse proxy it documents — configure an issuer and a client id and nothing
// else. Sent verbatim, an empty `redirect_uri` is a parameter the provider rejects.
func TestAnEmptyRedirectURIIsDerivedFromTheRequest(t *testing.T) {
	cfg := oidcSettings()
	cfg.RedirectURI = ""
	p := oidcProvider(t, conforming(), cfg, nil)

	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/start", nil)
	r.Host = "labview.internal:8080"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "lab.example.com")

	target, cookie, err := p.Start(context.Background(), r)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	q, _ := url.ParseQuery(strings.SplitN(target, "?", 2)[1])
	if got, want := q.Get("redirect_uri"), "https://lab.example.com"+DefaultCallbackPath; got != want {
		t.Fatalf("redirect_uri is %q, want the forwarded host's %q", got, want)
	}
	// The transient cookie is scoped to the *derived* callback path, not to the default the
	// unresolved-empty value would have produced by accident.
	if cookie.Path != DefaultCallbackPath {
		t.Fatalf("the handshake cookie is scoped to %q, want %q", cookie.Path, DefaultCallbackPath)
	}
}

// With no proxy in front there is nothing to honour, so the request's own host and scheme are the
// answer. A derived URI that guessed https here would send the provider to a URL this instance does
// not answer on.
func TestAnEmptyRedirectURIWithNoProxyUsesTheRequestsOwnHostAndScheme(t *testing.T) {
	cfg := oidcSettings()
	cfg.RedirectURI = ""
	p := oidcProvider(t, conforming(), cfg, nil)

	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/start", nil)
	r.Host = "192.0.2.10:8080"

	target, _, err := p.Start(context.Background(), r)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	q, _ := url.ParseQuery(strings.SplitN(target, "?", 2)[1])
	if got, want := q.Get("redirect_uri"), "http://192.0.2.10:8080"+DefaultCallbackPath; got != want {
		t.Fatalf("redirect_uri is %q, want %q", got, want)
	}
}

// A configured URI is used exactly as configured. The derivation is a fallback, not a correction: an
// operator who wrote a redirect URI has registered that string with their provider, and rewriting it
// from a header would break the one deployment that was explicit about it.
func TestAConfiguredRedirectURIIsNeverRewrittenByAForwardedHeader(t *testing.T) {
	p := oidcProvider(t, conforming(), oidcSettings(), nil)

	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/start", nil)
	r.Header.Set("X-Forwarded-Host", "attacker.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")

	target, _, err := p.Start(context.Background(), r)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	q, _ := url.ParseQuery(strings.SplitN(target, "?", 2)[1])
	if got := q.Get("redirect_uri"); got != redirectURI {
		t.Fatalf("redirect_uri is %q, want the configured %q", got, redirectURI)
	}
}

// The token exchange MUST send the same `redirect_uri` the authorization request did — the provider
// compares them and refuses the code when they differ. With the value derived rather than
// configured, that equality is a property of the derivation, so it is asserted rather than assumed.
func TestTheDerivedRedirectURIIsIdenticalOnTheExchange(t *testing.T) {
	cfg := oidcSettings()
	cfg.RedirectURI = ""
	fixture := conforming()
	p := oidcProvider(t, fixture, cfg, nil)

	proxied := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "labview.internal:8080"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", "lab.example.com")
		return r
	}

	target, cookie, err := p.Start(context.Background(), proxied("/auth/oidc/start"))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	sent, _ := url.ParseQuery(strings.SplitN(target, "?", 2)[1])

	var held Handshake
	raw, err := p.unseal(cookie.Value)
	if err != nil {
		t.Fatalf("unsealing the handshake: %v", err)
	}
	if err := json.Unmarshal(raw, &held); err != nil {
		t.Fatalf("the handshake is not the expected object: %v", err)
	}
	tokenResponse(t, fixture, held.Nonce)

	back := proxied("/auth/oidc/callback?code=abc&state=" + url.QueryEscape(held.State))
	back.AddCookie(cookie)
	if _, err := p.Callback(context.Background(), back); err != nil {
		t.Fatalf("Callback: %v", err)
	}

	exchanged, err := url.ParseQuery(string(fixture.last(t, tokenURL).Body))
	if err != nil {
		t.Fatalf("the token request body does not parse: %v", err)
	}
	if got, want := exchanged.Get("redirect_uri"), sent.Get("redirect_uri"); got != want {
		t.Fatalf("the exchange sent redirect_uri %q, the authorization request sent %q", got, want)
	}
}

// §19's `X-Forwarded-Host` precedence differs between the CSRF check and this derivation, and the
// difference is deliberate — so the helper is pinned directly.
func TestEffectiveHostPrefersTheForwardedNameAndFallsBackToTheRequests(t *testing.T) {
	for _, tc := range []struct {
		name      string
		host      string
		forwarded string
		want      string
	}{
		{"no header", "labview.internal:8080", "", "labview.internal:8080"},
		{"forwarded wins", "labview.internal:8080", "lab.example.com", "lab.example.com"},
		{"first of a list", "labview.internal", "lab.example.com, edge.example.com", "lab.example.com"},
		{"blank header ignored", "labview.internal", "   ", "labview.internal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = tc.host
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-Host", tc.forwarded)
			}
			if got := EffectiveHost(r); got != tc.want {
				t.Fatalf("EffectiveHost is %q, want %q", got, tc.want)
			}
		})
	}
}
