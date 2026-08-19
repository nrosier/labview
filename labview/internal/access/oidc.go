package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nrosier/labview/internal/conn"
	"github.com/nrosier/labview/internal/payload"
	"github.com/nrosier/labview/internal/transport"
)

// OIDC (§19): authorization code with PKCE S256, through the same HTTP chokepoint as every other
// target (§15).
//
// Through the chokepoint and not through a library's own client, because that is what makes a provider
// that will not resolve report the same phases as a Docker socket that will not: the timeout, the 64
// KiB cap and the phase classification are one implementation, so `dns`, `connect` and `tls` mean the
// same thing in a login error as they do in a connection report.
//
// Every pure part takes the current time as a parameter (§19), so the 300-second handshake window, the
// discovery cache and the token's expiry are all testable without waiting.

// The two windows §19 states.
const (
	// DiscoveryTTL is how long a discovery document is reused. Ten minutes: an endpoint set changes
	// when a provider is reconfigured, which is rare, and re-fetching it on every sign-in would put a
	// request on the provider for every page load of a login form.
	DiscoveryTTL = 10 * time.Minute

	// HandshakeWindow is how long a started sign-in may take to come back. Five minutes is a slow
	// human with a password manager and a second factor; an hour would leave a usable state cookie
	// lying in a browser long after the person walked away.
	HandshakeWindow = 300 * time.Second
)

// transientLabel domain-separates the handshake cookie's MAC from the session cookie's.
//
// It matters: both are signed with the same secret, and without separation a token minted as one could
// be presented as the other. A session payload is base64url and so contains no `.`, which means no
// session MAC input can ever equal a handshake MAC input.
const transientLabel = "oidc1"

// Doer is the HTTP chokepoint. It is an interface so the whole handshake is testable without a
// network, and `*transport.Client` is the only implementation in the program.
type Doer interface {
	Do(ctx context.Context, req transport.Request) transport.Result
}

// Discovery is the part of the provider's metadata this program uses. Four fields: everything else in
// the document is either advisory or about a flow LabView does not run.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Handshake is what the transient cookie carries: the four values a callback must be checked against.
type Handshake struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Exp      int64  `json:"exp"`
}

// Provider runs the handshake for one configured issuer.
type Provider struct {
	// Config is the OIDC configuration as it stands, re-read rather than held so a rescan's
	// configuration reload reaches the handshake (§3).
	Config func() OIDCSettings

	// HTTP is the chokepoint. Required.
	HTTP Doer

	// Signer signs the transient cookie. Required — the same signer as sessions, domain-separated by
	// transientLabel.
	Signer *Signer

	// Now is the injected clock. Nil is time.Now.
	Now func() time.Time

	mu sync.Mutex

	// discovered is the cached document and when it was fetched.
	discovered *Discovery
	at         time.Time

	// keys is the cached JWKS and where it came from, so a rotation at a new URI is not answered from
	// the old one's cache.
	keys    []JWK
	keysURI string
	keysAt  time.Time
}

// OIDCSettings is the configuration a provider needs.
//
// It is a struct of its own rather than config.OIDCConfig, so nothing in the handshake depends on the
// shape of the configuration file: `enabled`, the label and the timeout are decisions made before a
// handshake starts, and a provider that could read them would be a provider that could second-guess
// the posture (§19). The server assembles one from configuration.
type OIDCSettings struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	Scopes        []string
	UsernameClaim string
}

// Failure is a handshake that did not complete: the code the browser is redirected with, the reason for
// the log, and the connection report when a network read was involved.
//
// Two messages, as everywhere in the gate: **a reply says less than the log** (§19). The browser gets
// one of eight codes, which is enough to render a sentence and not enough to describe the provider's
// configuration to whoever is holding the browser.
type Failure struct {
	Code   payload.LoginFailureReason
	Reason string
	Report *payload.ConnectionReport
}

func (f Failure) Error() string { return string(f.Code) + ": " + f.Reason }

// Redirect is where a failed handshake sends the browser (§19).
func (f Failure) Redirect() string {
	// The code is one of a closed set, but it is escaped anyway: a value that reached here from
	// somewhere unexpected must not be able to break out of the query string.
	return "/?" + payload.LoginErrorParam + "=" + url.QueryEscape(string(f.Code))
}

func fail(code payload.LoginFailureReason, reason string) Failure {
	return Failure{Code: code, Reason: reason}
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

// Start begins a sign-in: it returns where to send the browser and the transient cookie to set.
func (p *Provider) Start(ctx context.Context, r *http.Request) (string, *http.Cookie, error) {
	cfg := p.settings(r)
	now := p.clock()()

	document, err := p.Discover(ctx)
	if err != nil {
		return "", nil, err
	}

	state, nonce, verifier, err := freshHandshake()
	if err != nil {
		return "", nil, fail(payload.FailOIDCState, "could not generate handshake values: "+err.Error())
	}

	sealed, err := p.seal(Handshake{
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		Exp:      now.Add(HandshakeWindow).Unix(),
	})
	if err != nil {
		return "", nil, fail(payload.FailOIDCState, "could not seal the handshake: "+err.Error())
	}

	query := url.Values{
		"response_type": {"code"},
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURI},
		"scope":         {strings.Join(scopes(cfg.Scopes), " ")},
		"state":         {state},
		"nonce":         {nonce},
		// PKCE S256, never `plain`. A `plain` challenge is the verifier itself, so an attacker who
		// intercepted the authorization request would hold everything needed to redeem the code — the
		// mechanism would be present and worthless.
		"code_challenge":        {challenge(verifier)},
		"code_challenge_method": {"S256"},
	}

	target := document.AuthorizationEndpoint
	joiner := "?"
	if strings.Contains(target, "?") {
		// A provider whose authorization endpoint already carries a query keeps it. Overwriting it
		// with our own would drop a tenant or realm parameter some providers put there.
		joiner = "&"
	}

	return target + joiner + query.Encode(), p.transientCookie(r, sealed, cfg), nil
}

// scopes is the requested scope list, always containing `openid`.
//
// Always, because without it the provider runs a plain OAuth flow and returns no ID token — and the ID
// token is the only thing here that says who signed in. A configuration that omitted it would produce
// a handshake that completes and identifies nobody.
func scopes(configured []string) []string {
	out := make([]string, 0, len(configured)+1)
	seen := map[string]bool{}
	for _, s := range append([]string{"openid"}, configured...) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// challenge is the S256 code challenge for a verifier.
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// freshHandshake generates the three unguessable values.
//
// 32 bytes each. The state defends the callback, the nonce ties the token to this request and the
// verifier proves the redemption comes from whoever started the flow; all three are worthless if
// guessable, and none of them has any structure worth having.
func freshHandshake() (state, nonce, verifier string, err error) {
	values := make([]string, 3)
	for i := range values {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", "", "", err
		}
		values[i] = base64.RawURLEncoding.EncodeToString(b)
	}
	return values[0], values[1], values[2], nil
}

// TransientCookieName is the handshake cookie's name. Distinct from the session cookie, so a browser
// holding both sends both and neither can be mistaken for the other.
const TransientCookieName = "labview_oidc"

// transientCookie builds the handshake cookie, **scoped to the callback path** (§19).
//
// Scoped, because it is only ever read by one route. A cookie on `/` would be sent on every request to
// every path in the program — including the API — which is a handshake secret travelling constantly
// for no reason. `SameSite=Lax` rather than `Strict`: the callback arrives as a top-level navigation
// from the provider, and Strict would not send the cookie on it, so the handshake could never complete.
func (p *Provider) transientCookie(r *http.Request, value string, cfg OIDCSettings) *http.Cookie {
	return &http.Cookie{
		Name:     TransientCookieName,
		Value:    value,
		Path:     callbackPath(cfg.RedirectURI),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   EffectiveScheme(r) == "https",
		// The browser's copy of the window. The authoritative one is inside the signed payload and is
		// re-checked on the callback (§19), because Max-Age is advice a client may ignore.
		MaxAge: int(HandshakeWindow.Seconds()),
	}
}

// ClearTransient removes the handshake cookie. Called on both outcomes: a completed handshake has no
// further use for it, and a failed one must not leave a state a second callback could replay.
func (p *Provider) ClearTransient(r *http.Request) *http.Cookie {
	// Through settings rather than Config, so a derived redirect URI produces the same `Path` the
	// cookie was set with — a clear-cookie on the wrong path leaves the handshake in the browser.
	cfg := p.settings(r)
	return &http.Cookie{
		Name:     TransientCookieName,
		Value:    "",
		Path:     callbackPath(cfg.RedirectURI),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   EffectiveScheme(r) == "https",
		MaxAge:   -1,
	}
}

// settings is the configured OIDC settings with the redirect URI resolved against this request.
//
// **An empty `redirectUri` is derived from the request** (§3.2), honouring `X-Forwarded-Proto` and
// `X-Forwarded-Host` — so the ordinary deployment, one container behind the reverse proxy it
// documents, needs no OIDC configuration beyond an issuer and a client id.
//
// It is resolved here rather than in the `Config` closure because a closure has no request, and
// resolved on **every** use rather than once at start-up because the same binary may be reached
// through more than one hostname and the value has to match the host the browser is actually on.
//
// The derived value is identical on the start and the callback for one sign-in — both are requests
// from the same browser through the same proxy — which matters because the provider requires the
// token exchange's `redirect_uri` to equal the authorization request's. Deriving it is therefore
// only safe while a proxy sets those headers consistently; a deployment reached both directly and
// through a proxy should configure the URI rather than let it be inferred.
func (p *Provider) settings(r *http.Request) OIDCSettings {
	cfg := p.Config()
	if strings.TrimSpace(cfg.RedirectURI) != "" {
		return cfg
	}
	cfg.RedirectURI = EffectiveScheme(r) + "://" + EffectiveHost(r) + DefaultCallbackPath
	return cfg
}

// EffectiveHost is the host the *client* addressed, which is not always the one in `r.Host`.
//
// `X-Forwarded-Host` wins when present, which is the opposite precedence from the CSRF check's
// `hosts` — and deliberately so. That check asks *could this request have come from us*, and answers
// it by accepting either spelling. This one asks *what public URL is this instance on*, which has one
// answer: the name the browser used, which is the forwarded one whenever a proxy rewrote `Host`.
//
// Only the first value of a comma-joined list is read, since that is the original client's.
func EffectiveHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		first := forwarded
		if i := strings.Index(first, ","); i >= 0 {
			first = first[:i]
		}
		if host := strings.TrimSpace(first); host != "" {
			return host
		}
	}
	return r.Host
}

// callbackPath is the redirect URI's path, defaulted when it names none.
func callbackPath(redirect string) string {
	u, err := url.Parse(redirect)
	if err != nil || u.Path == "" || u.Path == "/" {
		return DefaultCallbackPath
	}
	return u.Path
}

// DefaultCallbackPath is where the callback lives when the redirect URI does not say.
//
// Outside `/api`, as §19 requires, so the API's public-path allowlist stays a statement about the API.
const DefaultCallbackPath = "/auth/oidc/callback"

// ---------------------------------------------------------------------------
// Callback
// ---------------------------------------------------------------------------

// Identity is a completed handshake: who signed in.
type Identity struct {
	Username string
	Claims   IDClaims
}

// Callback completes a sign-in.
func (p *Provider) Callback(ctx context.Context, r *http.Request) (Identity, error) {
	cfg := p.settings(r)
	now := p.clock()()

	// The provider's own error comes first. A user who pressed Cancel produces `error=access_denied`
	// and no code, and reporting that as a state failure would send an operator looking for a cookie
	// problem that does not exist.
	if given := r.URL.Query().Get("error"); given != "" {
		return Identity{}, fail(payload.FailOIDCProvider,
			"the provider refused the authorization request: "+safeIdentifier(given))
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return Identity{}, fail(payload.FailOIDCState, "the callback carried no authorization code")
	}

	held, err := p.openTransient(r, now)
	if err != nil {
		return Identity{}, err
	}

	// The state comparison hashes both sides (§19's rule for the session MAC, applied here for the
	// same reason): the two values are attacker-influenced and a length-sensitive comparison would
	// distinguish *truncated* from *wrong*.
	if !equalHashed([]byte(r.URL.Query().Get("state")), []byte(held.State)) {
		return Identity{}, fail(payload.FailOIDCState, "the callback state does not match the one this browser started with")
	}

	document, err := p.Discover(ctx)
	if err != nil {
		return Identity{}, err
	}

	idToken, err := p.exchange(ctx, document, cfg, code, held.Verifier)
	if err != nil {
		return Identity{}, err
	}

	claims, err := p.verify(ctx, document, cfg, idToken, held.Nonce, now)
	if err != nil {
		return Identity{}, err
	}

	name, err := UsernameFrom(claims, cfg.UsernameClaim)
	if err != nil {
		return Identity{}, fail(payload.FailOIDCIdentity, err.Error())
	}

	return Identity{Username: name, Claims: claims}, nil
}

// openTransient reads and checks the handshake cookie.
func (p *Provider) openTransient(r *http.Request, now time.Time) (Handshake, error) {
	cookie, err := r.Cookie(TransientCookieName)
	if err != nil || cookie.Value == "" {
		// The commonest cause is a bookmarked callback URL or a sign-in started in another browser,
		// and both are indistinguishable from a forged callback — which is exactly why the cookie is
		// required rather than merely preferred.
		return Handshake{}, fail(payload.FailOIDCState, "the callback carried no handshake cookie")
	}

	raw, err := p.unseal(cookie.Value)
	if err != nil {
		return Handshake{}, fail(payload.FailOIDCState, "the handshake cookie did not verify: "+err.Error())
	}
	var held Handshake
	if err := json.Unmarshal(raw, &held); err != nil {
		return Handshake{}, fail(payload.FailOIDCState, "the handshake cookie is not the expected object")
	}
	if held.State == "" || held.Nonce == "" || held.Verifier == "" {
		return Handshake{}, fail(payload.FailOIDCState, "the handshake cookie is missing a required value")
	}

	// **The window is re-checked from the payload** (§19). The cookie's own Max-Age is advice to a
	// browser; a client that ignores it would otherwise present a state from last week, and the
	// signature would verify because the signature says nothing about time.
	if held.Exp == 0 || !now.Before(time.Unix(held.Exp, 0)) {
		return Handshake{}, fail(payload.FailOIDCState, "this sign-in took longer than the handshake window")
	}
	return held, nil
}

// exchange redeems the authorization code for an ID token.
func (p *Provider) exchange(ctx context.Context, document Discovery, cfg OIDCSettings, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {cfg.RedirectURI},
		"client_id":    {cfg.ClientID},
		// The verifier, which is what makes an intercepted code useless to whoever intercepted it.
		"code_verifier": {verifier},
	}
	header := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if cfg.ClientSecret != "" {
		// The secret goes in the body rather than in a Basic header. Both are legal; the body keeps it
		// out of anything that logs request headers, and this program's own transport reports the
		// *names* of the headers it sent (I6) — a name is safe, but there is no reason to put the
		// secret where a name is expected.
		form.Set("client_secret", cfg.ClientSecret)
	}

	res := p.HTTP.Do(ctx, transport.Request{
		Method: http.MethodPost,
		URL:    document.TokenEndpoint,
		Header: header,
		Body:   []byte(form.Encode()),
	})
	if !res.OK() {
		return "", p.providerFailure("the token exchange failed", document.TokenEndpoint, res)
	}

	var body struct {
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil {
		return "", Failure{
			Code:   payload.FailOIDCProvider,
			Reason: "the token endpoint did not return JSON",
			Report: reportOf(payload.PhaseProtocol, document.TokenEndpoint, "the token endpoint did not return JSON"),
		}
	}
	if body.Error != "" {
		return "", fail(payload.FailOIDCProvider, "the token endpoint refused the exchange: "+safeIdentifier(body.Error))
	}
	if body.IDToken == "" {
		// A flow that returned an access token and no ID token is an OAuth flow, not an OIDC one —
		// usually because `openid` was dropped from the scopes somewhere between here and the provider.
		return "", fail(payload.FailOIDCToken, "the token response carried no id_token")
	}
	// The access token is deliberately not kept. LabView calls no provider API, so holding one would be
	// holding a credential with no use (I5, I6).
	return body.IDToken, nil
}

// verify checks the ID token, refetching the JWKS **exactly once** on an unknown key id (§19).
//
// Exactly once, and the retry lives here rather than inside verification, so the number of provider
// requests a forged token can cause is one. An unbounded refetch would let anybody with a made-up
// `kid` aim this program at the provider's JWKS endpoint as fast as they can post callbacks.
func (p *Provider) verify(ctx context.Context, document Discovery, cfg OIDCSettings, token, nonce string, now time.Time) (IDClaims, error) {
	want := Expectations{Issuer: document.Issuer, ClientID: cfg.ClientID, Nonce: nonce}

	keys, err := p.jwks(ctx, document, now, false)
	if err != nil {
		return IDClaims{}, err
	}

	claims, err := VerifyIDToken(token, keys, want, now)
	if errors.Is(err, ErrUnknownKey) {
		// The one legitimate reason for an unknown key id is a rotation since the cache was filled.
		keys, ferr := p.jwks(ctx, document, now, true)
		if ferr != nil {
			return IDClaims{}, ferr
		}
		claims, err = VerifyIDToken(token, keys, want, now)
	}
	if err != nil {
		return claims, fail(payload.FailOIDCToken, err.Error())
	}
	return claims, nil
}

// jwks returns the provider's keys, from cache unless forced or expired.
func (p *Provider) jwks(ctx context.Context, document Discovery, now time.Time, forced bool) ([]JWK, error) {
	p.mu.Lock()
	fresh := p.keysURI == document.JWKSURI && now.Sub(p.keysAt) < DiscoveryTTL && len(p.keys) > 0
	held := p.keys
	p.mu.Unlock()

	if fresh && !forced {
		return held, nil
	}

	res := p.HTTP.Do(ctx, transport.Request{URL: document.JWKSURI})
	if !res.OK() {
		return nil, p.providerFailure("the provider's key set could not be read", document.JWKSURI, res)
	}

	var set JWKS
	if err := json.Unmarshal(res.Body, &set); err != nil {
		return nil, Failure{
			Code:   payload.FailOIDCProvider,
			Reason: "the key set is not JSON",
			Report: reportOf(payload.PhaseProtocol, document.JWKSURI, "the key set is not JSON"),
		}
	}
	usable := set.Usable()
	if len(usable) == 0 {
		return nil, fail(payload.FailOIDCProvider, "the key set contains no usable signing key")
	}

	p.mu.Lock()
	p.keys, p.keysURI, p.keysAt = usable, document.JWKSURI, now
	p.mu.Unlock()
	return usable, nil
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// Discover returns the provider's metadata, cached for DiscoveryTTL.
func (p *Provider) Discover(ctx context.Context) (Discovery, error) {
	cfg := p.Config()
	now := p.clock()()

	if strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.ClientID) == "" {
		// Not live, and this is the one place that can be reached with the method disabled — a browser
		// that kept a login page open across a configuration change.
		return Discovery{}, fail(payload.FailMethodUnavailable, "provider sign-in is not configured")
	}

	p.mu.Lock()
	if p.discovered != nil && now.Sub(p.at) < DiscoveryTTL {
		held := *p.discovered
		p.mu.Unlock()
		return held, nil
	}
	p.mu.Unlock()

	target := strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	res := p.HTTP.Do(ctx, transport.Request{URL: target})
	if !res.OK() {
		return Discovery{}, p.providerFailure("the provider's configuration could not be read", target, res)
	}

	var document Discovery
	if err := json.Unmarshal(res.Body, &document); err != nil {
		return Discovery{}, Failure{
			Code:   payload.FailOIDCProvider,
			Reason: "the discovery document is not JSON",
			Report: reportOf(payload.PhaseProtocol, target, "the discovery document is not JSON"),
		}
	}
	if err := CheckDiscovery(document, cfg.Issuer); err != nil {
		return Discovery{}, fail(payload.FailOIDCProvider, err.Error())
	}

	p.mu.Lock()
	p.discovered, p.at = &document, now
	p.mu.Unlock()
	return document, nil
}

// CheckDiscovery is §19's two rules about a discovery document, kept pure.
//
// It is exported because it is the whole of what LabView trusts about a provider before it starts
// sending it authorization requests, and it should be readable and testable on its own.
func CheckDiscovery(d Discovery, configured string) error {
	// **The document's own issuer MUST equal the configured one** (§19). This is the check that makes
	// discovery safe at all: without it, a compromised or mistyped issuer URL could hand back a
	// document pointing every endpoint at somebody else's provider, and the sign-in would complete
	// against an identity provider nobody chose.
	//
	// Trailing slashes are forgiven, because operators write `https://idp.example.com/` and providers
	// publish `https://idp.example.com`, and refusing that is a support burden with no security value.
	// Nothing else is forgiven — not case, not a differing path, not http against https.
	if trimSlash(d.Issuer) != trimSlash(configured) {
		return errors.New("the discovery document declares a different issuer than the one configured")
	}

	for name, endpoint := range map[string]string{
		"authorization endpoint": d.AuthorizationEndpoint,
		"token endpoint":         d.TokenEndpoint,
		"jwks uri":               d.JWKSURI,
	} {
		if strings.TrimSpace(endpoint) == "" {
			return errors.New("the discovery document names no " + name)
		}
		if err := requireHTTPS(endpoint); err != nil {
			return fmt.Errorf("the %s is not usable: %w", name, err)
		}
	}
	return nil
}

// requireHTTPS is §19's transport rule for provider endpoints: **https, loopback excepted**.
//
// A client secret and an authorization code both travel to the token endpoint, so plain HTTP there
// means handing them to the network. Loopback is excepted because a provider running on the same host
// is not on a network at all, and refusing it would make a local development setup impossible without
// a certificate.
func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("it is not an absolute URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && loopback(u.Hostname()) {
		return nil
	}
	return errors.New("it is not https and is not loopback")
}

// loopback reports whether a host is this machine.
//
// `localhost` by name and any address in a loopback range by value. A name that merely *resolves* to
// 127.0.0.1 is not accepted: resolution happens later and elsewhere, and a check that trusted DNS
// would let whoever controls DNS turn the https requirement off.
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func trimSlash(s string) string { return strings.TrimSuffix(strings.TrimSpace(s), "/") }

// ---------------------------------------------------------------------------
// Sealing the transient cookie
// ---------------------------------------------------------------------------

func (p *Provider) seal(h Handshake) (string, error) {
	body, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	encoded := enc(body)
	return encoded + "." + enc(p.Signer.mac([]byte(transientLabel+"."+encoded))), nil
}

func (p *Provider) unseal(token string) ([]byte, error) {
	if len(token) > MaxTokenBytes {
		return nil, errors.New("the cookie is too long to be a handshake")
	}
	i := strings.Index(token, ".")
	if i <= 0 || i == len(token)-1 {
		return nil, errors.New("it is not payload.signature")
	}
	body, mac := token[:i], token[i+1:]

	given, err := dec(mac)
	if err != nil {
		return nil, errors.New("the signature is not base64url")
	}
	if !equalHashed(given, p.Signer.mac([]byte(transientLabel+"."+body))) {
		return nil, errors.New("the signature does not verify")
	}
	raw, err := dec(body)
	if err != nil {
		return nil, errors.New("the payload is not base64url")
	}
	return raw, nil
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

// providerFailure turns a transport result into a Failure carrying the same phase vocabulary every
// other target uses (§15, §19).
func (p *Provider) providerFailure(what, endpoint string, res transport.Result) Failure {
	detail := conn.Prose(res.Phase)
	if res.Code != "" {
		detail = res.Code + " — " + detail
	}
	return Failure{
		Code:   payload.FailOIDCProvider,
		Reason: what + ": " + detail,
		Report: reportOf(res.Phase, endpoint, detail),
	}
}

// reportOf builds the connection report for an OIDC failure. The endpoint goes through the transport's
// one credential-free formatter (§20), because a token endpoint URL an operator wrote may carry a query
// string and this string reaches a log.
func reportOf(phase payload.ConnectionPhase, endpoint, detail string) *payload.ConnectionReport {
	out := conn.Report(conn.TargetOIDC, phase, transport.Endpoint(endpoint), payload.SourceDiscovered, detail)
	return &out
}

func (p *Provider) clock() func() time.Time {
	if p.Now == nil {
		return time.Now
	}
	return p.Now
}
