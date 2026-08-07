package access

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nrosier/labview/internal/payload"
)

// Sessions are signed, not stored (§19).
//
// A token carries its own claims and a MAC over them, so there is no session table to grow, to
// synchronise or to lose on restart. **No persistence across restarts is a stated non-goal** — a new
// signing secret at startup invalidates every outstanding token, which for a lab viewer is the right
// trade: the cost is one sign-in and the benefit is no state.
//
// The whole format is one line:
//
//	v1.<base64url(payload)>.<base64url(HMAC-SHA256(payload))>
//
// Version first, because a format change has to be distinguishable from a corrupt token. base64url
// unpadded, because the value goes in a cookie and `=` and `/` are both awkward there.

// The session token's shape.
const (
	// TokenVersion is the prefix every token carries.
	TokenVersion = "v1"

	// MaxTokenBytes bounds what will be parsed. A token is around 200 bytes; anything approaching a
	// kilobyte is not a token, and refusing it before base64-decoding means a megabyte cookie costs
	// nothing.
	MaxTokenBytes = 1024
)

// Claims is the signed payload: `{u, via, iat, exp, jti}` (§19).
//
// The names are short because they are transmitted on every request. The fields are exactly five —
// there is no room here for a role, a permission or a scope, since §19 states no roles as a non-goal
// and a claim nobody checks is a claim somebody will eventually trust.
type Claims struct {
	// U is the username, always already sanitised (§16). Sanitised before signing rather than after
	// parsing, so a hostile name cannot be inside a *valid* token at all.
	U string `json:"u"`

	// Via is which method minted this session, for the session endpoint and the log.
	Via payload.LoginMethod `json:"via"`

	// Iat and Exp are Unix seconds. Seconds rather than milliseconds because a cookie's Max-Age is in
	// seconds and two units for one lifetime is two chances to be off by a thousand.
	Iat int64 `json:"iat"`
	Exp int64 `json:"exp"`

	// Jti is the identifier logout revokes. Random per session and never derived from the username or
	// the time: a predictable identifier would let anybody revoke anybody's session.
	Jti string `json:"jti"`
}

// User is what this session says about who is signed in.
func (c Claims) User() payload.SessionUser {
	return payload.SessionUser{Name: Username(c.U), Via: c.Via}
}

// Expiry is Exp as a time.
func (c Claims) Expiry() time.Time { return time.Unix(c.Exp, 0) }

// ErrNoSession is what a request with no cookie at all produces. It is separate from a rejection
// because it is not one: an anonymous request to an enforcing server is the ordinary case, and
// reporting it as `malformed` would fill the log with every unauthenticated hit.
var ErrNoSession = errors.New("no session cookie")

// Signer mints and verifies tokens.
//
// The secret is held here and nowhere else, and there is no accessor for it: a struct with no getter
// cannot have its key logged by a handler that means well (I6).
type Signer struct {
	secret []byte
	ttl    time.Duration

	// revoked is the one revocation set (§19). It is on the signer rather than beside it because
	// verification consults it and there is exactly one of both.
	revoked *revocations
}

// SessionTTLFloor is the shortest session worth issuing. A TTL of zero or less would mint a token
// that has already expired, so it is treated as *use the default* rather than as a lock-out (I4).
const SessionTTLFloor = time.Minute

// DefaultSessionTTL matches §3's `auth.session.ttlMinutes` default of 720.
const DefaultSessionTTL = 720 * time.Minute

// NewSigner builds a signer. A secret shorter than 32 bytes is stretched by hashing rather than
// refused: refusing would be a lock-out over a configuration value, and hashing a weak secret does
// not make it strong but does make it the right length for HMAC.
func NewSigner(secret string, ttl time.Duration) *Signer {
	key := []byte(secret)
	if len(key) < sha256.Size {
		sum := sha256.Sum256(key)
		key = sum[:]
	}
	if ttl < SessionTTLFloor {
		ttl = DefaultSessionTTL
	}
	return &Signer{secret: key, ttl: ttl, revoked: &revocations{}}
}

// RandomSecret is the secret used when configuration names none.
//
// A random secret per process rather than a constant: a committed default signing key means anybody
// with the source can mint a session for any LabView that never set one, which is every default
// install. The cost is that sessions do not survive a restart, which §19 already accepts.
func RandomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Unreachable on any supported platform. A degraded secret still gates; a refusal to start
		// does not (I4).
		return "labview session secret fallback"
	}
	return hex.EncodeToString(b)
}

// TTL is how long a minted session lasts.
func (s *Signer) TTL() time.Duration { return s.ttl }

// Mint produces a token for user signed in via method, valid from now.
//
// now is a parameter because §19 requires every pure part to take the current time — and because a
// test for *expired* that has to wait for a real clock is a test nobody runs.
func (s *Signer) Mint(user string, via payload.LoginMethod, now time.Time) (string, Claims, error) {
	jti, err := newJTI()
	if err != nil {
		return "", Claims{}, err
	}

	claims := Claims{
		// Sanitised here, at the moment of minting. Every later reader of a valid token therefore
		// holds a name that already satisfies the pattern (§16).
		U:   Username(user),
		Via: via,
		Iat: now.Unix(),
		Exp: now.Add(s.ttl).Unix(),
		Jti: jti,
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", Claims{}, err
	}

	encoded := enc(body)
	return TokenVersion + "." + encoded + "." + enc(s.mac([]byte(encoded))), claims, nil
}

// Verify checks a token and returns its claims.
//
// **The checks run in exactly §19's order: shape, MAC, expiry, revocation.** The order is the
// security property, not a style: checking expiry before the MAC would answer a question about a
// document that has not been shown to be ours, and reporting `expired` for a forged token would tell
// a forger that their signature was the only thing wrong. Revocation last because it is the only
// check that touches shared state, and an unauthenticated caller should not be able to make the
// server take a lock.
func (s *Signer) Verify(token string, now time.Time) (Claims, payload.SessionRejection, error) {
	if len(token) > MaxTokenBytes {
		return Claims{}, payload.RejectMalformed, errors.New("session token is too long")
	}

	// Shape.
	version, body, mac, ok := cut(token)
	if !ok || version != TokenVersion {
		return Claims{}, payload.RejectMalformed, errors.New("session token is not " + TokenVersion + ".payload.signature")
	}
	given, err := dec(mac)
	if err != nil {
		return Claims{}, payload.RejectMalformed, errors.New("session signature is not base64url")
	}

	// MAC — before the payload is unmarshalled, so no attacker-chosen structure is interpreted until
	// it has been shown to be ours.
	if !equalHashed(given, s.mac([]byte(body))) {
		return Claims{}, payload.RejectSignature, errors.New("session signature does not verify")
	}

	raw, err := dec(body)
	if err != nil {
		// Reachable only for a token we signed ourselves, so it is a bug rather than an attack — but
		// it is still reported rather than trusted.
		return Claims{}, payload.RejectMalformed, errors.New("session payload is not base64url")
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Claims{}, payload.RejectMalformed, errors.New("session payload is not the expected object")
	}
	if claims.U == "" || claims.Jti == "" || claims.Exp == 0 {
		return Claims{}, payload.RejectMalformed, errors.New("session payload is missing a required claim")
	}

	// Expiry.
	if !now.Before(claims.Expiry()) {
		return claims, payload.RejectExpired, errors.New("session expired")
	}

	// Revocation.
	if s.revoked.has(claims.Jti) {
		return claims, payload.RejectRevoked, errors.New("session was signed out")
	}

	return claims, "", nil
}

// Revoke adds a session's identifier to the revocation set (§19).
func (s *Signer) Revoke(c Claims, now time.Time) { s.revoked.add(c.Jti, c.Expiry(), now) }

// Revocations is how many identifiers are held, for a test and a diagnostic.
func (s *Signer) Revocations() int { return s.revoked.len() }

// mac is the HMAC over the encoded payload.
//
// Over the *encoded* payload rather than the raw JSON, because that is the byte string actually
// present in the token: signing the decoded form would mean two different tokens could carry the same
// signature if base64 had any slack, and unpadded base64url of an attacker-chosen string is exactly
// where that slack lives.
func (s *Signer) mac(body []byte) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write(body)
	return m.Sum(nil)
}

// equalHashed compares two MACs in constant time, **hashing both sides first** (§19).
//
// hmac.Equal is already constant-time in its content, but it returns immediately when the lengths
// differ — so a caller could learn the MAC's length by timing, and more usefully could tell
// *truncated* from *wrong*. Hashing makes both sides 32 bytes whatever came in, so length tells
// nothing and there is exactly one comparison path.
func equalHashed(a, b []byte) bool {
	ha, hb := sha256.Sum256(a), sha256.Sum256(b)
	return hmac.Equal(ha[:], hb[:])
}

// cut splits a token into its three parts without allocating a slice.
func cut(token string) (version, body, mac string, ok bool) {
	first := strings.Index(token, ".")
	if first < 0 {
		return "", "", "", false
	}
	rest := token[first+1:]
	second := strings.Index(rest, ".")
	if second < 0 {
		return "", "", "", false
	}
	body, mac = rest[:second], rest[second+1:]
	if body == "" || mac == "" || strings.Contains(mac, ".") {
		return "", "", "", false
	}
	return token[:first], body, mac, true
}

func enc(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// newJTI produces a session identifier from 16 random bytes.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return enc(b), nil
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// MaxRevocations is the cap §19 states.
//
// A bound is needed because logout is reachable by anybody holding a token, and a set that grew
// without limit would be a memory leak with a public trigger. 10 000 is more sign-outs than a lab
// produces in a session lifetime.
const MaxRevocations = 10000

// revocations is the one revocation set: identifier to the expiry after which it no longer matters.
//
// Keyed on the identifier and valued on the expiry, because that is what makes pruning possible: an
// entry whose session has expired is already refused by the expiry check, so keeping it would be
// holding state to answer a question that is answered earlier.
type revocations struct {
	mu sync.Mutex
	at map[string]time.Time
}

// add revokes an identifier, **pruning by expiry on every write** (§19).
//
// Pruning on write rather than on a timer: writes are rare (a logout), reads are constant (every
// request), and a background goroutine to sweep a map this small would be more moving parts than the
// map.
func (r *revocations) add(jti string, expiry, now time.Time) {
	if jti == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.at == nil {
		r.at = map[string]time.Time{}
	}
	for held, exp := range r.at {
		if !now.Before(exp) {
			delete(r.at, held)
		}
	}
	r.at[jti] = expiry

	if len(r.at) > MaxRevocations {
		r.evict()
	}
}

// evict drops down to the cap, **earliest expiry first** (§19). The caller holds the lock.
//
// Earliest expiry rather than oldest insertion, because an entry that expires soonest is the one whose
// removal costs least: it is about to stop mattering anyway. Evicting by insertion order would drop a
// long-lived session's revocation while keeping one that expires in a minute — which is exactly
// backwards, since the dropped one is the token still usable.
func (r *revocations) evict() {
	type entry struct {
		jti string
		exp time.Time
	}
	all := make([]entry, 0, len(r.at))
	for jti, exp := range r.at {
		all = append(all, entry{jti, exp})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].exp.Equal(all[j].exp) {
			// Tie broken on the identifier so eviction is deterministic (I7) rather than dependent on
			// map order.
			return all[i].jti < all[j].jti
		}
		return all[i].exp.Before(all[j].exp)
	})
	for i := 0; i < len(all) && len(r.at) > MaxRevocations; i++ {
		delete(r.at, all[i].jti)
	}
}

func (r *revocations) has(jti string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.at[jti]
	return ok
}

func (r *revocations) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.at)
}

// ---------------------------------------------------------------------------
// The cookie
// ---------------------------------------------------------------------------

// DefaultCookieName is the session cookie's name when configuration names none.
const DefaultCookieName = "labview_session"

// Cookies mints and clears the session cookie.
type Cookies struct {
	// Name is the cookie's name. Empty takes DefaultCookieName.
	Name string

	// Secure is `auto`, `true` or `false` (§3). `auto` follows the effective scheme.
	Secure string
}

func (c Cookies) name() string {
	if strings.TrimSpace(c.Name) == "" {
		return DefaultCookieName
	}
	return c.Name
}

// Set builds the Set-Cookie for a minted token.
//
// The four properties are not configurable, because each of them is the thing that makes the cookie
// safe rather than a preference:
//
//   - HttpOnly, so a script cannot read the token. LabView renders no untrusted HTML, but a session
//     readable by JavaScript is one XSS away from being stolen rather than merely being used.
//   - SameSite=Lax, which is half of the CSRF defence (§19) — the other half is the Origin check.
//   - Path=/, because the UI, the API and the OIDC routes are all under it.
//   - Max-Age from the TTL, so a browser drops the cookie at the same moment the server stops
//     honouring it, and a user is not shown a signed-in shell that 401s on every request.
func (c Cookies) Set(r *http.Request, token string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     c.name(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   c.secure(r),
		MaxAge:   int(ttl.Seconds()),
	}
}

// Clear builds the Set-Cookie that removes the session.
//
// Same name, path and flags as Set. A clearing cookie whose attributes differ from the one it is
// clearing is not the same cookie as far as a browser is concerned, and the session would survive the
// logout it was told about.
func (c Cookies) Clear(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     c.name(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   c.secure(r),
		MaxAge:   -1,
	}
}

// Token reads the session token from a request, or ErrNoSession.
func (c Cookies) Token(r *http.Request) (string, error) {
	cookie, err := r.Cookie(c.name())
	if err != nil || cookie.Value == "" {
		return "", ErrNoSession
	}
	return cookie.Value, nil
}

// secure resolves the `Secure` attribute.
func (c Cookies) secure(r *http.Request) bool {
	switch c.Secure {
	case "true":
		return true
	case "false":
		return false
	default:
		return EffectiveScheme(r) == "https"
	}
}

// EffectiveScheme is the scheme the *client* used, which is not always the one this server saw.
//
// **`X-Forwarded-Proto` first** (§19). LabView normally sits behind the very reverse proxy it
// documents, terminating TLS and forwarding plain HTTP — so `r.TLS == nil` is the usual case for a
// server whose users are on https, and trusting it would mean never setting Secure in the one
// deployment that most needs it.
//
// The trade is stated plainly: a header is client-controlled unless a proxy overwrites it, so a
// direct-to-LabView request can claim https and get a Secure cookie it cannot then send back. That
// fails closed — the user cannot sign in over plain HTTP — whereas the other mistake ships a session
// cookie in the clear. Only the first value of a comma-joined list is read, since that is the
// original client's.
func EffectiveScheme(r *http.Request) string {
	if r == nil {
		return "http"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		first := forwarded
		if i := strings.Index(first, ","); i >= 0 {
			first = first[:i]
		}
		if scheme := strings.ToLower(strings.TrimSpace(first)); scheme == "https" || scheme == "http" {
			return scheme
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
