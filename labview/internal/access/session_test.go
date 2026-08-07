package access

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nrosier/labview/internal/payload"
)

func signer(t *testing.T) *Signer {
	t.Helper()
	return NewSigner("a test signing secret that is long enough", time.Hour)
}

func TestAMintedTokenVerifiesAndCarriesWhoSignedIn(t *testing.T) {
	s := signer(t)
	now := at(0)

	token, minted, err := s.Mint("ada", payload.MethodPasswd, now)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if !strings.HasPrefix(token, TokenVersion+".") {
		t.Fatalf("the token does not start with its version: %q", token)
	}
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Fatalf("the token has %d parts, want 3", len(parts))
	}

	got, kind, err := s.Verify(token, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("a freshly minted token does not verify: %v (%s)", err, kind)
	}
	if kind != "" {
		t.Fatalf("a valid token reported a rejection: %s", kind)
	}
	if got.U != "ada" || got.Via != payload.MethodPasswd {
		t.Fatalf("the claims do not describe the sign-in: %+v", got)
	}
	if got.Jti != minted.Jti {
		t.Fatal("the verified identifier is not the minted one")
	}
	if user := got.User(); user.Name != "ada" || user.Via != payload.MethodPasswd {
		t.Fatalf("User() disagrees with the claims: %+v", user)
	}
}

// §19: the four rejections, *checked in exactly that order — shape, then MAC, then expiry, then
// revocation*.
func TestTheFourRejectionsAreReportedByKind(t *testing.T) {
	s := signer(t)
	now := at(0)

	valid, claims, err := s.Mint("ada", payload.MethodPasswd, now)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// A token signed by somebody else, same shape.
	other := NewSigner("a different signing secret entirely!!", time.Hour)
	forged, _, _ := other.Mint("ada", payload.MethodPasswd, now)

	for _, tc := range []struct {
		name  string
		token string
		when  time.Time
		want  payload.SessionRejection
	}{
		{"no dots", "notatoken", now, payload.RejectMalformed},
		{"two parts", "v1.abc", now, payload.RejectMalformed},
		{"four parts", "v1.abc.def.ghi", now, payload.RejectMalformed},
		{"wrong version", "v2." + strings.SplitN(valid, ".", 2)[1], now, payload.RejectMalformed},
		{"signature not base64url", "v1.abc.!!!!", now, payload.RejectMalformed},
		{"too long", "v1." + strings.Repeat("a", MaxTokenBytes) + ".b", now, payload.RejectMalformed},
		{"another signer", forged, now, payload.RejectSignature},
		{"expired", valid, now.Add(2 * time.Hour), payload.RejectExpired},
	} {
		_, kind, err := s.Verify(tc.token, tc.when)
		if err == nil {
			t.Fatalf("%s: verified", tc.name)
		}
		if kind != tc.want {
			t.Fatalf("%s: reported %q, want %q", tc.name, kind, tc.want)
		}
	}

	s.Revoke(claims, now)
	if _, kind, err := s.Verify(valid, now.Add(time.Minute)); err == nil || kind != payload.RejectRevoked {
		t.Fatalf("a revoked token reported %q (err %v)", kind, err)
	}
}

// The order is the security property: a token whose signature is wrong *and* which has expired must be
// reported as a signature failure, because until the MAC verifies nothing in the payload — including its
// expiry — is a fact about anything LabView issued.
func TestABadSignatureIsReportedBeforeAnExpiry(t *testing.T) {
	s := signer(t)
	other := NewSigner("a different signing secret entirely!!", time.Hour)

	forged, _, _ := other.Mint("ada", payload.MethodPasswd, at(0))

	_, kind, err := s.Verify(forged, at(0).Add(10*time.Hour))
	if err == nil {
		t.Fatal("a forged, expired token verified")
	}
	if kind != payload.RejectSignature {
		t.Fatalf("reported %q; the MAC must be checked before the expiry", kind)
	}
}

// A tampered payload must not be reported as malformed: the shape is fine, the signature is not.
func TestAnEditedPayloadIsASignatureFailureAndNotAMalformedOne(t *testing.T) {
	s := signer(t)
	token, _, _ := s.Mint("ada", payload.MethodPasswd, at(0))

	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding our own payload: %v", err)
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshalling our own payload: %v", err)
	}
	claims.U = "root"
	edited, _ := json.Marshal(claims)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(edited) + "." + parts[2]

	got, kind, err := s.Verify(tampered, at(0).Add(time.Minute))
	if err == nil {
		t.Fatalf("a token whose username was rewritten verified as %q", got.U)
	}
	if kind != payload.RejectSignature {
		t.Fatalf("reported %q, want signature", kind)
	}
}

// §19: *Comparison MUST hash both sides before comparing, so a length difference leaks nothing.*
func TestATruncatedSignatureIsRefusedByTheSameComparisonAsAWrongOne(t *testing.T) {
	s := signer(t)
	token, _, _ := s.Mint("ada", payload.MethodPasswd, at(0))
	parts := strings.Split(token, ".")

	// A signature a byte short, which a length-sensitive comparison would refuse before comparing.
	short := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1]

	_, kind, err := s.Verify(short, at(0).Add(time.Minute))
	if err == nil {
		t.Fatal("a truncated signature verified")
	}
	if kind != payload.RejectSignature {
		t.Fatalf("a truncated signature reported %q; hashing both sides means it is a signature failure like any other", kind)
	}

	// And the property itself, at the comparison.
	if equalHashed([]byte("abc"), []byte("abcd")) {
		t.Fatal("equalHashed accepted two different values")
	}
	if !equalHashed([]byte("abc"), []byte("abc")) {
		t.Fatal("equalHashed refused two identical values")
	}
}

func TestAUsernameOutsideThePatternIsSanitisedBeforeItIsSigned(t *testing.T) {
	s := signer(t)

	_, claims, err := s.Mint("ada\nsigned in: root", payload.MethodPasswd, at(0))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if claims.U != UnknownUsername {
		t.Fatalf("a hostile name was signed as %q; §16 requires it sanitised", claims.U)
	}
}

func TestATokenMissingARequiredClaimIsMalformedEvenThoughItVerifies(t *testing.T) {
	s := signer(t)

	// Signed by us, so the MAC is right; the payload is not a session.
	body, _ := json.Marshal(map[string]string{"hello": "world"})
	encoded := base64.RawURLEncoding.EncodeToString(body)
	token := TokenVersion + "." + encoded + "." + base64.RawURLEncoding.EncodeToString(s.mac([]byte(encoded)))

	_, kind, err := s.Verify(token, at(0))
	if err == nil {
		t.Fatal("a signed object with no session claims verified")
	}
	if kind != payload.RejectMalformed {
		t.Fatalf("reported %q, want malformed", kind)
	}
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

func TestRevocationsArePrunedByExpiryOnEveryWrite(t *testing.T) {
	s := NewSigner("a test signing secret that is long enough", time.Hour)

	// Three sessions, expiring at 10, 20 and 30 minutes.
	for i, minutes := range []int{10, 20, 30} {
		s.Revoke(Claims{Jti: "j" + itoa(i), Exp: at(minutes * 60).Unix()}, at(0))
	}
	if s.Revocations() != 3 {
		t.Fatalf("%d revocations held, want 3", s.Revocations())
	}

	// A write at 25 minutes prunes the two that have already expired.
	s.Revoke(Claims{Jti: "j9", Exp: at(60 * 60).Unix()}, at(25*60))

	if got := s.Revocations(); got != 2 {
		t.Fatalf("%d revocations held after pruning, want 2 (the 30-minute one and the new one)", got)
	}
	if s.revoked.has("j0") || s.revoked.has("j1") {
		t.Fatal("an expired revocation survived a write")
	}
	if !s.revoked.has("j2") || !s.revoked.has("j9") {
		t.Fatal("a live revocation was pruned")
	}
}

// §19: capped at **10 000** entries with the **earliest expiry** evicted first.
func TestTheRevocationSetIsCappedWithTheEarliestExpiryEvictedFirst(t *testing.T) {
	s := NewSigner("a test signing secret that is long enough", time.Hour)

	// Every entry expires in the future so nothing is pruned, and the earliest is the one added first.
	for i := 0; i <= MaxRevocations; i++ {
		s.Revoke(Claims{Jti: "j" + itoa(i), Exp: at(3600 + i).Unix()}, at(0))
	}

	if got := s.Revocations(); got > MaxRevocations {
		t.Fatalf("%d revocations held, cap is %d", got, MaxRevocations)
	}
	if s.revoked.has("j0") {
		t.Fatal("the earliest-expiring revocation survived; §19 says it is evicted first")
	}
	if !s.revoked.has("j" + itoa(MaxRevocations)) {
		t.Fatal("the newest revocation was evicted, which would leave a signed-out token usable")
	}
}

func TestRevokingAnEmptyIdentifierDoesNothing(t *testing.T) {
	s := signer(t)
	s.Revoke(Claims{}, at(0))

	if s.Revocations() != 0 {
		t.Fatal("an empty identifier was added to the revocation set")
	}
}

func TestTwoSignersDoNotShareARevocationSet(t *testing.T) {
	a, b := signer(t), signer(t)
	a.Revoke(Claims{Jti: "j0", Exp: at(3600).Unix()}, at(0))

	if b.Revocations() != 0 {
		t.Fatal("two signers share one revocation set")
	}
}

// ---------------------------------------------------------------------------
// The cookie
// ---------------------------------------------------------------------------

func TestTheSessionCookieCarriesTheFourPropertiesThatMakeItSafe(t *testing.T) {
	cookies := Cookies{Secure: "auto"}
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)

	got := cookies.Set(r, "v1.a.b", 30*time.Minute)

	if got.Name != DefaultCookieName {
		t.Fatalf("name is %q", got.Name)
	}
	if !got.HttpOnly {
		t.Fatal("the session cookie is readable by script")
	}
	if got.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite is %v, want Lax (half of §19's CSRF defence)", got.SameSite)
	}
	if got.Path != "/" {
		t.Fatalf("path is %q, want /", got.Path)
	}
	if got.MaxAge != 1800 {
		t.Fatalf("Max-Age is %d, want the TTL in seconds", got.MaxAge)
	}
}

func TestTheClearingCookieMatchesTheOneItClears(t *testing.T) {
	cookies := Cookies{Name: "lab", Secure: "true"}
	r := httptest.NewRequest(http.MethodPost, "/api/logout", nil)

	set, clear := cookies.Set(r, "v1.a.b", time.Hour), cookies.Clear(r)

	if clear.Name != set.Name || clear.Path != set.Path || clear.HttpOnly != set.HttpOnly ||
		clear.SameSite != set.SameSite || clear.Secure != set.Secure {
		t.Fatalf("the clearing cookie differs in an attribute, so a browser would keep the session:\nset   %+v\nclear %+v", set, clear)
	}
	if clear.MaxAge != -1 {
		t.Fatalf("Max-Age is %d, want -1", clear.MaxAge)
	}
	if clear.Value != "" {
		t.Fatalf("the clearing cookie carries a value: %q", clear.Value)
	}
}

// §19: `Secure` follows the **effective** scheme — `X-Forwarded-Proto` first.
func TestSecureFollowsTheEffectiveSchemeAndNotTheLocalOne(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure string
		forwarded string
		want      bool
	}{
		{"auto, plain, no proxy header", "auto", "", false},
		{"auto, behind a proxy terminating TLS", "auto", "https", true},
		{"auto, proxy on plain http", "auto", "http", false},
		{"auto, a list from a chain of proxies", "auto", "https, http", true},
		{"auto, a nonsense header", "auto", "gopher", false},
		{"forced on", "true", "", true},
		{"forced off", "false", "https", false},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		if tc.forwarded != "" {
			r.Header.Set("X-Forwarded-Proto", tc.forwarded)
		}

		got := Cookies{Secure: tc.configure}.Set(r, "v1.a.b", time.Hour)

		if got.Secure != tc.want {
			t.Fatalf("%s: Secure=%v, want %v", tc.name, got.Secure, tc.want)
		}
	}
}

func TestReadingTheTokenFromARequestWithNoCookieIsNotAnError(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/overview", nil)

	if _, err := (Cookies{}).Token(r); err != ErrNoSession {
		t.Fatalf("got %v, want ErrNoSession", err)
	}

	r.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: ""})
	if _, err := (Cookies{}).Token(r); err != ErrNoSession {
		t.Fatalf("an empty cookie value: got %v, want ErrNoSession", err)
	}
}

func TestATTLBelowTheFloorTakesTheDefaultRatherThanMintingADeadToken(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Hour, time.Second} {
		s := NewSigner("a test signing secret that is long enough", ttl)
		if s.TTL() != DefaultSessionTTL {
			t.Fatalf("a TTL of %v produced %v, want the default", ttl, s.TTL())
		}

		token, _, err := s.Mint("ada", payload.MethodPasswd, at(0))
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if _, _, err := s.Verify(token, at(1)); err != nil {
			t.Fatalf("a token minted with a TTL of %v does not verify a second later: %v", ttl, err)
		}
	}
}

func TestASecretShorterThanTheHashIsStretchedRatherThanRefused(t *testing.T) {
	s := NewSigner("x", time.Hour)

	token, _, err := s.Mint("ada", payload.MethodPasswd, at(0))
	if err != nil {
		t.Fatalf("Mint with a short secret: %v", err)
	}
	if _, _, err := s.Verify(token, at(1)); err != nil {
		t.Fatalf("a short secret produced a token that does not verify: %v", err)
	}
	// And it is still a different key from another short secret.
	if _, _, err := NewSigner("y", time.Hour).Verify(token, at(1)); err == nil {
		t.Fatal("two different short secrets verify each other's tokens")
	}
}

func TestARandomSecretIsDifferentEveryTime(t *testing.T) {
	if RandomSecret() == RandomSecret() {
		t.Fatal("RandomSecret returned the same value twice; a committed default key would let anybody mint a session")
	}
}

func TestTwoSessionsNeverShareAnIdentifier(t *testing.T) {
	s := signer(t)
	seen := map[string]bool{}

	for i := 0; i < 200; i++ {
		_, claims, err := s.Mint("ada", payload.MethodPasswd, at(0))
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if seen[claims.Jti] {
			t.Fatal("two sessions were minted with one identifier, so revoking one would revoke both")
		}
		seen[claims.Jti] = true
	}
}
