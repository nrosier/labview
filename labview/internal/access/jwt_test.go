package access

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// The keys are generated once for the whole package: a 2048-bit RSA keygen per test row would dominate
// the suite's runtime and prove nothing.
var (
	provider = sync.OnceValue(func() *rsa.PrivateKey { return mustRSA(MinRSABits) })
	stranger = sync.OnceValue(func() *rsa.PrivateKey { return mustRSA(MinRSABits) })
	curveKey = sync.OnceValue(func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		return key
	})
)

func mustRSA(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return key
}

const (
	testIssuer   = "https://idp.example.com"
	testClientID = "labview"
	testNonce    = "a-nonce-from-this-handshake"
	// testSecret stands in for the client secret, which is the value an HS256 forgery would be signed
	// with. §19 names this attack, so the test names it too.
	testSecret = "the client secret from the environment"
)

func expectations() Expectations {
	return Expectations{Issuer: testIssuer, ClientID: testClientID, Nonce: testNonce}
}

// idClaims builds a token body that passes every check, so each test can break exactly one thing. A nil
// override deletes the claim.
func idClaims(now time.Time, overrides map[string]any) map[string]any {
	out := map[string]any{
		"iss":   testIssuer,
		"sub":   "user-1",
		"aud":   testClientID,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nonce": testNonce,
	}
	for name, value := range overrides {
		if value == nil {
			delete(out, name)
			continue
		}
		out[name] = value
	}
	return out
}

// sign builds a JWT. key is a *rsa.PrivateKey, an *ecdsa.PrivateKey, a []byte HMAC secret, or nil for
// `alg: none`.
func sign(t *testing.T, alg, kid string, key any, claims map[string]any) string {
	t.Helper()

	head := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		head["kid"] = kid
	}
	rawHead, err := json.Marshal(head)
	if err != nil {
		t.Fatalf("marshalling the header: %v", err)
	}
	rawClaims, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshalling the claims: %v", err)
	}

	signing := base64.RawURLEncoding.EncodeToString(rawHead) + "." + base64.RawURLEncoding.EncodeToString(rawClaims)
	return signing + "." + base64.RawURLEncoding.EncodeToString(signatureOver(t, alg, key, []byte(signing)))
}

func signatureOver(t *testing.T, alg string, key any, signing []byte) []byte {
	t.Helper()

	if alg == "none" {
		return nil
	}
	if strings.HasPrefix(alg, "HS") {
		m := hmac.New(sha256.New, key.([]byte))
		m.Write(signing)
		return m.Sum(nil)
	}

	h, ok := asymmetric[alg]
	if !ok {
		t.Fatalf("the test asked for %q, which this program does not know how to sign", alg)
	}
	digest := digestOf(h, signing)

	switch priv := key.(type) {
	case *rsa.PrivateKey:
		var out []byte
		var err error
		if strings.HasPrefix(alg, "PS") {
			out, err = rsa.SignPSS(rand.Reader, priv, h, digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       h,
			})
		} else {
			out, err = rsa.SignPKCS1v15(rand.Reader, priv, h, digest)
		}
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
		return out

	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
		size := (priv.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out
	}

	t.Fatalf("no signer for %T", key)
	return nil
}

func rsaJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(pub *ecdsa.PublicKey, kid string) JWK {
	size := (pub.Curve.Params().BitSize + 7) / 8
	x, y := make([]byte, size), make([]byte, size)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return JWK{
		Kty: "EC",
		Kid: kid,
		Crv: pub.Curve.Params().Name,
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}
}

// providerKeys is the JWKS a well-behaved provider publishes.
func providerKeys() []JWK { return []JWK{rsaJWK(&provider().PublicKey, "k1")} }

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

func TestAConformingIDTokenVerifiesAndYieldsItsClaims(t *testing.T) {
	now := at(0)
	token := sign(t, "RS256", "k1", provider(), idClaims(now, nil))

	got, err := VerifyIDToken(token, providerKeys(), expectations(), now)
	if err != nil {
		t.Fatalf("a conforming token does not verify: %v", err)
	}
	if got.Iss != testIssuer || got.Sub != "user-1" || got.Nonce != testNonce {
		t.Fatalf("the claims were not read back: %+v", got)
	}
	if !got.Aud.Has(testClientID) {
		t.Fatalf("aud is %v", got.Aud)
	}
}

func TestEveryAcceptedAlgorithmActuallyVerifies(t *testing.T) {
	now := at(0)

	for _, tc := range []struct {
		alg  string
		key  any
		keys []JWK
	}{
		{"RS256", provider(), providerKeys()},
		{"RS384", provider(), providerKeys()},
		{"RS512", provider(), providerKeys()},
		{"PS256", provider(), providerKeys()},
		{"PS384", provider(), providerKeys()},
		{"PS512", provider(), providerKeys()},
		{"ES256", curveKey(), []JWK{ecJWK(&curveKey().PublicKey, "e1")}},
	} {
		kid := "k1"
		if strings.HasPrefix(tc.alg, "ES") {
			kid = "e1"
		}
		token := sign(t, tc.alg, kid, tc.key, idClaims(now, nil))

		if _, err := VerifyIDToken(token, tc.keys, expectations(), now); err != nil {
			t.Fatalf("%s: an allowlisted algorithm does not verify: %v", tc.alg, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Asymmetric only — the refusal §19 names
// ---------------------------------------------------------------------------

// §19: *`alg: none` and every HMAC algorithm are refused, and there is no configuration that re-enables
// them.* The HS256 case is the one that matters: the client secret is in this process's environment, so
// an accepted HS256 would let anybody holding that secret mint a token that verifies as the provider's.
func TestAnHS256TokenSignedWithTheClientSecretIsRefused(t *testing.T) {
	now := at(0)
	token := sign(t, "HS256", "k1", []byte(testSecret), idClaims(now, nil))

	if _, err := VerifyIDToken(token, providerKeys(), expectations(), now); err == nil {
		t.Fatal("a token signed with the client secret verified as if the provider had issued it")
	}

	// And it is refused even when the "JWKS" hands over the secret as a key, which is the shape a
	// confused-deputy implementation takes.
	secretAsKey := []JWK{{Kty: "oct", Kid: "k1", Alg: "HS256"}}
	if _, err := VerifyIDToken(token, secretAsKey, expectations(), now); err == nil {
		t.Fatal("an HS256 token verified against a symmetric key")
	}
}

func TestAnUnsignedTokenIsRefused(t *testing.T) {
	now := at(0)

	for _, alg := range []string{"none", "None", "NONE", "", "HS384", "HS512", "RS256x", "rs256"} {
		token := sign(t, "none", "k1", nil, idClaims(now, nil))
		// Rewrite the header's alg to the case under test, leaving the empty signature.
		parts := strings.Split(token, ".")
		head, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT"})
		forged := base64.RawURLEncoding.EncodeToString(head) + "." + parts[1] + "."

		if _, err := VerifyIDToken(forged, providerKeys(), expectations(), now); err == nil {
			t.Fatalf("a token with alg %q and no signature verified", alg)
		}
	}
}

// The refused algorithm is echoed back through safeIdentifier, so a header claiming a megabyte of
// control characters cannot write them into a log line (§16).
func TestARefusedAlgorithmIsNotEchoedRaw(t *testing.T) {
	now := at(0)
	head, _ := json.Marshal(map[string]any{"alg": "HS256\n2026-03-14 signed in: root"})
	body, _ := json.Marshal(idClaims(now, nil))
	token := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(body) + "."

	_, err := VerifyIDToken(token, providerKeys(), expectations(), now)
	if err == nil {
		t.Fatal("verified")
	}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("the error carries a newline from the token's header: %q", err)
	}
}

// ---------------------------------------------------------------------------
// The order
// ---------------------------------------------------------------------------

// §19 states the order *signature → iss → aud → azp → exp/iat → nonce*, and the order is the property:
// a token that is wrong in several ways must be reported on the earliest, or the report tells a forger
// which field to fix next.
func TestTheSignatureIsCheckedBeforeAnythingInThePayload(t *testing.T) {
	now := at(0)

	// Wrong issuer, wrong audience, expired, wrong nonce — and signed by a stranger.
	token := sign(t, "RS256", "k1", stranger(), idClaims(now, map[string]any{
		"iss":   "https://attacker.example.com",
		"aud":   "someone-else",
		"exp":   now.Add(-time.Hour).Unix(),
		"nonce": "not this handshake",
	}))

	_, err := VerifyIDToken(token, providerKeys(), expectations(), now)
	if err == nil {
		t.Fatal("a token signed by a stranger verified")
	}
	for _, leaked := range []string{"issuer", "audience", "expired", "nonce"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("an unverified token was reported on its %s: %q", leaked, err)
		}
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected a signature failure, got %q", err)
	}
}

func TestTheIssuerIsCheckedBeforeTheAudience(t *testing.T) {
	now := at(0)
	token := sign(t, "RS256", "k1", provider(), idClaims(now, map[string]any{
		"iss": "https://attacker.example.com",
		"aud": "someone-else",
	}))

	_, err := VerifyIDToken(token, providerKeys(), expectations(), now)
	if err == nil {
		t.Fatal("verified")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("expected an issuer failure, got %q; an audience match against the wrong issuer's token is meaningless", err)
	}
}

// §19: the issuer is compared **exactly**. Trailing-slash forgiveness applies to the discovery
// document's self-declared issuer, not to the token's claim.
func TestTheTokenIssuerIsComparedExactlyWithNoForgiveness(t *testing.T) {
	now := at(0)

	for _, claimed := range []string{
		testIssuer + "/",
		strings.ToUpper(testIssuer),
		testIssuer + "/realms",
		" " + testIssuer,
		"http://idp.example.com",
	} {
		token := sign(t, "RS256", "k1", provider(), idClaims(now, map[string]any{"iss": claimed}))

		if _, err := VerifyIDToken(token, providerKeys(), expectations(), now); err == nil {
			t.Fatalf("an issuer of %q was accepted for %q", claimed, testIssuer)
		}
	}
}

func TestAnAudienceThatDoesNotNameThisClientIsRefused(t *testing.T) {
	now := at(0)

	for _, aud := range []any{
		"someone-else",
		[]string{"someone-else"},
		[]string{"someone-else", "another"},
		[]string{},
		nil,
	} {
		token := sign(t, "RS256", "k1", provider(), idClaims(now, map[string]any{"aud": aud}))

		if _, err := VerifyIDToken(token, providerKeys(), expectations(), now); err == nil {
			t.Fatalf("an audience of %v was accepted", aud)
		}
	}
}

// A provider may send `aud` as a string or as an array, and both mean the same thing.
func TestBothLegalFormsOfAudienceAreAccepted(t *testing.T) {
	now := at(0)

	for _, aud := range []any{
		testClientID,
		[]string{testClientID},
		[]string{"another-client", testClientID},
	} {
		token := sign(t, "RS256", "k1", provider(), idClaims(now, map[string]any{"aud": aud}))

		if _, err := VerifyIDToken(token, providerKeys(), expectations(), now); err != nil {
			t.Fatalf("an audience of %v was refused: %v", aud, err)
		}
	}

	var a audience
	if err := a.UnmarshalJSON([]byte(`42`)); err == nil {
		t.Fatal("a numeric audience decoded")
	}
}

// §19: `azp` is checked **only when present** — required for a multi-audience token, correctly omitted
// on a single-audience one.
func TestTheAuthorizedPartyIsCheckedOnlyWhenPresent(t *testing.T) {
	now := at(0)

	absent := sign(t, "RS256", "k1", provider(), idClaims(now, map[string]any{"azp": nil}))
	if _, err := VerifyIDToken(absent, providerKeys(), expectations(), now); err != nil {
		t.Fatalf("a token with no azp was refused: %v", err)
	}

	ours := sign(t, "RS256", "k1", provider(), idClaims(now, map[string]any{"azp": testClientID}))
	if _, err := VerifyIDToken(ours, providerKeys(), expectations(), now); err != nil {
		t.Fatalf("a token whose azp is this client was refused: %v", err)
	}

	theirs := sign(t, "RS256", "k1", provider(), idClaims(now, map[string]any{
		"azp": "another-client",
		"aud": []string{testClientID, "another-client"},
	}))
	if _, err := VerifyIDToken(theirs, providerKeys(), expectations(), now); err == nil {
		t.Fatal("a token minted for another client, with this client merely in the audience, verified")
	}
}

// §19: `exp` and `iat` with **60 seconds** of tolerance, applied symmetrically.
func TestTheClockToleranceIsSixtySecondsEachWay(t *testing.T) {
	now := at(0)

	for _, tc := range []struct {
		name   string
		claims map[string]any
		ok     bool
	}{
		{"expiring in an hour", map[string]any{}, true},
		{"expired thirty seconds ago", map[string]any{"exp": now.Add(-30 * time.Second).Unix()}, true},
		{"expired two minutes ago", map[string]any{"exp": now.Add(-2 * time.Minute).Unix()}, false},
		{"no expiry at all", map[string]any{"exp": nil}, false},
		{"issued thirty seconds from now", map[string]any{"iat": now.Add(30 * time.Second).Unix()}, true},
		{"issued two minutes from now", map[string]any{"iat": now.Add(2 * time.Minute).Unix()}, false},
		{"no iat", map[string]any{"iat": nil}, true},
	} {
		token := sign(t, "RS256", "k1", provider(), idClaims(now, tc.claims))

		_, err := VerifyIDToken(token, providerKeys(), expectations(), now)
		if (err == nil) != tc.ok {
			t.Fatalf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// The nonce is what ties a valid token to *this* sign-in. Without it a token captured from one handshake
// replays into another, and every other check still passes.
func TestATokenFromAnotherHandshakeIsRefusedOnItsNonce(t *testing.T) {
	now := at(0)
	token := sign(t, "RS256", "k1", provider(), idClaims(now, map[string]any{"nonce": "another handshake"}))

	_, err := VerifyIDToken(token, providerKeys(), expectations(), now)
	if err == nil {
		t.Fatal("a replayed token verified")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("expected a nonce failure, got %q", err)
	}
}

func TestATokenWithNoNonceIsRefusedAndSoIsExpectingNone(t *testing.T) {
	now := at(0)

	missing := sign(t, "RS256", "k1", provider(), idClaims(now, map[string]any{"nonce": nil}))
	if _, err := VerifyIDToken(missing, providerKeys(), expectations(), now); err == nil {
		t.Fatal("a token carrying no nonce verified")
	}

	// Expecting no nonce means the handshake state was lost, which must fail rather than skip the check.
	fine := sign(t, "RS256", "k1", provider(), idClaims(now, nil))
	want := expectations()
	want.Nonce = ""
	if _, err := VerifyIDToken(fine, providerKeys(), want, now); err == nil {
		t.Fatal("a token verified against no expected nonce, so the replay check was skipped")
	}
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

// §19: an unknown `kid` triggers **exactly one** refetch, so it is reported as its own error rather than
// as a signature failure — the caller cannot distinguish *refetch might help* from *this is a forgery*
// otherwise.
func TestAnUnknownKeyIdIsReportedAsSuchSoTheCallerCanRefetchOnce(t *testing.T) {
	now := at(0)
	token := sign(t, "RS256", "k9", provider(), idClaims(now, nil))

	_, err := VerifyIDToken(token, providerKeys(), expectations(), now)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v, want ErrUnknownKey", err)
	}

	// An empty JWKS is the same case.
	if _, err := VerifyIDToken(token, nil, expectations(), now); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("an empty JWKS reported %v, want ErrUnknownKey", err)
	}
}

// §19: a token naming a key id is verified against **that key only**. Trying every key would mean a
// token naming key A but signed with key B verifies, which defeats naming a key at all.
func TestATokenNamingOneKeyIsNotVerifiedAgainstAnother(t *testing.T) {
	now := at(0)
	keys := []JWK{
		rsaJWK(&provider().PublicKey, "k1"),
		rsaJWK(&stranger().PublicKey, "k2"),
	}

	// Names k1, signed with the k2 key.
	token := sign(t, "RS256", "k1", stranger(), idClaims(now, nil))

	_, err := VerifyIDToken(token, keys, expectations(), now)
	if err == nil {
		t.Fatal("a token naming one key verified against another")
	}
	if errors.Is(err, ErrUnknownKey) {
		t.Fatal("the named key was present, so this is a signature failure and must not drive a refetch")
	}
}

func TestATokenWithNoKeyIdIsTriedAgainstEveryKeyOfTheRightType(t *testing.T) {
	now := at(0)
	keys := []JWK{
		rsaJWK(&stranger().PublicKey, "k2"),
		rsaJWK(&provider().PublicKey, "k1"),
	}
	token := sign(t, "RS256", "", provider(), idClaims(now, nil))

	if _, err := VerifyIDToken(token, keys, expectations(), now); err != nil {
		t.Fatalf("a provider publishing several keys and signing without a kid was refused: %v", err)
	}
}

// §19: below the RSA floor the signature check passes while providing no assurance, so the key is
// refused instead.
func TestAnRSAKeyBelowTheFloorIsRefusedEvenThoughItsSignatureIsValid(t *testing.T) {
	now := at(0)
	small := mustRSA(1024)
	token := sign(t, "RS256", "k1", small, idClaims(now, nil))

	if _, err := VerifyIDToken(token, []JWK{rsaJWK(&small.PublicKey, "k1")}, expectations(), now); err == nil {
		t.Fatalf("a %d-bit RSA key was accepted; the floor is %d", small.N.BitLen(), MinRSABits)
	}
}

func TestAnECDSASignatureOfTheWrongLengthIsRefusedRatherThanPadded(t *testing.T) {
	now := at(0)
	key := ecJWK(&curveKey().PublicKey, "e1")
	token := sign(t, "ES256", "e1", curveKey(), idClaims(now, nil))

	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding our own signature: %v", err)
	}

	// Left-padded with a zero byte, which is the same number and the wrong length.
	padded := parts[0] + "." + parts[1] + "." +
		base64.RawURLEncoding.EncodeToString(append([]byte{0}, raw...))

	if _, err := VerifyIDToken(padded, []JWK{key}, expectations(), now); err == nil {
		t.Fatal("an ECDSA signature of the wrong length verified")
	}
}

func TestAnECPointOffTheCurveIsNotAKey(t *testing.T) {
	pub := curveKey().PublicKey
	key := ecJWK(&pub, "e1")

	// Move x by one, which almost certainly leaves the curve.
	x, _ := base64.RawURLEncoding.DecodeString(key.X)
	x[len(x)-1] ^= 0x01
	key.X = base64.RawURLEncoding.EncodeToString(x)

	if _, err := key.ecdsa(); err == nil {
		t.Fatal("a point off the curve was accepted as a public key")
	}
}

func TestTheJWKSIsFilteredToKeysThisProgramCanVerifyWith(t *testing.T) {
	set := JWKS{Keys: []JWK{
		{Kty: "RSA", Kid: "sig", Use: "sig"},
		{Kty: "RSA", Kid: "no-use-stated"},
		{Kty: "RSA", Kid: "enc", Use: "enc"},
		{Kty: "oct", Kid: "symmetric"},
		{Kty: "OKP", Kid: "ed25519"},
		{Kty: "EC", Kid: "ec"},
	}}

	got := set.Usable()

	var kids []string
	for _, key := range got {
		kids = append(kids, key.Kid)
	}
	if strings.Join(kids, ",") != "sig,no-use-stated,ec" {
		t.Fatalf("kept %v; an encryption key and a symmetric key must both be dropped", kids)
	}
}

func TestTheJWKSIsCappedSoAKeyRotationCannotBecomeADenialOfService(t *testing.T) {
	var keys []JWK
	for i := 0; i < 100; i++ {
		keys = append(keys, JWK{Kty: "RSA", Kid: "k" + itoa(i)})
	}

	if got := len(JWKS{Keys: keys}.Usable()); got != MaxJWKSKeys {
		t.Fatalf("%d keys kept, cap is %d", got, MaxJWKSKeys)
	}
}

func TestAKeyWhoseAlgorithmDisagreesWithTheTokenIsNotACandidate(t *testing.T) {
	now := at(0)
	// The provider's key, but declared as an ES256 key.
	declared := rsaJWK(&provider().PublicKey, "k1")
	declared.Alg = "ES256"
	token := sign(t, "RS256", "k1", provider(), idClaims(now, nil))

	if _, err := VerifyIDToken(token, []JWK{declared}, expectations(), now); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v; a key declaring another algorithm is not a candidate for this token", err)
	}
}

// ---------------------------------------------------------------------------
// Shape and caps
// ---------------------------------------------------------------------------

func TestAMalformedTokenIsRefusedBeforeAnyCryptography(t *testing.T) {
	now := at(0)

	for _, tc := range []struct{ name, token string }{
		{"empty", ""},
		{"one part", "abc"},
		{"two parts", "abc.def"},
		{"four parts", "abc.def.ghi.jkl"},
		{"header not base64url", "!!!.def.ghi"},
		{"header not an object", base64.RawURLEncoding.EncodeToString([]byte(`"a string"`)) + ".def.ghi"},
		{"implausibly large", strings.Repeat("a", MaxJWTBytes+1)},
	} {
		if _, err := VerifyIDToken(tc.token, providerKeys(), expectations(), now); err == nil {
			t.Fatalf("%s: verified", tc.name)
		}
	}
}

func TestASignatureThatIsNotBase64urlIsRefused(t *testing.T) {
	now := at(0)
	token := sign(t, "RS256", "k1", provider(), idClaims(now, nil))
	parts := strings.Split(token, ".")

	if _, err := VerifyIDToken(parts[0]+"."+parts[1]+".!!!!", providerKeys(), expectations(), now); err == nil {
		t.Fatal("verified")
	}
}

func TestAPayloadEditedAfterSigningDoesNotVerify(t *testing.T) {
	now := at(0)
	token := sign(t, "RS256", "k1", provider(), idClaims(now, nil))
	parts := strings.Split(token, ".")

	body, _ := json.Marshal(idClaims(now, map[string]any{"sub": "root"}))
	edited := parts[0] + "." + base64.RawURLEncoding.EncodeToString(body) + "." + parts[2]

	if _, err := VerifyIDToken(edited, providerKeys(), expectations(), now); err == nil {
		t.Fatal("a token whose subject was rewritten after signing verified")
	}
}

// ---------------------------------------------------------------------------
// The username
// ---------------------------------------------------------------------------

// §19's chain: configured claim → `preferred_username` → `email` → `sub`.
func TestTheUsernameComesFromTheFirstClaimInTheChainThatHoldsAValidName(t *testing.T) {
	for _, tc := range []struct {
		name       string
		claims     IDClaims
		configured string
		want       string
	}{
		{
			name: "preferred_username first by default",
			claims: IDClaims{
				Sub:               "d2b0f5e0",
				PreferredUsername: "ada",
				Email:             "ada@example.com",
			},
			want: "ada",
		},
		{
			name:       "a configured claim wins",
			claims:     IDClaims{Sub: "d2b0f5e0", PreferredUsername: "ada", Extra: extra(`{"lab_user":"grace"}`)},
			configured: "lab_user",
			want:       "grace",
		},
		{
			name:   "email when there is no preferred_username",
			claims: IDClaims{Sub: "d2b0f5e0", Email: "ada@example.com"},
			want:   "ada@example.com",
		},
		{
			name:   "sub last, because it is usually opaque",
			claims: IDClaims{Sub: "d2b0f5e0"},
			want:   "d2b0f5e0",
		},
		{
			name:       "a configured claim that is absent falls through",
			claims:     IDClaims{Sub: "d2b0f5e0", PreferredUsername: "ada"},
			configured: "lab_user",
			want:       "ada",
		},
		{
			name:       "a configured claim that is not a string falls through",
			claims:     IDClaims{Sub: "d2b0f5e0", PreferredUsername: "ada", Extra: extra(`{"lab_user":{"name":"grace"}}`)},
			configured: "lab_user",
			want:       "ada",
		},
		{
			name:   "a candidate outside the pattern is skipped, not sanitised",
			claims: IDClaims{Sub: "d2b0f5e0", PreferredUsername: "Ada Lovelace"},
			want:   "d2b0f5e0",
		},
	} {
		got, err := UsernameFrom(tc.claims, tc.configured)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// §19: a name that cannot be trusted must **fail the handshake**, not become `?`. A session for `?` is a
// session shared by everybody else whose claims also failed the pattern.
func TestANameThatFailsThePatternIsNeverTurnedIntoTheUnknownMarker(t *testing.T) {
	got, err := UsernameFrom(IDClaims{
		Sub:               "a subject with spaces",
		PreferredUsername: "Ada Lovelace",
		Email:             "ada lovelace@example.com",
	}, "")

	if err == nil {
		t.Fatalf("a token with no usable name produced the username %q", got)
	}
	if got == UnknownUsername {
		t.Fatal("a session would have been signed for the unknown-username marker, which every failing user shares")
	}
	if got != "" {
		t.Fatalf("got %q with an error, want the empty string", got)
	}
}

func TestTheUsernameFailureNamesThePatternAndNotTheClaimValue(t *testing.T) {
	_, err := UsernameFrom(IDClaims{Sub: "root\nsigned in"}, "")
	if err == nil {
		t.Fatal("verified")
	}
	if strings.Contains(err.Error(), "root") {
		t.Fatalf("the provider's value was echoed into an error: %q", err)
	}
	if !strings.Contains(err.Error(), UsernamePattern) {
		t.Fatalf("the error does not say what a name must look like: %q", err)
	}
}

// extra decodes a JSON object into the shape IDClaims.Extra holds.
func extra(s string) map[string]json.RawMessage {
	var out map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		panic(err)
	}
	return out
}

// A guard on the allowlist itself: it is data, and data is editable without a reviewer noticing what was
// added. Nothing symmetric, and nothing that means "unsigned", may ever be in it.
func TestTheAllowlistHoldsNothingSymmetric(t *testing.T) {
	for alg := range asymmetric {
		switch {
		case strings.HasPrefix(alg, "HS"):
			t.Fatalf("%q is an HMAC algorithm and is in the asymmetric allowlist", alg)
		case strings.EqualFold(alg, "none"), alg == "":
			t.Fatalf("%q is in the allowlist, which would accept an unsigned token", alg)
		}
		if _, ok := map[crypto.Hash]bool{
			crypto.SHA256: true, crypto.SHA384: true, crypto.SHA512: true,
		}[asymmetric[alg]]; !ok {
			t.Fatalf("%q maps to a hash this program cannot compute", alg)
		}
	}
}
