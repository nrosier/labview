package access

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ID-token verification (§19).
//
// **Asymmetric algorithms only.** There is no `alg: none`, every HMAC algorithm is refused, and there
// is no configuration to re-enable them. The reason is specific and worth stating where the refusal
// is: an OIDC client holds a client secret, and that secret is in this process's environment. If
// `HS256` were accepted, a token signed with the client secret would verify as if the provider had
// issued it — and the client secret is shared with every other party that holds it, including anything
// that has ever seen a token exchange. An allowlist of asymmetric algorithms makes that whole class of
// forgery unrepresentable rather than merely unlikely.
//
// Everything in this file is pure. The current time arrives as a parameter and the keys arrive as a
// parameter, so every check below is a table row.

// Skew is the clock tolerance §19 states for `exp` and `iat`.
//
// Sixty seconds, because a provider and a lab host that are both synchronised to within a minute is
// realistic and one synchronised to the second is not. Applied symmetrically: a token that expired 30
// seconds ago is accepted and one issued 30 seconds in the future is too, since both are more likely
// to be clock drift than an attack.
const Skew = 60 * time.Second

// MaxJWTBytes bounds a token before any of it is parsed. An ID token is a couple of kilobytes; 16 KiB
// is generous, and refusing beyond it means a provider (or something pretending to be one) cannot make
// this process parse a megabyte of base64.
const MaxJWTBytes = 16 << 10

// asymmetric is the allowlist, written as data so it can be read at a glance.
//
// RS256 first because it is what every provider issues. PS* and ES* are here because some issue them;
// nothing else is, and adding one means editing this list, which is a change a reviewer sees.
var asymmetric = map[string]crypto.Hash{
	"RS256": crypto.SHA256,
	"RS384": crypto.SHA384,
	"RS512": crypto.SHA512,
	"PS256": crypto.SHA256,
	"PS384": crypto.SHA384,
	"PS512": crypto.SHA512,
	"ES256": crypto.SHA256,
	"ES384": crypto.SHA384,
	"ES512": crypto.SHA512,
}

// header is the JWS header, of which exactly two fields are used.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// IDClaims is what an ID token asserts. Only the claims §19 checks, plus the three the username may
// come from.
type IDClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`

	// Aud is a string or an array of strings in the specification, so it is decoded loosely.
	Aud audience `json:"aud"`

	// Azp is the authorized party, checked only when present.
	Azp string `json:"azp"`

	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`

	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`

	// Extra holds every other claim, so a configured username claim that is not one of the above can
	// still be read without this struct having to know its name in advance.
	Extra map[string]json.RawMessage `json:"-"`
}

// audience decodes `aud` in either of its two legal forms.
//
// A single string and a one-element array mean the same thing, and a provider may send either. A
// decoder that only accepted the array form would refuse half the providers in the world; one that
// only accepted the string form would refuse the other half.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("aud is neither a string nor an array of strings")
	}
	*a = audience(many)
	return nil
}

// Has reports whether the audience contains v.
func (a audience) Has(v string) bool {
	for _, have := range a {
		if have == v {
			return true
		}
	}
	return false
}

// ErrUnknownKey is the one error the caller reacts to rather than reports: it triggers **exactly one**
// JWKS refetch (§19).
//
// Exactly one, and it is the caller's loop rather than this function's, because a refetch inside
// verification would let anybody holding a made-up key id drive unbounded requests at the provider —
// a denial of service aimed at the identity provider and launched through LabView.
var ErrUnknownKey = errors.New("no key in the JWKS matches this token's key id")

// VerifyIDToken runs §19's checks **in order**: signature → `iss` → `aud` → `azp` → `exp`/`iat` →
// `nonce`.
//
// The order is the security property. Signature first, because every later check reads a value from a
// document that has not yet been shown to come from the provider — and a program that reported *wrong
// nonce* for an unsigned token would be telling a forger which field to fix next. `iss` before `aud`,
// because an audience match against the wrong issuer's token is a token from a provider we do not
// trust that happens to name our client id. `nonce` last, because it is the only check that is about
// this particular handshake rather than about the token.
func VerifyIDToken(token string, keys []JWK, want Expectations, now time.Time) (IDClaims, error) {
	claims, alg, err := verifySignature(token, keys)
	if err != nil {
		return IDClaims{}, err
	}

	// `iss` exactly. Not a prefix, not case-insensitive, not with trailing slashes forgiven — that
	// forgiveness applies to the *discovery document's* self-declared issuer (§19), where it exists
	// because operators configure `https://idp/` and providers publish `https://idp`. Here the value
	// is compared to what discovery already agreed on, so any difference is a different issuer.
	if claims.Iss != want.Issuer {
		return claims, fmt.Errorf("id token issuer is not the configured issuer (alg %s)", alg)
	}

	if !claims.Aud.Has(want.ClientID) {
		return claims, errors.New("id token audience does not contain this client id")
	}

	// `azp` only when present. It is required only for a multi-audience token, and a provider that
	// omits it on a single-audience token is correct — so demanding it would refuse conforming
	// providers, and ignoring it when present would accept a token minted for a different client.
	if claims.Azp != "" && claims.Azp != want.ClientID {
		return claims, errors.New("id token authorized party is not this client id")
	}

	if claims.Exp == 0 {
		return claims, errors.New("id token has no expiry")
	}
	if now.After(time.Unix(claims.Exp, 0).Add(Skew)) {
		return claims, errors.New("id token has expired")
	}
	if claims.Iat != 0 && time.Unix(claims.Iat, 0).After(now.Add(Skew)) {
		return claims, errors.New("id token was issued in the future")
	}

	// The nonce ties this token to the authorization request this browser started. Without it, a token
	// captured from one sign-in could be replayed into another — the token is valid, correctly signed
	// and for the right client, and only the nonce says it is not for *this* handshake.
	if want.Nonce == "" {
		return claims, errors.New("no nonce was expected, which means the handshake state was lost")
	}
	if claims.Nonce != want.Nonce {
		return claims, errors.New("id token nonce does not match this sign-in")
	}

	return claims, nil
}

// Expectations is what a token is checked against: the values this handshake already committed to.
type Expectations struct {
	Issuer   string
	ClientID string
	Nonce    string
}

// verifySignature does the shape and the cryptography, and nothing about the claims' meaning.
func verifySignature(token string, keys []JWK) (IDClaims, string, error) {
	if len(token) > MaxJWTBytes {
		return IDClaims{}, "", errors.New("id token is implausibly large")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return IDClaims{}, "", errors.New("id token is not three dot-separated parts")
	}

	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return IDClaims{}, "", errors.New("id token header is not base64url")
	}
	var h header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return IDClaims{}, "", errors.New("id token header is not an object")
	}

	hash, ok := asymmetric[h.Alg]
	if !ok {
		// The refusal, and the message deliberately does not say *which* algorithms are accepted. An
		// operator debugging their provider reads the documentation; a forger probing for an accepted
		// algorithm learns nothing from a list they were handed. `alg: none` and `HS256` both land
		// here, which is the point: there is one rejection path and no configuration reaches it.
		return IDClaims{}, h.Alg, fmt.Errorf("id token algorithm %q is not an accepted asymmetric algorithm", safeIdentifier(h.Alg))
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return IDClaims{}, h.Alg, errors.New("id token signature is not base64url")
	}

	// The signed input is the first two parts exactly as they arrived, including their base64 encoding.
	// Re-encoding a decoded header would verify a different string than the provider signed.
	signed := []byte(parts[0] + "." + parts[1])

	candidates := matching(keys, h.Kid, h.Alg)
	if len(candidates) == 0 {
		return IDClaims{}, h.Alg, ErrUnknownKey
	}

	verified := false
	for _, key := range candidates {
		if key.verify(hash, h.Alg, signed, signature) {
			verified = true
			break
		}
	}
	if !verified {
		return IDClaims{}, h.Alg, errors.New("id token signature does not verify against the provider's keys")
	}

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return IDClaims{}, h.Alg, errors.New("id token payload is not base64url")
	}
	var claims IDClaims
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return IDClaims{}, h.Alg, errors.New("id token payload is not an object")
	}
	// Decoded a second time into a map, so a configured username claim of any name can be read
	// without this program knowing it in advance.
	_ = json.Unmarshal(rawClaims, &claims.Extra)

	return claims, h.Alg, nil
}

// matching picks the keys a token's `kid` and `alg` allow.
//
// A token with no `kid` is matched against every key of the right type, which is what a provider
// publishing a single key expects. A token *with* a `kid` is matched against that key only: trying
// every key would mean a token naming key A but signed with key B verifies, which defeats the point of
// naming a key at all.
func matching(keys []JWK, kid, alg string) []JWK {
	var out []JWK
	for _, key := range keys {
		if kid != "" && key.Kid != kid {
			continue
		}
		if key.Alg != "" && key.Alg != alg {
			continue
		}
		if !key.suits(alg) {
			continue
		}
		out = append(out, key)
	}
	return out
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

// JWK is one public key from the provider's JWKS. Only RSA and EC are parsed, because only asymmetric
// algorithms are accepted — an `oct` key is a symmetric secret and there is nothing here that could
// use one.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`

	// RSA.
	N string `json:"n"`
	E string `json:"e"`

	// EC.
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS is the document at the provider's `jwks_uri`.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// MaxJWKSKeys bounds how many keys are kept from one document. A provider publishes one to a handful;
// a document with a thousand keys would make every verification a thousand signature checks, which is
// a denial of service dressed as a key rotation.
const MaxJWKSKeys = 16

// Usable filters a JWKS down to the keys this program can verify with.
//
// A key marked for encryption is dropped: `use: enc` says the provider does not sign with it, and
// verifying a signature against an encryption key is either a provider bug or somebody's attempt to
// find one.
func (j JWKS) Usable() []JWK {
	var out []JWK
	for _, key := range j.Keys {
		if len(out) >= MaxJWKSKeys {
			break
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if key.Kty != "RSA" && key.Kty != "EC" {
			continue
		}
		out = append(out, key)
	}
	return out
}

// suits reports whether this key's type can carry the algorithm.
func (k JWK) suits(alg string) bool {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return k.Kty == "RSA"
	case strings.HasPrefix(alg, "ES"):
		return k.Kty == "EC"
	default:
		return false
	}
}

// verify checks one signature against this key. It returns only a boolean: which of the several ways a
// key can be unusable it was is not information any caller acts on differently, and a detailed
// per-key error is a detailed report about the provider's key material.
func (k JWK) verify(hash crypto.Hash, alg string, signed, signature []byte) bool {
	digest := digestOf(hash, signed)
	if digest == nil {
		return false
	}

	switch k.Kty {
	case "RSA":
		pub, err := k.rsa()
		if err != nil {
			return false
		}
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(pub, hash, digest, signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       hash,
			}) == nil
		}
		return rsa.VerifyPKCS1v15(pub, hash, digest, signature) == nil

	case "EC":
		pub, err := k.ecdsa()
		if err != nil {
			return false
		}
		// A JWS ECDSA signature is the fixed-width r‖s pair, not the ASN.1 form crypto/ecdsa's
		// ASN1 verifier expects. Half each, and a signature of the wrong length is refused rather
		// than padded — a length mismatch means this is not a signature from this curve.
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return false
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		return ecdsa.Verify(pub, digest, r, s)
	}
	return false
}

func digestOf(hash crypto.Hash, b []byte) []byte {
	switch hash {
	case crypto.SHA256:
		sum := sha256.Sum256(b)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(b)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(b)
		return sum[:]
	}
	return nil
}

// MinRSABits is the smallest RSA modulus accepted.
//
// 2048 is the floor every provider has met for a decade, and a 512-bit key is factorable on a laptop —
// so accepting a small modulus would mean the signature check passes while providing no assurance at
// all. A provider publishing one is misconfigured, and the right answer is a refusal an operator can
// read rather than a verification that means nothing.
const MinRSABits = 2048

func (k JWK) rsa() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, errors.New("rsa modulus is not base64url")
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, errors.New("rsa exponent is not base64url")
	}
	if len(n) == 0 || len(e) == 0 || len(e) > 8 {
		return nil, errors.New("rsa key is malformed")
	}

	modulus := new(big.Int).SetBytes(n)
	if modulus.BitLen() < MinRSABits {
		return nil, fmt.Errorf("rsa key is %d bits, below the %d-bit floor", modulus.BitLen(), MinRSABits)
	}
	exponent := new(big.Int).SetBytes(e)
	if !exponent.IsInt64() || exponent.Int64() < 3 {
		return nil, errors.New("rsa exponent is out of range")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

func (k JWK) ecdsa() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, errors.New("unsupported elliptic curve")
	}

	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, errors.New("ec x coordinate is not base64url")
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, errors.New("ec y coordinate is not base64url")
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	// A point that is not on the curve is not a public key. Checked rather than assumed, because
	// verifying against an off-curve point is undefined behaviour in the arithmetic sense and has been
	// a real vulnerability in other implementations.
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("ec point is not on the curve")
	}
	return pub, nil
}

// ---------------------------------------------------------------------------
// The username
// ---------------------------------------------------------------------------

// UsernameFrom reads the signed-in name from a verified token's claims (§19).
//
// The chain is configured claim → `preferred_username` → `email` → `sub`, and the result MUST satisfy
// the username pattern. `sub` is last rather than first because it is the only claim guaranteed to
// exist and is usually an opaque identifier: a dashboard showing a UUID where a name belongs is
// technically correct and useless, so it is the fallback rather than the answer.
//
// A value that fails the pattern does not become `?` here. `?` is the right thing to *log* about a
// name that cannot be trusted, and the wrong thing to sign a session for — a session for `?` is a
// session for whoever else also failed the pattern. So this returns an error and the handshake fails
// with `oidc-identity`.
func UsernameFrom(claims IDClaims, configured string) (string, error) {
	for _, candidate := range []string{
		fromClaim(claims, configured),
		claims.PreferredUsername,
		claims.Email,
		claims.Sub,
	} {
		if candidate == "" {
			continue
		}
		if ValidUsername(candidate) {
			return candidate, nil
		}
		// Not returned, and deliberately not reported either: the value came from a provider and may
		// be anything. The chain continues, so a provider whose `preferred_username` contains a space
		// still signs in under its `email` or `sub`.
	}
	return "", errors.New("no claim in the token holds a name matching " + UsernamePattern)
}

// fromClaim reads the configured claim, which may be absent or not a string.
func fromClaim(claims IDClaims, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	raw, ok := claims.Extra[name]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		// A claim that is a number, an object or an array is not a username. Silently skipped rather
		// than reported, since the chain has three more candidates.
		return ""
	}
	return s
}
