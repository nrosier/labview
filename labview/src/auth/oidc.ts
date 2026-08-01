/**
 * OIDC authorization-code login with PKCE.
 *
 * Written out rather than delegated to an OIDC library for the same reason the rest of
 * the enrichment code is: the flow LabView needs is one discovery read, one authorize
 * redirect, one token POST and one signature check, and every general-purpose library
 * for it brings a dependency tree that has to be audited, updated and shipped in an
 * alpine image. What is *not* hand-rolled is the crypto — `node:crypto` does the
 * signature verification, and the checks around it are written down explicitly below so
 * they can be asserted one at a time.
 *
 * The HTTP goes through `enrich/http.ts`, which already guarantees the three things a
 * login flow needs: a request never throws, a credential never reaches an error string,
 * and a failure names the stage it failed at. A token endpoint sitting behind an SSO
 * gate answers with an HTML login page exactly like every other gated endpoint, and
 * `getJson` already has a word for that.
 *
 * Everything that can be pure is pure and takes `now` — the PKCE derivation, the
 * authorize URL, the discovery-document validation, the ID-token check. {@link
 * OidcClient} is only the part that has to hold a cache and a `fetch`.
 */
import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from "node:crypto";
import { constants as cryptoConstants } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { getJson, isObject, postForm, str, type FetchLike, type JsonResult } from "../enrich/http.js";
import { isValidUsername, sanitizeUsername } from "../model/access.js";

/** The resolved OIDC settings, with the client secret already read from its file. */
export interface OidcSettings {
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Empty means "derive it from the request", which only works behind a sane proxy. */
  redirectUri: string;
  scopes: string[];
  usernameClaim: string;
  timeoutMs: number;
}

/** The four endpoints LabView uses out of a discovery document. */
export interface OidcDiscovery {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
}

/** The transient per-login state, carried in a signed cookie rather than server-side. */
export interface OidcTransient {
  state: string;
  nonce: string;
  verifier: string;
  /** Epoch seconds after which this login attempt is abandoned. */
  exp: number;
}

/**
 * The digest algorithms LabView accepts on an ID token, and how `node:crypto` verifies
 * each one.
 *
 * **Asymmetric only.** `alg: none` is refused because it is not a signature, and every
 * HMAC alg (`HS256` and friends) is refused because a symmetric algorithm alongside a
 * JWKS is a well-known confusion vector: a verifier that accepts both can be handed a
 * token signed with the *public* key as the HMAC secret, which anyone can fetch. There
 * is no configuration to turn that back on.
 *
 * `null` as the hash means "the algorithm is decided by the key", which is how
 * `node:crypto` verifies Ed25519.
 */
const ALG_SPEC: Record<
  string,
  { hash: string | null; kty: string[]; options?: { padding?: number; saltLength?: number; dsaEncoding?: "ieee-p1363" } }
> = {
  RS256: { hash: "sha256", kty: ["RSA"] },
  RS384: { hash: "sha384", kty: ["RSA"] },
  RS512: { hash: "sha512", kty: ["RSA"] },
  PS256: {
    hash: "sha256",
    kty: ["RSA"],
    options: { padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST },
  },
  PS384: {
    hash: "sha384",
    kty: ["RSA"],
    options: { padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST },
  },
  PS512: {
    hash: "sha512",
    kty: ["RSA"],
    options: { padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST },
  },
  ES256: { hash: "sha256", kty: ["EC"], options: { dsaEncoding: "ieee-p1363" } },
  ES384: { hash: "sha384", kty: ["EC"], options: { dsaEncoding: "ieee-p1363" } },
  ES512: { hash: "sha512", kty: ["EC"], options: { dsaEncoding: "ieee-p1363" } },
  EdDSA: { hash: null, kty: ["OKP"] },
};

/** How much clock difference between LabView and the provider is tolerated. */
export const CLOCK_SKEW_SECONDS = 60;

/** How long an in-flight login may take before its transient cookie is stale. */
export const LOGIN_WINDOW_SECONDS = 300;

/** How long a discovery document is reused. */
export const DISCOVERY_TTL_MS = 10 * 60 * 1000;

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

/** A PKCE code verifier: 43 characters of base64url, per RFC 7636. */
export function createVerifier(): string {
  return b64url(randomBytes(32));
}

/** The `S256` challenge for a verifier. Pure, so the derivation itself is assertable. */
export function pkceChallenge(verifier: string): string {
  return b64url(createHash("sha256").update(verifier).digest());
}

/** Opaque random value, for `state` and `nonce`. */
export function randomToken(): string {
  return b64url(randomBytes(24));
}

/**
 * Validate a discovery document. Pure.
 *
 * Two rules beyond "the fields are present":
 *
 * **The document's own `issuer` must equal the configured one.** This is the standard
 * mix-up defence: without it, a redirect to an attacker's authorization server would be
 * followed by a token exchange at the attacker's token endpoint, and the tokens would
 * verify against the attacker's keys.
 *
 * **Every endpoint must be https**, loopback excepted so a local stub issuer can be used
 * in a test. A discovery document is fetched over the network and then decides where
 * LabView POSTs a client secret; refusing a plain-http endpoint means a downgraded
 * document cannot turn the exchange into a cleartext one.
 */
export function parseDiscovery(
  body: unknown,
  configuredIssuer: string,
): { ok: true; doc: OidcDiscovery } | { ok: false; detail: string } {
  if (!isObject(body)) return { ok: false, detail: "the discovery document was not a JSON object" };
  const issuer = str(body.issuer) ?? "";
  const authorizationEndpoint = str(body.authorization_endpoint) ?? "";
  const tokenEndpoint = str(body.token_endpoint) ?? "";
  const jwksUri = str(body.jwks_uri) ?? "";

  for (const [field, value] of [
    ["issuer", issuer],
    ["authorization_endpoint", authorizationEndpoint],
    ["token_endpoint", tokenEndpoint],
    ["jwks_uri", jwksUri],
  ] as const) {
    if (!value) return { ok: false, detail: `the discovery document has no ${field}` };
  }

  // Trailing slashes are the one difference worth forgiving: an operator copying the
  // issuer out of a provider's UI very often gains or loses one, and the identifier is
  // otherwise identical. Nothing else about the comparison is loosened.
  if (trimSlash(issuer) !== trimSlash(configuredIssuer)) {
    return {
      ok: false,
      detail: "the discovery document's issuer does not match the configured issuer — check auth.oidc.issuer",
    };
  }
  for (const [field, value] of [
    ["authorization_endpoint", authorizationEndpoint],
    ["token_endpoint", tokenEndpoint],
    ["jwks_uri", jwksUri],
  ] as const) {
    if (!isSecureUrl(value)) {
      return { ok: false, detail: `the discovery document's ${field} is not an https URL` };
    }
  }

  return { ok: true, doc: { issuer, authorizationEndpoint, tokenEndpoint, jwksUri } };
}

function trimSlash(s: string): string {
  return s.replace(/\/+$/, "");
}

/** https, or http on loopback — where a local stub issuer lives. */
export function isSecureUrl(value: string): boolean {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return false;
  }
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]");
}

/**
 * The authorize URL for one login attempt. Pure.
 *
 * `prompt` and `max_age` are deliberately not sent: whether the provider re-prompts is
 * the provider's policy, and a dashboard has no business overriding it.
 */
export function buildAuthorizeUrl(
  doc: OidcDiscovery,
  settings: OidcSettings,
  redirectUri: string,
  transient: { state: string; nonce: string; verifier: string },
): string {
  const u = new URL(doc.authorizationEndpoint);
  const params = u.searchParams;
  params.set("response_type", "code");
  params.set("client_id", settings.clientId);
  params.set("redirect_uri", redirectUri);
  params.set("scope", scopeString(settings.scopes));
  params.set("state", transient.state);
  params.set("nonce", transient.nonce);
  params.set("code_challenge", pkceChallenge(transient.verifier));
  params.set("code_challenge_method", "S256");
  return u.toString();
}

/**
 * The scope parameter: whatever was configured, with `openid` guaranteed.
 *
 * Without `openid` the provider runs a plain OAuth2 flow and returns no ID token, and
 * the failure surfaces as "no ID token" several steps later. Adding it here makes a
 * mis-set `LABVIEW_OIDC_SCOPES` harmless instead of confusing.
 */
export function scopeString(scopes: string[]): string {
  const out = ["openid"];
  for (const s of scopes) {
    const v = s.trim();
    if (v && !out.includes(v)) out.push(v);
  }
  return out.join(" ");
}

/**
 * The redirect URI to use: the configured one, or one derived from the request.
 *
 * Deriving trusts the `Host` (or `X-Forwarded-Host`) header, which is why the
 * documentation tells operators to set `auth.oidc.redirectUri` explicitly — a provider
 * matches it exactly anyway, so a wrong derivation is a rejected login rather than a
 * hijacked one, and Authentik's "strict" redirect mode makes it a non-event. Derivation
 * exists so a first attempt on a LAN address works without a config edit.
 */
export function redirectUriFor(configured: string, protocol: string, host: string): string {
  const set = configured.trim();
  if (set) return set;
  return `${protocol}://${host}/auth/oidc/callback`;
}

export interface IdTokenClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  exp: number;
  iat: number;
  nonce?: string;
  azp?: string;
  [claim: string]: unknown;
}

export type IdTokenCheck =
  | { ok: true; claims: IdTokenClaims; kid?: string }
  | { ok: false; detail: string; unknownKid?: string };

/**
 * Verify an ID token against a JWKS. Pure, given the keys and the clock.
 *
 * Order matters and is not negotiable: the signature is checked **before** any claim is
 * believed. Reading `exp` or `aud` off an unverified token and acting on it is how
 * verifiers end up trusting attacker-supplied JSON.
 *
 * Then, in order: `iss` exactly equal to the configured issuer; `aud` containing the
 * client id; `azp` equal to the client id when present (it is what marks the party the
 * token was issued *for* when the audience has several); `exp` not passed and `iat` not
 * in the future, both within {@link CLOCK_SKEW_SECONDS}; and `nonce` equal to the one
 * this browser's login attempt generated, which is what binds the token to this attempt
 * rather than to a replay of an older one.
 *
 * `unknownKid` on the failure is the one recoverable case: the provider rotated its
 * keys, and the caller should refetch the JWKS once and try again.
 */
export function verifyIdToken(
  token: string,
  jwks: unknown,
  opts: { issuer: string; clientId: string; nonce: string; now: Date },
): IdTokenCheck {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, detail: "the ID token is not a three-part JWT" };
  const [rawHeader, rawPayload, rawSignature] = parts as [string, string, string];

  const header = decodeSegment(rawHeader);
  if (!isObject(header)) return { ok: false, detail: "the ID token header is not JSON" };
  const alg = str(header.alg) ?? "";
  const spec = ALG_SPEC[alg];
  if (!spec) {
    // Named, because the fix is a provider setting: an operator who selected an HMAC
    // signing key in Authentik needs to be told which algorithm was refused.
    return { ok: false, detail: `the ID token is signed with ${alg || "no algorithm"}, which LabView does not accept` };
  }
  const kid = str(header.kid);

  const keys = jwkList(jwks).filter((k) => {
    if (kid && str(k.kid) && str(k.kid) !== kid) return false;
    const kty = str(k.kty) ?? "";
    if (!spec.kty.includes(kty)) return false;
    // A key marked for encryption is not a signing key, and one that names its own alg
    // has to name this one. Both keep a JWKS with several key types from being used
    // interchangeably.
    if (str(k.use) && str(k.use) !== "sig") return false;
    if (str(k.alg) && str(k.alg) !== alg) return false;
    return true;
  });
  if (keys.length === 0) {
    return kid
      ? { ok: false, detail: "the ID token names a signing key the provider's JWKS does not have", unknownKid: kid }
      : { ok: false, detail: "the provider's JWKS has no key usable for this algorithm" };
  }

  const signature = Buffer.from(rawSignature, "base64url");
  const signed = Buffer.from(`${rawHeader}.${rawPayload}`, "utf8");
  const verified = keys.some((jwk) => {
    const key = publicKeyFromJwk(jwk);
    if (!key) return false;
    try {
      return cryptoVerify(spec.hash, signed, { key, ...(spec.options ?? {}) }, signature);
    } catch {
      // A malformed signature makes `verify` throw rather than return false — for the
      // fixed-width ECDSA encoding in particular. Same outcome either way.
      return false;
    }
  });
  if (!verified) return { ok: false, detail: "the ID token's signature did not verify" };

  const payload = decodeSegment(rawPayload);
  if (!isObject(payload)) return { ok: false, detail: "the ID token payload is not JSON" };
  const claims = payload as IdTokenClaims;

  if (trimSlash(str(claims.iss) ?? "") !== trimSlash(opts.issuer)) {
    return { ok: false, detail: "the ID token's iss is not the configured issuer" };
  }
  const aud = Array.isArray(claims.aud) ? claims.aud.map((a) => str(a) ?? "") : [str(claims.aud) ?? ""];
  if (!aud.includes(opts.clientId)) {
    return { ok: false, detail: "the ID token's aud does not include this client id" };
  }
  const azp = str(claims.azp);
  if (azp !== undefined && azp !== opts.clientId) {
    return { ok: false, detail: "the ID token's azp is another client" };
  }
  const nowSeconds = Math.floor(opts.now.getTime() / 1000);
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_SECONDS < nowSeconds) {
    return { ok: false, detail: "the ID token has expired" };
  }
  if (typeof claims.iat !== "number" || claims.iat - CLOCK_SKEW_SECONDS > nowSeconds) {
    return { ok: false, detail: "the ID token was issued in the future — check the clocks" };
  }
  if ((str(claims.nonce) ?? "") !== opts.nonce) {
    return { ok: false, detail: "the ID token's nonce does not match this sign-in attempt" };
  }

  return { ok: true, claims, ...(kid ? { kid } : {}) };
}

function decodeSegment(segment: string): unknown {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as unknown;
  } catch {
    return undefined;
  }
}

function jwkList(jwks: unknown): Record<string, unknown>[] {
  if (!isObject(jwks) || !Array.isArray(jwks.keys)) return [];
  return jwks.keys.filter(isObject);
}

/**
 * A `KeyObject` from a JWK, or `undefined` if the JWK cannot make one.
 *
 * Only the string members are passed through: `node:crypto` wants the key material,
 * `x5c` and `key_ops` are arrays it does not need, and dropping them keeps a JWKS entry
 * with an unexpected field from being rejected wholesale.
 */
function publicKeyFromJwk(jwk: Record<string, unknown>): KeyObject | undefined {
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(jwk)) if (typeof v === "string") clean[k] = v;
  try {
    return createPublicKey({ key: clean, format: "jwk" });
  } catch {
    return undefined;
  }
}

/**
 * The username for a set of verified claims, or `undefined`.
 *
 * Tries the configured claim, then `preferred_username`, then `email`, then `sub` —
 * because `sub` is the only claim a provider is required to send, and an operator who
 * has not configured a scope that carries a name should still be able to sign in rather
 * than see "no usable username".
 *
 * The result must satisfy {@link isValidUsername}: a name from an identity provider is
 * still untrusted input, it lands in log lines and the topbar, and a `sub` that is a
 * UUID passes while one containing a newline does not.
 */
export function usernameFromClaims(claims: IdTokenClaims, usernameClaim: string): string | undefined {
  const candidates = [usernameClaim, "preferred_username", "email", "sub"];
  for (const key of candidates) {
    if (!key) continue;
    const value = str(claims[key])?.trim();
    if (value && isValidUsername(value)) return value;
  }
  return undefined;
}

/** Why a login through the provider did not finish. Maps to a `LoginFailureReason`. */
export type OidcStage = "provider" | "token" | "identity";

export interface OidcFailure {
  stage: OidcStage;
  /** For the log: names the check that failed, never a token, code or secret. */
  detail: string;
}

/**
 * The stateful half: a `fetch`, a discovery cache and a JWKS cache.
 *
 * Both caches exist to keep a login from making three extra network requests, and both
 * are keyed by URL so a config change is picked up by the next login rather than
 * needing a restart.
 */
export class OidcClient {
  private discovery?: { doc: OidcDiscovery; at: number };
  private jwks?: { uri: string; body: unknown; at: number };

  constructor(
    private readonly settings: OidcSettings,
    private readonly doFetch: FetchLike,
  ) {}

  /** The discovery document, from cache or from the provider. */
  async discover(now: Date, force = false): Promise<{ ok: true; doc: OidcDiscovery } | { ok: false; failure: OidcFailure }> {
    const fresh = this.discovery && !force && now.getTime() - this.discovery.at < DISCOVERY_TTL_MS;
    if (fresh && this.discovery) return { ok: true, doc: this.discovery.doc };

    const url = `${trimSlash(this.settings.issuer)}/.well-known/openid-configuration`;
    const res = await getJson(this.doFetch, url, { timeoutMs: this.settings.timeoutMs });
    if (!res.ok) {
      return { ok: false, failure: { stage: "provider", detail: `${res.phase}: ${res.error ?? "unknown"}` } };
    }
    const parsed = parseDiscovery(res.body, this.settings.issuer);
    if (!parsed.ok) return { ok: false, failure: { stage: "provider", detail: parsed.detail } };
    this.discovery = { doc: parsed.doc, at: now.getTime() };
    return { ok: true, doc: parsed.doc };
  }

  /**
   * Exchange an authorization code for an ID token, then verify it.
   *
   * The client authenticates with its secret when one is configured and with PKCE alone
   * when it is not — which is the difference between Authentik's confidential and public
   * client types, and the reason `clientSecret` is optional rather than required.
   */
  async redeem(
    code: string,
    redirectUri: string,
    transient: OidcTransient,
    now: Date,
  ): Promise<{ ok: true; username: string } | { ok: false; failure: OidcFailure }> {
    const found = await this.discover(now);
    if (!found.ok) return found;
    const { doc } = found;

    const form: Record<string, string> = {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: this.settings.clientId,
      code_verifier: transient.verifier,
    };
    if (this.settings.clientSecret) form.client_secret = this.settings.clientSecret;

    const res: JsonResult = await postForm(this.doFetch, doc.tokenEndpoint, form, {
      timeoutMs: this.settings.timeoutMs,
      hint: (status) =>
        status === 401 || status === 400
          ? " — the provider rejected the client credentials or the redirect URI; check the client id, secret and the redirect URI registered with the provider"
          : undefined,
    });
    if (!res.ok) {
      return { ok: false, failure: { stage: "token", detail: `${res.phase}: ${res.error ?? "unknown"}` } };
    }
    const idToken = isObject(res.body) ? str(res.body.id_token) : undefined;
    if (!idToken) {
      return {
        ok: false,
        failure: {
          stage: "token",
          detail: "the token response carried no id_token — the provider may not have the openid scope enabled",
        },
      };
    }

    let checked = verifyIdToken(idToken, await this.keys(doc.jwksUri, now), {
      issuer: this.settings.issuer,
      clientId: this.settings.clientId,
      nonce: transient.nonce,
      now,
    });
    if (!checked.ok && checked.unknownKid) {
      // Key rotation: exactly one refetch, so an unknown `kid` cannot be used to make
      // LabView hammer the provider's JWKS endpoint.
      checked = verifyIdToken(idToken, await this.keys(doc.jwksUri, now, true), {
        issuer: this.settings.issuer,
        clientId: this.settings.clientId,
        nonce: transient.nonce,
        now,
      });
    }
    if (!checked.ok) return { ok: false, failure: { stage: "token", detail: checked.detail } };

    const username = usernameFromClaims(checked.claims, this.settings.usernameClaim);
    if (!username) {
      return {
        ok: false,
        failure: {
          stage: "identity",
          detail: `no usable username in the ID token — tried ${this.settings.usernameClaim}, preferred_username, email, sub; add the profile or email scope, or set auth.oidc.usernameClaim`,
        },
      };
    }
    return { ok: true, username: sanitizeUsername(username) };
  }

  private async keys(uri: string, now: Date, force = false): Promise<unknown> {
    if (!force && this.jwks && this.jwks.uri === uri && now.getTime() - this.jwks.at < DISCOVERY_TTL_MS) {
      return this.jwks.body;
    }
    const res = await getJson(this.doFetch, uri, { timeoutMs: this.settings.timeoutMs });
    if (!res.ok) return this.jwks?.uri === uri ? this.jwks.body : undefined;
    this.jwks = { uri, body: res.body, at: now.getTime() };
    return res.body;
  }
}
