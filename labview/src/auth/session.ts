/**
 * Sessions: a signed token in a cookie, and nothing on the server.
 *
 * The token carries who signed in, how, when it was issued and when it stops being
 * valid, MAC'd with a secret. There is no session store, which is deliberate — a
 * dashboard that degrades to "sign in again" after a restart is a better trade than a
 * database, and it means two replicas behind the same proxy work with no shared state
 * beyond `auth.session.secret`.
 *
 * The one piece of server state is the revocation set, so that signing out
 * invalidates the token rather than merely dropping the browser's copy of it. It is
 * in memory and bounded, and a restart clears it along with every session it could
 * apply to — consistent, if not durable.
 *
 * The clock is a parameter everywhere. Every rule here — expiry, the transient
 * cookie's five-minute window, pruning — is a comparison against `now`, and the only
 * way to assert those is to be able to move it.
 *
 * Cookie handling is written out rather than delegated to `@fastify/cookie`, for the
 * reason `cookiePairs` in `enrich/http.ts` gives: this is `split("; ")` and a header
 * string, and a dependency for it would have to be audited, updated and shipped.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { LoginMethod } from "../model/types.js";
import { isValidUsername } from "../model/access.js";

/** Version prefix, so a format change is a rejected token rather than a misread one. */
const VERSION = "v1";

export interface SessionPayload {
  /** Username. Always one {@link isValidUsername} accepts. */
  u: string;
  /** Which method signed this session in. */
  via: LoginMethod;
  /** Issued at, epoch seconds. */
  iat: number;
  /** Expires at, epoch seconds. */
  exp: number;
  /** Token id, for revocation on sign-out. */
  jti: string;
}

export type SessionRejection = "malformed" | "signature" | "expired" | "revoked";

export type SessionCheck =
  | { ok: true; payload: SessionPayload }
  | { ok: false; reason: SessionRejection };

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function mac(data: string, secret: string): string {
  return b64url(createHmac("sha256", secret).update(data).digest());
}

/**
 * Constant-time string compare that tolerates a length difference.
 *
 * `timingSafeEqual` throws on mismatched lengths, and the obvious `a.length ===
 * b.length &&` guard in front of it leaks the length — which for a fixed-width MAC is
 * nothing, but this helper is also used on the OIDC `state`. Hashing both sides first
 * makes the comparison fixed-width regardless of the inputs.
 */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHmac("sha256", "compare").update(a).digest();
  const hb = createHmac("sha256", "compare").update(b).digest();
  return timingSafeEqual(ha, hb);
}

/**
 * `v1.<payload>.<mac>` — a signed, *not encrypted*, JSON payload.
 *
 * Both segments are base64url, so the result is safe in a cookie value with no
 * escaping: no `;`, no `,`, no whitespace, no `=` padding.
 *
 * Not encrypted because nothing in either payload is a secret — a username the
 * browser's owner already knows, and an expiry. What matters is that neither can be
 * *changed*, which is what the MAC is for.
 */
export function signPayload(payload: unknown, secret: string): string {
  const body = b64url(Buffer.from(JSON.stringify(payload), "utf8"));
  return `${VERSION}.${body}.${mac(body, secret)}`;
}

/**
 * The payload of a token whose MAC verifies, or `undefined`.
 *
 * Checks only the signature: what the fields have to contain is the caller's
 * question, and keeping the two apart is what lets the session token and the OIDC
 * transient cookie share this without sharing a shape.
 */
export function unsignPayload(token: string, secret: string): unknown | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  const [version, body, signature] = parts;
  if (version !== VERSION || !body || !signature) return undefined;
  if (!safeEqual(signature, mac(body, secret))) return undefined;
  try {
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as unknown;
  } catch {
    return undefined;
  }
}

/** A fresh session token for `user`, valid for `ttlMinutes` from `now`. */
export function issueSession(
  user: string,
  via: LoginMethod,
  secret: string,
  ttlMinutes: number,
  now: Date,
): { token: string; payload: SessionPayload } {
  const iat = Math.floor(now.getTime() / 1000);
  const payload: SessionPayload = {
    u: user,
    via,
    iat,
    exp: iat + Math.max(1, Math.floor(ttlMinutes)) * 60,
    jti: randomBytes(12).toString("base64url"),
  };
  return { token: signPayload(payload, secret), payload };
}

/**
 * Check a token, in the order the checks cost: shape, then signature, then expiry,
 * then revocation.
 *
 * Expiry after the signature on purpose — an unsigned token's claimed `exp` is not
 * worth reading, and reporting `expired` for one would tell a forger their guess had
 * been parsed.
 */
export function verifySession(
  token: string,
  secret: string,
  now: Date,
  revoked?: { has(jti: string): boolean },
): SessionCheck {
  const raw = unsignPayload(token, secret);
  if (raw === undefined) {
    // A malformed token and a bad signature are one answer to the caller; they are
    // distinguished here only so a log line can say which, and `unsignPayload`
    // deliberately does not tell them apart.
    return { ok: false, reason: token.split(".").length === 3 ? "signature" : "malformed" };
  }
  const p = raw as Partial<SessionPayload>;
  if (
    typeof p.u !== "string" ||
    !isValidUsername(p.u) ||
    (p.via !== "passwd" && p.via !== "oidc") ||
    typeof p.iat !== "number" ||
    typeof p.exp !== "number" ||
    typeof p.jti !== "string" ||
    !p.jti
  ) {
    return { ok: false, reason: "malformed" };
  }
  if (p.exp * 1000 <= now.getTime()) return { ok: false, reason: "expired" };
  if (revoked?.has(p.jti)) return { ok: false, reason: "revoked" };
  return { ok: true, payload: p as SessionPayload };
}

/**
 * Signed-out token ids, until they would have expired anyway.
 *
 * Bounded twice over: entries are dropped once `now` passes their own expiry, and the
 * map is capped so that a script calling `/api/logout` in a loop cannot grow it
 * without limit. At the cap the oldest expiry goes first, which is the entry closest
 * to being useless.
 */
export class SessionRevocations {
  private readonly until = new Map<string, number>();

  constructor(private readonly max = 10_000) {}

  revoke(jti: string, expEpochSeconds: number, now: Date): void {
    this.prune(now);
    if (this.until.size >= this.max) {
      let oldest: string | undefined;
      let oldestExp = Infinity;
      for (const [k, v] of this.until) {
        if (v < oldestExp) {
          oldest = k;
          oldestExp = v;
        }
      }
      if (oldest !== undefined) this.until.delete(oldest);
    }
    this.until.set(jti, expEpochSeconds);
  }

  has(jti: string): boolean {
    return this.until.has(jti);
  }

  prune(now: Date): void {
    const cutoff = Math.floor(now.getTime() / 1000);
    for (const [k, v] of this.until) if (v <= cutoff) this.until.delete(k);
  }

  get size(): number {
    return this.until.size;
  }
}

export interface CookieOptions {
  name: string;
  value: string;
  /** Seconds. `0` expires the cookie immediately, which is how sign-out clears it. */
  maxAgeSeconds: number;
  secure: boolean;
  path: string;
}

/**
 * One `Set-Cookie` value.
 *
 * `HttpOnly` because no script has any reason to read a session token, and it is the
 * difference between an XSS bug being a bug and being an account takeover.
 *
 * `SameSite=Lax` rather than `Strict`: `Strict` withholds the cookie on a
 * cross-site *navigation*, which is exactly what returning from an identity provider
 * is — the OIDC callback would arrive with no session and loop. `Lax` sends it on a
 * top-level GET and withholds it on a cross-site POST, which is the CSRF case that
 * matters, and the POST routes check `Origin` as well.
 */
export function serializeCookie(o: CookieOptions): string {
  const parts = [
    `${o.name}=${o.value}`,
    `Path=${o.path}`,
    `Max-Age=${Math.max(0, Math.floor(o.maxAgeSeconds))}`,
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (o.secure) parts.push("Secure");
  return parts.join("; ");
}

/** The value of one cookie from a request's `Cookie` header. First wins. */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const token of header.split(";")) {
    const eq = token.indexOf("=");
    if (eq <= 0) continue;
    if (token.slice(0, eq).trim() !== name) continue;
    return token.slice(eq + 1).trim();
  }
  return undefined;
}

/**
 * The scheme the *browser* used, which is the only one that decides whether a
 * `Secure` cookie will come back.
 *
 * LabView is meant to sit behind a reverse proxy, so its own socket is very often
 * plain HTTP while the request that reached it was HTTPS. Reading
 * `X-Forwarded-Proto` is the standard way to know, and the first value is the
 * client-facing hop when several proxies have appended to it.
 */
export function effectiveProtocol(forwardedProto: string | undefined, ownProtocol: string): string {
  const first = forwardedProto?.split(",")[0]?.trim().toLowerCase();
  return first || ownProtocol.toLowerCase();
}

/**
 * The host the browser addressed, for the `Origin` check and for a derived redirect URI.
 *
 * Same reasoning as {@link effectiveProtocol}: behind a proxy the request's own `Host`
 * may be an internal name, and `X-Forwarded-Host` is what the browser typed. Only the
 * host is compared anywhere — never the scheme — because a TLS-terminating proxy makes
 * the two disagree by design.
 */
export function effectiveHost(forwardedHost: string | undefined, ownHost: string): string {
  const first = forwardedHost?.split(",")[0]?.trim().toLowerCase();
  return first || ownHost.toLowerCase();
}

/**
 * Whether an `Origin` header belongs to the same host the request arrived on.
 *
 * The CSRF check for every POST while enforcing, on top of `SameSite=Lax`. A **missing**
 * `Origin` passes: browsers send it on every cross-site POST, so its absence means the
 * request did not come from a page — `curl`, a script, a health checker — and those have
 * no ambient cookie to abuse. An `Origin` that is present and different is refused.
 */
export function originAllowed(origin: string | undefined, host: string): boolean {
  if (!origin) return true;
  try {
    return new URL(origin).host.toLowerCase() === host.toLowerCase();
  } catch {
    // `Origin: null` — a sandboxed iframe or a redirected form post. Not this host.
    return false;
  }
}

/**
 * Whether to mark cookies `Secure`.
 *
 * `auto` follows the effective scheme, which is right in both deployments that
 * matter: behind a TLS proxy the cookie is `Secure`, and on a plain-HTTP LAN address
 * it is not — because a `Secure` cookie over HTTP is never stored, and the symptom is
 * a login form that accepts the password and comes straight back, with nothing in any
 * log to say why. `true` and `false` exist for an operator whose proxy does not set
 * the header.
 */
export function shouldSecureCookie(setting: string, protocol: string): boolean {
  if (setting === "true") return true;
  if (setting === "false") return false;
  return protocol === "https";
}
