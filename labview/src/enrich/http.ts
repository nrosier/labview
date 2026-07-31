/**
 * The HTTP plumbing shared by every enrichment client that reads another system's
 * API (Authentik's, Traefik's).
 *
 * Two rules hold for all of them and are enforced here rather than restated in
 * each client:
 *
 *  - **A request never throws.** Timeout, connection refused, a body that is not
 *    JSON: every path returns a result explaining itself, so a scan degrades to
 *    whatever the config alone can say (invariant I4).
 *  - **A credential never reaches an error string.** Error text carries the status,
 *    an optional caller-supplied hint and nothing else. Nothing in here has the
 *    headers in scope at the point a message is built.
 *  - **A failure names the stage that failed.** Every result carries a
 *    `ConnectionPhase`, classified here because here is the only place the error
 *    object still exists — `fetch` collapses DNS, refused connections and certificate
 *    problems into one `"fetch failed"` message and puts the reason on `cause.code`.
 *    Doing it at the chokepoint is also what makes a client added later diagnosable
 *    without writing any of this again.
 */
import type { ConnectionPhase } from "../model/types.js";

/** Minimal shape of a `fetch` response, so a test can supply a stub. */
export interface HttpResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  /**
   * Response headers, when the implementation exposes them. Optional so a stub can
   * omit them: only the cookie handling in the Traefik client reads them, and it
   * treats their absence as "no cookie was set".
   */
  headers?: { get(name: string): string | null };
}

/** The subset of `fetch` these modules use. The global `fetch` satisfies it. */
export type FetchLike = (
  url: string,
  init?: { headers?: Record<string, string>; signal?: AbortSignal },
) => Promise<HttpResponse>;

export interface JsonResult {
  ok: boolean;
  /** HTTP status, when a response was received at all. */
  status?: number;
  body?: unknown;
  /** Why the request did not produce a body, with no credential in the text. */
  error?: string;
  /** Which stage failed, or `connected`. */
  phase: ConnectionPhase;
  /** The transport code or status behind the phase — a constant, never an address. */
  code?: string;
  /** Raw `set-cookie`, when the response sent one and headers were available. */
  setCookie?: string;
}

/**
 * The stage a transport-level failure belongs to.
 *
 * Node reports these as short constants on the error (or on `fetch`'s `cause`), and
 * they are the only thing distinguishing a wrong hostname from a service that is not
 * listening from a certificate the trust store does not accept. An unrecognised code
 * falls through to `connect` rather than to a catch-all phase: something went wrong
 * while establishing the connection is the one thing that is certainly true, and the
 * code itself is kept alongside so nothing is lost by the generalisation.
 */
export function phaseForCode(code: string | undefined): ConnectionPhase {
  if (!code) return "connect";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return "resolve";
  // Certificate and handshake problems all mean the same thing to an operator — the
  // trust store does not accept what the far end presented — and OpenSSL's names for
  // them are many, so the shape of the name is matched rather than each constant.
  if (/^(ERR_TLS|ERR_SSL|CERT_|UNABLE_TO_|SELF_SIGNED|DEPTH_ZERO|EPROTO$|HOSTNAME_MISMATCH)/.test(code)) {
    return "tls";
  }
  if (code === "ETIMEDOUT" || code === "ERR_SOCKET_TIMEOUT" || code === "UND_ERR_HEADERS_TIMEOUT") {
    return "timeout";
  }
  return "connect";
}

/** The stage an error status belongs to. */
export function phaseForStatus(status: number): ConnectionPhase {
  if (status === 401 || status === 407) return "authenticate";
  if (status === 403) return "authorize";
  if (status === 404 || status === 405) return "path";
  return "status";
}

export interface GetJsonOptions {
  headers?: Record<string, string>;
  timeoutMs: number;
  /** Extra explanation appended to an HTTP-status error, e.g. what a 403 implies. */
  hint?: (status: number) => string | undefined;
}

/** One GET, with a timeout and no way to throw. */
export async function getJson(doFetch: FetchLike, url: string, opts: GetJsonOptions): Promise<JsonResult> {
  try {
    const res = await doFetch(url, {
      headers: opts.headers ?? { Accept: "application/json" },
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
    const setCookie = res.headers?.get("set-cookie") ?? undefined;
    if (!res.ok) {
      const hint = opts.hint?.(res.status);
      return {
        ok: false,
        status: res.status,
        error: `HTTP ${res.status}${hint ?? ""}`,
        phase: phaseForStatus(res.status),
        code: String(res.status),
        setCookie,
      };
    }
    // A 200 whose body is not JSON is its own outcome, not a parser bug. It is also the
    // single most likely way an endpoint behind an SSO gate answers: the login page is
    // served with a success status, so only the content type gives it away. Reporting
    // the parse error verbatim would read as a fault in LabView instead of the one
    // thing the operator needs to know — that something else answered.
    try {
      return { ok: true, status: res.status, body: await res.json(), phase: "connected", setCookie };
    } catch {
      return {
        ok: false,
        status: res.status,
        error: `HTTP ${res.status} but the body was not JSON — an HTML login page answers exactly like this`,
        phase: "protocol",
        code: String(res.status),
        setCookie,
      };
    }
  } catch (err) {
    const e = err as Error;
    if (e.name === "TimeoutError" || e.name === "AbortError") {
      return { ok: false, error: "timed out", phase: "timeout" };
    }
    // `fetch` reports every transport failure as the same opaque "fetch failed" and puts
    // the reason in `cause`. Kept, because the reasons call for entirely different
    // fixes: a name that does not resolve is a wrong hostname, a refused connection is
    // a service that is not listening, a certificate error is a trust-store problem.
    // The code is a constant like `ENOTFOUND`, never an address or a credential.
    const cause = (err as { cause?: unknown }).cause;
    const code = isObject(cause) && typeof cause.code === "string" ? cause.code : undefined;
    return { ok: false, error: code ? `${e.message} (${code})` : e.message, phase: phaseForCode(code), code };
  }
}

/**
 * The `name=value` pairs of a `set-cookie` header, without their attributes.
 *
 * A single header value can carry several cookies, and `Headers.get` concatenates
 * them with a comma — which is also legal inside an `Expires` date. Rather than
 * trying to split cookies apart, every `k=v` token is collected and the known
 * attribute names are dropped, so a date fragment simply has no `=` to offer.
 */
export function cookiePairs(setCookie: string | undefined): string[] {
  if (!setCookie) return [];
  const attributes = new Set([
    "expires",
    "max-age",
    "domain",
    "path",
    "samesite",
    "secure",
    "httponly",
    "version",
    "priority",
    "partitioned",
  ]);
  const out = new Map<string, string>();
  for (const token of setCookie.split(/[;,]/)) {
    const eq = token.indexOf("=");
    if (eq <= 0) continue;
    const name = token.slice(0, eq).trim();
    const value = token.slice(eq + 1).trim();
    if (!name || attributes.has(name.toLowerCase())) continue;
    out.set(name, value);
  }
  return [...out].map(([k, v]) => `${k}=${v}`);
}

/** Scheme + host + port of a base URL, with any embedded credentials dropped. */
export function safeOrigin(base: string): string {
  try {
    return new URL(base).origin;
  } catch {
    return base.replace(/\/\/[^@/]*@/, "//");
  }
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function str(v: unknown): string | undefined {
  if (typeof v === "string") return v;
  if (typeof v === "number") return String(v);
  return undefined;
}
