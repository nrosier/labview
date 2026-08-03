/**
 * The HTTP plumbing shared by every enrichment client that reads another system's
 * API (Authentik's, Traefik's) or asks a scanned service what it answers (the probe).
 *
 * Three rules hold for all of them and are enforced here rather than restated in
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
  /**
   * The body as text. Only {@link getResponse} reads it, and only for HTML — a
   * scanned service's login page is the one body in this program that is read as text
   * rather than parsed as JSON.
   *
   * Optional so every existing stub still satisfies the type. Absent means the body
   * cannot be read, not that it was empty.
   */
  text?(): Promise<string>;
  /**
   * The body as a stream, when the implementation exposes one — a real `fetch`
   * response does; a stub does not.
   *
   * Preferred over {@link text} wherever it exists, because it is the only way to stop
   * reading. A response with no `Content-Length` gives no way to know its size in
   * advance, and `text()` has already bought the whole thing by the time it returns,
   * so a size cap enforced afterwards is not a cap at all. Reading the stream and
   * cancelling it at the cap is (invariant I8).
   */
  body?: ReadableStream<Uint8Array> | null;
}

/**
 * The subset of `fetch` these modules use. The global `fetch` satisfies it.
 *
 * `method` and `body` are optional and were added for the OIDC token exchange, the
 * one POST in the codebase. Optional so every existing stub — which only ever
 * received a URL and a signal — still satisfies the type.
 */
export type FetchLike = (
  url: string,
  init?: {
    headers?: Record<string, string>;
    signal?: AbortSignal;
    method?: string;
    body?: string;
    /**
     * `"manual"` hands the 3xx back instead of following it, which the probe needs:
     * where a redirect goes is the evidence, and a followed redirect destroys it by
     * reporting only what was at the end. Nothing else in the codebase sets this, so
     * every other request keeps `fetch`'s default.
     */
    redirect?: "manual";
  },
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
  return requestJson(doFetch, url, opts);
}

/**
 * One `application/x-www-form-urlencoded` POST, same rules as {@link getJson}: it
 * cannot throw, it names the stage that failed, and nothing it puts in `error` came
 * from the request.
 *
 * The OIDC token exchange is the only POST LabView makes — the sole request in the
 * whole program that is not a read — and it is here rather than in `auth/oidc.ts` so
 * that it inherits the timeout, the phase mapping and the not-JSON case instead of
 * reimplementing them. A token endpoint behind an SSO gate answers with an HTML login
 * page exactly like every other gated endpoint, and `protocol` is already the right
 * word for it.
 *
 * **The form body is never echoed.** It carries the client secret and the
 * authorization code, and `requestJson` only ever reports a status or a transport
 * code.
 */
export async function postForm(
  doFetch: FetchLike,
  url: string,
  form: Record<string, string>,
  opts: GetJsonOptions,
): Promise<JsonResult> {
  const body = new URLSearchParams(form).toString();
  return requestJson(doFetch, url, {
    ...opts,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      ...opts.headers,
    },
    method: "POST",
    body,
  });
}

/**
 * What one GET at a scanned service produced. See {@link getResponse}.
 *
 * `ok` means something different here than on {@link JsonResult}, and the difference is
 * the whole point of the second primitive: there, `ok` means the API returned the
 * payload that was wanted, so a 401 is a failure. Here it means **a response arrived at
 * all**, whatever its status — a 401 is the best answer a probe can get. So `phase` is
 * `connected` for every status code, and only a transport failure produces anything else.
 */
export interface ResponseResult {
  /** Whether an HTTP response arrived. Says nothing about its status. */
  ok: boolean;
  status?: number;
  /** `Location`, verbatim and unresolved — it may be relative. */
  location?: string;
  /** `WWW-Authenticate`, verbatim. Present is what matters, not what it says. */
  wwwAuthenticate?: string;
  contentType?: string;
  /** The body, only when it was HTML, and never more than {@link MAX_BODY_BYTES}. */
  body?: string;
  /** Why nothing arrived, with no credential in the text. */
  error?: string;
  /** `connected` whenever a response arrived; otherwise the transport stage that failed. */
  phase: ConnectionPhase;
  /** The transport code behind the phase — a constant, never an address. */
  code?: string;
}

/**
 * How much of an HTML body is read before the connection is cut.
 *
 * A login form's `<input type="password">` is in the first few kilobytes of every page
 * that has one — it is in the markup, not below a megabyte of inlined script — so a
 * larger cap would buy no additional evidence.
 */
export const MAX_BODY_BYTES = 64 * 1024;

/**
 * One GET at a scanned service, to see what it answers.
 *
 * The same three rules as {@link getJson} — cannot throw, names the stage that failed,
 * puts no credential in a message — with four differences, each of them something the
 * probe needs and no API client does:
 *
 *  - **`redirect: "manual"`.** Where a 3xx points is the evidence; following it would
 *    report what was at the far end instead.
 *  - **Every status is a success.** A 401 is the answer, not a fault, so `phase` is
 *    `connected` throughout and the status is carried in `status` for the rule to read.
 *  - **The three headers a login page is recognised by** are picked out: `Location`,
 *    `WWW-Authenticate`, `Content-Type`.
 *  - **The body is read only when it is HTML**, and then only up to
 *    {@link MAX_BODY_BYTES}, cancelling the stream at the cap. A JSON, image or archive
 *    response is never read at all.
 *
 * **No credential is ever sent.** Not by omission — no call path into this function has
 * one in scope. The point is to see what an unauthenticated request gets, so a
 * credential would destroy the measurement as surely as following a redirect would.
 */
export async function getResponse(
  doFetch: FetchLike,
  url: string,
  opts: { timeoutMs: number },
): Promise<ResponseResult> {
  try {
    const res = await doFetch(url, {
      // `*/*` after the HTML preference, because a service that answers only JSON should
      // answer rather than 406 — a 406 would be recorded as an exposure with no gate,
      // which is true, and a body LabView refused to accept would be a worse reason for
      // it than the one that is actually there.
      headers: { Accept: "text/html,*/*" },
      signal: AbortSignal.timeout(opts.timeoutMs),
      redirect: "manual",
    });
    const header = (name: string): string | undefined => res.headers?.get(name)?.trim() || undefined;
    const contentType = header("content-type");
    return {
      ok: true,
      status: res.status,
      location: header("location"),
      wwwAuthenticate: header("www-authenticate"),
      contentType,
      body: isHtml(contentType) ? await readCapped(res) : undefined,
      phase: "connected",
    };
  } catch (err) {
    const e = err as Error;
    if (e.name === "TimeoutError" || e.name === "AbortError") {
      return { ok: false, error: "timed out", phase: "timeout" };
    }
    const cause = (err as { cause?: unknown }).cause;
    const code = isObject(cause) && typeof cause.code === "string" ? cause.code : undefined;
    return { ok: false, error: code ? `${e.message} (${code})` : e.message, phase: phaseForCode(code), code };
  }
}

/** Whether a content type is HTML. `text/html; charset=utf-8` and bare `text/html` both. */
function isHtml(contentType: string | undefined): boolean {
  if (!contentType) return false;
  const type = contentType.split(";")[0]!.trim().toLowerCase();
  return type === "text/html" || type === "application/xhtml+xml";
}

/**
 * At most {@link MAX_BODY_BYTES} of a response body, as text.
 *
 * Streamed and cancelled at the cap where a stream is available, which is what makes the
 * cap real: a far end that keeps sending is cut off rather than waited out. Where it is
 * not — a stub in the smoke run, which is not untrusted input — `text()` is truncated
 * afterwards instead. Never throws: an unreadable body is no body, and the status and
 * headers already gathered are worth more than the read that failed.
 */
async function readCapped(res: HttpResponse): Promise<string | undefined> {
  try {
    const stream = res.body;
    if (stream) return await readStreamCapped(stream);
    if (!res.text) return undefined;
    const text = await res.text();
    return text.length > MAX_BODY_BYTES ? text.slice(0, MAX_BODY_BYTES) : text;
  } catch {
    return undefined;
  }
}

async function readStreamCapped(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < MAX_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value?.byteLength) continue;
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    // Releases the socket without draining whatever is still coming.
    await reader.cancel().catch(() => undefined);
  }
  const out = new Uint8Array(Math.min(total, MAX_BODY_BYTES));
  let at = 0;
  for (const chunk of chunks) {
    if (at >= out.length) break;
    const take = Math.min(chunk.byteLength, out.length - at);
    out.set(chunk.subarray(0, take), at);
    at += take;
  }
  // Non-fatal: a page truncated mid-character must still be searchable.
  return new TextDecoder("utf-8", { fatal: false }).decode(out);
}

async function requestJson(
  doFetch: FetchLike,
  url: string,
  opts: GetJsonOptions & { method?: string; body?: string },
): Promise<JsonResult> {
  try {
    const res = await doFetch(url, {
      headers: opts.headers ?? { Accept: "application/json" },
      signal: AbortSignal.timeout(opts.timeoutMs),
      ...(opts.method ? { method: opts.method } : {}),
      ...(opts.body !== undefined ? { body: opts.body } : {}),
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
