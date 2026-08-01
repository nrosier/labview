import type { Overview, SessionInfo } from "./model";

/**
 * A 401 from a gated route.
 *
 * A distinct type rather than a message, because the UI does two entirely different
 * things with the two failures: an unreachable server is a red error box with a Retry
 * button, and a 401 is the login card. Matching on a status code at the call site is what
 * keeps "sign in" from being reported as "could not load overview".
 */
export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

/**
 * All API URLs here are relative on purpose — `api/overview`, not `/api/overview` — so a
 * LabView served under a path prefix keeps working. The one exception is the OIDC start
 * link, which the server registers at an absolute path outside `/api`.
 */
async function getJson<T>(path: string, what: string): Promise<T> {
  const res = await fetch(path, { headers: { accept: "application/json" } });
  if (res.status === 401) throw new UnauthorizedError();
  if (!res.ok) throw new Error(`${what} failed: ${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

/** Fetch the current overview payload. */
export function fetchOverview(): Promise<Overview> {
  return getJson<Overview>("api/overview", "GET /api/overview");
}

/** Trigger a fresh scan on the server, returning the rebuilt overview. */
export async function rescan(): Promise<Overview> {
  const res = await fetch("api/rescan", { method: "POST", headers: { accept: "application/json" } });
  if (res.status === 401) throw new UnauthorizedError();
  if (!res.ok) throw new Error(`POST /api/rescan failed: ${res.status} ${res.statusText}`);
  return (await res.json()) as Overview;
}

/**
 * Who is signed in and which methods exist — the one API route a visitor may read.
 *
 * Fetched before the overview, because when LabView is enforcing there is no overview to
 * fetch yet, and asking for one first would put a 401 in the browser's console on every
 * cold load.
 */
export function fetchSession(): Promise<SessionInfo> {
  return getJson<SessionInfo>("api/session", "GET /api/session");
}

/** What a failed sign-in returns: the code, and how long a throttle has left. */
export interface LoginRejection {
  error: string;
  retryAfterSeconds?: number;
}

/**
 * Sign in with a password.
 *
 * Resolves either way: a rejection is a value, not a thrown error, because the caller has
 * to render its code through `loginFailureText` and a `catch` block cannot tell a wrong
 * password from a dropped connection.
 */
export async function login(
  username: string,
  password: string,
): Promise<{ ok: true; user: { name: string; via: string } } | { ok: false; rejection: LoginRejection }> {
  const res = await fetch("api/login", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (res.ok) {
    return { ok: true, user: (body.user ?? { name: username, via: "passwd" }) as { name: string; via: string } };
  }
  return {
    ok: false,
    rejection: {
      // A body LabView did not produce — a proxy's error page, say — still has to land on
      // something the login card can word, and "credentials" is the honest default for a
      // sign-in that did not sign in.
      error: typeof body.error === "string" ? body.error : "credentials",
      ...(typeof body.retryAfterSeconds === "number" ? { retryAfterSeconds: body.retryAfterSeconds } : {}),
    },
  };
}

/** Sign out. Revokes the session server-side and clears the cookie. */
export async function logout(): Promise<void> {
  await fetch("api/logout", { method: "POST", headers: { accept: "application/json" } });
}
