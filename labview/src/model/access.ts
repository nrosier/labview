/**
 * The vocabulary of LabView's own access control: what a failure says, what the
 * posture is called, and what a username is allowed to be.
 *
 * Pure, and free of any Node import — the login screen imports this file, and
 * `tsconfig.web.json` compiles the web project with `types: []`, so a stray
 * `node:crypto` here is a compile error rather than a bundle that breaks in the
 * browser. Everything that needs a hash, a file or a socket lives in `src/auth/`
 * instead, and none of it is reachable from `web/`.
 *
 * Here rather than in the routes or the component for the reason `model/ingress.ts`
 * gives: the server logs the posture, the login screen renders it and the failure
 * codes cross a redirect between them, so three places need the same answers. A
 * second copy of this wording inside a `.tsx` would also be unassertable — smoke
 * never mounts a DOM.
 */
import type { AccessMode, LoginFailureReason, LoginMethod } from "./types.js";

/**
 * What a visitor is told, per failure code.
 *
 * `credentials` says nothing about *which* half was wrong, because an unknown user
 * and a wrong password are the same answer here — see {@link LoginFailureReason}.
 * The OIDC codes name the stage that failed (LabView's own state, the provider,
 * the token, the identity in it) without naming an endpoint or a claim value: the
 * operator gets the detail from the log, and the browser gets only enough to know
 * whether retrying is worth anything.
 */
const LOGIN_FAILURE_TEXT: Record<LoginFailureReason, string> = {
  credentials: "Invalid username or password.",
  throttled: "Too many attempts. Wait a moment and try again.",
  "method-unavailable": "That sign-in method is not available.",
  "session-expired": "Your session expired. Sign in again.",
  "oidc-state": "The sign-in attempt expired or did not match. Try again.",
  "oidc-provider": "The identity provider could not be reached.",
  "oidc-token": "The identity provider's response was rejected.",
  "oidc-identity": "The identity provider did not return a usable username.",
};

export function loginFailureText(reason: LoginFailureReason): string {
  return LOGIN_FAILURE_TEXT[reason];
}

/**
 * Read a failure code back off a URL, or `undefined` if it is not one of ours.
 *
 * The OIDC callback can only hand the UI a query parameter, so this value arrives
 * from the address bar and is attacker-supplied by definition. Validating it
 * against the closed set here — rather than rendering it — is what keeps a crafted
 * `?login_error=<anything>` from putting arbitrary text on the login screen.
 */
export function parseLoginFailure(value: string | null | undefined): LoginFailureReason | undefined {
  if (!value) return undefined;
  return value in LOGIN_FAILURE_TEXT ? (value as LoginFailureReason) : undefined;
}

/**
 * The characters a LabView username may contain: letters, digits, and `. _ @ -`,
 * up to 64.
 *
 * Narrow on purpose, and applied in three places — parsing the passwd file, the
 * login form, and the claim an OIDC provider returns. A username reaches log lines
 * and the topbar, so anything permitting a newline or a control character would let
 * a passwd file or an identity provider forge log entries. `@` is allowed because
 * an email address is the most common thing a provider puts in
 * `preferred_username`.
 */
const USERNAME_RE = /^[A-Za-z0-9._@-]{1,64}$/;

export function isValidUsername(name: string): boolean {
  return USERNAME_RE.test(name);
}

/**
 * The safe form of an untrusted username, for a log line or an error path.
 *
 * Returns `"?"` rather than a truncated or scrubbed version of the input, because
 * a rejected username is not worth echoing: it came from a failed attempt, and the
 * only thing a partially-sanitised copy adds is a way to smuggle content into the
 * log. Valid names pass through unchanged.
 */
export function sanitizeUsername(raw: string): string {
  return isValidUsername(raw) ? raw : "?";
}

/** `Sign in with SSO` / `Sign in with authentik.example.com`. */
export function oidcButtonLabel(label: string, issuer: string): string {
  const named = label.trim();
  if (named) return named;
  return `Sign in with ${issuerHost(issuer) || "your provider"}`;
}

/**
 * The host of an issuer URL, for a button label and a log line.
 *
 * Returns `""` for anything unparseable rather than throwing — an issuer that is
 * not a URL is already reported as a configuration note, and a label is not the
 * place to fail.
 */
export function issuerHost(issuer: string): string {
  try {
    return new URL(issuer).host;
  } catch {
    return "";
  }
}

/**
 * The one line the log says at startup about who may read this LabView.
 *
 * Shaped after the `LabView scanning <root>` and `LabView connected to …` lines so
 * a startup block reads as one story, and shared with nothing else — but written
 * here, beside the wording the UI uses, so the two cannot come to describe
 * different postures.
 *
 * **Counts, never names.** A user list in a log file is an inventory of accounts to
 * try; the number is what tells the operator their file was read.
 */
export function accessModeSummary(
  mode: AccessMode,
  detail: { users: number; oidcHost: string },
): string {
  if (!mode.enforced) {
    return "LabView access control: none — the HTTP surface is open to anyone who can reach it, relying on your edge";
  }
  const parts: string[] = [];
  for (const m of mode.methods) {
    if (m === "passwd") parts.push(`password login (${detail.users} user${detail.users === 1 ? "" : "s"})`);
    if (m === "oidc") parts.push(`OIDC${detail.oidcHost ? ` (${detail.oidcHost})` : ""}`);
  }
  return `LabView access control: ${parts.join(" + ")} — /api requires a session`;
}

/** `password`, `OIDC` — for a note or a hint that has to name a method. */
export function methodLabel(method: LoginMethod): string {
  return method === "passwd" ? "password" : "OIDC";
}
