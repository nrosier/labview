/**
 * The sign-in card.
 *
 * Markup and state only. Which methods to offer comes from `/api/session`, what a failure
 * says comes from `loginFailureText`, and what the SSO button reads comes from
 * `oidcButtonLabel` — all in `src/model/access.ts`, where smoke can assert them. A rule
 * that lived here would be unfalsifiable: the smoke pass never mounts a DOM.
 *
 * The card is served to anyone who can reach the port, before any session exists. That is
 * safe only because of invariant **I2** — shipped artifacts carry no fleet-specific
 * identifier — so nothing below may render anything that came from a scan. The only
 * fleet-shaped thing on this screen is the identity provider's hostname in the button
 * label, which the redirect would reveal anyway and which `auth.oidc.label` overrides.
 */
import { useState } from "preact/hooks";
import type { LoginFailureReason, SessionInfo } from "../model";
import { loginFailureText, oidcButtonLabel, parseLoginFailure } from "../model";
import { login } from "../api";

/**
 * Where the OIDC flow starts.
 *
 * Absolute, unlike the `api/…` calls elsewhere, because the flow is absolute by
 * construction: the redirect URI is typed into the provider as a full URL, so a relative
 * start path that resolved somewhere else would only fail later and less clearly.
 */
const OIDC_START = "/auth/oidc/start";

export function Login({
  info,
  initialError,
  onSignedIn,
}: {
  info: SessionInfo;
  /** A code carried back from a redirect, already validated against the closed set. */
  initialError?: LoginFailureReason | undefined;
  onSignedIn: () => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState<LoginFailureReason | undefined>(initialError);
  const [retryAfter, setRetryAfter] = useState<number | undefined>(undefined);
  /** A network failure, which is not a `LoginFailureReason` — the server said nothing at all. */
  const [failed, setFailed] = useState<string | null>(null);

  const hasPasswd = info.methods.includes("passwd");
  const hasOidc = info.methods.includes("oidc");

  async function submit(e: Event) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setReason(undefined);
    setRetryAfter(undefined);
    setFailed(null);
    try {
      const result = await login(username, password);
      if (result.ok) {
        onSignedIn();
        return;
      }
      // The password is dropped on every rejection, so a retry is typed rather than
      // resubmitted — and a shared screen does not keep it in a field.
      setPassword("");
      setReason(parseLoginFailure(result.rejection.error) ?? "credentials");
      setRetryAfter(result.rejection.retryAfterSeconds);
    } catch (e) {
      setFailed(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="shell">
      <div class="login-card">
        <div class="brand">
          <span class="dot">●</span>
          <h1>LabView</h1>
        </div>
        <p class="login-lede">Sign in to read this fleet's documentation.</p>

        {reason && (
          <p class="login-error" role="alert">
            {loginFailureText(reason)}
            {retryAfter !== undefined && ` (${retryAfter}s)`}
          </p>
        )}
        {failed && (
          <p class="login-error" role="alert">
            Could not reach LabView: <span class="mono">{failed}</span>
          </p>
        )}

        {hasPasswd && (
          <form class="login-form" onSubmit={submit}>
            <label>
              <span>Username</span>
              <input
                type="text"
                name="username"
                autocomplete="username"
                autofocus
                value={username}
                onInput={(e) => setUsername((e.target as HTMLInputElement).value)}
                disabled={busy}
              />
            </label>
            <label>
              <span>Password</span>
              <input
                type="password"
                name="password"
                autocomplete="current-password"
                value={password}
                onInput={(e) => setPassword((e.target as HTMLInputElement).value)}
                disabled={busy}
              />
            </label>
            <button class="btn primary" type="submit" disabled={busy || !username || !password}>
              {busy ? <span class="spinner" /> : null} Sign in
            </button>
          </form>
        )}

        {hasPasswd && hasOidc && <div class="login-or">or</div>}

        {hasOidc && (
          <a class="btn oidc-btn" href={OIDC_START}>
            {/* The server sends the finished label, because only it knows the issuer.
                Falling back through the same function rather than to a literal keeps the
                generic wording in one place. */}
            {info.oidcLabel ?? oidcButtonLabel("", "")}
          </a>
        )}

        {info.notes.length > 0 && (
          <ul class="login-notes">
            {info.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
