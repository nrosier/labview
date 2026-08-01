/**
 * What posture LabView is in, and which paths that posture applies to.
 *
 * The rule this module exists to hold is **open unless configured**: LabView enforces
 * nothing until a method is both allowed *and* usable. `auth.passwd.enabled: true` with
 * no file is not a lock-out, it is the default state of an unconfigured install, and
 * pulling a new image can therefore never shut an operator out of a running deployment.
 * Enforcement begins the moment the passwd file holds a usable entry or an OIDC issuer
 * and client id are set.
 *
 * Two kinds of note come out of this, and they are deliberately not the same list:
 *
 *  - **public notes** ({@link AccessMode.notes}) reach an unauthenticated visitor
 *    through `/api/session`, so they carry no path, no count and no reason — only
 *    whether a method they can see is usable;
 *  - **log notes** carry the paths, the counts and the parse warnings, because the
 *    operator reading the log is the one who can fix them.
 */
import { readFileSync } from "node:fs";
import type { LabViewConfig } from "../config.js";
import type { AccessMode, LoginMethod } from "../model/types.js";
import { issuerHost } from "../model/access.js";
import { readPasswd, type PasswdFile } from "./passwd.js";
import type { OidcSettings } from "./oidc.js";

/**
 * The four paths reachable under `/api` without a session, matched **exactly**.
 *
 * Exact, not by prefix, and the reason is worth spelling out because the prefix version
 * looks equivalent and is not: `startsWith("/api/healthz")` also admits
 * `/api/healthz/../overview`, and `startsWith("/api/session")` admits `/api/sessionx`.
 * A path that is not literally one of these four requires a session, so every encoding
 * trick, dot segment and doubled slash fails closed by construction rather than by a
 * normaliser that has to be right.
 */
const PUBLIC_API_PATHS = new Set(["/api/healthz", "/api/session", "/api/login", "/api/logout"]);

function pathOf(url: string): string {
  const noQuery = url.split("?", 1)[0] ?? "";
  return noQuery.split("#", 1)[0] ?? "";
}

/** Whether this URL is one of the four unauthenticated API paths. */
export function isPublicPath(url: string): boolean {
  return PUBLIC_API_PATHS.has(pathOf(url));
}

/**
 * Whether this URL needs a session while enforcing.
 *
 * `/api/*` and nothing else — the SPA shell, `styles.css` and `app.js` stay public and
 * render a login card, which invariant **I2** is what makes safe: shipped artifacts
 * carry no fleet-specific identifier, so nothing about the fleet is served before
 * sign-in. `/auth/oidc/*` is outside `/api` on purpose and is therefore never gated;
 * the login flow could not complete if it were.
 *
 * Doubled slashes are collapsed and the path lower-cased *only here*, never in
 * {@link isPublicPath} — every normalisation in this direction can add a path to the
 * gated set and none can remove one.
 */
export function requiresSession(url: string): boolean {
  if (isPublicPath(url)) return false;
  const p = pathOf(url).replace(/\/{2,}/g, "/").toLowerCase();
  return p === "/api" || p.startsWith("/api/");
}

/** The facts the posture is derived from, so the derivation can be asserted directly. */
export interface AccessInputs {
  passwdEnabled: boolean;
  /**
   * Usable entries in the passwd file.
   *
   * A count, not the file's read state, because the posture cannot tell the two apart:
   * a missing file, a directory where the file should be and a file of nothing but
   * comments all mean "no password login". *Why* there are no users is an operator
   * question, and it is answered in {@link AccessSnapshot.logNotes} instead.
   */
  passwdUsers: number;
  oidcEnabled: boolean;
  oidcIssuer: string;
  oidcClientId: string;
}

/**
 * The posture these inputs produce. Pure.
 *
 * A method that is allowed but unusable never turns enforcement on and never fails the
 * start-up — it produces a note (**I4**). The order of `methods` is the order the login
 * card renders them in: password first, because an operator who configured both is most
 * likely to reach for the local account when the provider is the thing that is broken.
 */
export function resolveAccessMode(inputs: AccessInputs): AccessMode {
  const passwdLive = inputs.passwdEnabled && inputs.passwdUsers > 0;
  const oidcLive = inputs.oidcEnabled && Boolean(inputs.oidcIssuer.trim()) && Boolean(inputs.oidcClientId.trim());

  const methods: LoginMethod[] = [];
  if (passwdLive) methods.push("passwd");
  if (oidcLive) methods.push("oidc");

  const notes: string[] = [];
  if (methods.length > 0) {
    // Only said while enforcing, and only about a method the visitor might have been
    // told to expect. With nothing enforced there is no login card to explain.
    if (inputs.passwdEnabled && !passwdLive) notes.push("Password sign-in is configured but not available.");
    if (inputs.oidcEnabled && !oidcLive && (inputs.oidcIssuer.trim() || inputs.oidcClientId.trim())) {
      notes.push("Single sign-on is configured but not available.");
    }
  }

  return { enforced: methods.length > 0, methods, notes };
}

/** Everything the server needs to know about the current posture. */
export interface AccessSnapshot {
  mode: AccessMode;
  /** For the startup line. A count, never a list of names. */
  users: number;
  oidcHost: string;
  passwd: PasswdFile;
  /**
   * Something the operator should fix: a bad passwd line, a half-configured issuer.
   * Logged at `warn`. Log only — these carry paths and reasons.
   */
  warnings: string[];
  /**
   * Where LabView looked and found nothing. Logged at `debug`, because an unconfigured
   * install is not a fault and `levelFor` in `model/connections.ts` sets the same
   * precedent: an integration nobody switched on must never look like a failure.
   */
  hints: string[];
}

/**
 * How long a posture is reused before the passwd file is stat-ed again.
 *
 * Short, because the alternative is worse in both directions: resolving once at startup
 * means an operator who creates the passwd file and reloads the page sees no login and
 * concludes LabView is broken, while resolving per request puts a `stat` on the hot
 * path of every API call. Five seconds makes creating the file feel immediate and
 * bounds the syscall rate no matter how the page is hammered.
 */
export const POSTURE_TTL_MS = 5000;

/**
 * The posture, re-derived as the passwd file changes.
 *
 * Holds the memo and nothing else — the session secret, the throttle and the OIDC
 * client are the server's, because they must survive a posture change untouched.
 * `now` is a parameter so the TTL is assertable.
 */
export class AccessResolver {
  private cached?: { at: number; snapshot: AccessSnapshot };

  constructor(private readonly cfg: LabViewConfig) {}

  snapshot(now: Date, force = false): AccessSnapshot {
    if (!force && this.cached && now.getTime() - this.cached.at < POSTURE_TTL_MS) return this.cached.snapshot;
    const snapshot = readAccess(this.cfg);
    this.cached = { at: now.getTime(), snapshot };
    return snapshot;
  }
}

/** Read the passwd file and derive the posture from it. */
export function readAccess(cfg: LabViewConfig): AccessSnapshot {
  const file = cfg.auth.passwd.enabled
    ? readPasswd(cfg.auth.passwd.file)
    : ({ state: "missing", entries: new Map(), warnings: [] } satisfies PasswdFile);

  const mode = resolveAccessMode({
    passwdEnabled: cfg.auth.passwd.enabled,
    passwdUsers: file.entries.size,
    oidcEnabled: cfg.auth.oidc.enabled,
    oidcIssuer: cfg.auth.oidc.issuer,
    oidcClientId: cfg.auth.oidc.clientId,
  });

  const warnings = [...file.warnings];
  const hints: string[] = [];
  if (cfg.auth.passwd.enabled && file.state === "missing") {
    // A hint, not a warning: this is the unconfigured default, and the summary line
    // already says the surface is open. It is said at all so an operator who *meant* to
    // mount a file learns where LabView looked for it.
    hints.push(`no password file at ${cfg.auth.passwd.file}`);
  }
  if (cfg.auth.oidc.enabled && cfg.auth.oidc.issuer.trim() && !cfg.auth.oidc.clientId.trim()) {
    warnings.push("auth.oidc.issuer is set but auth.oidc.clientId is empty — OIDC sign-in stays off");
  }
  if (cfg.auth.oidc.enabled && cfg.auth.oidc.clientId.trim() && !cfg.auth.oidc.issuer.trim()) {
    warnings.push("auth.oidc.clientId is set but auth.oidc.issuer is empty — OIDC sign-in stays off");
  }
  if (!cfg.auth.passwd.enabled && !cfg.auth.oidc.enabled) {
    hints.push("both auth.passwd.enabled and auth.oidc.enabled are false — LabView will not ask for a sign-in");
  }

  return {
    mode,
    users: file.entries.size,
    oidcHost: issuerHost(cfg.auth.oidc.issuer),
    passwd: file,
    warnings,
    hints,
  };
}

/**
 * The OIDC settings with the client secret resolved, or `undefined` when OIDC is not
 * live.
 *
 * Follows `readToken` in `enrich/authentik.ts`: a `*File` beats an inline value, an
 * unreadable file is a note rather than a crash, and the value itself never reaches a
 * message. An empty secret is not an error — that is a public client, authenticating by
 * PKCE alone.
 */
export function resolveOidc(cfg: LabViewConfig): { settings?: OidcSettings; notes: string[] } {
  const o = cfg.auth.oidc;
  if (!o.enabled || !o.issuer.trim() || !o.clientId.trim()) return { notes: [] };

  const notes: string[] = [];
  const secret = readSecret(o.clientSecretFile, o.clientSecret, "OIDC client secret", notes);

  return {
    settings: {
      issuer: o.issuer.trim(),
      clientId: o.clientId.trim(),
      clientSecret: secret,
      redirectUri: o.redirectUri.trim(),
      scopes: o.scopes,
      usernameClaim: o.usernameClaim.trim(),
      timeoutMs: o.timeoutMs,
    },
    notes,
  };
}

/**
 * The session HMAC key, and whether it was generated.
 *
 * A missing secret is not a failure: one is generated so sessions work, and the note
 * says they will not survive a restart. Requiring the operator to invent one before the
 * login works at all would be a lock-out dressed up as strictness (**I4**).
 *
 * `randomBytes` is passed in rather than imported here so this stays assertable, and
 * because the caller is the only one that should decide when a key is minted.
 */
export function resolveSessionSecret(
  cfg: LabViewConfig,
  generate: () => string,
): { secret: string; generated: boolean; notes: string[] } {
  const notes: string[] = [];
  const configured = readSecret(cfg.auth.session.secretFile, cfg.auth.session.secret, "session secret", notes);
  if (configured) return { secret: configured, generated: false, notes };
  return {
    secret: generate(),
    generated: true,
    notes: [
      ...notes,
      "no auth.session.secret configured — using a random one, so a restart signs everyone out",
    ],
  };
}

/** A `*File` value when given one, else the inline value. Never echoes the value. */
function readSecret(file: string, inline: string, label: string, notes: string[]): string {
  const path = file.trim();
  if (path) {
    try {
      const value = readFileSync(path, "utf8").trim();
      if (value) return value;
      notes.push(`${label} file ${path} is empty`);
    } catch (err) {
      notes.push(`${label} file ${path} could not be read: ${(err as Error).message}`);
    }
  }
  return inline.trim();
}
