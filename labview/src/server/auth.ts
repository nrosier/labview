/**
 * The gate: one `onRequest` hook, one `onSend` hook, five routes.
 *
 * Everything that decides anything lives in `src/auth/` and `src/model/access.ts`, so
 * this file is wiring — read a cookie, call a decision, write a reply. That split is
 * what makes the rules assertable without a socket: `buildApp` hands smoke a Fastify
 * instance it can drive with `app.inject()`, and the hooks below are the one part of the
 * feature no unit test can prove.
 *
 * Three rules the routes hold to:
 *
 *  - **The gate never consults scanned data.** Whether a request is allowed depends on
 *    the config, the passwd file and the cookie — never on an overview, a container or
 *    anything an enrichment read returned. A Docker socket that goes away must not be
 *    able to change who may sign in.
 *  - **A reply says less than the log.** The browser gets a code from
 *    `LoginFailureReason`; the reason, the path and the provider's complaint go to the
 *    log (**I6**).
 *  - **A username is sanitised before it is logged.** It arrives in a request body or an
 *    ID token, and `sanitizeUsername` is what keeps a crafted one from forging a line.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { randomBytes } from "node:crypto";
import type { LabViewConfig } from "../config.js";
import type { LoginFailureReason, LoginMethod, SessionInfo } from "../model/types.js";
import { accessModeSummary, oidcButtonLabel, sanitizeUsername } from "../model/access.js";
import {
  AccessResolver,
  isPublicPath,
  requiresSession,
  resolveOidc,
  resolveSessionSecret,
  type AccessSnapshot,
} from "../auth/index.js";
import { MAX_PASSWORD_CHARS, verifyLogin } from "../auth/passwd.js";
import { LoginThrottle } from "../auth/throttle.js";
import {
  SessionRevocations,
  effectiveHost,
  effectiveProtocol,
  issueSession,
  originAllowed,
  readCookie,
  safeEqual,
  serializeCookie,
  shouldSecureCookie,
  signPayload,
  unsignPayload,
  verifySession,
  type SessionPayload,
} from "../auth/session.js";
import {
  LOGIN_WINDOW_SECONDS,
  OidcClient,
  buildAuthorizeUrl,
  createVerifier,
  randomToken,
  redirectUriFor,
  type OidcTransient,
} from "../auth/oidc.js";
import type { FetchLike, HttpResponse } from "../enrich/http.js";

export interface AccessControlOptions {
  /** Injectable `fetch`, for driving the OIDC flow in a test. */
  fetchImpl?: FetchLike;
  /** Injectable clock. Defaults to the real one. */
  now?: () => Date;
}

/** Where a failed sign-in sends the browser: the SPA, with a code it can render. */
function failureRedirect(reason: LoginFailureReason): string {
  return `/?login_error=${reason}`;
}

/**
 * Install the gate on `app`.
 *
 * Called before the API routes are registered so the hooks apply to them, and before
 * the `LabView scanning …` line so the startup block opens by saying who may read this
 * LabView.
 */
export function registerAccessControl(
  app: FastifyInstance,
  cfg: LabViewConfig,
  opts: AccessControlOptions = {},
): void {
  const clock = opts.now ?? (() => new Date());
  const resolver = new AccessResolver(cfg);

  const session = resolveSessionSecret(cfg, () => randomBytes(32).toString("base64url"));
  const secret = session.secret;
  const revocations = new SessionRevocations();
  const throttle = new LoginThrottle(cfg.auth.maxFailedAttempts, cfg.auth.lockoutSeconds);

  const oidcResolved = resolveOidc(cfg);
  const doFetch: FetchLike = opts.fetchImpl ?? ((url, init) => fetch(url, init) as Promise<HttpResponse>);
  const oidc = oidcResolved.settings ? new OidcClient(oidcResolved.settings, doFetch) : undefined;
  const oidcCookieName = `${cfg.auth.session.cookieName}_oidc`;
  const oidcCookiePath = "/auth/oidc";

  // The startup posture. `snapshot` is forced so the passwd file is read now rather than
  // on the first request — the operator should learn their file was parsed at start-up,
  // not five seconds into someone else's page load.
  const startup = resolver.snapshot(clock(), true);
  app.log.info(accessModeSummary(startup.mode, { users: startup.users, oidcHost: startup.oidcHost }));
  for (const note of [...startup.warnings, ...oidcResolved.notes, ...session.notes]) app.log.warn(`access: ${note}`);
  for (const hint of startup.hints) app.log.debug(`access: ${hint}`);
  if (session.generated && startup.mode.enforced) {
    // Only worth saying when there are sessions to lose. Said at `info` rather than
    // `warn` because it is a consequence of a default, not a misconfiguration.
    app.log.info("access: set auth.session.secret (or LABVIEW_SESSION_SECRET) to keep sessions across restarts");
  }

  /** What posture applies right now, re-read at most every `POSTURE_TTL_MS`. */
  let lastSummary = accessModeSummary(startup.mode, { users: startup.users, oidcHost: startup.oidcHost });
  function posture(): AccessSnapshot {
    const snap = resolver.snapshot(clock());
    // Say it when it changes, and only then — the same cadence `changedConnections` uses
    // for the integration lines, and the reason an operator who creates the passwd file
    // on a running LabView gets a line saying so instead of silence.
    const summary = accessModeSummary(snap.mode, { users: snap.users, oidcHost: snap.oidcHost });
    if (summary !== lastSummary) {
      lastSummary = summary;
      app.log.info(summary);
      for (const note of snap.warnings) app.log.warn(`access: ${note}`);
    }
    return snap;
  }

  function currentSession(req: FastifyRequest, now: Date): SessionPayload | undefined {
    const raw = readCookie(req.headers.cookie, cfg.auth.session.cookieName);
    if (!raw) return undefined;
    const check = verifySession(raw, secret, now, revocations);
    return check.ok ? check.payload : undefined;
  }

  function hostOf(req: FastifyRequest): string {
    return effectiveHost(headerValue(req, "x-forwarded-host"), req.headers.host ?? "");
  }

  function secureCookies(req: FastifyRequest): boolean {
    const proto = effectiveProtocol(headerValue(req, "x-forwarded-proto"), req.protocol);
    return shouldSecureCookie(cfg.auth.session.secure, proto);
  }

  function setSessionCookie(req: FastifyRequest, reply: FastifyReply, token: string): void {
    addCookie(
      reply,
      serializeCookie({
        name: cfg.auth.session.cookieName,
        value: token,
        maxAgeSeconds: cfg.auth.session.ttlMinutes * 60,
        secure: secureCookies(req),
        path: "/",
      }),
    );
  }

  function clearCookie(req: FastifyRequest, reply: FastifyReply, name: string, path: string): void {
    addCookie(reply, serializeCookie({ name, value: "", maxAgeSeconds: 0, secure: secureCookies(req), path }));
  }

  // ---- the gate ------------------------------------------------------------------

  app.addHook("onRequest", async (req, reply) => {
    const now = clock();
    const snap = posture();
    if (!snap.mode.enforced) return;

    // CSRF, on top of `SameSite=Lax`. Before the session check so a cross-site POST is
    // refused whether or not it managed to carry a cookie.
    if (req.method === "POST" && !originAllowed(headerValue(req, "origin"), hostOf(req))) {
      app.log.warn("access: refused a POST whose Origin is not this host");
      return reply.code(403).send({ error: "forbidden" });
    }

    if (!requiresSession(req.url)) return;
    if (currentSession(req, now)) return;
    return reply.code(401).send({ error: "unauthorized" });
  });

  app.addHook("onSend", async (req, reply, payload) => {
    // Cheap, always-correct headers. No CSP: mermaid and cytoscape both inject styles at
    // runtime, and a policy that breaks the graph tab is worse than none.
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "same-origin");
    reply.header("X-Frame-Options", "DENY");
    if (resolver.snapshot(clock()).mode.enforced && isGated(req.url)) {
      reply.header("Cache-Control", "no-store");
    }
    return payload;
  });

  // ---- routes --------------------------------------------------------------------

  app.get("/api/session", async (req) => {
    const now = clock();
    const snap = posture();
    const user = currentSession(req, now);
    const info: SessionInfo = {
      enforced: snap.mode.enforced,
      methods: snap.mode.methods,
      notes: snap.mode.notes,
      ...(user ? { user: { name: user.u, via: user.via } } : {}),
      ...(snap.mode.methods.includes("oidc")
        ? { oidcLabel: oidcButtonLabel(cfg.auth.oidc.label, cfg.auth.oidc.issuer) }
        : {}),
    };
    return info;
  });

  app.post("/api/login", async (req, reply) => {
    const now = clock();
    const snap = posture();
    if (!snap.mode.methods.includes("passwd")) {
      return reply.code(400).send({ error: "method-unavailable" satisfies LoginFailureReason });
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const rawUser = typeof body.username === "string" ? body.username : "";
    const password = typeof body.password === "string" ? body.password : "";
    const safe = sanitizeUsername(rawUser.trim());
    const key = LoginThrottle.key(safe);

    const allowed = throttle.check(key, now);
    if (!allowed.allowed) {
      app.log.warn(`access: sign-in for "${safe}" is throttled for ${allowed.retryAfterSeconds}s`);
      return reply
        .code(429)
        .header("Retry-After", String(allowed.retryAfterSeconds))
        .send({ error: "throttled" satisfies LoginFailureReason, retryAfterSeconds: allowed.retryAfterSeconds });
    }

    // Over-long passwords are rejected without hashing — `verifyLogin` checks the same
    // bound, this only avoids reading a megabyte into a compare.
    const ok = password.length <= MAX_PASSWORD_CHARS && (await verifyLogin(snap.passwd, rawUser, password));
    if (!ok) {
      const after = throttle.fail(key, now);
      app.log.warn(
        `access: failed password sign-in for "${safe}"${after.allowed ? "" : ` — locked out for ${after.retryAfterSeconds}s`}`,
      );
      // One message for an unknown user and a wrong password alike, so the response is
      // not a way to enumerate accounts. `verifyLogin` already makes the timing match.
      return reply.code(401).send({ error: "credentials" satisfies LoginFailureReason });
    }

    throttle.succeed(key);
    const issued = issueSession(safe, "passwd", secret, cfg.auth.session.ttlMinutes, now);
    setSessionCookie(req, reply, issued.token);
    app.log.info(`access: "${safe}" signed in with a password`);
    return reply.send({ ok: true, user: { name: safe, via: "passwd" satisfies LoginMethod } });
  });

  app.post("/api/logout", async (req, reply) => {
    const now = clock();
    const user = currentSession(req, now);
    if (user) {
      revocations.revoke(user.jti, user.exp, now);
      app.log.info(`access: "${user.u}" signed out`);
    }
    clearCookie(req, reply, cfg.auth.session.cookieName, "/");
    return reply.send({ ok: true });
  });

  // ---- OIDC ----------------------------------------------------------------------
  //
  // Off `/api` on purpose: the redirect URI is typed into the provider by a human and
  // shows up in browser history, and keeping it outside `/api` keeps the gate's
  // allowlist to four exact paths. These two are never gated, because a login flow that
  // needed a session could not complete.

  app.get("/auth/oidc/start", async (req, reply) => {
    const now = clock();
    const snap = posture();
    if (!oidc || !snap.mode.methods.includes("oidc")) {
      return reply.redirect(failureRedirect("method-unavailable"));
    }

    const found = await oidc.discover(now);
    if (!found.ok) {
      app.log.warn(`access: OIDC discovery failed — ${found.failure.detail}`);
      return reply.redirect(failureRedirect("oidc-provider"));
    }

    const transient: OidcTransient = {
      state: randomToken(),
      nonce: randomToken(),
      verifier: createVerifier(),
      exp: Math.floor(now.getTime() / 1000) + LOGIN_WINDOW_SECONDS,
    };
    const settings = oidcResolved.settings;
    if (!settings) return reply.redirect(failureRedirect("method-unavailable"));
    const redirectUri = redirectUriFor(
      settings.redirectUri,
      effectiveProtocol(headerValue(req, "x-forwarded-proto"), req.protocol),
      hostOf(req),
    );

    // Signed rather than stored: nothing is kept server-side, so a restart mid-login
    // fails cleanly instead of leaving state behind. `Path=/auth/oidc` keeps it off
    // every other request, and the five-minute window is in the payload as well as in
    // `Max-Age`, because a client is free to ignore the latter.
    addCookie(
      reply,
      serializeCookie({
        name: oidcCookieName,
        value: signPayload(transient, secret),
        maxAgeSeconds: LOGIN_WINDOW_SECONDS,
        secure: secureCookies(req),
        path: oidcCookiePath,
      }),
    );
    return reply.redirect(buildAuthorizeUrl(found.doc, settings, redirectUri, transient));
  });

  app.get("/auth/oidc/callback", async (req, reply) => {
    const now = clock();
    const snap = posture();
    const settings = oidcResolved.settings;
    if (!oidc || !settings || !snap.mode.methods.includes("oidc")) {
      return reply.redirect(failureRedirect("method-unavailable"));
    }

    const query = (req.query ?? {}) as Record<string, unknown>;
    const raw = readCookie(req.headers.cookie, oidcCookieName);
    clearCookie(req, reply, oidcCookieName, oidcCookiePath);

    const providerError = typeof query.error === "string" ? query.error : "";
    if (providerError) {
      // The provider's own code — `access_denied`, `consent_required` — is a fixed
      // vocabulary, not user text, and it is the one thing that explains a login the
      // operator will swear went through.
      app.log.warn(`access: the provider refused the sign-in (${sanitizeCode(providerError)})`);
      return reply.redirect(failureRedirect("oidc-provider"));
    }

    const transient = readTransient(raw, secret, now);
    const state = typeof query.state === "string" ? query.state : "";
    if (!transient || !state || !safeEqual(state, transient.state)) {
      app.log.warn("access: an OIDC callback arrived with no matching sign-in attempt");
      return reply.redirect(failureRedirect("oidc-state"));
    }

    const code = typeof query.code === "string" ? query.code : "";
    if (!code) {
      app.log.warn("access: an OIDC callback arrived with no authorization code");
      return reply.redirect(failureRedirect("oidc-token"));
    }

    const redirectUri = redirectUriFor(
      settings.redirectUri,
      effectiveProtocol(headerValue(req, "x-forwarded-proto"), req.protocol),
      hostOf(req),
    );
    const result = await oidc.redeem(code, redirectUri, transient, now);
    if (!result.ok) {
      app.log.warn(`access: OIDC sign-in failed — ${result.failure.detail}`);
      return reply.redirect(failureRedirect(`oidc-${result.failure.stage}`));
    }

    const issued = issueSession(result.username, "oidc", secret, cfg.auth.session.ttlMinutes, now);
    setSessionCookie(req, reply, issued.token);
    app.log.info(`access: "${result.username}" signed in through the identity provider`);
    return reply.redirect("/");
  });
}

/**
 * The transient cookie's payload, if it verifies and has not expired.
 *
 * The window is checked here rather than trusted to `Max-Age` because the cookie is a
 * value the browser sends back, and a browser that keeps sending an old one is not a
 * threat model worth relying on the client for.
 */
function readTransient(raw: string | undefined, secret: string, now: Date): OidcTransient | undefined {
  if (!raw) return undefined;
  const payload = unsignPayload(raw, secret);
  if (payload === null || typeof payload !== "object") return undefined;
  const t = payload as Partial<OidcTransient>;
  if (typeof t.state !== "string" || typeof t.nonce !== "string" || typeof t.verifier !== "string") return undefined;
  if (typeof t.exp !== "number" || t.exp * 1000 <= now.getTime()) return undefined;
  return { state: t.state, nonce: t.nonce, verifier: t.verifier, exp: t.exp };
}

/** Whether `Cache-Control: no-store` applies: everything under `/api`. */
function isGated(url: string): boolean {
  return requiresSession(url) || isPublicPath(url);
}

/**
 * One header value as a string.
 *
 * Node hands a repeated header back as an array, and every header read here — `origin`,
 * `x-forwarded-proto`, `x-forwarded-host` — is one an intermediary can duplicate. Taking
 * the first is the same choice `effectiveProtocol` makes about a comma-joined list.
 */
function headerValue(req: FastifyRequest, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}

/** A provider error code, reduced to something safe to log. */
function sanitizeCode(value: string): string {
  return /^[a-z0-9_-]{1,64}$/i.test(value) ? value : "?";
}

/**
 * Append a `Set-Cookie` value without dropping one already set.
 *
 * The callback sets two — a session and a cleared transient — and `reply.header` on a
 * repeated name replaces rather than appends unless the value is already an array.
 * Accumulating explicitly makes that independent of the framework's special-casing.
 */
function addCookie(reply: FastifyReply, value: string): void {
  const existing = reply.getHeader("set-cookie");
  if (existing === undefined) {
    reply.header("set-cookie", value);
    return;
  }
  const list = Array.isArray(existing) ? existing.map(String) : [String(existing)];
  reply.header("set-cookie", [...list, value]);
}
