import type {
  Service,
  AuthPosture,
  AuthMethod,
  AuthConfidence,
  AuthentikMatchStrength,
  AuthentikProvider,
  EnvVar,
  TraefikLiveMiddleware,
  TraefikLiveRouter,
} from "../model/types.js";
import type { LabViewConfig } from "../config.js";
import type { MiddlewareRegistry } from "../analyze/middlewares.js";

interface Detection {
  method: AuthMethod;
  detail: string;
  evidence: string[];
  confidence: AuthConfidence;
}

/**
 * Derive the authentication posture of a service from its Traefik middlewares
 * (resolved against the global middleware registry), its Cloudflare Access
 * policy, and its environment (OIDC/OAuth or LDAP).
 *
 * The mechanism and the provider are two separate conclusions, and only the
 * mechanism is usually certain. A `forwardauth` middleware definition proves a
 * gate exists; naming *whose* gate it is requires a value in the config that says
 * so — the forward-auth address, an issuer URL, or an LDAP host that matches a
 * provider identity discovered elsewhere in the fleet. Where the provider cannot
 * be established, the generic method (`forward-auth`, `other-oauth`, `ldap`) is
 * reported rather than the most likely vendor, and `confidence` records whether
 * the conclusion rests on a definition or only on a reference name.
 *
 * When the identity provider's API was readable, its records outrank all of that
 * and carry `confirmed` confidence: a label says what the operator meant to
 * configure, whereas the provider's own records say what it will enforce. The same
 * applies to the reverse proxy's API — see `liveChainComplete`.
 *
 * `exposedWithoutAuth` is left false here and finalized by the analyzer once the
 * ingress classification is known.
 *
 * @param liveChainComplete Whether the proxy's live configuration was read *fully*
 * (its runtime config **and** its entrypoints). Only then does a matched router's
 * live chain **replace** that router's label list, which is what allows a label
 * declaring a gate the proxy never attached to stop counting as protection. On a
 * partial read the two are unioned instead: an entrypoint-level middleware is
 * invisible without `/api/entrypoints`, and mistaking that for an absent gate would
 * invert the finding.
 */
export function deriveAuth(
  service: Service,
  cfg: LabViewConfig,
  registry: MiddlewareRegistry,
  providerHints: string[],
  liveChainComplete = false,
): AuthPosture {
  const a = cfg.labels.authentik;
  const detections: Detection[] = [];
  /**
   * Every provider the API reported gets an evidence line whether or not it gates
   * anything. A configured-but-unserved gate is precisely the thing a reader needs
   * told, and it produces no detection to carry the line for it.
   */
  const apiEvidence: string[] = [];

  // 1. The identity provider's own records, when its API answered. Only a provider
  //    that something actually serves is treated as a gate — see providerEnforces.
  for (const [i, app] of (service.authentik?.applications ?? []).entries()) {
    // Parallel arrays, so the tie that placed this application is at the same index.
    // Absent means the weakest reading, never the strongest.
    const strength = service.authentik?.strength[i] ?? "name";
    for (const provider of app.providers) {
      apiEvidence.push(authentikEvidence(app.name, provider));
      const d = classifyAuthentikProvider(app.name, provider, strength);
      if (d) detections.push(d);
    }
  }

  // 2. Traefik middlewares, per router.
  //
  // Per router rather than pooled across all of them: a live chain speaks for the
  // one router it belongs to, and pooling would let a protected router's chain
  // vouch for an unprotected one on the same service.
  //
  // Every live router the proxy is actually serving contributes its resolved chain
  // — including routers no label declares, which is how a file-provider gate gets
  // confirmed. A router the proxy reports as disabled or errored contributes
  // nothing: it is not in any request path, so it protects nothing either.
  const live = service.traefikLive ?? [];
  for (const router of live) {
    if (!routerIsServing(router)) continue;
    for (const mw of router.middlewares) {
      const d = classifyLiveMiddleware(router, mw, providerHints);
      if (d) detections.push(d);
    }
  }

  // Label middlewares stand for routers the live read did not account for. With no
  // live read at all — API disabled, unreachable, or nothing matched — that is every
  // router, which is exactly the label-only behaviour.
  const liveNames = new Set(live.filter(routerIsServing).map((r) => r.router.toLowerCase()));
  const superseded = (route: { router: string }) =>
    liveChainComplete && liveNames.has(route.router.toLowerCase());
  const referenced = new Set(service.traefik.filter((r) => !superseded(r)).flatMap((r) => r.middlewares));
  for (const mw of referenced) {
    const d = classifyMiddleware(mw, registry, providerHints);
    if (d) detections.push(d);
  }

  // 3. Cloudflare Access policy on a public route (an edge gate, stated in labels).
  for (const route of service.cloudflare) {
    if (route.access && (route.access.policy || route.access.group || route.access.emails?.length)) {
      const bits = [
        route.access.policy && `policy=${route.access.policy}`,
        route.access.group && `group=${route.access.group}`,
        route.access.emails?.length && `emails=${route.access.emails.join(",")}`,
      ].filter(Boolean);
      detections.push({
        method: "other-oauth",
        detail: `Cloudflare Access on ${route.hostname}`,
        evidence: [`Cloudflare Access (${bits.join(", ")})`],
        confidence: "observed",
      });
    }
  }

  // 4. Env-derived OIDC/OAuth. The keys prove the mechanism; only a value that
  //    resolves to a discovered provider identity may name the provider.
  const oauth = detectEnv(service.env, a.oauthEnvHints);
  if (oauth.hit) {
    const match = firstMatch(oauth.matchedValues, providerHints) ?? firstMatch(oauth.keys, providerHints);
    detections.push({
      method: match ? "authentik-oauth" : "other-oauth",
      detail: match
        ? `OAuth/OIDC SSO against Authentik (matched \`${match.hint}\` in ${match.subject})`
        : "OAuth/OIDC SSO — issuer does not resolve to a provider identified in this fleet",
      evidence: [...oauth.keys.map((k) => `env ${k}`), ...(match ? [] : [NO_PROVIDER])],
      confidence: "observed",
    });
  }

  // 5. Env-derived LDAP. An LDAP host matching a discovered provider identity is
  //    that provider's LDAP outpost; any other directory (OpenLDAP, AD, …) is one
  //    we cannot identify and must not be attributed to a vendor.
  const ldap = detectEnv(service.env, a.ldapEnvHints);
  if (ldap.hit) {
    const match = firstMatch(ldap.matchedValues, providerHints);
    detections.push({
      method: match ? "authentik-ldap" : "ldap",
      detail: match
        ? `LDAP bind against the Authentik LDAP outpost (matched \`${match.hint}\` in ${match.subject})`
        : "LDAP authentication — directory does not resolve to a provider identified in this fleet",
      evidence: [...ldap.keys.map((k) => `env ${k}`), ...(match ? [] : [NO_PROVIDER])],
      confidence: "observed",
    });
  }

  // Pick the primary method by precedence; keep everything else as evidence. A
  // proxy-level gate ranks first: it is what actually stops a request at the edge.
  const order: AuthMethod[] = [
    "authentik-forward-auth",
    "forward-auth",
    "authentik-oauth",
    "authentik-ldap",
    "ldap",
    "other-oauth",
    "basic-auth",
  ];
  // Mechanism first, then confidence: where a label and the provider's API report
  // the same mechanism, the API's account is the one worth showing.
  detections.sort(
    (x, y) =>
      order.indexOf(x.method) - order.indexOf(y.method) ||
      CONFIDENCE_RANK[x.confidence] - CONFIDENCE_RANK[y.confidence],
  );
  const primary = detections[0];
  const evidence = [...new Set([...apiEvidence, ...detections.flatMap((d) => d.evidence)])];

  if (!primary) {
    return {
      method: "none",
      detail: "No authentication detected",
      evidence,
      confidence: "observed",
      exposedWithoutAuth: false,
    };
  }

  const others = detections.slice(1).map((d) => d.detail);
  const detail = others.length ? `${primary.detail}; also: ${others.join("; ")}` : primary.detail;
  return {
    method: primary.method,
    detail,
    evidence,
    confidence: primary.confidence,
    exposedWithoutAuth: false,
  };
}

/** Evidence marker for a mechanism seen without an identifiable provider. */
const NO_PROVIDER = "provider not identified from the scanned config";

/** Strongest evidence first, used only to break a tie between equal mechanisms. */
const CONFIDENCE_RANK: Record<AuthConfidence, number> = { confirmed: 0, observed: 1, inferred: 2 };

/**
 * Whether a provider will actually stop a request.
 *
 * Being configured is not the same as being deployed. A proxy, LDAP or RADIUS
 * provider is enforced by an **outpost**, so one with no outpost attached is a gate
 * nothing is standing at — reporting it as protection would be exactly the kind of
 * false comfort this project exists to remove. OAuth2 and SAML are served by
 * Authentik's core server, so they need no outpost. SCIM provisions accounts
 * outbound and gates nothing at all, and an unmodelled type is not claimed either
 * way.
 */
export function providerEnforces(provider: AuthentikProvider): boolean {
  switch (provider.kind) {
    case "oauth2":
    case "saml":
      return true;
    case "proxy":
    case "ldap":
    case "radius":
      return provider.outposts.length > 0;
    default:
      return false;
  }
}

/** Whether the provider's API confirmed at least one enforced gate on this service. */
export function hasEnforcedAuthentikGate(service: Pick<Service, "authentik">): boolean {
  return (service.authentik?.applications ?? []).some((app) => app.providers.some(providerEnforces));
}

/**
 * Whether this scan **detected** authentication in front of a service, from every source
 * that is not a measurement and not a claim.
 *
 * Three terms, and each of them is a document or an API answering rather than an opinion:
 * a method {@link deriveAuth} settled on (a Traefik middleware, the live chain, an OIDC
 * issuer, an LDAP host, the Authentik API), a tunnel route carrying an Access policy, or
 * an Authentik provider the API reports something actually serves.
 *
 * Two things are deliberately *not* here:
 *
 *  - **The probe.** A login page LabView was answered with is protection it measured, and
 *    this predicate is what decides whether to go and measure — folding the answer into
 *    the question would be circular.
 *  - **A `.labview` declaration.** `supplies` is the operator's claim about their own
 *    service. Believing it and then not checking is how a claim quietly becomes a fact,
 *    which is what `fixtures/probe/declared-open` exists to catch.
 *
 * An `inferred` posture counts. A router naming `authentik@docker` whose definition was
 * in no scanned stack is still a gate this scan detected through Traefik, and it already
 * makes `hasEdgeAuth` true — so measuring it could not change the verdict either way.
 *
 * One definition with two callers, which is the point: `analyze/index.ts` reads it to
 * decide who gets probed and again to word the notes that explain the outcome. Two copies
 * could disagree, and a service skipped for a reason its own notes contradict is the one
 * failure mode this predicate has.
 */
export function hasDetectedAuth(service: Pick<Service, "auth" | "cloudflare" | "authentik">): boolean {
  if (service.auth.method !== "none") return true;
  // The policy, group or email list — not the mere presence of an `access` block, which
  // an operator can leave behind empty and which gates nothing on its own.
  if (service.cloudflare.some((r) => r.access && (r.access.policy || r.access.group || r.access.emails?.length))) {
    return true;
  }
  return hasEnforcedAuthentikGate(service);
}

/**
 * Turn one API-reported provider into a detection.
 *
 * Only the three kinds with an `AuthMethod` produce one. A SAML, RADIUS or
 * unmodelled provider is real protection but has no method to report it as, so it
 * contributes evidence and counts toward the service being protected
 * (`hasEnforcedAuthentikGate`) without being mislabelled as a mechanism it is not.
 *
 * A provider Authentik records is taken as being in use — an OAuth2 provider needs no
 * outpost and the application's own client configuration is not in the compose file to
 * corroborate, so the identity provider's record is the whole of the evidence. What
 * the record cannot establish is *which* service it belongs to, and `strength` is that:
 * an addressed or hostname tie is `confirmed`, a tie resting only on similar names is
 * `observed`, and the reason is spelled out so the reader can weigh it.
 */
function classifyAuthentikProvider(
  appName: string,
  provider: AuthentikProvider,
  strength: AuthentikMatchStrength,
): Detection | undefined {
  if (!providerEnforces(provider)) return undefined;

  const method: AuthMethod | undefined =
    provider.kind === "proxy"
      ? "authentik-forward-auth"
      : provider.kind === "oauth2"
        ? "authentik-oauth"
        : provider.kind === "ldap"
          ? "authentik-ldap"
          : undefined;
  if (!method) return undefined;

  const mode = provider.mode ? ` in \`${provider.mode}\` mode` : "";
  const tie = strength === "name" ? " — tied to this service by name alone" : "";
  return {
    method,
    detail: `Authentik ${provider.kind} provider "${provider.name}" for application "${appName}"${mode}, ${servedBy(provider)}${tie}`,
    evidence: [authentikEvidence(appName, provider)],
    confidence: strength === "name" ? "observed" : "confirmed",
  };
}

/** One line stating what the API reported, in the same voice as the other evidence. */
function authentikEvidence(appName: string, provider: AuthentikProvider): string {
  return `Authentik API: ${provider.rawKind} "${provider.name}" on application "${appName}" (${servedBy(provider)})`;
}

function servedBy(provider: AuthentikProvider): string {
  if (provider.outposts.length) return `served by outpost ${provider.outposts.join(", ")}`;
  return providerEnforces(provider)
    ? "served by the Authentik server"
    : "no outpost serves it, so it enforces nothing";
}

/**
 * Whether the proxy is actually serving a router.
 *
 * Traefik reports both a status and, separately, the errors that made it stop
 * serving; either one is disqualifying. A router that is not serving is not in any
 * request path, so it neither provides ingress nor enforces the middlewares it
 * names — reporting its chain as protection would be a gate on a road nobody drives.
 */
export function routerIsServing(router: TraefikLiveRouter): boolean {
  if (router.errors.length) return false;
  return !router.status || router.status.toLowerCase() === "enabled";
}

/**
 * Classify one entry of a live middleware chain.
 *
 * This is the same reasoning as `classifyMiddleware` with the guesswork removed. The
 * type comes from the proxy's own runtime configuration rather than from a definition
 * the scan had to find, so it is never `inferred` — which is precisely what retires
 * the `inferred` posture for a middleware defined in a file provider, the largest
 * known gap in label-only auth detection.
 *
 * A middleware the proxy reports an error for is skipped: Traefik does not apply a
 * middleware it could not build, so it stops nothing.
 */
function classifyLiveMiddleware(
  router: TraefikLiveRouter,
  mw: TraefikLiveMiddleware,
  providerHints: string[],
): Detection | undefined {
  if (mw.errors.length) return undefined;
  const where = liveOrigin(router, mw);

  if (mw.type === "basicauth" || mw.type === "digestauth") {
    return {
      method: "basic-auth",
      detail: `HTTP ${mw.type === "digestauth" ? "digest" : "basic"} auth via \`${mw.name}\`, live in the proxy`,
      evidence: [`Traefik API: ${mw.type} middleware \`${mw.name}\` ${where}`],
      confidence: "confirmed",
    };
  }

  if (mw.type === "forwardauth") {
    // As with a label-derived forward-auth, the address is the only statement of who
    // authenticates — and here it is the address the proxy will actually call.
    const match = mw.address ? firstMatch([mw.address], providerHints) : undefined;
    const evidence = [
      `Traefik API: forwardauth middleware \`${mw.name}\` ${where}`,
      ...(mw.address ? [`forwardauth -> ${mw.address}`] : []),
    ];
    if (match) {
      return {
        method: "authentik-forward-auth",
        detail: `Authentik forward-auth via \`${mw.name}\`, live in the proxy's chain for router \`${router.router}\``,
        evidence,
        confidence: "confirmed",
      };
    }
    return {
      method: "forward-auth",
      detail: `Forward-auth via \`${mw.name}\`, live in the proxy's chain for router \`${router.router}\`${mw.address ? ` -> ${mw.address}` : ""}`,
      evidence: [...evidence, NO_PROVIDER],
      confidence: "confirmed",
    };
  }
  return undefined;
}

/** Where in the live configuration a chain entry was attached, for its evidence line. */
function liveOrigin(router: TraefikLiveRouter, mw: TraefikLiveMiddleware): string {
  const via = mw.viaChain ? ` via chain \`${mw.viaChain}\`` : "";
  if (mw.viaEntrypoint) {
    return `on entrypoint ${router.entryPoints.join(", ") || "(unnamed)"}${via}, which router \`${router.router}\` listens on`;
  }
  return `on router \`${router.router}\`${via}`;
}

/**
 * Classify one referenced middleware.
 *
 * The registry entry is the proof: its type says what the middleware does and its
 * `forwardauth.address` says which service answers the auth request. When the
 * middleware is defined outside the scanned stacks (a Traefik file provider, or an
 * SSO deployment that lives elsewhere) there is no definition to read, and the
 * only signal left is the name the operator wrote in the label — usable, but
 * reported as `inferred` so it is never mistaken for a resolved address.
 */
function classifyMiddleware(
  mw: string,
  registry: MiddlewareRegistry,
  providerHints: string[],
): Detection | undefined {
  const bare = mw.replace(/@.*$/, "");
  const def = registry.get(bare);

  if (def?.type === "basicauth" || def?.type === "digestauth") {
    return {
      method: "basic-auth",
      detail: `HTTP ${def.type === "digestauth" ? "digest" : "basic"} auth via \`${mw}\``,
      evidence: [`middleware ${mw} (${def.type} defined in ${def.definedIn})`],
      confidence: "observed",
    };
  }

  if (def?.type === "forwardauth") {
    // The address is the only statement of who authenticates. A middleware named
    // after one provider but pointing at another is the address's story to tell.
    const match = def.address ? firstMatch([def.address], providerHints) : undefined;
    if (match) {
      return {
        method: "authentik-forward-auth",
        detail: `Authentik forward-auth via Traefik middleware \`${mw}\``,
        evidence: [`middleware ${mw}`, `forwardauth -> ${def.address}`],
        confidence: "observed",
      };
    }
    return {
      method: "forward-auth",
      detail: `Forward-auth via \`${mw}\`${def.address ? ` -> ${def.address}` : ""}`,
      evidence: [`middleware ${mw}`, ...(def.address ? [`forwardauth -> ${def.address}`] : []), NO_PROVIDER],
      confidence: "observed",
    };
  }

  // A definition exists and is not an auth type (headers, redirectscheme,
  // compress, ratelimit, chain, …): it gates nothing.
  if (def) return undefined;

  // Unresolved. Fall back to the reference name, which is still something the
  // operator wrote, but say plainly that no definition was found.
  if (!looksLikeAuthName(bare)) return undefined;
  const named = firstMatch([bare], providerHints);
  return {
    method: named ? "authentik-forward-auth" : "forward-auth",
    detail: named
      ? `Authentik forward-auth inferred from the name of \`${mw}\` — no definition found in the scanned stacks`
      : `Auth middleware inferred from the name of \`${mw}\` — no definition found in the scanned stacks`,
    evidence: [`middleware ${mw}`, "definition not found in any scanned stack", ...(named ? [] : [NO_PROVIDER])],
    confidence: "inferred",
  };
}

/**
 * Whether a label-referenced middleware would count as an auth gate on its own.
 *
 * Exported so the live-configuration report asks the *same* question `deriveAuth`
 * asks, rather than keeping a second opinion about what an auth middleware is: a
 * discrepancy note is only worth printing for a middleware whose absence from the
 * live chain would actually have changed the posture.
 */
export function isAuthMiddlewareRef(
  mw: string,
  registry: MiddlewareRegistry,
  providerHints: string[],
): boolean {
  return classifyMiddleware(mw, registry, providerHints) !== undefined;
}

/**
 * Whether a middleware name suggests an auth gate. Only consulted when the
 * definition could not be found, and deliberately narrow: `auth` must appear as
 * its own token, so `oauth-headers` or `author-cache` do not qualify, and an
 * explicitly non-auth name is excluded outright.
 */
function looksLikeAuthName(bare: string): boolean {
  if (/header|redirect|compress|ratelimit|retry|buffering|stripprefix|addprefix/i.test(bare)) return false;
  return tokensOf(bare).some((t) => t === "auth" || t === "sso" || t.includes("authentik"));
}

interface HintMatch {
  hint: string;
  subject: string;
}

/** First (subject, hint) pair where a hint identifies the subject. */
function firstMatch(subjects: string[], hints: string[]): HintMatch | undefined {
  for (const subject of subjects) {
    for (const hint of hints) {
      if (identifies(subject, hint)) return { hint, subject };
    }
  }
  return undefined;
}

/**
 * Whether `hint` identifies `value`.
 *
 * Matched at token boundaries rather than as a bare substring: a hint of `auth`
 * must not match `oauth.bigcorp.example.com`, which would attribute an unrelated
 * identity provider to Authentik on the strength of four shared letters. A token
 * boundary is the start/end of the value or any non-alphanumeric character, so
 * `authentik` still matches `http://authentik-server:9000/…`, and a fully
 * qualified hint like `sso.example.com` still matches an issuer URL that embeds
 * it. Leading/trailing dots in a hint (`auth.`) are ignored so a host-prefix
 * style hint behaves the same way.
 */
function identifies(value: string, hint: string): boolean {
  const v = value.toLowerCase();
  const h = hint.toLowerCase().replace(/^\.+|\.+$/g, "");
  if (!h) return false;
  for (let i = v.indexOf(h); i !== -1; i = v.indexOf(h, i + 1)) {
    const before = i === 0 ? "" : v[i - 1]!;
    const after = v[i + h.length] ?? "";
    if (!isWordChar(before) && !isWordChar(after)) return true;
  }
  return false;
}

function isWordChar(c: string): boolean {
  return c !== "" && /[a-z0-9]/.test(c);
}

/** Split an identifier into alphanumeric tokens (`authentik-server` -> [authentik, server]). */
function tokensOf(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

interface EnvHit {
  hit: boolean;
  keys: string[];
  matchedValues: string[];
}

function detectEnv(env: EnvVar[], hints: string[]): EnvHit {
  const upperHints = hints.map((h) => h.toUpperCase());
  const keys: string[] = [];
  const matchedValues: string[] = [];
  for (const e of env) {
    const K = e.key.toUpperCase();
    if (upperHints.some((h) => K.includes(h))) {
      keys.push(e.key);
      if (e.value) matchedValues.push(e.value);
    }
  }
  return { hit: keys.length > 0, keys, matchedValues };
}
