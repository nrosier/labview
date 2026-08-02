/**
 * Read the reverse proxy's own runtime configuration over Traefik's REST API.
 *
 * Compose labels state which routers and middlewares the operator *asked* for. Only
 * the proxy knows what it built from them, and three things follow from that gap
 * which no amount of label parsing can close:
 *
 *  - A router whose rule has a typo, or whose container Traefik never picked up,
 *    exists as a label and serves nothing.
 *  - `middlewares=authentik@docker` on a container proves nothing about the chain
 *    Traefik actually attached to that router.
 *  - A middleware defined in a *file* provider has no definition anywhere in the
 *    scanned stacks, so its type can only be guessed from its name.
 *
 * The same three rules as the Authentik client shape this module:
 *
 *  - **A credential is never sent speculatively.** Every candidate is probed
 *    unauthenticated first — Traefik's `/api/version` needs no auth when the API is
 *    reachable at all — and a credential follows only to an endpoint that either was
 *    configured by hand or was proved to belong to the service whose own labels
 *    declare it serves `api@internal`. A wrong guess costs a 404, never a leak.
 *  - **Read-only, always.** Only GETs are issued. Traefik's API has no write
 *    endpoints, but nothing here relies on that.
 *  - **Never throws, never blocks a scan** (invariant I4). Disabled, nothing to try,
 *    unreachable, unauthorized, a body in an unexpected shape: every path returns a
 *    summary explaining itself and the scan continues on labels alone.
 *
 * Unlike Authentik's API, Traefik's is frequently readable with no credential at
 * all (`api.insecure` on its own entrypoint), so this stage does useful work
 * unconfigured — and reports *that it needed no credential*, which is itself a
 * finding about the proxy's exposure.
 */
import type {
  AppStack,
  ConnectionAttempt,
  ConnectionReport,
  Service,
  TraefikLiveMiddleware,
  TraefikLiveRouter,
  TraefikLiveServer,
  TraefikSummary,
} from "../model/types.js";
import type { LabViewConfig } from "../config.js";
import { attemptText, dominantAttempt, hintFor, plural } from "../model/connections.js";
import { extractHosts } from "../labels/traefik.js";
import { lookupContainerAddress, serviceRefKey, type FleetIndex } from "../analyze/origins.js";
import {
  cookiePairs,
  getJson,
  isObject,
  safeOrigin,
  str,
  type FetchLike,
  type HttpResponse,
} from "./http.js";

/** A Traefik API base URL worth trying, and what makes it worth trying. */
export interface TraefikEndpoint {
  url: string;
  source: "config" | "discovered";
  /** How this candidate was arrived at, for the error message when none works. */
  why: string;
  /**
   * Whether a configured credential may be sent here. True only for a hand-written
   * URL or a hostname the scan proved belongs to the API-serving service — never for
   * a candidate that was merely guessed.
   */
  mayAuthenticate: boolean;
  /** `${stackId}/${serviceName}` of the service this endpoint addresses, when known. */
  serviceKey?: string;
}

export interface TraefikSnapshot {
  summary: TraefikSummary;
  /** Live routers, before any service match is recorded on them. */
  routers: TraefikLiveRouter[];
  /** The proxy service the endpoint that answered belongs to, when it was identified. */
  proxyServiceKey?: string;
  /** What happened on the way to the API, for the operator to read. */
  connection: ConnectionReport;
}

/** Traefik's documented API paths. All three are plain GETs. */
const VERSION_PATH = "/api/version";
const RAWDATA_PATH = "/api/rawdata";
const ENTRYPOINTS_PATH = "/api/entrypoints";

/**
 * The port `api.insecure` serves on. It is Traefik's own default for the dedicated
 * `traefik` entrypoint, so it is a documented value rather than a convention.
 */
const API_PORT = "8080";

/** How deep a `chain` middleware is followed before the nesting is called pathological. */
const MAX_CHAIN_DEPTH = 5;

/**
 * Base URLs to try, internal before public, in the order they are worth trying.
 *
 * Three kinds of evidence identify a proxy, strongest first:
 *
 *  1. **A router pointing at `api@internal`.** That is Traefik's own name for its
 *     API, so a container whose labels reference it is stating outright that it
 *     serves the API — and the router's rule names the exact hostname it does so on.
 *     No vendor detection involved.
 *  2. **A structurally resolved hop.** `resolveOrigins` identifies the service each
 *     tunnel origin actually lands on; such a service is an observed reverse proxy,
 *     whatever it runs.
 *  3. **The image name**, last resort only — the same precedent, and the same
 *     weakness, as `isAuthentikService`.
 *
 * The internal container address always comes first: a public hostname is fronted by
 * the very edge whose access policy would answer the probe with a login page, while
 * the container address is what a sibling container is meant to use.
 */
export function discoverTraefikEndpoints(stacks: AppStack[]): TraefikEndpoint[] {
  const internal: TraefikEndpoint[] = [];
  const external: TraefikEndpoint[] = [];
  const seenService = new Set<string>();

  for (const { stack, svc, why, apiHosts } of proxyCandidates(stacks)) {
    const key = `${stack.id}/${svc.name}`;
    if (seenService.has(key)) continue;
    seenService.add(key);

    for (const name of [svc.containerName, svc.name].filter(Boolean)) {
      for (const port of apiPorts(svc)) {
        internal.push({
          url: `http://${name}:${port}`,
          source: "discovered",
          why: `${why} (container ${name})`,
          // A guessed address gets no credential, only a probe.
          mayAuthenticate: false,
          serviceKey: key,
        });
      }
    }
    // Only hostnames the API router itself serves. Another hostname on the same
    // container fronts some other application, and sending a credential to it would
    // be sending it somewhere the scan never showed the API to be.
    for (const host of apiHosts) {
      external.push({
        url: `https://${host}`,
        source: "discovered",
        why: `${host} is served by this service's own \`api@internal\` router`,
        mayAuthenticate: true,
        serviceKey: key,
      });
    }
  }

  // Bounded like `discoverAuthentikEndpoints`, but with slots reserved: one proxy can
  // declare enough container/port combinations to fill the whole budget on its own,
  // and the gated public hostname is exactly the candidate worth keeping when the
  // internal ones are unreachable.
  return [...dedupeByUrl(internal).slice(0, 4), ...dedupeByUrl(external).slice(0, 2)];
}

/** One proxy candidate: the service, why it is one, and the hostnames its API router serves. */
interface ProxyCandidate {
  stack: AppStack;
  svc: Service;
  why: string;
  apiHosts: string[];
}

function proxyCandidates(stacks: AppStack[]): ProxyCandidate[] {
  const byApi: ProxyCandidate[] = [];
  const byHop: ProxyCandidate[] = [];
  const byImage: ProxyCandidate[] = [];

  // Services another service's tunnel origin resolved to — observed reverse proxies.
  const hops = new Set<string>();
  for (const stack of stacks) {
    for (const svc of stack.services) {
      for (const route of svc.cloudflare) {
        if (route.origin?.kind === "fleet-service" && route.origin.hopKey) hops.add(route.origin.hopKey);
      }
    }
  }

  for (const stack of stacks) {
    for (const svc of stack.services) {
      const key = `${stack.id}/${svc.name}`;
      const apiHosts = apiRouterHosts(svc);
      if (apiHosts.hasApiRouter) {
        byApi.push({
          stack,
          svc,
          why: `service ${key} declares a Traefik router serving \`api@internal\``,
          apiHosts: apiHosts.hosts,
        });
        continue;
      }
      if (hops.has(key)) {
        byHop.push({
          stack,
          svc,
          why: `service ${key} is where another service's tunnel origin resolved, so it acts as a reverse proxy`,
          apiHosts: [],
        });
        continue;
      }
      if (isTraefikImage(svc.image)) {
        byImage.push({ stack, svc, why: `service ${key} runs the Traefik image`, apiHosts: [] });
      }
    }
  }
  return [...byApi, ...byHop, ...byImage];
}

/**
 * Whether an image reference is Traefik's own published image.
 *
 * Only the image *name* is tested, not the whole reference: `traefik/whoami` is
 * published by the same project and is not a proxy. Being the weakest of the three
 * signals, this one is also the one most worth keeping narrow — though a wrong
 * candidate still costs only a failed probe.
 */
function isTraefikImage(image: string | undefined): boolean {
  const name = (image ?? "").split("/").pop() ?? "";
  return /^traefik(:|@|$)/i.test(name);
}

/**
 * Whether a service's own routers point at Traefik's internal API, and on which
 * hostnames.
 *
 * `api@internal` is Traefik's built-in service name, so a router targeting it is the
 * operator declaring "this container serves the API". The hostnames come from those
 * routers' rules specifically, which is what makes them provably the API's own
 * addresses rather than the container's addresses in general — the distinction the
 * credential rule rests on.
 */
function apiRouterHosts(svc: Service): { hasApiRouter: boolean; hosts: string[] } {
  const api = svc.traefik.filter((r) => (r.service ?? "").trim().toLowerCase() === "api@internal");
  return { hasApiRouter: api.length > 0, hosts: [...new Set(api.flatMap((r) => r.hosts))] };
}

/**
 * Ports worth trying on a proxy container, the API's own port first.
 *
 * A service's declared `ports` are included because an operator may have moved the
 * API entrypoint, but they are tried after 8080: a proxy declares 80 and 443 too,
 * and neither answers `/api/version` — a request without a matching Host header gets
 * the catch-all, not the API.
 */
function apiPorts(svc: Service): string[] {
  const declared = svc.ports.map((p) => p.target).filter((t) => /^\d+$/.test(t));
  return [...new Set([API_PORT, ...declared])];
}

function dedupeByUrl(list: TraefikEndpoint[]): TraefikEndpoint[] {
  const seen = new Set<string>();
  return list.filter((e) => (seen.has(e.url) ? false : (seen.add(e.url), true)));
}

/**
 * Identify the scanned service a configured endpoint addresses.
 *
 * A hand-written URL carries no `serviceKey`, but it usually names a container the
 * scan knows about, and knowing which service answered is what lets the graph draw
 * live routers from the proxy and lets the "API answered with no credential" note
 * land on the right service.
 */
export function attributeEndpoint(endpoint: string | undefined, index: FleetIndex): string | undefined {
  if (!endpoint) return undefined;
  const refs = lookupContainerAddress(endpoint, index);
  return refs.length === 1 ? serviceRefKey(refs[0]!) : undefined;
}

/**
 * Query Traefik and return its live routers, with their middleware chains resolved.
 *
 * `candidates` is tried in order; the first one that answers `/api/version` and then
 * yields a parseable `/api/rawdata` wins.
 */
export async function snapshotTraefik(
  cfg: LabViewConfig,
  candidates: TraefikEndpoint[],
  fetchImpl?: FetchLike,
): Promise<TraefikSnapshot> {
  const cred = readCredential(cfg);
  const attempts: ConnectionAttempt[] = [];
  const report = (over: Partial<ConnectionReport>): ConnectionReport => ({
    target: "traefik",
    ok: false,
    phase: "not-configured",
    attempts,
    ...over,
  });
  const empty = (
    over: Partial<TraefikSummary>,
    conn: Partial<ConnectionReport>,
  ): TraefikSnapshot => ({
    summary: {
      enabled: cfg.traefik.enabled,
      configured: false,
      reachable: false,
      credential: "none",
      entrypointsRead: false,
      routers: 0,
      middlewares: 0,
      services: 0,
      matchedServices: 0,
      unmatchedRouters: [],
      ...over,
      error: joinErrors([over.error, cred.error]),
    },
    routers: [],
    connection: report(conn),
  });

  if (!cfg.traefik.enabled) {
    return empty(
      { error: "Traefik API lookup disabled in config" },
      { phase: "disabled", detail: "Traefik API lookup is disabled in configuration" },
    );
  }
  if (!candidates.length) {
    // Unlike Authentik, this stage needs no credential, so a fleet with no Traefik at all
    // is the ordinary case and stays quiet. A *configured* credential changes that: it
    // says the operator expects an API here, and never finding one is worth showing.
    const expected = Boolean(cred.basic || cred.error);
    return empty(
      {
        error:
          "no Traefik endpoint: none configured, and no scanned service was identified as a Traefik proxy",
      },
      expected
        ? {
            phase: "not-found",
            detail:
              "a credential is configured but there was nowhere to send it: no URL configured, and no scanned service was identified as a Traefik proxy",
            hint: hintFor("traefik", "not-found"),
          }
        : {
            phase: "not-configured",
            detail:
              "no URL is configured and no scanned service was identified as a Traefik proxy",
          },
    );
  }

  const doFetch: FetchLike = fetchImpl ?? ((url, init) => fetch(url, init) as Promise<HttpResponse>);
  const timeoutMs = cfg.traefik.timeoutMs;

  for (const candidate of candidates) {
    const base = candidate.url.replace(/\/+$/, "");
    const origin = safeOrigin(base);
    // Authentik's outpost sets a cookie it expects echoed on the follow-up requests,
    // so cookies picked up during this exchange are replayed within it — and only
    // within it, since the next candidate is a different host.
    const jar = new Map<string, string>();

    const get = (path: string, authenticate: boolean) =>
      getJson(doFetch, `${base}${path}`, {
        headers: headers(jar, authenticate ? cred.basic : undefined),
        timeoutMs,
        hint: credentialHint,
      }).then((res) => {
        for (const pair of cookiePairs(res.setCookie)) {
          const eq = pair.indexOf("=");
          jar.set(pair.slice(0, eq), pair.slice(eq + 1));
        }
        return res;
      });

    // Probe with no credential whatsoever. Traefik's `/api/version` is unauthenticated
    // when the API is reachable, so this both confirms the host and answers whether
    // the API is open — without which the credential question cannot be asked safely.
    let probe = await get(VERSION_PATH, false);
    let credential: "none" | "basic" = "none";

    // Anything other than a Traefik version body — 401, 403, or a login page whose
    // HTML is not JSON — is a candidate that may simply be gated. Retrying with the
    // credential is allowed only where ownership was established.
    if (!isVersionBody(probe.body) && cred.basic && candidate.mayAuthenticate) {
      probe = await get(VERSION_PATH, true);
      credential = "basic";
    }
    if (!isVersionBody(probe.body)) {
      // A candidate that answered JSON of the wrong shape is at `protocol`: it is
      // listening and speaking HTTP, it is simply not Traefik's API.
      attempts.push({
        endpoint: origin,
        why: candidate.why,
        phase: probe.ok ? "protocol" : probe.phase,
        code: probe.code,
        detail: probe.error ?? "not a Traefik API",
      });
      continue;
    }

    const authenticate = credential === "basic";
    const version = versionOf(probe.body);
    const found = {
      configured: true,
      endpoint: origin,
      endpointSource: candidate.source,
      credential,
      version,
    };

    const raw = await get(RAWDATA_PATH, authenticate);
    if (!raw.ok || !isObject(raw.body)) {
      const phase = raw.ok ? "protocol" : raw.phase;
      return empty(
        {
          ...found,
          error: `Traefik at ${origin} answered ${VERSION_PATH} but ${RAWDATA_PATH} could not be read: ${raw.error ?? "unexpected response body"}`,
        },
        {
          phase,
          endpoint: origin,
          source: candidate.source,
          code: raw.code,
          detail: `${VERSION_PATH} answered and ${RAWDATA_PATH} did not: ${raw.error ?? "unexpected response body"}`,
          hint: hintFor("traefik", phase),
        },
      );
    }

    // Entrypoints are read before anything is concluded about a *missing* gate: a
    // middleware attached to an entrypoint applies to every router on it and appears
    // in no router's own list.
    const eps = await get(ENTRYPOINTS_PATH, authenticate);
    const entrypointMiddlewares = eps.ok ? parseEntrypoints(eps.body) : undefined;

    const parsed = parseRawData(raw.body, entrypointMiddlewares ?? new Map());
    // A half-configured credential is still worth reporting on a read that succeeded
    // without one: the operator configured something that did not work.
    const gap = joinErrors([
      entrypointMiddlewares
        ? undefined
        : `${ENTRYPOINTS_PATH} could not be read (${eps.error ?? "unexpected response body"}), so entrypoint-level middlewares are unknown`,
      cred.error,
    ]);
    return {
      summary: {
        enabled: true,
        reachable: true,
        ...found,
        entrypointsRead: entrypointMiddlewares !== undefined,
        error: gap,
        routers: parsed.routers.length,
        middlewares: parsed.middlewareCount,
        services: parsed.serviceCount,
        matchedServices: 0,
        unmatchedRouters: [],
      },
      routers: parsed.routers,
      proxyServiceKey: candidate.serviceKey,
      connection: report({
        ok: true,
        phase: gap ? "partial" : "connected",
        endpoint: origin,
        source: candidate.source,
        read: [
          version ? `Traefik ${version}` : "Traefik",
          plural(parsed.routers.length, "router"),
          plural(parsed.middlewareCount, "middleware"),
          plural(parsed.serviceCount, "service"),
          credential === "basic" ? "with a credential" : "no credential",
        ].join(", "),
        detail: gap,
        hint: gap ? hintFor("traefik", "partial") : undefined,
      }),
    };
  }

  // Every candidate failed. The phase is the furthest any of them got: a host that
  // answered 401 is the API, and reporting an earlier candidate's DNS failure instead
  // would send the operator to their resolver over a working address.
  const worst = dominantAttempt(attempts);
  return empty(
    {
      configured: true,
      error: `no Traefik API endpoint answered — tried ${attempts.map(attemptText).join("; ")}`,
    },
    worst
      ? {
          phase: worst.phase,
          endpoint: worst.endpoint,
          code: worst.code,
          detail: `${plural(candidates.length, "candidate")} tried, none answered as Traefik's API — the furthest got to ${worst.phase}: ${worst.detail}`,
          hint: hintFor("traefik", worst.phase),
        }
      : { phase: "not-found", detail: "no candidate could be tried" },
  );
}

/** Request headers: JSON, the cookies gathered in this exchange, and Basic when allowed. */
function headers(jar: Map<string, string>, basic: string | undefined): Record<string, string> {
  const out: Record<string, string> = { Accept: "application/json" };
  if (jar.size) out.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  if (basic) out.Authorization = basic;
  return out;
}

/** What a rejected request most likely means. Carries no credential in its text. */
function credentialHint(status: number): string | undefined {
  if (status === 401 || status === 403) {
    return " (rejected — the API is gated; behind an Authentik proxy provider Basic needs a user plus an *app password* or token, and the provider must have header authentication enabled)";
  }
  if (status === 404) return " (no API at this address — is `api: {}` enabled?)";
  return undefined;
}

/**
 * Resolve the Basic credential from the two variables that carry it.
 *
 * Two ways to be half-configured, both reported rather than absorbed, because either one
 * produces a request that cannot succeed. A password variable that is *present and empty*
 * is an unresolved `${…}` nine times in ten (§3.10). A password with no username is the
 * other half: inventing one would mean picking a vendor's reserved account name on the
 * operator's behalf. Neither answer carries the value (**I6**).
 */
function readCredential(cfg: LabViewConfig): { basic?: string; error?: string } {
  const username = cfg.traefik.username.trim();
  if (cfg.blankCredentialVars.includes("LABVIEW_TRAEFIK_PASSWORD")) {
    return { error: "LABVIEW_TRAEFIK_PASSWORD is set but carries nothing" };
  }
  const password = cfg.traefik.password.trim();
  if (!password) return {};
  if (!username) {
    return { error: "a Traefik API password is configured but no username, so no credential was sent" };
  }
  return { basic: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}` };
}

function joinErrors(parts: (string | undefined)[]): string | undefined {
  const list = parts.filter((p): p is string => Boolean(p));
  return list.length ? list.join("; ") : undefined;
}

/**
 * Whether a body is Traefik's version document.
 *
 * Requiring the version field is what makes the probe *distinctive*: any host can
 * return `{}` from an unknown path, and treating that as a confirmed Traefik would
 * send a credential to whatever answered.
 */
function isVersionBody(body: unknown): boolean {
  return isObject(body) && Object.keys(body).some((k) => /^version$/i.test(k));
}

function versionOf(body: unknown): string | undefined {
  if (!isObject(body)) return undefined;
  for (const [k, v] of Object.entries(body)) if (/^version$/i.test(k)) return str(v);
  return undefined;
}

/**
 * Entrypoint name -> the middleware names attached to it.
 *
 * `/api/entrypoints` returns an array of `{name, address, http: {middlewares}}`; a
 * map keyed by name is accepted too, so a change in either direction degrades to an
 * empty result rather than a crash.
 */
function parseEntrypoints(body: unknown): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const { key, obj } of normalize(body)) {
    const name = str(obj.name) ?? key;
    if (!name) continue;
    const http = isObject(obj.http) ? obj.http : undefined;
    const mws = http && Array.isArray(http.middlewares) ? http.middlewares : [];
    const names = mws.map((m) => str(m)).filter((m): m is string => Boolean(m));
    if (names.length) out.set(name, names);
  }
  return out;
}

interface ParsedRawData {
  routers: TraefikLiveRouter[];
  middlewareCount: number;
  serviceCount: number;
}

/**
 * Turn `/api/rawdata` into routers with resolved chains and known backends.
 *
 * The field names come from Traefik's runtime model rather than a published schema,
 * so every one of them is optional here: a rename upstream costs the corresponding
 * detail and nothing else (invariant I4).
 */
function parseRawData(
  body: Record<string, unknown>,
  entrypointMiddlewares: Map<string, string[]>,
): ParsedRawData {
  // HTTP only. `tcpRouters`/`udpRouters` carry no middleware chain of the kind this
  // module reasons about, and nothing in the scanned labels maps onto them.
  const middlewares = new Map<string, RawMiddleware>();
  for (const { key, obj } of normalize(body.middlewares)) {
    const name = str(obj.name) ?? key;
    if (!name) continue;
    middlewares.set(qualified(name, providerOf(name, obj)), readMiddleware(name, obj));
  }

  const services = new Map<string, TraefikLiveServer[]>();
  for (const { key, obj } of normalize(body.services)) {
    const name = str(obj.name) ?? key;
    if (!name) continue;
    services.set(qualified(name, providerOf(name, obj)), readServers(obj));
  }

  const routers: TraefikLiveRouter[] = [];
  for (const { key, obj } of normalize(body.routers)) {
    const full = str(obj.name) ?? key;
    if (!full) continue;
    const provider = providerOf(full, obj);
    const rule = str(obj.rule);
    const entryPoints = stringList(obj.entryPoints ?? obj.entrypoints);
    const service = str(obj.service);
    const referenced = stringList(obj.middlewares);

    // Entrypoint middlewares first: they run before the router's own, and a gate
    // attached there protects the router just as effectively.
    const chain: TraefikLiveMiddleware[] = [];
    for (const ep of entryPoints) {
      for (const name of entrypointMiddlewares.get(ep) ?? []) {
        chain.push(...resolve(name, provider, middlewares, { viaEntrypoint: true }));
      }
    }
    for (const name of referenced) {
      chain.push(...resolve(name, provider, middlewares, {}));
    }

    routers.push({
      router: bareName(full),
      provider,
      status: str(obj.status),
      errors: stringList(obj.error),
      rule,
      hosts: rule ? extractHosts(rule) : [],
      entryPoints,
      middlewares: dedupeChain(chain),
      service,
      servers: service ? (services.get(qualified(service, provider)) ?? []) : [],
      tls: obj.tls !== undefined && obj.tls !== null && obj.tls !== false,
      evidence: [],
    });
  }
  routers.sort((a, b) => `${a.router}@${a.provider}`.localeCompare(`${b.router}@${b.provider}`));
  return { routers, middlewareCount: middlewares.size, serviceCount: services.size };
}

interface RawMiddleware {
  name: string;
  type: string;
  address?: string;
  errors: string[];
  /** Names this middleware delegates to, for a `chain`. */
  chain: string[];
}

/**
 * Read one middleware definition.
 *
 * Traefik keys the configuration by the middleware's *type* — `{forwardAuth: {...}}`,
 * `{basicAuth: {...}}` — so the type is whichever key is not bookkeeping. Reading it
 * this way means a middleware type this version has never heard of is still reported
 * with its real type rather than as unknown.
 */
function readMiddleware(name: string, obj: Record<string, unknown>): RawMiddleware {
  const meta = new Set(["name", "provider", "status", "usedby", "error", "type"]);
  let type = "";
  let config: Record<string, unknown> | undefined;
  for (const [k, v] of Object.entries(obj)) {
    if (meta.has(k.toLowerCase())) continue;
    type = k.toLowerCase();
    config = isObject(v) ? v : undefined;
    break;
  }
  return {
    name,
    type: type || "unknown",
    address: config ? str(config.address) : undefined,
    errors: stringList(obj.error),
    chain: config ? stringList(config.middlewares) : [],
  };
}

/**
 * Expand one middleware reference into chain entries.
 *
 * A `chain` middleware is a real gate when it wraps a `forwardAuth`, so it is
 * followed rather than reported as an opaque name — bounded by depth and by a
 * visited set, since a configuration can reference itself.
 */
function resolve(
  reference: string,
  routerProvider: string,
  defs: Map<string, RawMiddleware>,
  opts: { viaEntrypoint?: boolean; viaChain?: string; depth?: number; seen?: Set<string> },
): TraefikLiveMiddleware[] {
  const depth = opts.depth ?? 0;
  const seen = opts.seen ?? new Set<string>();
  const key = qualified(reference, routerProvider);
  const def = findDefinition(reference, key, defs);

  const base = {
    name: def?.name ?? key,
    viaChain: opts.viaChain,
    viaEntrypoint: opts.viaEntrypoint,
  };
  if (!def) {
    // Referenced but undefined: report it as existing with nothing behind it rather
    // than inventing a type from its name, which is the very inference this closes.
    return [
      {
        ...base,
        type: "unknown",
        errors: ["no definition for this middleware in the proxy's runtime configuration"],
      },
    ];
  }
  if (seen.has(key) || depth >= MAX_CHAIN_DEPTH) {
    return [
      {
        ...base,
        type: def.type,
        address: def.address,
        errors: [...def.errors, `middleware chain not followed further (depth ${depth})`],
      },
    ];
  }
  seen.add(key);

  const self: TraefikLiveMiddleware = {
    ...base,
    type: def.type,
    address: def.address,
    errors: def.errors,
  };
  if (def.type !== "chain" || !def.chain.length) return [self];
  const nested = def.chain.flatMap((child) =>
    resolve(child, providerSuffix(def.name) || routerProvider, defs, {
      viaEntrypoint: opts.viaEntrypoint,
      viaChain: def.name,
      depth: depth + 1,
      seen,
    }),
  );
  return [self, ...nested];
}

/**
 * Find a middleware definition for a reference.
 *
 * A router's reference is normally fully qualified (`authentik@docker`), but an
 * unqualified one means "the same provider as the router" — and a chain member
 * declared in a file provider may be referenced from a docker router either way. So:
 * the qualified form, then the reference verbatim, then a unique match on the bare
 * name. An ambiguous bare name resolves to nothing rather than to a coin toss.
 */
function findDefinition(
  reference: string,
  key: string,
  defs: Map<string, RawMiddleware>,
): RawMiddleware | undefined {
  const direct = defs.get(key) ?? defs.get(reference);
  if (direct) return direct;
  if (reference.includes("@")) return undefined;
  const matches = [...defs].filter(([k]) => bareName(k) === reference);
  return matches.length === 1 ? matches[0]![1] : undefined;
}

/** Backends of a service, with the health Traefik last observed for each. */
function readServers(obj: Record<string, unknown>): TraefikLiveServer[] {
  // Only a load balancer names concrete backends. `weighted`, `mirroring` and
  // `failover` compose other services, so they yield no backend evidence at all
  // rather than a partial guess.
  const lb = isObject(obj.loadBalancer) ? obj.loadBalancer : isObject(obj.loadbalancer) ? obj.loadbalancer : undefined;
  const status = isObject(obj.serverStatus) ? obj.serverStatus : undefined;
  const out: TraefikLiveServer[] = [];
  for (const s of lb && Array.isArray(lb.servers) ? lb.servers : []) {
    if (!isObject(s)) continue;
    const url = str(s.url) ?? str(s.address);
    if (!url) continue;
    out.push({ url, status: status ? str(status[url]) : undefined });
  }
  return out;
}

/** One entry per record, whether the payload was a map keyed by name or an array. */
function normalize(value: unknown): { key: string; obj: Record<string, unknown> }[] {
  if (Array.isArray(value)) {
    return value.filter(isObject).map((obj) => ({ key: str(obj.name) ?? "", obj }));
  }
  if (isObject(value)) {
    return Object.entries(value)
      .filter((e): e is [string, Record<string, unknown>] => isObject(e[1]))
      .map(([key, obj]) => ({ key, obj }));
  }
  return [];
}

/** `name@provider`, adding the provider only when the name does not already carry one. */
function qualified(name: string, provider: string): string {
  return name.includes("@") || !provider ? name : `${name}@${provider}`;
}

function bareName(full: string): string {
  const at = full.lastIndexOf("@");
  return at > 0 ? full.slice(0, at) : full;
}

function providerSuffix(full: string): string {
  const at = full.lastIndexOf("@");
  return at > 0 ? full.slice(at + 1) : "";
}

/** Provider from the qualified name, falling back to an explicit field. */
function providerOf(name: string, obj: Record<string, unknown>): string {
  return providerSuffix(name) || str(obj.provider) || "";
}

/** Duplicate chain entries add no information: the same gate reached twice is one gate. */
function dedupeChain(chain: TraefikLiveMiddleware[]): TraefikLiveMiddleware[] {
  const seen = new Set<string>();
  return chain.filter((m) => (seen.has(m.name) ? false : (seen.add(m.name), true)));
}

function stringList(value: unknown): string[] {
  if (typeof value === "string") return value.trim() ? [value.trim()] : [];
  if (!Array.isArray(value)) return [];
  return value.map((v) => str(v)?.trim()).filter((v): v is string => Boolean(v));
}
