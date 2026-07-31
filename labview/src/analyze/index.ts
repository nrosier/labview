import type {
  AppStack,
  Service,
  Overview,
  OverviewStats,
  IngressKind,
  ScanMeta,
} from "../model/types.js";
import type { LabViewConfig } from "../config.js";
import { parseDockflare } from "../labels/dockflare.js";
import { parseTraefik } from "../labels/traefik.js";
import {
  deriveAuth,
  hasEnforcedAuthentikGate,
  isAuthMiddlewareRef,
  providerEnforces,
} from "../labels/auth.js";
import { maskEnv } from "../secrets.js";
import { buildGraph } from "./graph.js";
import { buildMiddlewareRegistry, type MiddlewareRegistry } from "./middlewares.js";
import { buildFleetIndex, lookupContainerAddress, resolveOrigins, serviceRefKey } from "./origins.js";
import { matchAuthentik } from "./authentik.js";
import { matchTraefik, noteTraefikLive, type TraefikLiveContext } from "./traefik.js";
import { snapshotDocker, composeKey, type DockerDeps, type DockerSnapshot } from "../enrich/docker.js";
import {
  discoverAuthentikEndpoints,
  isAuthentikService,
  snapshotAuthentik,
  type FetchLike,
} from "../enrich/authentik.js";
import { attributeEndpoint, discoverTraefikEndpoints, snapshotTraefik } from "../enrich/traefik.js";
import { scanStacks } from "../scan/index.js";

const VERSION = "0.1.0";

/** Injectable side-effects, so the pipeline can be driven offline in tests. */
export interface BuildDeps {
  /** HTTP layer for the Authentik and Traefik exchanges. Defaults to the global `fetch`. */
  fetchImpl?: FetchLike;
  /**
   * Engine client factory, passed through to `snapshotDocker`. Defaults to a real
   * `dockerode`.
   *
   * Here so the live-merge path can be driven offline, which is what makes the rule
   * behind change detection assertable: two builds over one unedited fixture root, an
   * Engine reporting different container state each time, and a diff that still says
   * nothing changed.
   */
  createDocker?: DockerDeps["createDocker"];
}

/** Full pipeline: scan -> enrich -> analyze -> Overview. `now` is injected for determinism. */
export async function buildOverview(cfg: LabViewConfig, now: Date, deps: BuildDeps = {}): Promise<Overview> {
  const started = Date.now();
  const { stacks, warnings } = scanStacks(cfg);

  // A configured endpoint depends on nothing in the scan, so those exchanges overlap
  // the docker snapshot instead of waiting behind it. A discovered one cannot start
  // until pass 1 has parsed the routes.
  const configuredUrl = cfg.authentik.url.trim();
  const configuredAk = configuredUrl
    ? snapshotAuthentik(
        cfg,
        [{ url: configuredUrl, source: "config", why: "endpoint from configuration" }],
        deps.fetchImpl,
      )
    : undefined;
  const configuredTraefikUrl = cfg.traefik.url.trim();
  const configuredTf = configuredTraefikUrl
    ? snapshotTraefik(
        cfg,
        [
          {
            url: configuredTraefikUrl,
            source: "config",
            why: "endpoint from configuration",
            // A hand-written endpoint is the operator naming the API themselves, which
            // is the ownership evidence a discovered hostname has to earn.
            mayAuthenticate: true,
          },
        ],
        deps.fetchImpl,
      )
    : undefined;

  const snapshot = await snapshotDocker(cfg, { createDocker: deps.createDocker });
  const registry = buildMiddlewareRegistry(stacks, cfg.labels.traefik.prefix);

  // Pass 1: parse routes, merge live docker state, classify ingress.
  for (const stack of stacks) {
    for (const svc of stack.services) {
      parseRoutes(stack, svc, snapshot, cfg);
    }
  }

  // Where each tunnel origin points. Cross-stack by nature — an origin routinely
  // names a proxy defined in a different stack — so it runs over the whole fleet
  // once, after the routes exist and before the graph is drawn from them.
  //
  // Ahead of the discovered exchanges rather than after them: a resolved origin
  // identifies the service acting as reverse proxy, which is one of the three signals
  // Traefik endpoint discovery rests on, and running it first also lets both discovered
  // exchanges go out together instead of one round trip after the other.
  const fleet = buildFleetIndex(stacks);
  resolveOrigins(stacks, fleet);

  const [ak, tf] = await Promise.all([
    configuredAk ?? snapshotAuthentik(cfg, discoverAuthentikEndpoints(stacks), deps.fetchImpl),
    configuredTf ?? snapshotTraefik(cfg, discoverTraefikEndpoints(stacks), deps.fetchImpl),
  ]);

  // Authentik hostnames can only be discovered once routes are parsed. An endpoint
  // that answered the API is itself proof of identity, so it joins the hints — which
  // is what attributes an OIDC issuer correctly when Authentik runs outside the
  // scanned root and its address had to be configured by hand.
  const authHints = discoverAuthentikHints(stacks, cfg, ak.summary.endpoint);

  // The same index resolves an Authentik proxy provider's internal host, which is
  // the same kind of address as a tunnel origin and matched by the same rules.
  const matched = matchAuthentik(stacks, ak.applications, fleet);
  const matchedRouters = matchTraefik(stacks, tf.routers, fleet);

  // What the live read is allowed to conclude, decided once for the whole fleet
  // because it is a property of the read and not of any one service.
  const live: TraefikLiveContext = {
    reachable: tf.summary.reachable,
    chainComplete: tf.summary.reachable && tf.summary.entrypointsRead,
    endpoint: tf.summary.endpoint,
    credential: tf.summary.credential,
    // A configured endpoint carries no service key of its own, but it usually names a
    // container the scan knows, and the proxy has to be identified for its own notes
    // and for the graph to draw live routes from it.
    proxyKey: tf.proxyServiceKey ?? attributeEndpoint(tf.summary.endpoint, fleet),
    liveRouterNames: new Set(tf.routers.map((r) => r.router.toLowerCase())),
    isAuthMiddleware: (mw) => isAuthMiddlewareRef(mw, registry, authHints),
    resolveDelegate: (address) => {
      const refs = lookupContainerAddress(address, fleet);
      return refs.length === 1 ? serviceRefKey(refs[0]!) : undefined;
    },
  };

  // Pass 2: derive auth posture, finalize exposure, mask secrets.
  for (const stack of stacks) {
    for (const svc of stack.services) {
      finalizeAuth(svc, `${stack.id}/${svc.name}`, cfg, registry, authHints, live);
    }
  }

  const graph = buildGraph(stacks, live.proxyKey);
  const stats = computeStats(stacks);

  const meta: ScanMeta = {
    scannedAt: now.toISOString(),
    appsRoot: cfg.appsRoot,
    dockerAvailable: snapshot.available,
    dockerError: snapshot.error,
    authentik: {
      ...ak.summary,
      matchedServices: matched.matchedServices,
      unmatchedApplications: matched.unmatchedApplications,
    },
    traefik: {
      ...tf.summary,
      matchedServices: matchedRouters.matchedServices,
      unmatchedRouters: matchedRouters.unmatchedRouters,
    },
    // In the order LabView reads them. Carried in `meta` rather than logged from here
    // because this function takes no logger and must stay deterministic (invariant I7):
    // the server and the CLI turn these into lines, exactly as they already do for
    // `dockerError`.
    connections: [snapshot.connection, ak.connection, tf.connection],
    durationMs: Date.now() - started,
    warnings,
    version: VERSION,
  };

  return { meta, stats, stacks, graph };
}

/**
 * Learn which hostnames and container names represent Authentik *in this fleet*,
 * from the fleet itself: a service whose image is the published Authentik image,
 * or whose labels define the Authentik outpost forward-auth endpoint. Whatever
 * hostnames that service is reachable on become identities for it.
 *
 * This is what lets an issuer of `https://sso.example.com/application/o/app/` be
 * attributed correctly without the operator naming their SSO host anywhere in
 * LabView's configuration, and equally what stops an unrelated provider from
 * being attributed to Authentik: with no such service in the fleet, nothing is
 * learned and every OIDC issuer stays generic.
 *
 * An endpoint that answered the Authentik API is the strongest identity of all —
 * it identified itself — so its host joins the same set.
 *
 * Hints are matched against arbitrary values downstream, so a hint that is too
 * generic mislabels unrelated services. The upstream Authentik compose file names
 * its services `server` and `worker`; learning those verbatim would make every
 * `OIDC_ISSUER=https://server.example.com` look like Authentik. Only container
 * names specific enough to be meaningful are learned; hostnames are always safe
 * since they are fully qualified by construction.
 */
function discoverAuthentikHints(stacks: AppStack[], cfg: LabViewConfig, apiEndpoint?: string): string[] {
  const hints = new Set(cfg.labels.authentik.hostHints.map((h) => h.toLowerCase()));
  for (const stack of stacks) {
    for (const svc of stack.services) {
      if (!isAuthentikService(svc)) continue;
      const container = svc.containerName.toLowerCase();
      if (isSpecificHint(container)) hints.add(container);
      for (const r of svc.cloudflare) if (r.hostname) hints.add(r.hostname.toLowerCase());
      for (const r of svc.traefik) for (const h of r.hosts) hints.add(h.toLowerCase());
    }
  }
  // The API host is subject to the same specificity test: a discovered endpoint may
  // be a bare container name, and `server` is no safer as a hint for having answered.
  const apiHost = endpointHost(apiEndpoint);
  if (apiHost && isSpecificHint(apiHost)) hints.add(apiHost);
  return [...hints].filter(Boolean);
}

/** Hostname of the API endpoint, which is stored as an origin (`https://host:port`). */
function endpointHost(endpoint: string | undefined): string | undefined {
  if (!endpoint) return undefined;
  try {
    return new URL(endpoint).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

/**
 * A discovered name is usable as a hint only if it is unlikely to appear inside
 * an unrelated value: it either mentions Authentik outright, or it is a
 * compound/qualified name (`authentik-server`, `sso.example.com`) rather than a
 * bare English word like `server`, `worker` or `proxy`.
 */
function isSpecificHint(name: string): boolean {
  if (name.length < 6) return false;
  if (name.includes("authentik")) return true;
  return /[.\-_]/.test(name);
}

/** Pass 1: parse DockFlare/Traefik labels, merge docker state, classify ingress. */
function parseRoutes(stack: AppStack, svc: Service, snapshot: DockerSnapshot, cfg: LabViewConfig): void {
  svc.cloudflare = parseDockflare(svc.labels, cfg.labels.dockflare.prefix);
  svc.traefik = parseTraefik(svc.labels, cfg.labels.traefik.prefix);

  // Live docker state (try compose project/service, then container name).
  svc.docker =
    snapshot.byKey.get(composeKey(stack.projectName, svc.name)) ??
    snapshot.byKey.get(svc.containerName) ??
    undefined;

  svc.ingress = classifyIngress(svc);
}

/** Pass 2: derive auth posture, finalize exposure, then mask secrets. */
function finalizeAuth(
  svc: Service,
  key: string,
  cfg: LabViewConfig,
  registry: MiddlewareRegistry,
  authHints: string[],
  live: TraefikLiveContext,
): void {
  svc.auth = deriveAuth(svc, cfg, registry, authHints, live.chainComplete);

  const hasCloudflareAccess = svc.cloudflare.some(
    (r) => r.access && (r.access.policy || r.access.group || r.access.emails?.length),
  );
  // A confirmed gate counts even when it has no `AuthMethod` to be reported as —
  // a SAML application is protected, and calling it exposed would be plainly wrong.
  const hasEdgeAuth = svc.auth.method !== "none" || hasCloudflareAccess || hasEnforcedAuthentikGate(svc);
  // Anything other than `internal` is answerable by someone: via the tunnel, via
  // the proxy, or straight at a published host port.
  const reachable = svc.ingress !== "internal";
  svc.auth.exposedWithoutAuth = reachable && !hasEdgeAuth;

  if (svc.auth.exposedWithoutAuth) {
    svc.notes.push(`Reachable (${svc.ingress}) with no detected proxy/SSO authentication.`);
  }
  // An inferred posture rests on a name, not on a definition this scan could read.
  // Say so on the service rather than presenting it as an established fact.
  if (svc.auth.confidence === "inferred") {
    svc.notes.push(
      `Auth posture (${svc.auth.method}) inferred from a middleware name — its definition was not found in any scanned stack, so it could not be confirmed.`,
    );
  }
  noteHostPortBypass(svc);
  noteAuthentikGaps(svc);
  noteTraefikLive(svc, key, live);
  if (svc.cloudflare.some((r) => !r.hostname)) {
    svc.notes.push("DockFlare route present but hostname could not be resolved.");
  }

  // Mask secrets last so analysis could use raw values.
  svc.env = maskEnv(svc.env, cfg);
}

/**
 * Classify reachability from the tunnel routes, the proxy routes, and published
 * host ports. A published port is real reachability: `ports: ["8096:8096"]` makes
 * the service answerable at `hostIP:8096` with no proxy and no SSO in the path.
 *
 * It is only promoted to an ingress kind of its own when nothing else fronts the
 * service. When Traefik does front it, the published port is a *bypass* rather
 * than the primary path, and is reported as a note by `noteHostPortBypass` — most
 * services in a typical fleet publish a port, so folding that into the kind would
 * flatten the whole distribution into a single value.
 */
function classifyIngress(svc: Service): IngressKind {
  const isPublic = svc.cloudflare.some((r) => r.hostname);
  const isLocal = svc.traefik.some((r) => r.hosts.length > 0 || r.rule);
  // Every entry under `ports:` is host-published — that is precisely what
  // distinguishes it from `expose:`. A short form with no host side
  // (`ports: ["9100"]`) still publishes, just on an ephemeral host port, so the
  // presence of the mapping is the signal rather than a parsed host port number.
  const hasHostPort = svc.ports.length > 0;
  if (isPublic && isLocal) return "public+local";
  if (isPublic) return hasHostPort ? "public+host-port" : "public";
  if (isLocal) return "local";
  if (hasHostPort) return "host-port";
  return "internal";
}

/**
 * Warn when a proxied service also publishes a host port. The proxy may enforce
 * SSO, but the published port answers without it, so "protected" would otherwise
 * overstate the posture.
 */
function noteHostPortBypass(svc: Service): void {
  if (svc.ingress !== "local" && svc.ingress !== "public+local") return;
  if (svc.ports.length === 0) return;
  const list = svc.ports.map((p) => p.published ?? `(ephemeral)->${p.target}`).join(", ");
  const guard = svc.auth.method === "none" ? "the proxy" : `the proxy and its ${svc.auth.method} SSO`;
  svc.notes.push(
    `Also published on host port(s) ${list} — directly reachable on the LAN, bypassing ${guard}.`,
  );
}

/**
 * Report what the provider's records and the scanned config disagree about.
 *
 * Two findings, both only obtainable by holding the two sources side by side:
 *
 *  - A **provider with no outpost** is configured but deployed nowhere, so the gate
 *    the operator believes is there will not stop anything.
 *  - A **proxy provider bypassed by the tunnel**. A proxy provider is enforced by an
 *    outpost standing in the request path, so a tunnel origin that resolved straight
 *    to this service reaches it without passing that outpost. The note is deliberately
 *    limited to proxy providers: an OAuth2 or SAML application performs its own login
 *    regardless of the network path, so a direct origin bypasses nothing there.
 */
function noteAuthentikGaps(svc: Service): void {
  const providers = (svc.authentik?.applications ?? []).flatMap((app) => app.providers);
  if (!providers.length) return;

  const unserved = providers.filter((p) => !providerEnforces(p) && p.kind !== "scim" && p.kind !== "other");
  if (unserved.length) {
    svc.notes.push(
      `Authentik ${unserved.map((p) => `${p.kind} provider "${p.name}"`).join(", ")} has no outpost serving it — configured, but not deployed, so it enforces nothing.`,
    );
  }

  const enforcedProxies = providers.filter((p) => p.kind === "proxy" && providerEnforces(p));
  if (!enforcedProxies.length) return;
  const direct = svc.cloudflare.filter(
    (r) => r.origin?.kind === "self-network" || r.origin?.kind === "self-host-port",
  );
  if (!direct.length) return;
  svc.notes.push(
    `Authentik proxy provider "${enforcedProxies[0]!.name}" protects this service, but the tunnel origin for ${direct
      .map((r) => r.hostname)
      .filter(Boolean)
      .join(", ")} resolves to this service directly, so a request arriving over the tunnel never passes the outpost.`,
  );
}

function computeStats(stacks: AppStack[]): OverviewStats {
  const stats: OverviewStats = {
    stacks: stacks.length,
    services: 0,
    running: 0,
    publicServices: 0,
    localOnlyServices: 0,
    hostPortServices: 0,
    internalServices: 0,
    authProtected: 0,
    exposedWithoutAuth: 0,
    byAuthMethod: {},
  };
  for (const stack of stacks) {
    for (const svc of stack.services) {
      stats.services++;
      if (svc.docker?.running) stats.running++;
      if (svc.ingress === "public" || svc.ingress === "public+local" || svc.ingress === "public+host-port")
        stats.publicServices++;
      else if (svc.ingress === "local") stats.localOnlyServices++;
      else if (svc.ingress === "host-port") stats.hostPortServices++;
      else stats.internalServices++;
      if (svc.auth.method !== "none") stats.authProtected++;
      if (svc.auth.exposedWithoutAuth) stats.exposedWithoutAuth++;
      stats.byAuthMethod[svc.auth.method] = (stats.byAuthMethod[svc.auth.method] ?? 0) + 1;
    }
  }
  return stats;
}
