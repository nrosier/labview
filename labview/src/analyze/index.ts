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
import { compareDeclaredAuth, declaredAuthSummary, detectedAuthSubject } from "../model/declarations.js";
import {
  diffIngress,
  externalIngress,
  formatIngress,
  isExternallyReachable,
  normalizeIngress,
} from "../model/ingress.js";
import { maskEnv } from "../secrets.js";
import { buildGraph } from "./graph.js";
import { realNetworks } from "./networks.js";
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

  // Pass 1: parse routes and merge live docker state.
  for (const stack of stacks) {
    for (const svc of stack.services) {
      parseRoutes(stack, svc, snapshot, cfg);
    }
  }

  // Ingress is classified after that loop rather than inside it, because `internal`
  // is a statement about *other* containers: it needs every service's networks, and
  // `realNetworks` prefers the live names that pass 1 has only just attached. A
  // service classified mid-loop would be judged against a half-built fleet.
  const shared = sharedNetworks(stacks);
  for (const stack of stacks) {
    for (const svc of stack.services) {
      svc.ingress = classifyIngress(svc, stack, shared);
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

/** Pass 1: parse DockFlare/Traefik labels and merge docker state. */
function parseRoutes(stack: AppStack, svc: Service, snapshot: DockerSnapshot, cfg: LabViewConfig): void {
  svc.cloudflare = parseDockflare(svc.labels, cfg.labels.dockflare.prefix);
  svc.traefik = parseTraefik(svc.labels, cfg.labels.traefik.prefix);

  // Live docker state (try compose project/service, then container name).
  svc.docker =
    snapshot.byKey.get(composeKey(stack.projectName, svc.name)) ??
    snapshot.byKey.get(svc.containerName) ??
    undefined;
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
  // Answerable by someone outside the container network: via the tunnel, via the
  // proxy, or straight at a published port on the LAN. `internal` and `none` are
  // not — a container reaching another container is not exposure.
  const reachable = isExternallyReachable(svc.ingress);
  // The verdict, and the one place a `.labview` file changes an answer. `hasEdgeAuth`
  // above stays evidence-only; the declaration is a separate term, so the two sources
  // never merge and the count can always be reconstructed with the term dropped.
  //
  // Deliberately not `!svc.declared?.unauthenticatedAccepted` as well: an acceptance
  // says the exposure is fine, which leaves it an exposure. A declared mechanism says
  // there is no exposure. Only the second is grounds for not counting it.
  const wouldBeExposed = reachable && !hasEdgeAuth;
  const declaredAuth = svc.declared?.auth ?? [];
  svc.auth.exposedWithoutAuth = wouldBeExposed && declaredAuth.length === 0;

  if (svc.auth.exposedWithoutAuth) {
    // An accepted exposure is still an exposure — the flag above is not cleared. What
    // changes is only the sentence a reader gets: the same finding, with the operator's
    // reason attached, instead of a second note about the same fact.
    const declared = svc.declared;
    const accepted = declared?.unauthenticatedAccepted;
    // Only the kinds that make it reachable are named: `internal` alongside them
    // would read as a reason it is exposed, which it is not.
    const base = `Reachable (${formatIngress(externalIngress(svc.ingress))}) with no detected proxy/SSO authentication`;
    svc.notes.push(
      declared && accepted ? `${base} — accepted in ${declared.file}: ${accepted.reason}` : `${base}.`,
    );
  }
  // An inferred posture rests on a name, not on a definition this scan could read.
  // Say so on the service rather than presenting it as an established fact.
  if (svc.auth.confidence === "inferred") {
    svc.notes.push(
      `Auth posture (${svc.auth.method}) inferred from a middleware name — its definition was not found in any scanned stack, so it could not be confirmed.`,
    );
  }
  noteDeclarations(svc, wouldBeExposed);
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
 * Every way in, as a set of independent kinds. Each is decided on its own evidence
 * and none excludes another: a container behind the tunnel, behind the proxy, and
 * publishing a host port is all three things at once, and a reader who is told only
 * the first of them has been told the least useful one.
 *
 *  - `public` — a tunnel route with a resolved hostname.
 *  - `traefik` — a proxy route with hosts or a rule.
 *  - `lan` — `ports:` is non-empty. Every entry there is host-published, which is
 *    precisely what distinguishes it from `expose:`; a short form with no host side
 *    (`ports: ["9100"]`) still publishes, just on an ephemeral port, so the presence
 *    of the mapping is the signal rather than a parsed host port number. Reported
 *    whether or not something else fronts the service — when the proxy does,
 *    `noteHostPortBypass` additionally says the port answers without it.
 *  - `internal` — another container can demonstrably reach it: a declared `expose:`
 *    port, or a real network shared with another scanned service. Positive evidence,
 *    never a fallback.
 *  - `none` — supplied by `normalizeIngress` when nothing above holds.
 *
 * `internal` deliberately does not consider `depends_on`: a dependency across two
 * disjoint networks is not reachability.
 */
function classifyIngress(svc: Service, stack: AppStack, shared: ReadonlySet<string>): IngressKind[] {
  const kinds: IngressKind[] = [];
  if (svc.cloudflare.some((r) => r.hostname)) kinds.push("public");
  if (svc.traefik.some((r) => r.hosts.length > 0 || r.rule)) kinds.push("traefik");
  if (svc.ports.length > 0) kinds.push("lan");
  if (svc.expose.length > 0 || realNetworks(stack, svc).some((n) => shared.has(n))) kinds.push("internal");
  return normalizeIngress(kinds);
}

/**
 * Real network names carrying more than one scanned service — the fleet-wide half of
 * the `internal` rule.
 *
 * Counted over `realNetworks`, not over `svc.networks`, so it sees what docker sees:
 * the implicit `default` network compose gives a file that declares none (which is
 * what makes two services in one stack mutually reachable without either saying so),
 * an `external:` network under its verbatim name (which is what lets two *stacks*
 * share one), and live names in preference to implied ones.
 */
function sharedNetworks(stacks: AppStack[]): Set<string> {
  const count = new Map<string, number>();
  for (const stack of stacks) {
    for (const svc of stack.services) {
      // Deduped per service: one service listing a network twice is not two services.
      for (const name of new Set(realNetworks(stack, svc))) {
        count.set(name, (count.get(name) ?? 0) + 1);
      }
    }
  }
  return new Set([...count].filter(([, n]) => n >= 2).map(([name]) => name));
}

/**
 * Compare what the operator declared in a `.labview` sidecar against what the scan
 * found: report the part the scan could not see, stay silent about the part it already
 * says, and record a disagreement where the two contradict each other.
 *
 * The only place in the analyzer that reads a declaration. It touches
 * `AuthPosture` not at all — `method`, `detail`, `evidence` and `confidence` are
 * measurements and a declaration is not evidence (invariant I1). `exposedWithoutAuth`
 * is settled by the caller, which is where the one term a declaration contributes to
 * that verdict lives; here it is only read.
 *
 * Three drift checks, all of them for the same reason: a declaration is the one input
 * that can go stale in silence. The compose file changes, the sidecar does not, and
 * a statement written for last year's setup would otherwise keep describing — or
 * excusing — a service that has since moved.
 *
 * @param wouldBeExposed the exposure verdict with the declaration left out.
 */
function noteDeclarations(svc: Service, wouldBeExposed: boolean): void {
  const declared = svc.declared;
  if (!declared) return;

  const agreement = compareDeclaredAuth(declared.auth, svc.auth.method, wouldBeExposed);
  declared.authAgreement = agreement;
  const summary = declaredAuthSummary(declared.auth);
  if (agreement === "supplies") {
    // Not silent. This service is the one case where the report says "no finding here"
    // on the strength of something it cannot check, so it says exactly that, in place
    // of the exposure note it would otherwise have carried.
    svc.notes.push(
      `Reachable (${formatIngress(externalIngress(svc.ingress))}) with no detected proxy/SSO authentication — ` +
        `${declared.file} declares the service authenticates itself (${summary}). Not counted as exposed on the ` +
        `strength of that declaration, which this scan cannot verify.`,
    );
  } else if (agreement === "conflicts") {
    // Both sides named the same tier and named it differently. Which of the two is
    // stale is not knowable from here, so the note states both and neither wins.
    declared.drift.push(
      `${declared.file} declares ${summary}, but the scan detected ${svc.auth.method} (${svc.auth.detail}) — ` +
        `both describe ${detectedAuthSubject(svc.auth.method)}, so one of the two is out of date.`,
    );
    svc.notes.push(`Authentication declared in ${declared.file}: ${summary}.`);
  } else if (agreement === "supplements") {
    // Something the scan cannot observe, alongside or behind whatever it did. The
    // ordinary case, and the only wording that may say "not detected" — under the other
    // outcomes it either was detected, or it is the reason there is no finding.
    svc.notes.push(`Authentication declared in ${declared.file} (not detected by this scan): ${summary}.`);
  }
  // `redundant` deliberately pushes nothing: the scan already reports this mechanism,
  // and repeating it as a declaration would invite a reader to check two sources that
  // say the same thing.

  // An acceptance that no longer applies. The service is now protected, or no longer
  // reachable, or — contradicting itself — declares authentication in the same file. In
  // every case the sidecar describes something the scan no longer finds, and quietly
  // ignoring it would leave the file looking correct.
  if (declared.unauthenticatedAccepted && !svc.auth.exposedWithoutAuth) {
    const why = !isExternallyReachable(svc.ingress)
      ? "unreachable from outside the container network"
      : agreement === "supplies"
        ? "authenticated by the mechanism declared in the same file"
        : "authenticated at the edge";
    declared.drift.push(
      `${declared.file} marks this service as intentionally unauthenticated, but the scan found it ${why} — the declaration no longer applies.`,
    );
  }

  // The expectation is a tripwire, never an override: the classification stands and the
  // disagreement is reported. Compared as sets and reported in both directions, because
  // expecting `public, traefik` and finding `public, lan` is a disagreement about the
  // proxy — and diffing two lists by eye is exactly what the operator should not have
  // to do to see that.
  const expected = declared.expectedIngress;
  if (expected) {
    const { missing, unexpected } = diffIngress(expected, svc.ingress);
    if (missing.length || unexpected.length) {
      const detail = [
        missing.length ? `missing: ${formatIngress(missing)}` : "",
        unexpected.length ? `unexpected: ${formatIngress(unexpected)}` : "",
      ]
        .filter(Boolean)
        .join("; ");
      declared.drift.push(
        `${declared.file} expects ingress "${formatIngress(expected)}"; the scan classified this service as "${formatIngress(svc.ingress)}" (${detail}).`,
      );
    }
  }
}

/**
 * Warn when a proxied service also publishes a host port. The proxy may enforce
 * SSO, but the published port answers without it, so "protected" would otherwise
 * overstate the posture.
 */
function noteHostPortBypass(svc: Service): void {
  if (!svc.ingress.includes("traefik")) return;
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
    traefikServices: 0,
    lanServices: 0,
    internalServices: 0,
    noIngressServices: 0,
    authProtected: 0,
    exposedWithoutAuth: 0,
    byAuthMethod: {},
    declaredAuth: 0,
    declaredAuthProtected: 0,
    exposureAccepted: 0,
    declarationDrift: 0,
  };
  for (const stack of stacks) {
    for (const svc of stack.services) {
      stats.services++;
      if (svc.docker?.running) stats.running++;
      // Five independent counters, not a chain: a service tunnelled *and* proxied is
      // counted in both, which is why these overlap and do not sum to `services`.
      if (svc.ingress.includes("public")) stats.publicServices++;
      if (svc.ingress.includes("traefik")) stats.traefikServices++;
      if (svc.ingress.includes("lan")) stats.lanServices++;
      if (svc.ingress.includes("internal")) stats.internalServices++;
      if (svc.ingress.includes("none")) stats.noIngressServices++;
      if (svc.auth.method !== "none") stats.authProtected++;
      if (svc.auth.exposedWithoutAuth) stats.exposedWithoutAuth++;
      stats.byAuthMethod[svc.auth.method] = (stats.byAuthMethod[svc.auth.method] ?? 0) + 1;
      // Declarations are counted separately from all of the above, and none of the
      // detection counters above consults `svc.declared` — a fleet with no sidecar
      // anywhere reads exactly as it did before the feature existed.
      const declared = svc.declared;
      if (declared?.auth.length) stats.declaredAuth++;
      // Read off the agreement the analyzer recorded rather than re-deriving the
      // condition, so this counter and the badge beside it cannot disagree about which
      // services left the exposed count.
      if (declared?.authAgreement === "supplies") stats.declaredAuthProtected++;
      if (svc.auth.exposedWithoutAuth && declared?.unauthenticatedAccepted) stats.exposureAccepted++;
      if (declared?.drift.length) stats.declarationDrift++;
    }
  }
  return stats;
}
