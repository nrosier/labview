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
import { probeGateText } from "../model/probe.js";
import { maskEnv } from "../secrets.js";
import { resolveDeclaredDependencies, type ResolvedDependency } from "./dependencies.js";
import { buildGraph } from "./graph.js";
import {
  buildNetworkIndex,
  realNetworks,
  serviceKey,
  sharedWith,
  type NetworkIndex,
} from "./networks.js";
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
import { probeServices } from "../enrich/probe.js";
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
  //
  // The membership index is built here, at the first moment it can be trusted, and
  // then threaded to everything downstream that asks about networks — the ingress
  // rule, the fleet index and the graph — so all three answer from one pass.
  const nets = buildNetworkIndex(stacks);
  const shared = sharedNetworks(nets);
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
  const fleet = buildFleetIndex(stacks, nets);
  resolveOrigins(stacks, fleet);

  // Cross-stack dependencies the operator declared. Resolved here because that needs the
  // whole fleet — the target is in another stack by definition — and reported here rather
  // than from the graph, which is drawn from the services and must not edit them.
  const declaredDeps = resolveDeclaredDependencies(stacks, fleet, nets);

  // A dependency the two containers have no network in common to carry, from either
  // source. After resolution, so the declared half can be told apart from the compose
  // half: only one of the two orders startup, and claiming otherwise would be a false
  // reassurance about the very case being reported.
  flagUnreachableDependencies(stacks, nets, declaredDeps);

  // The probe joins these two rather than running after them, because it needs the same
  // thing they do and nothing more: pass 1's parsed routes. It asks the *services* instead
  // of an API, so it is the one exchange here that is off unless the operator turned it on —
  // and when it is off, `probeServices` returns its `disabled` report without a request.
  const [ak, tf, pr] = await Promise.all([
    configuredAk ?? snapshotAuthentik(cfg, discoverAuthentikEndpoints(stacks), deps.fetchImpl),
    configuredTf ?? snapshotTraefik(cfg, discoverTraefikEndpoints(stacks), deps.fetchImpl),
    probeServices(cfg, stacks, deps.fetchImpl),
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
      const key = `${stack.id}/${svc.name}`;
      // Attached before the posture is settled, because `finalizeAuth` reads it as
      // evidence. Absent on most services: only the ones whose own labels showed an HTTP
      // address were asked, and only when probing was enabled at all.
      svc.probe = pr.byKey.get(key);
      finalizeAuth(svc, key, cfg, registry, authHints, live);
    }
  }

  const graph = buildGraph(stacks, live.proxyKey, nets, declaredDeps);
  const stats = computeStats(stacks, nets, declaredDeps);

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
    connections: [snapshot.connection, ak.connection, tf.connection, pr.connection],
    // What *this* build did about probing, reported unconditionally for the same reason
    // `connections` is: silence would have to be interpreted. `source` is `config` here
    // and can only be `config` here — this function reads a `LabViewConfig` and cannot
    // tell one that was rewritten for a single request from one that came off disk. The
    // server's build closure is the only place that knows, so it is the only place that
    // says otherwise.
    probe: { enabled: cfg.probe.enabled, source: "config" },
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
  // A login page LabView was answered with, which is protection it *measured* — the same
  // kind of thing as the other three terms and unlike a declaration, which is a claim.
  // It names no mechanism, and does not become one: `svc.auth` is untouched by it, the
  // service is counted in `probeGated`, and `noAuthReason` reports it as `probed-gate`,
  // exactly as an Authentik gate with no readable method is reported as `unnamed-gate`.
  const probeGate = svc.probe?.gate !== undefined;
  // A confirmed gate counts even when it has no `AuthMethod` to be reported as —
  // a SAML application is protected, and calling it exposed would be plainly wrong.
  //
  // Kept as two terms so the notes can tell "the probe is the only protection LabView
  // found" from "the probe agrees with a gate that was already detected". Those are
  // different things to a reader, and only the first is load-bearing for the count.
  const configuredEdgeAuth =
    svc.auth.method !== "none" || hasCloudflareAccess || hasEnforcedAuthentikGate(svc);
  const hasEdgeAuth = configuredEdgeAuth || probeGate;
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
    const finding =
      declared && accepted ? `${base} — accepted in ${declared.file}: ${accepted.reason}.` : `${base}.`;
    // The same finding, measured instead of inferred. Appended to the exposure note rather
    // than added beside it, because it is not a second finding: LabView asked the service
    // at its own address and was served the application, which is this note corroborated.
    svc.notes.push(finding + probeOpenClause(svc));
  }
  // An inferred posture rests on a name, not on a definition this scan could read.
  // Say so on the service rather than presenting it as an established fact.
  if (svc.auth.confidence === "inferred") {
    svc.notes.push(
      `Auth posture (${svc.auth.method}) inferred from a middleware name — its definition was not found in any scanned stack, so it could not be confirmed.`,
    );
  }
  noteProbe(svc, configuredEdgeAuth);
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
 *    never a fallback. Decided here on its own evidence like the rest, and then
 *    *withheld* by `normalizeIngress` on any service that already carries an external
 *    kind — see there for why. So this function's own answer is "can a neighbour reach
 *    it", and what survives into `svc.ingress` is "is that the only thing that can".
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
 * Read off {@link buildNetworkIndex}, which counts over `realNetworks` rather than
 * `svc.networks` so it sees what docker sees: the implicit `default` network compose
 * gives a file that declares none (which is what makes two services in one stack
 * mutually reachable without either saying so), an `external:` network under its
 * verbatim name (which is what lets two *stacks* share one), and live names in
 * preference to implied ones.
 *
 * The same index the graph draws its connections from, deliberately: "shares a network"
 * has to mean one thing, or a service could be classified `internal` by a rule the
 * picture beside it contradicts.
 */
function sharedNetworks(nets: NetworkIndex): Set<string> {
  const out = new Set<string>();
  for (const [name, net] of nets.byName) {
    if (net.members.length >= 2) out.add(name);
  }
  return out;
}

/**
 * Note every dependency whose target shares no network with the dependent.
 *
 * For a compose `depends_on`, the stack still comes up and looks fine — compose orders
 * startup — and the two containers simply cannot address each other, which is the kind of
 * thing that is discovered later by an application timing out. Worth one note, on the
 * dependent: it is the service that will fail to connect. Only same-stack targets are
 * considered, because that is all `depends_on` can name.
 *
 * A **declared** dependency in the same position needs different words. Nothing orders
 * those two containers and nothing was ever going to, so "startup is ordered" would be a
 * false reassurance; what the note can say is that the two do not share a network, and
 * therefore that whatever carries the dependency is outside what this scan can see.
 * Stated rather than dropped: it is either a real gap or a sidecar naming the wrong
 * service, and both are worth a look.
 */
function flagUnreachableDependencies(
  stacks: AppStack[],
  nets: NetworkIndex,
  declared: readonly ResolvedDependency[],
): void {
  for (const stack of stacks) {
    for (const svc of stack.services) {
      const key = serviceKey(stack, svc);
      for (const dep of svc.dependsOn) {
        const target = stack.services.find((s) => s.name === dep);
        if (!target) continue;
        if (sharedWith(nets, key, serviceKey(stack, target)).length > 0) continue;
        svc.notes.push(
          `depends_on ${dep}, but the two share no docker network: startup is ordered, ` +
            `yet neither container can reach the other`,
        );
      }
      for (const dep of declared) {
        if (dep.from !== key || dep.via.length > 0) continue;
        svc.notes.push(
          `${dep.to} is declared as a dependency in ${dep.file}, but the two share no ` +
            `docker network — if they communicate it is over something this scan cannot ` +
            `see (a published port, the host, or a proxy)`,
        );
      }
    }
  }
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

  // A declaration the probe contradicts. Only under `supplies`, where the declaration is
  // the sole reason a finding is being withheld — and LabView has just been served the
  // application at the service's own address without authenticating. This is the case the
  // probe was added for: an unverifiable claim was the only thing standing between a
  // reader and an exposure, and now something can be said about it.
  //
  // Reported as drift rather than as an override, on the same terms as every other check
  // here: the two may both be true. A service can serve `/` to anyone and authenticate
  // everything past it, and the probe only ever asked for `/`.
  const openProbe = svc.probe?.phase === "connected" && !svc.probe.gate ? svc.probe : undefined;
  if (agreement === "supplies" && openProbe) {
    declared.drift.push(
      `${declared.file} declares the service authenticates itself (${summary}), but LabView requested ${openProbe.endpoint} and was answered without a login page (HTTP ${openProbe.status}) — either the declaration is out of date, or the mechanism it names does not apply to that address.`,
    );
  }

  // An acceptance that no longer applies. The service is now protected, or no longer
  // reachable, or — contradicting itself — declares authentication in the same file. In
  // every case the sidecar describes something the scan no longer finds, and quietly
  // ignoring it would leave the file looking correct.
  if (declared.unauthenticatedAccepted && !svc.auth.exposedWithoutAuth) {
    const why = !isExternallyReachable(svc.ingress)
      ? "unreachable from outside the container network"
      : // Above the declared arm for the same reason `probed-gate` outranks `declared` in
        // `noAuthReason`: what was measured describes the service better than what was
        // claimed about it. And it is its own arm rather than falling through to the last,
        // because a login page the application serves itself is not an edge — saying
        // "authenticated at the edge" here would send the operator to look at a proxy.
        svc.probe?.gate
        ? `answering with a login page when LabView requested ${svc.probe.endpoint}`
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
 * The measured half of the exposure note, or nothing.
 *
 * Appended to the exposure finding rather than pushed beside it, because "reachable with
 * no detected authentication" and "LabView asked and got the application" are one finding
 * at two strengths, not two findings. Only when a response actually arrived and carried
 * none of the gate signals — a service that did not answer measured nothing, and saying
 * otherwise would be the false comfort this whole stage exists to remove.
 */
function probeOpenClause(svc: Service): string {
  const probe = svc.probe;
  if (!probe || probe.phase !== "connected" || probe.gate) return "";
  return ` LabView requested ${probe.endpoint} from its own vantage point and was answered without a login page (HTTP ${probe.status}), so this is measured rather than inferred.`;
}

/**
 * What the probe observed, where the exposure note has not already said it.
 *
 * Two cases, and neither changes a verdict on its own:
 *
 *  - **A gate answered.** The service is not counted as exposed, and this is the note
 *    that says why — the same discipline the `supplies` declaration branch keeps, since
 *    both are cases where the report withholds a finding and therefore owes the reader
 *    its grounds. Worded differently depending on whether a gate had already been
 *    detected: then the probe corroborates a mechanism that is already named, and there
 *    is nothing being withheld on its strength.
 *  - **No gate, and a gate was detected anyway.** The posture stands untouched, on the
 *    `chainComplete` precedent in `labels/auth.ts`: a read that may not have travelled
 *    the gated path may not supersede a label. LabView's request came from inside the
 *    fleet — or straight at a published port, which is what `noteHostPortBypass` is
 *    about — so it may simply have gone around the edge that gates real visitors. That
 *    is worth knowing and is not grounds for downgrading anything.
 *
 * A service that did not answer gets no note. Its `ServiceProbe` is on the payload with
 * the phase and every attempt, the aggregate report says how many were silent, and a
 * fleet whose container cannot resolve its own public hostnames would otherwise collect
 * one identical note per service.
 */
function noteProbe(svc: Service, configuredEdgeAuth: boolean): void {
  const probe = svc.probe;
  if (!probe || probe.phase !== "connected") return;

  if (probe.gate) {
    const what = `${probeGateText(probe.gate).label.toLowerCase()}, HTTP ${probe.status}`;
    svc.notes.push(
      configuredEdgeAuth
        ? `LabView requested ${probe.endpoint} and was answered with a login page (${what}), which is what the detected gate looks like from outside.`
        : `LabView requested ${probe.endpoint} and was answered with a login page (${what}), so this service is not reachable without authenticating and is not counted as exposed. Which mechanism is behind that page is unknown — one address answering at one moment is the whole of the evidence.`,
    );
    return;
  }
  if (configuredEdgeAuth) {
    svc.notes.push(
      `A gate is detected for this service, and LabView's own request to ${probe.endpoint} was answered without a login page (HTTP ${probe.status}). The posture stands: the request came from LabView's vantage point, which may not be the path a visitor from outside takes.`,
    );
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

function computeStats(
  stacks: AppStack[],
  nets: NetworkIndex,
  declaredDeps: readonly ResolvedDependency[],
): OverviewStats {
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
    // Resolved pairs, so a reference that named nothing is not counted as a dependency
    // here — it is already counted, as drift, on the line above.
    declaredDependencies: declaredDeps.length,
    probeGated: 0,
    probeOpen: 0,
    networks: nets.byName.size,
    connectingNetworks: 0,
    crossStackNetworks: 0,
    soloLocalNetworks: 0,
  };
  for (const net of nets.byName.values()) {
    if (net.members.length >= 2) stats.connectingNetworks++;
    else if (net.scope === "stack-local") stats.soloLocalNetworks++;
    if (net.stacks.length >= 2) stats.crossStackNetworks++;
  }
  for (const stack of stacks) {
    for (const svc of stack.services) {
      stats.services++;
      if (svc.docker?.running) stats.running++;
      // Five independent counters, not a chain: a service tunnelled *and* proxied is
      // counted in both, which is why these overlap and do not sum to `services`. Read
      // off the tag set rather than re-derived, so `internalServices` counts what the
      // badges show — the services a neighbour and only a neighbour can reach.
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
      // The probe's two counters, and the same discipline as the declaration ones above:
      // neither touches `authProtected` or `byAuthMethod`, because a login page answering
      // proves protection without naming a mechanism. Read off the record the probe wrote
      // rather than re-derived, so the numbers and the row in the drawer cannot disagree
      // about which services answered. Split under one `connected` test rather than as two
      // independent conditions, which is what makes them disjoint by construction: a
      // service that never answered is in neither.
      if (svc.probe?.phase === "connected") {
        if (svc.probe.gate) stats.probeGated++;
        else stats.probeOpen++;
      }
    }
  }
  return stats;
}
