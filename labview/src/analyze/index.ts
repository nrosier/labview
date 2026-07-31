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
import { deriveAuth } from "../labels/auth.js";
import { maskEnv } from "../secrets.js";
import { buildGraph } from "./graph.js";
import { buildMiddlewareRegistry, type MiddlewareRegistry } from "./middlewares.js";
import { buildFleetIndex, resolveOrigins } from "./origins.js";
import { snapshotDocker, composeKey, type DockerSnapshot } from "../enrich/docker.js";
import { scanStacks } from "../scan/index.js";

const VERSION = "0.1.0";

/** Full pipeline: scan -> enrich -> analyze -> Overview. `now` is injected for determinism. */
export async function buildOverview(cfg: LabViewConfig, now: Date): Promise<Overview> {
  const started = Date.now();
  const { stacks, warnings } = scanStacks(cfg);
  const snapshot = await snapshotDocker(cfg);
  const registry = buildMiddlewareRegistry(stacks, cfg.labels.traefik.prefix);

  // Pass 1: parse routes, merge live docker state, classify ingress.
  for (const stack of stacks) {
    for (const svc of stack.services) {
      parseRoutes(stack, svc, snapshot, cfg);
    }
  }

  // Authentik hostnames can only be discovered once routes are parsed.
  const authHints = discoverAuthentikHints(stacks, cfg);

  // Where each tunnel origin points. Cross-stack by nature — an origin routinely
  // names a proxy defined in a different stack — so it runs over the whole fleet
  // once, after the routes exist and before the graph is drawn from them.
  resolveOrigins(stacks, buildFleetIndex(stacks));

  // Pass 2: derive auth posture, finalize exposure, mask secrets.
  for (const stack of stacks) {
    for (const svc of stack.services) {
      finalizeAuth(svc, cfg, registry, authHints);
    }
  }

  const graph = buildGraph(stacks);
  const stats = computeStats(stacks);

  const meta: ScanMeta = {
    scannedAt: now.toISOString(),
    appsRoot: cfg.appsRoot,
    dockerAvailable: snapshot.available,
    dockerError: snapshot.error,
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
 * Hints are matched against arbitrary values downstream, so a hint that is too
 * generic mislabels unrelated services. The upstream Authentik compose file names
 * its services `server` and `worker`; learning those verbatim would make every
 * `OIDC_ISSUER=https://server.example.com` look like Authentik. Only container
 * names specific enough to be meaningful are learned; hostnames are always safe
 * since they are fully qualified by construction.
 */
function discoverAuthentikHints(stacks: AppStack[], cfg: LabViewConfig): string[] {
  const hints = new Set(cfg.labels.authentik.hostHints.map((h) => h.toLowerCase()));
  for (const stack of stacks) {
    for (const svc of stack.services) {
      const isAuthentik =
        /goauthentik|authentik/i.test(svc.image ?? "") ||
        Object.entries(svc.labels).some(
          ([k, v]) => /forwardauth\.address$/i.test(k) && /goauthentik\.io/i.test(v),
        );
      if (!isAuthentik) continue;
      const container = svc.containerName.toLowerCase();
      if (isSpecificHint(container)) hints.add(container);
      for (const r of svc.cloudflare) if (r.hostname) hints.add(r.hostname.toLowerCase());
      for (const r of svc.traefik) for (const h of r.hosts) hints.add(h.toLowerCase());
    }
  }
  return [...hints].filter(Boolean);
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
  cfg: LabViewConfig,
  registry: MiddlewareRegistry,
  authHints: string[],
): void {
  svc.auth = deriveAuth(svc, cfg, registry, authHints);

  const hasCloudflareAccess = svc.cloudflare.some(
    (r) => r.access && (r.access.policy || r.access.group || r.access.emails?.length),
  );
  const hasEdgeAuth = svc.auth.method !== "none" || hasCloudflareAccess;
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
