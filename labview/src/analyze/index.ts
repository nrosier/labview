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
import { deriveAuth } from "../labels/authentik.js";
import { maskEnv } from "../secrets.js";
import { buildGraph } from "./graph.js";
import { buildMiddlewareRegistry, type MiddlewareRegistry } from "./middlewares.js";
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
 * Discover the hostnames/identifiers that represent Authentik in this fleet, so
 * OIDC/LDAP issuers pointing at (e.g.) `sso.bunbun.be` are recognized as
 * Authentik even though the string "authentik" never appears. Learns from any
 * service running the goauthentik image or defining the outpost forward-auth.
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
      hints.add(svc.containerName.toLowerCase());
      hints.add(svc.name.toLowerCase());
      for (const r of svc.cloudflare) if (r.hostname) hints.add(r.hostname.toLowerCase());
      for (const r of svc.traefik) for (const h of r.hosts) hints.add(h.toLowerCase());
    }
  }
  return [...hints].filter(Boolean);
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
  const reachable = svc.ingress === "public" || svc.ingress === "local" || svc.ingress === "public+local";
  svc.auth.exposedWithoutAuth = reachable && !hasEdgeAuth;

  if (svc.auth.exposedWithoutAuth) {
    svc.notes.push(`Reachable (${svc.ingress}) with no detected proxy/SSO authentication.`);
  }
  if (svc.cloudflare.some((r) => !r.hostname)) {
    svc.notes.push("DockFlare route present but hostname could not be resolved.");
  }

  // Mask secrets last so analysis could use raw values.
  svc.env = maskEnv(svc.env, cfg);
}

function classifyIngress(svc: Service): IngressKind {
  const isPublic = svc.cloudflare.some((r) => r.hostname);
  const isLocal = svc.traefik.some((r) => r.hosts.length > 0 || r.rule);
  if (isPublic && isLocal) return "public+local";
  if (isPublic) return "public";
  if (isLocal) return "local";
  return "internal";
}

function computeStats(stacks: AppStack[]): OverviewStats {
  const stats: OverviewStats = {
    stacks: stacks.length,
    services: 0,
    running: 0,
    publicServices: 0,
    localOnlyServices: 0,
    internalServices: 0,
    authProtected: 0,
    exposedWithoutAuth: 0,
    byAuthMethod: {},
  };
  for (const stack of stacks) {
    for (const svc of stack.services) {
      stats.services++;
      if (svc.docker?.running) stats.running++;
      if (svc.ingress === "public" || svc.ingress === "public+local") stats.publicServices++;
      else if (svc.ingress === "local") stats.localOnlyServices++;
      else stats.internalServices++;
      if (svc.auth.method !== "none") stats.authProtected++;
      if (svc.auth.exposedWithoutAuth) stats.exposedWithoutAuth++;
      stats.byAuthMethod[svc.auth.method] = (stats.byAuthMethod[svc.auth.method] ?? 0) + 1;
    }
  }
  return stats;
}
