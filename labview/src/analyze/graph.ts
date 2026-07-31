import type { AppStack, Service, Graph, GraphNode, GraphEdge } from "../model/types.js";
import { realNetworks } from "./networks.js";

/**
 * Build the relationship graph across all stacks:
 *  - service <-> network membership (real docker network names, so shared/external
 *    networks correctly connect services from different stacks)
 *  - service -> service depends_on
 *  - service <-> shared volumes (named volumes, and bind paths used by 2+ stacks)
 *  - ingress/auth hubs, each added only when something observed calls for it:
 *    a Cloudflare tunnel, Traefik, and either the identified SSO provider or a
 *    generic hub when only the mechanism could be established
 *
 * Tunnel ingress is drawn as the path the configuration describes rather than as a
 * straight line to the container. Where a route's origin resolved to another
 * scanned service (see `origins.ts`), that service is drawn as the hop it is:
 * `tunnel -> proxy -> service`. Where the origin resolved to the service itself,
 * or to nothing this scan can see, the direct edge is kept — an unproven hop is
 * never invented.
 */
export function buildGraph(stacks: AppStack[]): Graph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const addNode = (n: GraphNode) => {
    if (!nodes.has(n.id)) nodes.set(n.id, n);
  };
  // Two routes can describe the same link — a tunnel hostname and the Traefik
  // router serving it both put an edge between the same proxy and service — so
  // edges are kept unique by what they say, not just by id.
  const seenEdge = new Set<string>();
  const addEdge = (e: GraphEdge) => {
    const key = `${e.kind}|${e.source}|${e.target}|${e.label ?? ""}`;
    if (seenEdge.has(key) || seenEdge.has(e.id)) return;
    seenEdge.add(key);
    seenEdge.add(e.id);
    edges.push(e);
  };

  // Hubs (added lazily only if used).
  const hub = { cf: false, traefik: false, authentik: false, auth: false };

  // First pass: count bind-path usage across distinct stacks to find shared data.
  const bindStacks = new Map<string, Set<string>>();
  for (const stack of stacks) {
    for (const svc of stack.services) {
      for (const m of svc.mounts) {
        if (m.type === "bind" && m.source) {
          const key = normalizeBind(m.source);
          if (!bindStacks.has(key)) bindStacks.set(key, new Set());
          bindStacks.get(key)!.add(stack.id);
        }
      }
    }
  }

  const netsById = new Map<string, string[]>();
  for (const stack of stacks) {
    for (const svc of stack.services) {
      netsById.set(serviceId(stack, svc), realNetworks(stack, svc));
    }
  }

  /** Hostnames whose tunnel route terminates at a given hop, for one edge per hop. */
  const viaHop = new Map<string, Set<string>>();

  for (const stack of stacks) {
    for (const svc of stack.services) {
      const sid = serviceId(stack, svc);
      addNode({
        id: sid,
        label: svc.name,
        kind: "service",
        stack: stack.id,
        auth: svc.auth.method,
        ingress: svc.ingress,
        running: svc.docker?.running,
      });

      // Networks (prefer live docker names for accuracy).
      for (const name of netsById.get(sid) ?? []) {
        const nid = `net:${name}`;
        addNode({ id: nid, label: name, kind: "network" });
        addEdge({ id: `${sid}->${nid}`, source: sid, target: nid, kind: "network" });
      }

      // depends_on within the stack.
      for (const dep of svc.dependsOn) {
        const target = stack.services.find((s) => s.name === dep);
        if (target) {
          addEdge({
            id: `${sid}=>${serviceId(stack, target)}`,
            source: sid,
            target: serviceId(stack, target),
            kind: "depends_on",
          });
        }
      }

      // Volumes: named volumes always; bind paths only when shared across stacks.
      for (const m of svc.mounts) {
        if (!m.source) continue;
        if (m.type === "volume") {
          const decl = stack.declaredVolumes.find((v) => v.name === m.source);
          const vid = decl?.external ? `vol:ext:${decl.name}` : `vol:${stack.projectName}:${m.source}`;
          addNode({ id: vid, label: m.source, kind: "volume" });
          addEdge({ id: `${sid}~${vid}`, source: sid, target: vid, kind: "volume", label: m.target });
        } else if (m.type === "bind") {
          const key = normalizeBind(m.source);
          if ((bindStacks.get(key)?.size ?? 0) >= 2) {
            const vid = `bind:${key}`;
            addNode({ id: vid, label: m.source, kind: "volume" });
            addEdge({ id: `${sid}~${vid}`, source: sid, target: vid, kind: "volume", label: m.target });
          }
        }
      }

      // Ingress. A tunnel route is drawn through its resolved hop when the origin
      // named another scanned service, and straight at this service otherwise.
      let hopId: string | undefined;
      for (const r of svc.cloudflare) {
        hub.cf = true;
        const label = r.hostname || "tunnel";
        const hop = resolvedHop(r.origin?.hopKey, sid, netsById);
        if (hop) {
          hopId ??= hop;
          // Leg 1 is aggregated per hop below: a fleet routes many hostnames
          // through one proxy, and one edge per route would bundle dozens of
          // parallel lines between the same two nodes.
          if (!viaHop.has(hop)) viaHop.set(hop, new Set());
          viaHop.get(hop)!.add(label);
          addEdge({
            id: `${hop}->${sid}:${r.hostname}`,
            source: hop,
            target: sid,
            kind: "ingress",
            label,
          });
        } else {
          addEdge({
            id: `cf->${sid}:${r.hostname}`,
            source: "ext:cloudflare",
            target: sid,
            kind: "ingress",
            label,
          });
        }
      }
      // Proxy routes start at the hop this service's own tunnel origin resolved to,
      // since that service is an observed reverse proxy in front of it. Without
      // such a hop the responsible proxy is unknown — a Traefik instance picks up
      // routes from the docker socket, which no label records — so the generic hub
      // stands in rather than attributing the route to a proxy found elsewhere.
      const routerSource = hopId ?? "ext:traefik";
      for (const r of svc.traefik) {
        if (!hopId) hub.traefik = true;
        addEdge({
          id: `tr->${sid}:${r.router}`,
          source: routerSource,
          target: sid,
          kind: "ingress",
          label: r.hosts[0] ?? r.router,
        });
      }
      // Auth hub. Only a service whose provider was actually identified hangs off
      // the named hub; a mechanism-only detection gets the generic one, so the
      // graph never draws a vendor it could not establish from the config.
      if (svc.auth.method.startsWith("authentik")) {
        hub.authentik = true;
        addEdge({
          id: `ak->${sid}`,
          source: "ext:authentik",
          target: sid,
          kind: "auth",
          label: svc.auth.method.replace("authentik-", ""),
        });
      } else if (svc.auth.method === "forward-auth" || svc.auth.method === "other-oauth") {
        hub.auth = true;
        addEdge({
          id: `auth->${sid}`,
          source: "ext:auth",
          target: sid,
          kind: "auth",
          label: svc.auth.method,
        });
      }
    }
  }

  // Leg 1 of every chain: one edge per hop, not per route. Its label carries the
  // hostname when a single route uses the hop, and the count when many do — the
  // hostname-to-service mapping stays visible on leg 2 either way.
  for (const [hop, hostnames] of viaHop) {
    const only = hostnames.size === 1 ? [...hostnames][0] : undefined;
    addEdge({
      id: `cf->${hop}`,
      source: "ext:cloudflare",
      target: hop,
      kind: "ingress",
      label: only ?? `${hostnames.size} hostnames`,
    });
    // The node already exists as an ordinary service; being a hop is an extra fact
    // about it, not a different kind of thing.
    const node = nodes.get(hop);
    if (node) node.role = "proxy";
  }

  if (hub.cf) addNode({ id: "ext:cloudflare", label: "Cloudflare Tunnel", kind: "external" });
  if (hub.traefik) addNode({ id: "ext:traefik", label: "Traefik", kind: "external" });
  if (hub.authentik) addNode({ id: "ext:authentik", label: "Authentik", kind: "external" });
  if (hub.auth) addNode({ id: "ext:auth", label: "SSO (unidentified)", kind: "external" });

  return { nodes: [...nodes.values()], edges };
}

export function serviceId(stack: AppStack, svc: Service): string {
  return `svc:${stack.id}/${svc.name}`;
}

/**
 * The graph node for a resolved tunnel hop.
 *
 * `origins.ts` has already established that the hop exists and can reach this
 * service over a shared network, so this only maps its key to a node id and
 * guards the degenerate cases. Without a hop the caller keeps the direct edge.
 */
function resolvedHop(
  hopKey: string | undefined,
  sid: string,
  netsById: Map<string, string[]>,
): string | undefined {
  if (!hopKey) return undefined;
  const hop = `svc:${hopKey}`;
  if (hop === sid || !netsById.has(hop)) return undefined;
  return hop;
}

function normalizeBind(p: string): string {
  return p.replace(/\/+$/, "");
}
