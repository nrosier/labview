import type { AppStack, Service, Graph, GraphNode, GraphEdge } from "../model/types.js";
import { routerIsServing } from "../labels/auth.js";
import { primaryIngress } from "../model/ingress.js";
import { graphServiceId } from "../model/networks.js";
import type { ResolvedDependency } from "./dependencies.js";
import { buildNetworkIndex, serviceKey, sharedWith, type NetworkIndex } from "./networks.js";

/**
 * Build the relationship graph across all stacks:
 *  - service <-> network membership (real docker network names, so shared/external
 *    networks correctly connect services from different stacks), each network node
 *    carrying its scope and how many services and stacks it joins
 *  - service -> service dependency, drawn **through** the network that carries it:
 *    the membership edges either side of the shared network take the arrowheads, so
 *    the path reads dependent -> network -> dependency. The direct service-to-service
 *    edge stays in the model, marked with the networks the pair shares, and is only
 *    rendered when they share none — see `GraphEdge.via` and `showsDirectDependency`.
 *    Two sources, drawn by one rule: a compose `depends_on`, which can only name a
 *    service in the same project, and a `.labview` sidecar's `depends_on`, which is how
 *    a cross-stack dependency can be stated at all. A declared edge carries
 *    `declaredBy`, so no view can pass the operator's statement off as a measurement.
 *
 * **Sharing a network is not a dependency.** Two services on one network can reach each
 * other, and that is the whole of what the membership edges say: they attach a service to
 * the network node and carry no arrowhead. Every fleet has a proxy or monitoring network
 * that half the services are on, and treating co-membership as a relation would draw a
 * line between every pair of them — a statement about the fleet that is simply not true.
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
 *
 * @param proxyKey `${stackId}/${serviceName}` of the proxy whose API was read, when
 * one answered. It is the strongest possible statement about which proxy serves a
 * route — the proxy itself said so — so a router it reported is drawn from that
 * service rather than from the generic hub, in a fleet with no tunnel at all as
 * readily as in one with several.
 * @param nets the fleet's network membership, when the caller already built it. The
 * analyzer does, because the ingress rule needs it first, and sharing it is what makes
 * "shares a network" mean the same thing in the picture as in the classification.
 * @param declared cross-stack dependencies resolved from the fleet's sidecars, from
 * `resolveDeclaredDependencies`. Already resolved and already carrying the networks each
 * pair shares — nothing here re-reads a declaration, so the one place a sidecar reference
 * is interpreted stays the one place its four failure modes are reported.
 */
export function buildGraph(
  stacks: AppStack[],
  proxyKey?: string,
  nets?: NetworkIndex,
  declared: readonly ResolvedDependency[] = [],
): Graph {
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

  const index = nets ?? buildNetworkIndex(stacks);

  /** Every service that exists as a node, for the two hop guards below. */
  const drawn = new Set<string>();
  for (const stack of stacks) {
    for (const svc of stack.services) drawn.add(serviceId(stack, svc));
  }

  /**
   * Which of a service's networks carry a dependency, and which way it runs across
   * them — `out` where this service is the dependent, `in` where something on that
   * network depends on it. This is what lets the two membership edges either side of
   * a network take the arrowheads, so the dependency is drawn *through* the network
   * instead of as a second line beside it.
   *
   * Marked on every network the pair shares, not just one: they can talk over any of
   * them, and picking a favourite would draw an arrow across one network while an
   * equally usable one beside it looked unrelated.
   *
   * Each marking also records whether it came from a compose file or a sidecar, so the
   * arrowhead can be drawn as the kind of statement it is. Nothing marks a flow from
   * membership alone — that is the point of the whole distinction.
   */
  type Flow = { out: boolean; in: boolean; observed: boolean; declared: boolean };
  const flows = new Map<string, Map<string, Flow>>();
  const markFlow = (key: string, net: string, dir: "out" | "in", from: "observed" | "declared") => {
    let byNet = flows.get(key);
    if (!byNet) flows.set(key, (byNet = new Map()));
    const cur = byNet.get(net) ?? { out: false, in: false, observed: false, declared: false };
    cur[dir] = true;
    cur[from] = true;
    byNet.set(net, cur);
  };
  const markPair = (from: string, to: string, source: "observed" | "declared", via?: string[]) => {
    for (const net of via ?? sharedWith(index, from, to)) {
      markFlow(from, net, "out", source);
      markFlow(to, net, "in", source);
    }
  };
  for (const stack of stacks) {
    for (const svc of stack.services) {
      const from = serviceKey(stack, svc);
      for (const dep of svc.dependsOn) {
        const target = stack.services.find((s) => s.name === dep);
        if (!target) continue;
        markPair(from, serviceKey(stack, target), "observed");
      }
    }
  }
  // The declared half, over the networks the resolver already found the pair shares.
  for (const dep of declared) markPair(dep.from, dep.to, "declared", dep.via);

  /** Declared dependencies by dependent, so each service's own loop can emit its edges. */
  const declaredFrom = new Map<string, ResolvedDependency[]>();
  for (const dep of declared) {
    const list = declaredFrom.get(dep.from);
    if (list) list.push(dep);
    else declaredFrom.set(dep.from, [dep]);
  }

  /** Hostnames whose tunnel route terminates at a given hop, for one edge per hop. */
  const viaHop = new Map<string, Set<string>>();

  /** Service nodes shown to be acting as a proxy, tunnel or no tunnel. */
  const proxyRole = new Set<string>();

  for (const stack of stacks) {
    for (const svc of stack.services) {
      const sid = serviceId(stack, svc);
      addNode({
        id: sid,
        label: svc.name,
        kind: "service",
        stack: stack.id,
        auth: svc.auth.method,
        // A node has one background colour, so it carries the most exposed kind. The
        // full set is on the badges beside it — see `GraphNode.ingress`.
        ingress: primaryIngress(svc.ingress),
        running: svc.docker?.running,
      });

      // Networks, under their real docker names, so one `external:` network shared by
      // six stacks is one node with six spokes rather than six unrelated nodes. The
      // node carries what it joins — scope, services, stacks — because that is the
      // whole of what a reader wants from it and counting spokes is not an answer.
      const key = serviceKey(stack, svc);
      for (const name of index.byService.get(key) ?? []) {
        const net = index.byName.get(name);
        if (!net) continue;
        const nid = `net:${name}`;
        addNode({
          id: nid,
          label: name,
          kind: "network",
          scope: net.scope,
          memberCount: net.members.length,
          stackCount: net.stacks.length,
        });
        const flow = flows.get(key)?.get(name);
        addEdge({
          id: `${sid}->${nid}`,
          source: sid,
          target: nid,
          kind: "network",
          ...(flow
            ? {
                flow: flow.out && flow.in ? "both" : flow.out ? "to-network" : "to-service",
                flowSource:
                  flow.observed && flow.declared ? "both" : flow.observed ? "observed" : "declared",
              }
            : {}),
        });
      }

      // depends_on within the stack — all it can name. The edge records which networks
      // the pair shares rather than being dropped when they share one: the relation is
      // real and the drawer names the exact pair from it, while the fleet view draws it
      // through the network instead (`showsDirectDependency`). An empty `via` is the one
      // case with no network to draw it through, and the one worth an arrow of its own.
      for (const dep of svc.dependsOn) {
        const target = stack.services.find((s) => s.name === dep);
        if (target) {
          addEdge({
            id: `${sid}=>${serviceId(stack, target)}`,
            source: sid,
            target: serviceId(stack, target),
            kind: "depends_on",
            via: sharedWith(index, key, serviceKey(stack, target)),
          });
        }
      }

      // The same relation, declared instead of observed — the one way a dependency can
      // cross stacks. Same kind, same `via`, so every rule about how a dependency is
      // drawn applies to it unchanged; `declaredBy` is what keeps the two tellable apart.
      // A pair that is both declared *and* in the compose file collapses to the observed
      // edge above, by the same de-duplication that collapses two routes into one link:
      // the scan saw it, so it need not be taken on anyone's word.
      for (const dep of declaredFrom.get(key) ?? []) {
        addEdge({
          id: `${sid}=>svc:${dep.to}`,
          source: sid,
          target: `svc:${dep.to}`,
          kind: "depends_on",
          via: dep.via,
          declaredBy: { file: dep.file, ...(dep.detail ? { detail: dep.detail } : {}) },
        });
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
        const hop = resolvedHop(r.origin?.hopKey, sid, drawn);
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
      // Routers the proxy's own API reported for this service. Drawn from that proxy
      // because it is the proxy stating it serves them — no inference involved — and
      // drawn for routers no label declares, which is how ingress configured outside
      // the scanned stacks becomes visible at all. A router the proxy is not serving
      // is left out: an edge is a request path, and that one carries no requests.
      const proxyId = liveProxy(proxyKey, sid, drawn);
      const serving = (svc.traefikLive ?? []).filter(routerIsServing);
      if (proxyId && serving.length) {
        proxyRole.add(proxyId);
        for (const r of serving) {
          addEdge({
            id: `live->${sid}:${r.router}@${r.provider}`,
            source: proxyId,
            target: sid,
            kind: "ingress",
            label: r.hosts[0] ?? r.router,
          });
        }
      }

      // Proxy routes from labels. Those the live read already accounted for are drawn
      // above from the proxy that confirmed them; the rest start at the hop this
      // service's own tunnel origin resolved to, since that service is an observed
      // reverse proxy in front of it. Without either, the responsible proxy is unknown
      // — a Traefik instance picks up routes from the docker socket, which no label
      // records — so the generic hub stands in rather than attributing the route to a
      // proxy found elsewhere.
      const confirmed = new Set(proxyId ? serving.map((r) => r.router.toLowerCase()) : []);
      const routerSource = hopId ?? "ext:traefik";
      for (const r of svc.traefik) {
        if (confirmed.has(r.router.toLowerCase())) continue;
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
  // Same fact, established the other way round: a service whose API reported the
  // routes for other services is a proxy whether or not any tunnel lands on it.
  for (const id of proxyRole) {
    const node = nodes.get(id);
    if (node) node.role = "proxy";
  }

  if (hub.cf) addNode({ id: "ext:cloudflare", label: "Cloudflare Tunnel", kind: "external" });
  if (hub.traefik) addNode({ id: "ext:traefik", label: "Traefik", kind: "external" });
  if (hub.authentik) addNode({ id: "ext:authentik", label: "Authentik", kind: "external" });
  if (hub.auth) addNode({ id: "ext:auth", label: "SSO (unidentified)", kind: "external" });

  return { nodes: [...nodes.values()], edges };
}

export function serviceId(stack: AppStack, svc: Service): string {
  return graphServiceId(stack.id, svc.name);
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
  drawn: ReadonlySet<string>,
): string | undefined {
  if (!hopKey) return undefined;
  const hop = `svc:${hopKey}`;
  if (hop === sid || !drawn.has(hop)) return undefined;
  return hop;
}

/**
 * The graph node for the proxy whose API answered.
 *
 * Guards the two degenerate cases: no proxy was identified, and the proxy is the very
 * service being drawn — a Traefik instance routinely serves a router for its own
 * dashboard, and an edge from a node to itself states nothing.
 */
function liveProxy(
  proxyKey: string | undefined,
  sid: string,
  drawn: ReadonlySet<string>,
): string | undefined {
  if (!proxyKey) return undefined;
  const id = `svc:${proxyKey}`;
  if (id === sid || !drawn.has(id)) return undefined;
  return id;
}

function normalizeBind(p: string): string {
  return p.replace(/\/+$/, "");
}
