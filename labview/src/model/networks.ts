import type { Graph, GraphEdge, GraphNode, NetworkScope } from "./types.js";

/**
 * The network-connection vocabulary and every pure operation on it.
 *
 * The analyzer answers "who is on which network"; this module answers "what should be
 * drawn, and what does it say". Both halves matter and they are deliberately apart: the
 * graph in `Overview` carries the **complete** membership — every network, every spoke,
 * every dependency and the networks it can travel over — and the rules for pruning that
 * down to something readable live here, where a test can call them.
 *
 * That split is what makes the two views agree. The fleet graph hides a network that
 * connects nothing and caps the spokes of one that connects fifty; the service drawer
 * lists every peer of that same network exactly. Both read the same complete graph
 * through the same functions, so neither can quietly disagree with the other about who
 * is connected to whom — and none of it is decided inside a `.tsx`, where it would be
 * unassertable.
 *
 * One shape underlies everything here: a connection between two services is
 * `service → network → service`, with the network in the middle. A network hanging off
 * one service says nothing, and a line straight between two services hides the thing
 * that actually joins them.
 *
 * And one rule decides when that shape is drawn at all: **a line between two services
 * requires a dependency**, from a compose file or from a sidecar. Sharing a network is
 * reachability, not dependency — every fleet has a proxy network half the services sit on,
 * and drawing each pair of them as connected would state something about the fleet that is
 * not true. Co-members are still worth naming, so they are named in words, under a heading
 * that says only what they are.
 */

/**
 * How many spokes one network node may draw in the fleet graph.
 *
 * A real fleet has a network everything is on — a proxy or monitoring network with
 * dozens of members — and drawing every spoke turns the graph into a hairball in which
 * the small, informative networks cannot be found. Spokes carrying a dependency are
 * kept first, since those are the ones with something to say, and the node states how
 * many it did not draw so nothing is silently missing.
 */
export const MAX_GRAPH_SPOKES = 12;

/** How many peers one network may name in the service drawer's diagram. */
export const MAX_DRAWER_PEERS = 8;

/** How many members one network may list in the fleet-level Networks section. */
export const MAX_LIST_PEERS = 12;

export interface NetworkScopeMeta {
  key: NetworkScope;
  label: string;
  /** Why this scope means what it means, for the pill's tooltip. */
  title: string;
}

/**
 * Both scopes, external first — the order they are listed in and the order that matters
 * to a reader, since only an external network can join two stacks.
 */
export const NETWORK_SCOPES: readonly NetworkScopeMeta[] = [
  {
    key: "external",
    label: "External",
    title:
      "Declared external, or created outside the scanned stacks. Several stacks can be on it, and so can containers this scan cannot see.",
  },
  {
    key: "stack-local",
    label: "Stack-local",
    title:
      "Created by one stack's compose project. Only that stack's own services can be on it.",
  },
];

export function networkScopeMeta(scope: NetworkScope): NetworkScopeMeta {
  return NETWORK_SCOPES.find((s) => s.key === scope) ?? NETWORK_SCOPES[0]!;
}

/**
 * Whether a network node is worth drawing in the fleet graph.
 *
 * Two members is the point at which a network *connects* something, which is what the
 * fleet view is about. The exception is a single-member **external** network: it says
 * this service shares a network with something outside the scan, and that is a real
 * statement about reachability even though the far end cannot be drawn. A single-member
 * stack-local network says the opposite — nothing else can join it, so nothing else is
 * on it — and is the one case that is dropped.
 *
 * Never applied to the drawer, which lists every network a service is on regardless.
 */
export function showsNetworkNode(node: GraphNode): boolean {
  if (node.kind !== "network") return true;
  return (node.memberCount ?? 0) >= 2 || node.scope === "external";
}

/**
 * Whether a `depends_on` edge is drawn as a line straight between the two services.
 *
 * Only when they share no network. With a shared network the dependency is drawn
 * *through* it — the arrowheads on the two membership edges either side — and a direct
 * line beside that would state the same relation twice while hiding the network that
 * carries it.
 *
 * Where they share none, the direct edge is the only honest drawing: compose orders
 * startup, but neither container can address the other, and that is worth seeing.
 */
export function showsDirectDependency(edge: GraphEdge): boolean {
  if (edge.kind !== "depends_on") return true;
  return !edge.via?.length;
}

export interface SpokeSelection {
  /** The membership edges to draw. */
  kept: GraphEdge[];
  /** How many members are not drawn. */
  omitted: number;
}

/**
 * Which of a network's membership edges to draw, and how many were left out.
 *
 * Dependency-carrying spokes first — an arrowhead is the only thing in the fleet view
 * that says more than "attached", so it must survive the cap — then the rest in graph
 * order, which is scan order and therefore stable across rescans.
 */
export function visibleSpokes(
  edges: readonly GraphEdge[],
  limit: number = MAX_GRAPH_SPOKES,
): SpokeSelection {
  if (edges.length <= limit) return { kept: [...edges], omitted: 0 };
  const withFlow = edges.filter((e) => e.flow);
  const rest = edges.filter((e) => !e.flow);
  const kept = [...withFlow, ...rest].slice(0, Math.max(0, limit));
  return { kept, omitted: edges.length - kept.length };
}

/**
 * A network node's label: its name, what it joins, and what was left undrawn.
 *
 * The counts are on the node rather than inferred from the spokes beside it because
 * the spokes are capped — a reader counting six lines on a node that joins fifty
 * services would be reading a number that is not there.
 *
 * @param drawn how many spokes the caller is actually drawing. Omit where every member
 * is drawn, as the drawer and the Networks section do.
 */
export function networkNodeLabel(node: GraphNode, drawn?: number): string {
  const members = node.memberCount ?? 0;
  const parts: string[] = [`${members} ${members === 1 ? "service" : "services"}`];
  if ((node.stackCount ?? 0) >= 2) parts.push(`${node.stackCount} stacks`);
  const omitted = drawn === undefined ? 0 : Math.max(0, members - drawn);
  if (omitted > 0) parts.push(`+${omitted} not drawn`);
  return `${node.label}\n${parts.join(" · ")}`;
}

/**
 * The one-line note that accounts for the network nodes the fleet graph does not draw.
 *
 * Stated rather than left implicit: a view that silently drops a third of the networks
 * reads exactly like a view that found none.
 */
export function hiddenNetworksNote(soloLocalNetworks: number): string {
  if (soloLocalNetworks <= 0) return "";
  return soloLocalNetworks === 1
    ? "1 stack-local network with a single service on it is not drawn."
    : `${soloLocalNetworks} stack-local networks with a single service on them are not drawn.`;
}

/**
 * Which way a dependency runs between two services.
 *
 *  - `depends-on` — this service depends on the other one.
 *  - `required-by` — the other one depends on this service.
 *
 * Both are read off the same edge, from whichever end is being looked at. That is what
 * lets a dependency be declared once, on the dependent, and still appear in the drawer of
 * the service it points at — the backup service in the request that prompted this shows
 * every database that named it, with nothing in its own sidecar.
 */
export type DependencyRelation = "depends-on" | "required-by";

/**
 * What one service is to another across a shared network: a dependency in one direction
 * or the other, or `peer` — neither, meaning they are simply both attached to it.
 *
 * `peer` is the answer for most pairs in a real fleet, and it is **not** a connection.
 * Two services on one network can reach each other; nothing about that says one needs the
 * other, and a proxy network with thirty members would otherwise read as thirty
 * services all connected to each other. Wherever a co-member is shown it is shown as a
 * member of the network, never as a peer of the service.
 */
export type NetworkRelation = DependencyRelation | "peer";

/**
 * How a relation is worded wherever it is shown.
 *
 * `peer` reads as `reachable` rather than as any kind of dependency: it is the plain
 * consequence of sharing a network, which is all that was observed.
 */
export function relationLabel(relation: NetworkRelation): string {
  return relation === "depends-on" ? "depends on" : relation === "required-by" ? "required by" : "reachable";
}

/**
 * The graph node id for a service.
 *
 * Here rather than in the analyzer because both ends need it: `buildGraph` mints the ids
 * and the drawer looks a service up among them. Two spellings of one prefix would fail
 * silently — every lookup would simply find nothing and the drawer would report a service
 * with no connections at all.
 */
export function graphServiceId(stackId: string, serviceName: string): string {
  return `svc:${stackId}/${serviceName}`;
}

/** A service as the connection views refer to it. */
export interface ServiceRefView {
  /** Graph node id, `svc:<stack>/<service>`. */
  id: string;
  stack: string;
  service: string;
}

/** A service this one depends on, or that depends on it, across one network. */
export interface NetworkPeerView extends ServiceRefView {
  relation: DependencyRelation;
  /**
   * Set when the dependency was stated in a `.labview` sidecar rather than read from a
   * compose file, with the file it was stated in — so a view can show it as the
   * unverifiable statement it is (invariant I1) instead of as something observed.
   *
   * Set on **both** ends of a declared dependency: the service that declared it and the
   * service it named. `file` names the sidecar the statement came from either way, which
   * on the target's side is a file belonging to another stack.
   */
  declared?: boolean;
  file?: string;
  /** What the operator said about the dependency, when they said anything. */
  detail?: string;
}

/** One network a service is on: what it connects it to, and who else is attached. */
export interface NetworkLink {
  /** Graph node id, `net:<name>`. */
  id: string;
  name: string;
  scope: NetworkScope;
  memberCount: number;
  stackCount: number;
  /**
   * Services this network carries a dependency to or from, dependents first, capped at
   * the caller's limit. **The only members that are drawn as connected.**
   */
  dependencies: NetworkPeerView[];
  /** Dependencies beyond the cap. */
  dependenciesOmitted: number;
  /**
   * Every other scanned service attached to it, in scan order, capped separately.
   *
   * Reachable, not dependent — which is why these are a list and never a line: they
   * answer "who else is on this network", and nothing more than that was observed.
   */
  alsoOn: ServiceRefView[];
  /** Co-members beyond their cap. */
  alsoOnOmitted: number;
}

/**
 * Every network one service is on, split into what it depends on across each and who else
 * is merely attached.
 *
 * Read off the complete graph, so it is exact even for a network whose spokes the fleet
 * view caps — this is the view that answers "and who else is on it", which is the whole
 * question a dangling `net: x` node never answered.
 *
 * The split is the point. A dependency is a relation between two services; membership is a
 * relation between a service and a network. Returning one mixed list is what let a
 * renderer draw thirty co-members of a proxy network as thirty connections.
 *
 * @param limit how many dependencies one network may name — the diagram's cap, since
 * those are what it draws.
 * @param alsoOnLimit how many co-members one network may name. Separate, and larger:
 * a list of names is cheap where a diagram leg is not.
 */
export function networkLinks(
  graph: Graph,
  serviceId: string,
  limit: number = MAX_DRAWER_PEERS,
  alsoOnLimit: number = MAX_LIST_PEERS,
): NetworkLink[] {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const membership = graph.edges.filter((e) => e.kind === "network");
  const links: NetworkLink[] = [];

  for (const own of membership) {
    if (own.source !== serviceId) continue;
    const net = nodes.get(own.target);
    if (!net || net.kind !== "network") continue;

    const dependencies: NetworkPeerView[] = [];
    const alsoOn: ServiceRefView[] = [];
    for (const other of membership) {
      if (other.target !== own.target || other.source === serviceId) continue;
      const node = nodes.get(other.source);
      if (!node || node.kind !== "service") continue;
      const ref: ServiceRefView = { id: node.id, stack: node.stack ?? "", service: node.label };
      const dep = dependencyOver(graph, serviceId, node.id, net.label);
      if (!dep) {
        alsoOn.push(ref);
        continue;
      }
      const declaredBy = dep.edge.declaredBy;
      dependencies.push({
        ...ref,
        relation: dep.relation,
        ...(declaredBy
          ? { declared: true, file: declaredBy.file, ...(declaredBy.detail ? { detail: declaredBy.detail } : {}) }
          : {}),
      });
    }
    dependencies.sort((a, b) => RELATION_ORDER[a.relation] - RELATION_ORDER[b.relation]);

    links.push({
      id: net.id,
      name: net.label,
      scope: net.scope ?? "external",
      memberCount: net.memberCount ?? dependencies.length + alsoOn.length + 1,
      stackCount: net.stackCount ?? 1,
      dependencies: dependencies.slice(0, Math.max(0, limit)),
      dependenciesOmitted: Math.max(0, dependencies.length - Math.max(0, limit)),
      alsoOn: alsoOn.slice(0, Math.max(0, alsoOnLimit)),
      alsoOnOmitted: Math.max(0, alsoOn.length - Math.max(0, alsoOnLimit)),
    });
  }
  return links;
}

/**
 * What to say about a network that connects this service to nothing.
 *
 * Three cases, and the difference between the last two is the whole distinction this
 * module rests on.
 *
 * **Nothing else on it.** The two scopes need different words, and getting them the wrong
 * way round would be a false claim in one direction or the other. On a stack-local network
 * nothing else *can* be attached, so "nothing else is on it" is the whole truth. On an
 * external one the scan simply cannot see the far end — a container outside the scanned
 * stacks may well be on it — so the sentence has to stop at what was observed.
 *
 * **Members, but no dependency across it.** The ordinary case for a proxy or monitoring
 * network. Said in words rather than drawn as lines, and said explicitly: a diagram with
 * one network node and no legs beside a list of fourteen names would otherwise read as
 * something the view failed to draw.
 *
 * Empty for a network that does carry a dependency, so a caller can use it as the
 * condition.
 */
export function networkMembershipText(link: NetworkLink): string {
  if (link.dependencies.length > 0) return "";
  const others = Math.max(0, link.memberCount - 1);
  if (others === 0) {
    return link.scope === "stack-local"
      ? "Nothing else is on it. It belongs to this stack's compose project, so only this stack's own services could be."
      : "No other scanned service is on it. It is external to the scanned stacks, so containers this scan cannot see may be.";
  }
  return (
    `${others} other ${others === 1 ? "service is" : "services are"} on it. Sharing a network ` +
    `makes them reachable, not dependent — nothing declares a dependency across it.`
  );
}

/** Everything one service's drawer says about what it is connected to. */
export interface ServiceConnections {
  /** Every network it is on, with what it depends on across each and who else is attached. */
  links: NetworkLink[];
  /**
   * Dependencies drawn as a direct arrow because no network carries them.
   *
   * Normally empty. A non-empty entry is the oddity {@link showsDirectDependency}
   * describes: a compose `depends_on` orders the two containers' startup, yet neither can
   * address the other — or a sidecar declares a dependency on a service this scan can find
   * no path to at all. The analyzer states both in words on the service's notes; this is
   * the same fact in the diagram.
   *
   * Both directions, like the network-carried dependencies: the service at the far end of
   * an unreachable dependency has the same problem, seen from the other side.
   */
  direct: NetworkPeerView[];
}

/**
 * The drawer's whole view of one service's connections, from the complete graph.
 *
 * One function rather than two because the two answers are complements — a dependency is
 * either carried by a network or drawn on its own — and computing them apart invites a
 * renderer to draw a dependency twice, or not at all.
 */
export function serviceConnections(
  graph: Graph,
  serviceId: string,
  limit: number = MAX_DRAWER_PEERS,
  alsoOnLimit: number = MAX_LIST_PEERS,
): ServiceConnections {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const direct: NetworkPeerView[] = [];
  for (const e of graph.edges) {
    if (e.kind !== "depends_on" || !showsDirectDependency(e)) continue;
    const far = e.source === serviceId ? e.target : e.target === serviceId ? e.source : undefined;
    if (!far) continue;
    const node = nodes.get(far);
    if (node?.kind !== "service") continue;
    direct.push({
      id: node.id,
      stack: node.stack ?? "",
      service: node.label,
      relation: e.source === serviceId ? "depends-on" : "required-by",
      ...(e.declaredBy
        ? {
            declared: true,
            file: e.declaredBy.file,
            ...(e.declaredBy.detail ? { detail: e.declaredBy.detail } : {}),
          }
        : {}),
    });
  }
  direct.sort((a, b) => RELATION_ORDER[a.relation] - RELATION_ORDER[b.relation]);
  return { links: networkLinks(graph, serviceId, limit, alsoOnLimit), direct };
}

/**
 * Sort key for peers within a network. Stable, so two rescans of one fleet order the
 * same peers the same way.
 */
const RELATION_ORDER: Record<NetworkRelation, number> = {
  "depends-on": 0,
  "required-by": 1,
  peer: 2,
};

/**
 * The dependency between `a` and `b` that `net` carries, if any, and which way it runs.
 *
 * A dependency counts only when the network is one of those the pair actually shares —
 * `via` — so a service that depends on a sibling over the stack's own network is not
 * drawn as depending on it over an unrelated external one they also both happen to join.
 *
 * `undefined` for a pair that merely shares the network. The edge comes back with the
 * answer because whether the dependency was observed or declared is on it, and the caller
 * has to be able to say which.
 */
function dependencyOver(
  graph: Graph,
  a: string,
  b: string,
  net: string,
): { relation: DependencyRelation; edge: GraphEdge } | undefined {
  for (const e of graph.edges) {
    if (e.kind !== "depends_on" || !e.via?.includes(net)) continue;
    if (e.source === a && e.target === b) return { relation: "depends-on", edge: e };
    if (e.source === b && e.target === a) return { relation: "required-by", edge: e };
  }
  return undefined;
}

/** One network and everything it connects, for the fleet-level Networks section. */
export interface NetworkGroup {
  id: string;
  name: string;
  scope: NetworkScope;
  memberCount: number;
  stackCount: number;
  /**
   * Every scanned service on it, in scan order.
   *
   * A membership list, and only that: being on this network with twenty others says each
   * of them can reach the rest, not that any of them needs another. What the network
   * actually connects is `pairs`.
   */
  members: ServiceRefView[];
  /** The dependencies this network carries, dependent first. */
  pairs: NetworkPairView[];
}

/** One dependency a network carries, as the fleet-level list shows it. */
export interface NetworkPairView {
  from: ServiceRefView;
  to: ServiceRefView;
  /** Stated in a sidecar rather than read from a compose file, with the file that said so. */
  declared?: boolean;
  file?: string;
}

/**
 * Every network that connects something, most connecting first.
 *
 * Ordered by stacks joined, then services joined, then name: a network spanning six
 * stacks is the one a reader came to find, and a name breaks ties so the order does not
 * depend on scan order.
 *
 * Filtered by the same {@link showsNetworkNode} rule the fleet graph draws with, so the
 * list and the picture contain the same networks by construction.
 */
export function networkGroups(graph: Graph): NetworkGroup[] {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const ref = (id: string): ServiceRefView | undefined => {
    const node = nodes.get(id);
    if (!node || node.kind !== "service") return undefined;
    return { id: node.id, stack: node.stack ?? "", service: node.label };
  };

  const groups: NetworkGroup[] = [];
  for (const node of graph.nodes) {
    if (node.kind !== "network" || !showsNetworkNode(node)) continue;
    const members = graph.edges
      .filter((e) => e.kind === "network" && e.target === node.id)
      .map((e) => ref(e.source))
      .filter((r): r is ServiceRefView => Boolean(r));
    const pairs = graph.edges
      .filter((e) => e.kind === "depends_on" && e.via?.includes(node.label))
      .map((e) => ({
        from: ref(e.source),
        to: ref(e.target),
        ...(e.declaredBy ? { declared: true, file: e.declaredBy.file } : {}),
      }))
      .filter((p): p is NetworkPairView => Boolean(p.from && p.to));
    groups.push({
      id: node.id,
      name: node.label,
      scope: node.scope ?? "external",
      memberCount: node.memberCount ?? members.length,
      stackCount: node.stackCount ?? 1,
      members,
      pairs,
    });
  }
  groups.sort(
    (a, b) => b.stackCount - a.stackCount || b.memberCount - a.memberCount || a.name.localeCompare(b.name),
  );
  return groups;
}
