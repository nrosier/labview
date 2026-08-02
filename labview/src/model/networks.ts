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
 * What one service is to another across a shared network.
 *
 *  - `depends-on` — this service declares `depends_on` the peer.
 *  - `required-by` — the peer declares `depends_on` this service.
 *  - `peer` — neither; they are simply on the same network and can reach each other.
 *
 * `peer` is not a weaker answer. A backup service and the databases it reads declare no
 * dependency on each other at all, and the shared network is the entire relationship.
 */
export type NetworkRelation = "depends-on" | "required-by" | "peer";

/** How a relation is worded wherever it is shown. */
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

export interface NetworkPeerView extends ServiceRefView {
  relation: NetworkRelation;
}

/** One network a service is on, and who else is on it. */
export interface NetworkLink {
  /** Graph node id, `net:<name>`. */
  id: string;
  name: string;
  scope: NetworkScope;
  memberCount: number;
  stackCount: number;
  /** Peers, dependencies first, capped at the caller's limit. */
  peers: NetworkPeerView[];
  /** Peers beyond the cap. */
  omitted: number;
}

/**
 * Every network one service is on, with the other services on each.
 *
 * Read off the complete graph, so it is exact even for a network whose spokes the fleet
 * view caps — this is the view that answers "and who else is on it", which is the whole
 * question a dangling `net: x` node never answered.
 *
 * Dependencies come first within a network and are never dropped by the cap: `peers`
 * fills with `depends-on`, then `required-by`, then plain peers in scan order.
 */
export function networkLinks(
  graph: Graph,
  serviceId: string,
  limit: number = MAX_DRAWER_PEERS,
): NetworkLink[] {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const membership = graph.edges.filter((e) => e.kind === "network");
  const links: NetworkLink[] = [];

  for (const own of membership) {
    if (own.source !== serviceId) continue;
    const net = nodes.get(own.target);
    if (!net || net.kind !== "network") continue;

    const peers: NetworkPeerView[] = [];
    for (const other of membership) {
      if (other.target !== own.target || other.source === serviceId) continue;
      const node = nodes.get(other.source);
      if (!node || node.kind !== "service") continue;
      peers.push({
        id: node.id,
        stack: node.stack ?? "",
        service: node.label,
        relation: relationOver(graph, serviceId, node.id, net.label),
      });
    }
    peers.sort((a, b) => RELATION_ORDER[a.relation] - RELATION_ORDER[b.relation]);

    links.push({
      id: net.id,
      name: net.label,
      scope: net.scope ?? "external",
      memberCount: net.memberCount ?? peers.length + 1,
      stackCount: net.stackCount ?? 1,
      peers: peers.slice(0, Math.max(0, limit)),
      omitted: Math.max(0, peers.length - Math.max(0, limit)),
    });
  }
  return links;
}

/**
 * What to say about a network with no other scanned service on it.
 *
 * The two scopes need different words, and getting them the wrong way round would be a
 * false claim in one direction or the other. On a stack-local network nothing else *can*
 * be attached, so "nothing else is on it" is the whole truth. On an external one the scan
 * simply cannot see the far end — a container outside the scanned stacks may well be on
 * it — so the sentence has to stop at what was observed.
 *
 * Empty for a network that does have peers, so a caller can use it as the condition.
 */
export function peerlessNetworkText(link: NetworkLink): string {
  if (link.peers.length > 0) return "";
  return link.scope === "stack-local"
    ? "Nothing else is on it. It belongs to this stack's compose project, so only this stack's own services could be."
    : "No other scanned service is on it. It is external to the scanned stacks, so containers this scan cannot see may be.";
}

/** Everything one service's drawer says about what it is connected to. */
export interface ServiceConnections {
  /** Every network it is on, with the other services on each. */
  links: NetworkLink[];
  /**
   * Dependencies drawn as a direct arrow because no network carries them.
   *
   * Normally empty. A non-empty entry is the oddity {@link showsDirectDependency}
   * describes: compose orders the two containers' startup, yet neither can address the
   * other. The analyzer states it in words on the service's notes; this is the same fact
   * in the diagram.
   */
  direct: ServiceRefView[];
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
): ServiceConnections {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const direct: ServiceRefView[] = [];
  for (const e of graph.edges) {
    if (e.kind !== "depends_on" || e.source !== serviceId || !showsDirectDependency(e)) continue;
    const node = nodes.get(e.target);
    if (node?.kind === "service") {
      direct.push({ id: node.id, stack: node.stack ?? "", service: node.label });
    }
  }
  return { links: networkLinks(graph, serviceId, limit), direct };
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
 * What `a` is to `b` across the network `net`.
 *
 * A dependency counts only when the network is one of those the pair actually shares —
 * `via` — so a service that depends on a sibling over the stack's own network is not
 * drawn as depending on it over an unrelated external one they also both happen to join.
 */
function relationOver(graph: Graph, a: string, b: string, net: string): NetworkRelation {
  for (const e of graph.edges) {
    if (e.kind !== "depends_on" || !e.via?.includes(net)) continue;
    if (e.source === a && e.target === b) return "depends-on";
    if (e.source === b && e.target === a) return "required-by";
  }
  return "peer";
}

/** One network and everything it connects, for the fleet-level Networks section. */
export interface NetworkGroup {
  id: string;
  name: string;
  scope: NetworkScope;
  memberCount: number;
  stackCount: number;
  /** Every scanned service on it, in scan order. */
  members: ServiceRefView[];
  /** The dependencies this network carries, dependent first. */
  pairs: { from: ServiceRefView; to: ServiceRefView }[];
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
      .map((e) => ({ from: ref(e.source), to: ref(e.target) }))
      .filter((p): p is { from: ServiceRefView; to: ServiceRefView } => Boolean(p.from && p.to));
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
