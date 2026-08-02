import { useEffect, useMemo, useState } from "preact/hooks";
import type { Graph, NetworkGroup } from "../model";
import { MAX_LIST_PEERS, hiddenNetworksNote, networkGroups, networkScopeMeta } from "../model";

/**
 * Every network that connects two or more services, and what it connects.
 *
 * The fleet graph shows the same networks as a picture, and a picture is the wrong shape
 * for one question a reader keeps asking: *which* services are on this network? A node
 * with a cap of twelve spokes cannot answer it, and a fifty-spoke node answers it
 * illegibly. This list answers it exactly, in text, with no layout engine involved — and
 * it is the target the graph's network nodes link to.
 *
 * Membership and dependency are one relation here, as everywhere else in this feature: a
 * row names the services on the network, then the dependencies that travel over it. Which
 * rows exist is decided by `showsNetworkNode` inside `networkGroups`, the same rule the
 * graph draws with, so the two cannot disagree about which networks matter.
 */
export function NetworksSection({
  graph,
  soloLocalNetworks,
  highlight,
  onOpenService,
}: {
  graph: Graph;
  /**
   * Stack-local networks with a single service on them — the ones deliberately left out.
   * Stated in the header rather than dropped silently, since a list that hides a third of
   * the networks reads exactly like a fleet that has none.
   */
  soloLocalNetworks: number;
  /** A network name to open at and mark, set when a graph node was tapped. */
  highlight?: string | null;
  onOpenService: (stackId: string, serviceName: string) => void;
}) {
  const groups = useMemo(() => networkGroups(graph), [graph]);
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // A tap on a network node in the graph lands here, so the row it means has to be
  // visible and findable — opening the list is part of answering.
  useEffect(() => {
    if (!highlight) return;
    setOpen(true);
    const el = document.getElementById(rowId(highlight));
    el?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [highlight, groups]);

  if (groups.length === 0 && soloLocalNetworks === 0) return null;

  const connecting = groups.filter((g) => g.memberCount >= 2).length;
  const crossStack = groups.filter((g) => g.stackCount >= 2).length;

  return (
    <div class="netpanel">
      <button class="netpanel-head" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <span class="caret">{open ? "▾" : "▸"}</span>
        <h3>Networks</h3>
        <span class="muted-inline">
          {connecting} connect two or more services
          {crossStack > 0 && ` · ${crossStack} span two or more stacks`}
        </span>
      </button>
      {open && (
        <div class="netpanel-body">
          {groups.map((g) => (
            <Row
              key={g.id}
              group={g}
              marked={g.name === highlight}
              expanded={expanded.has(g.id)}
              onExpand={() =>
                setExpanded((prev) => {
                  const next = new Set(prev);
                  next.add(g.id);
                  return next;
                })
              }
              onOpenService={onOpenService}
            />
          ))}
          {/* The omission, in words. */}
          {soloLocalNetworks > 0 && <div class="muted-inline">{hiddenNetworksNote(soloLocalNetworks)}</div>}
        </div>
      )}
    </div>
  );
}

function Row({
  group,
  marked,
  expanded,
  onExpand,
  onOpenService,
}: {
  group: NetworkGroup;
  marked: boolean;
  expanded: boolean;
  onExpand: () => void;
  onOpenService: (stackId: string, serviceName: string) => void;
}) {
  const scope = networkScopeMeta(group.scope);
  const shown = expanded ? group.members : group.members.slice(0, MAX_LIST_PEERS);
  const omitted = group.members.length - shown.length;

  return (
    <div class={`netrow${marked ? " marked" : ""}`} id={rowId(group.name)}>
      <div class="nethead">
        <span class="mono">{group.name}</span>
        <span class="pill" title={scope.title}>
          {scope.label}
        </span>
        <span class="muted-inline">
          {group.memberCount} {group.memberCount === 1 ? "service" : "services"}
          {group.stackCount >= 2 && ` · ${group.stackCount} stacks`}
        </span>
      </div>
      <div class="chips">
        {shown.map((m) => (
          <button
            key={m.id}
            class="chip"
            onClick={() => onOpenService(m.stack, m.service)}
            title={`Open ${m.stack}/${m.service}`}
          >
            {m.service}
            <span class="pill">{m.stack}</span>
          </button>
        ))}
        {omitted > 0 && (
          <button class="chip" onClick={onExpand}>
            +{omitted} more
          </button>
        )}
      </div>
      {/* The dependencies this network carries. In the graph these are arrowheads on the
          spokes, which cannot say which arrow pairs with which once two dependencies cross
          the same network; here the pair is named outright. */}
      {group.pairs.map((p) => (
        <div class="netpair" key={`${p.from.id}->${p.to.id}`}>
          <span class="mono">{p.from.service}</span> depends on <span class="mono">{p.to.service}</span> over
          this network
        </div>
      ))}
    </div>
  );
}

/**
 * A stable DOM id per network row, so a tap on a graph node can scroll to it.
 *
 * Network names contain characters that are not valid in a CSS selector, which is why the
 * lookup is `getElementById` and not `querySelector`.
 */
function rowId(name: string): string {
  return `net-row-${name}`;
}
