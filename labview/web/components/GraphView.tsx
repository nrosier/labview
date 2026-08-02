import { useEffect, useRef, useState } from "preact/hooks";
import cytoscape from "cytoscape";
import type { Core, ElementDefinition, NodeSingular } from "cytoscape";
import type { Graph, GraphEdge } from "../model";
import {
  NETWORK_SCOPES,
  networkNodeLabel,
  showsDirectDependency,
  showsNetworkNode,
  visibleSpokes,
} from "../model";
import { INGRESS_META, ingressLabel, isDarkTheme, resolveVar } from "../lib/palette";

/**
 * Full relationship graph. Service nodes are colored by ingress exposure and
 * shaped by kind; networks, volumes and the Cloudflare/Traefik/Authentik hubs
 * are distinct shapes so the topology reads at a glance. Clicking a service
 * opens its detail drawer.
 *
 * Two services that share a network are connected *through* it: the network sits in the
 * middle and the arrowheads sit on the two membership edges either side, so following
 * them reads dependent → network → dependency. A line straight between two services
 * appears only where they share no network at all — see `showsDirectDependency`.
 *
 * This is the one view where a plain membership spoke belongs: it is the fleet's membership
 * picture, and a spoke says "attached", which is true. What a spoke never gets is an
 * arrowhead from co-membership alone — only a dependency puts one there, and a dependency
 * comes from a compose `depends_on` or a `.labview` sidecar, never from sharing a network.
 * A dependency that was declared rather than observed is **dashed** wherever it appears:
 * the arrowhead means the same thing, but the line says the scan is repeating a statement
 * instead of reporting a measurement (invariant I1).
 *
 * What gets drawn is not decided here. `showsNetworkNode`, `visibleSpokes` and
 * `networkNodeLabel` are pure functions in `model/networks.ts`, which is what makes the
 * cap and the visibility rule assertable and keeps this view and the Networks section
 * showing the same set of networks.
 */
export function GraphView({
  graph,
  themeKey,
  onOpenService,
  onOpenNetwork,
}: {
  graph: Graph;
  themeKey: string;
  onOpenService: (stackId: string, serviceName: string) => void;
  /** Reveal a network's row in the Networks section, which names every member. */
  onOpenNetwork?: (name: string) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    if (!container.current) return;

    const c = {
      ink: resolveVar("--ink"),
      muted: resolveVar("--muted"),
      baseline: resolveVar("--baseline"),
      gridline: resolveVar("--gridline"),
      surface: resolveVar("--surface"),
    };
    // Derived from INGRESS_META so a new ingress kind cannot silently fall back
    // to the muted default here while the badges and bars show it correctly.
    const ingressColor: Record<string, string> = Object.fromEntries(
      INGRESS_META.map((m) => [m.key, resolveVar(m.cssVar)]),
    );
    const hub: Record<string, string> = {
      "ext:cloudflare": resolveVar("--hub-cloudflare"),
      "ext:traefik": resolveVar("--hub-traefik"),
      "ext:authentik": resolveVar("--hub-auth"),
      "ext:auth": resolveVar("--hub-auth"),
    };
    const edgeColor: Record<string, string> = {
      network: c.gridline,
      depends_on: resolveVar("--c8"),
      volume: resolveVar("--node-volume"),
      ingress: c.muted,
      auth: resolveVar("--hub-auth"),
    };

    // Membership edges per network, so each network's spokes can be capped as a set —
    // and so a network node whose spokes are all dropped drops with them.
    const spokesByNet = new Map<string, GraphEdge[]>();
    for (const e of graph.edges) {
      if (e.kind !== "network") continue;
      const list = spokesByNet.get(e.target);
      if (list) list.push(e);
      else spokesByNet.set(e.target, [e]);
    }

    const nodes: ElementDefinition[] = [];
    const spokeEdges: ElementDefinition[] = [];
    for (const n of graph.nodes) {
      if (n.kind !== "network") {
        nodes.push({ data: { ...n } });
        continue;
      }
      if (!showsNetworkNode(n)) continue;
      const { kept } = visibleSpokes(spokesByNet.get(n.id) ?? []);
      // `drawn` is the spoke count, not the member count: the label has to report what
      // the reader can see beside it, and say how many it cannot.
      nodes.push({ data: { ...n, display: networkNodeLabel(n, kept.length) } });
      for (const e of kept) spokeEdges.push({ data: { ...e } });
    }

    const shown = new Set(nodes.map((n) => String((n.data as { id: string }).id)));
    const elements: ElementDefinition[] = [
      ...nodes,
      ...spokeEdges,
      // Everything else, minus the dependencies now drawn through a network and anything
      // pointing at a network that was dropped.
      ...graph.edges
        .filter((e) => e.kind !== "network" && showsDirectDependency(e))
        .filter((e) => shown.has(e.source) && shown.has(e.target))
        .map((e) => ({ data: { ...e } })),
    ];

    const cy = cytoscape({
      container: container.current,
      elements,
      wheelSensitivity: 0.25,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: c.ink,
            "font-size": 9,
            "font-family": 'system-ui, -apple-system, "Segoe UI", sans-serif',
            "text-valign": "bottom",
            "text-margin-y": 3,
            "text-wrap": "wrap",
            "text-max-width": "90px",
            width: 22,
            height: 22,
            "border-width": 1,
            "border-color": c.baseline,
          },
        },
        {
          selector: 'node[kind = "service"]',
          style: {
            shape: "ellipse",
            "background-color": (ele: NodeSingular) => ingressColor[ele.data("ingress")] ?? c.muted,
          },
        },
        {
          // A service that another service's tunnel origin resolved to. It stays a
          // service node — same shape, same click target, same drawer — but reads as
          // the infrastructure it was observed to act as. Declared after the service
          // rule so it wins on colour.
          selector: 'node[role = "proxy"]',
          style: {
            "background-color": resolveVar("--hub-traefik"),
            width: 30,
            height: 30,
            "border-width": 2,
            "font-weight": "bold" as unknown as number,
          },
        },
        {
          selector: 'node[kind = "network"]',
          style: {
            // The counts belong on the node: its spokes are capped, so a reader counting
            // lines would be reading a number that is not there.
            label: "data(display)",
            shape: "round-rectangle",
            "background-color": c.surface,
            "border-color": resolveVar("--node-network"),
            "border-width": 2,
            color: c.ink,
          },
        },
        {
          // A stack-local network can only ever carry one stack's own services, so it is
          // drawn as the weaker boundary it is — dashed against the solid border of an
          // external one, which anything outside the scan may also be on.
          selector: 'node[scope = "stack-local"]',
          style: { "border-style": "dashed" },
        },
        {
          selector: 'node[kind = "volume"]',
          style: {
            shape: "hexagon",
            "background-color": c.surface,
            "border-color": resolveVar("--node-volume"),
            "border-width": 2,
            color: c.ink,
          },
        },
        {
          selector: 'node[kind = "external"]',
          style: {
            shape: "diamond",
            width: 34,
            height: 34,
            "font-size": 10,
            "font-weight": "bold" as unknown as number,
            "background-color": (ele: NodeSingular) => hub[ele.data("id")] ?? c.muted,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.2,
            "line-color": (ele) => edgeColor[ele.data("kind")] ?? c.gridline,
            "curve-style": "bezier",
            opacity: 0.7,
          },
        },
        {
          // Only survives where the pair shares no network — compose orders their
          // startup, but neither can address the other. Drawn as the oddity it is.
          selector: 'edge[kind = "depends_on"]',
          style: {
            "target-arrow-shape": "triangle",
            "target-arrow-color": edgeColor.depends_on!,
            "line-style": "dashed",
          },
        },
        {
          // A membership edge carrying a dependency: same colour as the direct edge it
          // replaces, and full opacity, so the path dependent → network → dependency
          // stands out from the plain membership lines around it.
          selector: "edge[flow]",
          style: {
            "line-color": edgeColor.depends_on!,
            "arrow-scale": 0.9,
            width: 1.8,
            opacity: 1,
          },
        },
        {
          // Arrowhead at the network end: this service depends on something else on it.
          selector: 'edge[flow = "to-network"], edge[flow = "both"]',
          style: {
            "target-arrow-shape": "triangle",
            "target-arrow-color": edgeColor.depends_on!,
          },
        },
        {
          // Arrowhead at the service end: something else on the network depends on it.
          selector: 'edge[flow = "to-service"], edge[flow = "both"]',
          style: {
            "source-arrow-shape": "triangle",
            "source-arrow-color": edgeColor.depends_on!,
          },
        },
        {
          // A membership spoke whose only dependency was declared: dashed against the solid
          // line of an observed one, so the arrowhead can mean the same thing while the line
          // says the scan is repeating a statement. A spoke carrying both kinds stays solid
          // — something crossing it *was* observed.
          selector: 'edge[flowSource = "declared"]',
          style: { "line-style": "dashed" },
        },
        {
          // The same provenance on a direct edge, where dashed is already taken: that edge
          // exists only because the pair shares no network, and dropping that meaning to
          // show provenance would trade one fact for another. Dotted says both.
          selector: "edge[declaredBy]",
          style: { "line-style": "dotted" },
        },
        {
          selector: 'edge[kind = "auth"]',
          style: { "line-style": "dotted", width: 1.6, "line-color": edgeColor.auth! },
        },
        {
          selector: 'edge[kind = "volume"]',
          style: { "line-style": "dotted" },
        },
        {
          selector: ".dim",
          style: { opacity: 0.12 },
        },
        {
          selector: ".hit",
          style: { "border-width": 3, "border-color": resolveVar("--c1") },
        },
      ],
      layout: {
        name: "cose",
        animate: false,
        nodeRepulsion: () => 12000,
        idealEdgeLength: () => 90,
        padding: 24,
      } as cytoscape.LayoutOptions,
    });

    cy.on("tap", 'node[kind = "service"]', (evt) => {
      const n = evt.target as NodeSingular;
      const stackId = n.data("stack");
      const label = n.data("label");
      if (stackId && label) onOpenService(stackId, label);
    });

    // A network node answers "who else is on this", which the capped spokes beside it
    // cannot. Tapping it goes to the row that names every member.
    cy.on("tap", 'node[kind = "network"]', (evt) => {
      const name = (evt.target as NodeSingular).data("label");
      if (name) onOpenNetwork?.(name);
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, themeKey]);

  // Search highlight
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass("dim hit");
      const q = query.trim().toLowerCase();
      if (!q) return;
      const matches = cy.nodes().filter((n) => String(n.data("label") ?? "").toLowerCase().includes(q));
      if (matches.length === 0) return;
      const keep = matches.union(matches.neighborhood());
      cy.elements().not(keep).addClass("dim");
      matches.addClass("hit");
    });
  }, [query]);

  const dark = isDarkTheme();
  const swatch = (v: string, cls = "") => <span class={`swatch ${cls}`} style={`background:var(${v})`} />;
  /** A network, drawn as the node is: outlined, and dashed when only one stack can join it. */
  const netSwatch = (dashed: boolean) => (
    <span
      class="swatch"
      style={`background:var(--surface);border:1.5px ${dashed ? "dashed" : "solid"} var(--node-network)`}
    />
  );
  /** A dependency, drawn as its line is: solid where observed, dashed where only declared. */
  const depSwatch = (declared: boolean) => (
    <span
      class="swatch"
      style={`background:${declared ? "transparent" : "var(--c8)"};border:1.5px ${declared ? "dashed" : "solid"} var(--c8)`}
    />
  );

  return (
    <div class="graph-panel">
      <div class="graph-toolbar">
        <input
          type="search"
          placeholder="Highlight node…"
          value={query}
          onInput={(e) => setQuery((e.target as HTMLInputElement).value)}
          style="flex:0 1 200px;padding:6px 10px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--ink);font:inherit;"
        />
        <button class="btn" onClick={() => cyRef.current?.fit(undefined, 30)}>
          Fit
        </button>
        <button
          class="btn"
          onClick={() =>
            cyRef.current?.layout({ name: "cose", animate: true } as cytoscape.LayoutOptions).run()
          }
        >
          Re-layout
        </button>
        <div class="spacer" style="flex:1" />
        <div class="graph-legend" aria-hidden={dark ? "false" : "false"}>
          {/* Derived from INGRESS_META, like the node colours themselves — a legend with
              its own list of kinds drifts from the graph the moment one is added or
              renamed, and did. */}
          {INGRESS_META.map((m) => (
            <span class="item" key={m.key}>
              {swatch(m.cssVar, "round")} {ingressLabel(m.key).toLowerCase()}
            </span>
          ))}
          <span class="item">{swatch("--hub-traefik", "round")} proxy hop</span>
          {NETWORK_SCOPES.map((s) => (
            <span class="item" key={s.key} title={s.title}>
              {netSwatch(s.key === "stack-local")} {s.label.toLowerCase()} network
            </span>
          ))}
          <span class="item" title="A dependency drawn through the network that carries it: the arrowhead points from the dependent towards the network, and on again to the service it needs. Sharing a network is not one — a spoke with no arrowhead says only that the service is attached.">
            {depSwatch(false)} dependency
          </span>
          <span class="item" title="A dependency stated in a .labview sidecar rather than read from a compose file — the only way to state one across stacks. Drawn the same way, dashed, because it was taken on the operator's word.">
            {depSwatch(true)} declared dependency
          </span>
          <span class="item">{swatch("--node-volume", "diamond")} volume</span>
          <span class="item">{swatch("--hub-auth", "diamond")} hub</span>
        </div>
      </div>
      <div id="cy" ref={container} />
    </div>
  );
}
