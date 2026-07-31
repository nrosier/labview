import { useEffect, useRef, useState } from "preact/hooks";
import cytoscape from "cytoscape";
import type { Core, ElementDefinition, NodeSingular } from "cytoscape";
import type { Graph } from "../model";
import { INGRESS_META, isDarkTheme, resolveVar } from "../lib/palette";

/**
 * Full relationship graph. Service nodes are colored by ingress exposure and
 * shaped by kind; networks, volumes and the Cloudflare/Traefik/Authentik hubs
 * are distinct shapes so the topology reads at a glance. Clicking a service
 * opens its detail drawer.
 */
export function GraphView({
  graph,
  themeKey,
  onOpenService,
}: {
  graph: Graph;
  themeKey: string;
  onOpenService: (stackId: string, serviceName: string) => void;
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

    const elements: ElementDefinition[] = [
      ...graph.nodes.map((n) => ({ data: { ...n } })),
      ...graph.edges.map((e) => ({ data: { ...e } })),
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
            shape: "round-rectangle",
            "background-color": c.surface,
            "border-color": resolveVar("--node-network"),
            "border-width": 2,
            color: c.ink,
          },
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
          selector: 'edge[kind = "depends_on"]',
          style: {
            "target-arrow-shape": "triangle",
            "target-arrow-color": edgeColor.depends_on!,
            "line-style": "dashed",
          },
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
          <span class="item">{swatch("--ing-public", "round")} public</span>
          <span class="item">{swatch("--ing-local", "round")} local</span>
          <span class="item">{swatch("--ing-hostport", "round")} host port</span>
          <span class="item">{swatch("--ing-internal", "round")} internal</span>
          <span class="item">{swatch("--hub-traefik", "round")} proxy hop</span>
          <span class="item">{swatch("--node-network")} network</span>
          <span class="item">{swatch("--node-volume", "diamond")} volume</span>
          <span class="item">{swatch("--hub-auth", "diamond")} hub</span>
        </div>
      </div>
      <div id="cy" ref={container} />
    </div>
  );
}
