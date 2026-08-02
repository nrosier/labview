import type { AppStack, Service, ServiceConnections } from "../model";
import { primaryIngress } from "../model";
import { resolveVar, ingressVar } from "./palette";

/**
 * Build a Mermaid `flowchart` definition for a single service, showing how it is
 * reached (Cloudflare / Traefik), what protects it (Authentik / basic auth),
 * which networks it joins **and who else is on them**, which named volumes / shared binds
 * it uses, and what it depends on. Colors are resolved from the live CSS palette so the
 * diagram matches the current theme (the component re-renders on theme change).
 *
 * Networks and dependencies are one block, not two. A network is drawn with the services
 * it joins on the far side of it, and a dependency is drawn as the path it travels —
 * `svc ==> net ==> peer` — so the network sits between the two services rather than
 * dangling off one of them while a separate arrow connects them directly. Direction is
 * the entire encoding, as in the fleet graph: no leg touching a network node is labelled,
 * because any wording for it would describe the network as the party to the relation.
 *
 * @param conn what the graph says this service is connected to, from
 * `serviceConnections()`. Peers are already capped there; `conn.direct` holds the
 * dependencies no network carries, which are the only ones still drawn service-to-service.
 */
export function buildServiceMermaid(svc: Service, stack: AppStack, conn: ServiceConnections): string {
  const lines: string[] = ["flowchart LR"];
  let n = 0;
  const ids = new Map<string, string>();
  const id = (key: string): string => {
    let existing = ids.get(key);
    if (existing) return existing;
    existing = `n${n++}`;
    ids.set(key, existing);
    return existing;
  };
  const esc = (s: string): string => s.replace(/"/g, "'").replace(/[\r\n]+/g, " ").trim();
  // A tunnel hostname and the proxy router serving it describe the same link, so
  // an edge is kept once no matter how many routes assert it.
  const seenEdge = new Set<string>();
  const edge = (line: string): void => {
    if (seenEdge.has(line)) return;
    seenEdge.add(line);
    lines.push(line);
  };

  // Node shapes: () rounded = service, [[ ]] subroutine = external hub,
  // ([ ]) stadium = network, [( )] cylinder = volume.
  const svcId = id(`svc:${svc.name}`);
  lines.push(`  ${svcId}("${esc(svc.name)}")`);
  lines.push(`  class ${svcId} svc`);

  /**
   * The service a tunnel origin resolved to, drawn as the service it is — rounded
   * like any other, since it is one — but coloured as the proxy it was observed to
   * act as. Named from `hopKey`, qualified by stack only when it lives elsewhere.
   */
  const definedHops = new Set<string>();
  const hopNode = (hopKey: string): string => {
    const nid = id(`hop:${hopKey}`);
    if (!definedHops.has(hopKey)) {
      definedHops.add(hopKey);
      const slash = hopKey.indexOf("/");
      const sameStack = slash > 0 && hopKey.slice(0, slash) === stack.id;
      lines.push(`  ${nid}("${esc(sameStack ? hopKey.slice(slash + 1) : hopKey)}")`);
      lines.push(`  class ${nid} tf`);
    }
    return nid;
  };

  // Ingress: Cloudflare tunnel (public). A route whose origin resolved to another
  // scanned service is drawn through that service — the hop the configuration
  // names — instead of as a straight line to this container. Every other kind of
  // origin keeps the direct edge, since no hop was established.
  const cfRoutes = svc.cloudflare.filter((r) => r.hostname);
  let hopId: string | undefined;
  if (cfRoutes.length) {
    const cf = id("hub:cf");
    lines.push(`  ${cf}[["Cloudflare Tunnel"]]`);
    lines.push(`  class ${cf} cf`);
    for (const r of cfRoutes) {
      const host = esc(r.hostname!);
      const hopKey = r.origin?.kind === "fleet-service" ? r.origin.hopKey : undefined;
      if (hopKey) {
        const hop = hopNode(hopKey);
        hopId ??= hop;
        edge(`  ${cf} ==>|"${host}"| ${hop}`);
        edge(`  ${hop} -->|"${host}"| ${svcId}`);
      } else {
        edge(`  ${cf} ==>|"${host}"| ${svcId}`);
      }
    }
  }
  // Ingress: proxy routes (local). They start at the resolved hop when there is
  // one — that service was observed to front this one, so drawing a second,
  // synthetic proxy beside it would claim two hops where the config shows one.
  //
  // Routers the proxy's API reported count as routes here even when no label declares
  // them: a file-provider route reaches this service exactly as a labelled one does,
  // and leaving it out would draw a service the proxy is serving as unreachable. Only
  // routers the proxy is actually serving are drawn, for the same reason.
  const liveRouters = (svc.traefikLive ?? []).filter(
    (r) => r.errors.length === 0 && (!r.status || r.status.toLowerCase() === "enabled"),
  );
  const tHosts = [
    ...new Set([...svc.traefik.flatMap((r) => r.hosts), ...liveRouters.flatMap((r) => r.hosts)]),
  ];
  const hasTraefik = svc.traefik.length > 0 || liveRouters.length > 0;
  if (hasTraefik) {
    let tf = hopId;
    if (!tf) {
      tf = id("hub:tf");
      lines.push(`  ${tf}[["Traefik"]]`);
      lines.push(`  class ${tf} tf`);
    }
    const labels = tHosts.length ? tHosts : ["route"];
    for (const h of labels) edge(`  ${tf} -->|"${esc(h)}"| ${svcId}`);
  }

  // Auth posture (dashed "protected by" edge). The node is named after whatever
  // the scan could establish: the provider when it was identified, otherwise the
  // mechanism alone — never the vendor it most likely is.
  if (svc.auth.method !== "none") {
    const isAk = svc.auth.method.startsWith("authentik");
    const ak = id(isAk ? "hub:ak" : "hub:auth");
    const label = isAk
      ? "Authentik"
      : svc.auth.method === "basic-auth"
        ? "Basic auth"
        : svc.auth.method === "ldap"
          ? "LDAP directory"
          : svc.auth.method === "forward-auth"
            ? "Forward-auth (unidentified)"
            : "OAuth";
    lines.push(`  ${ak}[["${label}"]]`);
    lines.push(`  class ${ak} auth`);
    lines.push(`  ${svcId} -.->|"${esc(svc.auth.method)}"| ${ak}`);
  }

  // Networks, and through them the services on the other side. Real docker names, so a
  // stack-local network and an `external:` one shared by six stacks are told apart —
  // by name, by the counts in the label and by the classDef.
  // A peer can sit on two of this service's networks; it is one node with two legs.
  const definedPeers = new Set<string>();
  const peerNode = (key: string, label: string, cls: string): string => {
    const nid = id(key);
    if (!definedPeers.has(key)) {
      definedPeers.add(key);
      lines.push(`  ${nid}("${esc(label)}")`);
      lines.push(`  class ${nid} ${cls}`);
    }
    return nid;
  };
  for (const link of conn.links) {
    const nid = id(`net:${link.name}`);
    const counts = [`${link.memberCount} ${link.memberCount === 1 ? "service" : "services"}`];
    if (link.stackCount >= 2) counts.push(`${link.stackCount} stacks`);
    lines.push(`  ${nid}(["net: ${esc(link.name)} · ${counts.join(" · ")}"])`);
    lines.push(`  class ${nid} ${link.scope === "stack-local" ? "netlocal" : "net"}`);

    // The leg to this service, directed by what crosses the network: away from it where
    // it is the dependent, towards it where something on the network needs it, both ways
    // where both are true, and undirected where the network only makes them reachable.
    const out = link.peers.some((p) => p.relation === "depends-on");
    const inn = link.peers.some((p) => p.relation === "required-by");
    edge(out && inn ? `  ${svcId} <==> ${nid}` : out ? `  ${svcId} ==> ${nid}` : inn ? `  ${nid} ==> ${svcId}` : `  ${svcId} --- ${nid}`);

    for (const p of link.peers) {
      const label = p.stack === stack.id ? p.service : `${p.stack}/${p.service}`;
      const pid = peerNode(`peer:${p.id}`, label, "dep");
      edge(
        p.relation === "depends-on"
          ? `  ${nid} ==> ${pid}`
          : p.relation === "required-by"
            ? `  ${pid} ==> ${nid}`
            : `  ${nid} --- ${pid}`,
      );
    }
    // What the cap left out, said rather than dropped: a network shared by fifty
    // services must not silently look like one shared by eight.
    if (link.omitted > 0) {
      const mid = id(`more:${link.name}`);
      lines.push(`  ${mid}(["+${link.omitted} more services"])`);
      lines.push(`  class ${mid} more`);
      edge(`  ${nid} --- ${mid}`);
    }
  }

  // Named volumes + binds
  for (const m of svc.mounts) {
    if (!m.source) continue;
    const vid = id(`vol:${m.type}:${m.source}`);
    const shape = `[("${esc(m.source)}${m.readOnly ? " (ro)" : ""}")]`;
    lines.push(`  ${vid}${shape}`);
    lines.push(`  class ${vid} vol`);
    lines.push(`  ${svcId} --> ${vid}`);
  }

  // depends_on that no network carries — the only dependency still drawn as a line
  // straight between two services, because there is no network to draw it through.
  // Dotted and labelled with what that means: docker orders the two containers, and
  // neither can reach the other. Everything else is above, routed through its network.
  for (const dep of conn.direct) {
    const did = peerNode(`peer:${dep.id}`, dep.service, "dep");
    edge(`  ${svcId} -. "depends on, no shared network" .-> ${did}`);
  }

  // classDefs resolved from the live palette
  const ink = resolveVar("--ink");
  const surface = resolveVar("--surface-2");
  const border = resolveVar("--baseline");
  const styleFor = (fill: string, text = "#ffffff") =>
    `fill:${fill},stroke:${border},color:${text},stroke-width:1px`;
  // One `classDef` means one colour, so the most exposed kind wins here too.
  lines.push(`  classDef svc ${styleFor(resolveVar(ingressVar(primaryIngress(svc.ingress))))}`);
  lines.push(`  classDef cf ${styleFor(resolveVar("--hub-cloudflare"))}`);
  lines.push(`  classDef tf ${styleFor(resolveVar("--hub-traefik"))}`);
  lines.push(`  classDef auth ${styleFor(resolveVar("--hub-auth"))}`);
  lines.push(`  classDef net fill:${surface},stroke:${resolveVar("--node-network")},color:${ink},stroke-width:1.5px`);
  // A stack-local network reads as the weaker boundary it is — dashed here and in the
  // fleet graph — since only this stack's own services can ever join it.
  lines.push(
    `  classDef netlocal fill:${surface},stroke:${resolveVar("--node-network")},color:${ink},stroke-width:1.5px,stroke-dasharray: 4 3`,
  );
  lines.push(`  classDef vol fill:${surface},stroke:${resolveVar("--node-volume")},color:${ink},stroke-width:1.5px`);
  lines.push(`  classDef dep fill:${surface},stroke:${border},color:${ink},stroke-width:1px`);
  lines.push(`  classDef more fill:${surface},stroke:${border},color:${resolveVar("--muted")},stroke-width:1px,stroke-dasharray: 3 3`);
  return lines.join("\n");
}
