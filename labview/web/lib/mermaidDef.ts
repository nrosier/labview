import type { AppStack, Service } from "../model";
import { resolveVar, ingressVar } from "./palette";

/**
 * Build a Mermaid `flowchart` definition for a single service, showing how it is
 * reached (Cloudflare / Traefik), what protects it (Authentik / basic auth),
 * which networks it joins, which named volumes / shared binds it uses, and what
 * it depends on. Colors are resolved from the live CSS palette so the diagram
 * matches the current theme (the component re-renders on theme change).
 */
export function buildServiceMermaid(svc: Service, stack: AppStack): string {
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

  // Node shapes: () rounded = service, [[ ]] subroutine = external hub,
  // ([ ]) stadium = network, [( )] cylinder = volume.
  const svcId = id(`svc:${svc.name}`);
  lines.push(`  ${svcId}("${esc(svc.name)}")`);
  lines.push(`  class ${svcId} svc`);

  // Ingress: Cloudflare tunnel (public)
  const cfHosts = svc.cloudflare.map((r) => r.hostname).filter(Boolean);
  if (cfHosts.length) {
    const cf = id("hub:cf");
    lines.push(`  ${cf}[["Cloudflare Tunnel"]]`);
    lines.push(`  class ${cf} cf`);
    for (const h of cfHosts) lines.push(`  ${cf} ==>|"${esc(h)}"| ${svcId}`);
  }
  // Ingress: Traefik (local)
  const tHosts = [...new Set(svc.traefik.flatMap((r) => r.hosts))];
  const hasTraefik = svc.traefik.length > 0;
  if (hasTraefik) {
    const tf = id("hub:tf");
    lines.push(`  ${tf}[["Traefik"]]`);
    lines.push(`  class ${tf} tf`);
    const labels = tHosts.length ? tHosts : ["route"];
    for (const h of labels) lines.push(`  ${tf} -->|"${esc(h)}"| ${svcId}`);
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

  // Networks
  for (const net of svc.networks) {
    const nid = id(`net:${net}`);
    lines.push(`  ${nid}(["net: ${esc(net)}"])`);
    lines.push(`  class ${nid} net`);
    lines.push(`  ${svcId} --- ${nid}`);
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

  // depends_on — always define the target node so it renders with a label
  // (a bare edge reference would render as the raw node id).
  for (const dep of svc.dependsOn) {
    const did = id(`dep:${dep}`);
    lines.push(`  ${did}("${esc(dep)}")`);
    lines.push(`  class ${did} dep`);
    lines.push(`  ${svcId} -->|"depends on"| ${did}`);
  }

  // classDefs resolved from the live palette
  const ink = resolveVar("--ink");
  const surface = resolveVar("--surface-2");
  const border = resolveVar("--baseline");
  const styleFor = (fill: string, text = "#ffffff") =>
    `fill:${fill},stroke:${border},color:${text},stroke-width:1px`;
  lines.push(`  classDef svc ${styleFor(resolveVar(ingressVar(svc.ingress)))}`);
  lines.push(`  classDef cf ${styleFor(resolveVar("--hub-cloudflare"))}`);
  lines.push(`  classDef tf ${styleFor(resolveVar("--hub-traefik"))}`);
  lines.push(`  classDef auth ${styleFor(resolveVar("--hub-auth"))}`);
  lines.push(`  classDef net fill:${surface},stroke:${resolveVar("--node-network")},color:${ink},stroke-width:1.5px`);
  lines.push(`  classDef vol fill:${surface},stroke:${resolveVar("--node-volume")},color:${ink},stroke-width:1.5px`);
  lines.push(`  classDef dep fill:${surface},stroke:${border},color:${ink},stroke-width:1px`);
  return lines.join("\n");
}
