import type { AppStack, Service, Graph, GraphNode, GraphEdge } from "../model/types.js";

/**
 * Build the relationship graph across all stacks:
 *  - service <-> network membership (real docker network names, so shared/external
 *    networks correctly connect services from different stacks)
 *  - service -> service depends_on
 *  - service <-> shared volumes (named volumes, and bind paths used by 2+ stacks)
 *  - ingress/auth hubs, each added only when something observed calls for it:
 *    a Cloudflare tunnel, Traefik, and either the identified SSO provider or a
 *    generic hub when only the mechanism could be established
 */
export function buildGraph(stacks: AppStack[]): Graph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const addNode = (n: GraphNode) => {
    if (!nodes.has(n.id)) nodes.set(n.id, n);
  };
  const addEdge = (e: GraphEdge) => edges.push(e);

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
      for (const net of realNetworks(stack, svc)) {
        const nid = `net:${net.name}`;
        addNode({ id: nid, label: net.name, kind: "network" });
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

      // Ingress + auth hubs.
      for (const r of svc.cloudflare) {
        hub.cf = true;
        addEdge({
          id: `cf->${sid}:${r.hostname}`,
          source: "ext:cloudflare",
          target: sid,
          kind: "ingress",
          label: r.hostname || "tunnel",
        });
      }
      for (const r of svc.traefik) {
        hub.traefik = true;
        addEdge({
          id: `tr->${sid}:${r.router}`,
          source: "ext:traefik",
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

  if (hub.cf) addNode({ id: "ext:cloudflare", label: "Cloudflare Tunnel", kind: "external" });
  if (hub.traefik) addNode({ id: "ext:traefik", label: "Traefik", kind: "external" });
  if (hub.authentik) addNode({ id: "ext:authentik", label: "Authentik", kind: "external" });
  if (hub.auth) addNode({ id: "ext:auth", label: "SSO (unidentified)", kind: "external" });

  return { nodes: [...nodes.values()], edges };
}

export function serviceId(stack: AppStack, svc: Service): string {
  return `svc:${stack.id}/${svc.name}`;
}

interface RealNet {
  name: string;
}

/** Resolve the real docker network names a service is attached to. */
function realNetworks(stack: AppStack, svc: Service): RealNet[] {
  if (svc.docker?.networks?.length) {
    return svc.docker.networks.map((name) => ({ name }));
  }
  const keys = svc.networks.length ? svc.networks : ["default"];
  return keys.map((key) => {
    const decl = stack.declaredNetworks.find((n) => n.name === key);
    if (decl?.external) return { name: decl.name };
    return { name: `${stack.projectName}_${key}` };
  });
}

function normalizeBind(p: string): string {
  return p.replace(/\/+$/, "");
}
