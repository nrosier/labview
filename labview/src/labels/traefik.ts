import type { TraefikRoute } from "../model/types.js";

/**
 * Extract Traefik routers from a service's labels. Groups
 * `traefik.http.routers.<name>.*` into one TraefikRoute each and resolves the
 * load-balancer port from the associated `traefik.http.services.<svc>.*` block.
 */
export function parseTraefik(labels: Record<string, string>, prefix: string): TraefikRoute[] {
  const p = prefix.endsWith(".") ? prefix : `${prefix}.`;
  if (!truthy(labels[`${p}enable`])) {
    // Traefik ignores containers without enable=true (in the common label-provider
    // "explicit" mode). If any router labels exist we still surface them, but flag it.
    const hasRouters = Object.keys(labels).some((k) => k.startsWith(`${p}http.routers.`));
    if (!hasRouters) return [];
  }

  const routers = new Map<string, Record<string, string>>();
  const services = new Map<string, Record<string, string>>();

  for (const [key, value] of Object.entries(labels)) {
    let m = key.match(new RegExp(`^${escape(p)}http\\.routers\\.([^.]+)\\.(.+)$`));
    if (m) {
      const [, router, sub] = m;
      addTo(routers, router!, sub!, value);
      continue;
    }
    m = key.match(new RegExp(`^${escape(p)}http\\.services\\.([^.]+)\\.(.+)$`));
    if (m) {
      const [, service, sub] = m;
      addTo(services, service!, sub!, value);
    }
  }

  const out: TraefikRoute[] = [];
  for (const [router, bag] of routers) {
    const rule = bag["rule"];
    const svcName = bag["service"] ?? router;
    const svcBag = services.get(svcName) ?? services.get(router);
    const servicePort =
      svcBag?.["loadbalancer.server.port"] ?? svcBag?.["loadBalancer.server.port"];
    out.push({
      router,
      rule,
      hosts: rule ? extractHosts(rule) : [],
      pathPrefixes: rule ? extractPathPrefixes(rule) : [],
      entrypoints: splitList(bag["entrypoints"] ?? bag["entryPoints"]),
      tls: truthy(bag["tls"]) || bag["tls.certresolver"] != null || bag["tls.certResolver"] != null,
      certResolver: bag["tls.certresolver"] ?? bag["tls.certResolver"],
      middlewares: splitList(bag["middlewares"]),
      servicePort,
      // Kept verbatim rather than defaulted to the router name: only an explicitly
      // named service can be one of Traefik's built-ins, and `api@internal` is how a
      // container declares that it serves the proxy's own API.
      service: bag["service"],
    });
  }
  out.sort((a, b) => a.router.localeCompare(b.router));
  return out;
}

function addTo(map: Map<string, Record<string, string>>, name: string, sub: string, value: string) {
  let bag = map.get(name);
  if (!bag) {
    bag = {};
    map.set(name, bag);
  }
  bag[sub] = value;
}

/** Extract hostnames from Host(`a.com`,`b.com`) and HostSNI / HostRegexp forms. */
export function extractHosts(rule: string): string[] {
  const hosts = new Set<string>();
  const re = /Host(?:SNI|Regexp)?\(([^)]*)\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rule))) {
    const inner = m[1]!;
    for (const tok of inner.split(",")) {
      const cleaned = tok.trim().replace(/^[`'"]|[`'"]$/g, "");
      if (cleaned) hosts.add(cleaned);
    }
  }
  return [...hosts];
}

function extractPathPrefixes(rule: string): string[] {
  const paths = new Set<string>();
  const re = /Path(?:Prefix)?\(([^)]*)\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rule))) {
    for (const tok of m[1]!.split(",")) {
      const cleaned = tok.trim().replace(/^[`'"]|[`'"]$/g, "");
      if (cleaned) paths.add(cleaned);
    }
  }
  return [...paths];
}

function truthy(v: string | undefined): boolean {
  return v === "true" || v === "1" || v === "yes" || v === "on";
}

function splitList(v: string | undefined): string[] {
  if (!v) return [];
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
