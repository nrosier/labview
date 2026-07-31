import type { CloudflareRoute } from "../model/types.js";

/**
 * Extract DockFlare Cloudflare-tunnel routes from a service's labels.
 *
 * Supports the flat form:
 *   dockflare.enable=true
 *   dockflare.hostname=app.example.com
 *   dockflare.service=http://app:8080
 *   dockflare.path=/foo
 *   dockflare.access.group=nas-family
 *   dockflare.access.policy=authenticate
 *   dockflare.access.email=a@b.com,c@d.com
 *   dockflare.no-tls-verify=true
 *
 * ...and the indexed multi-route form used for several hostnames on one service:
 *   dockflare.0.hostname=app.example.com
 *   dockflare.1.hostname=api.example.com
 */
export function parseDockflare(labels: Record<string, string>, prefix: string): CloudflareRoute[] {
  const p = prefix.endsWith(".") ? prefix : `${prefix}.`;
  const relevant = Object.entries(labels).filter(([k]) => k === prefix || k.startsWith(p));
  if (relevant.length === 0) return [];

  const enabled = truthy(labels[`${p}enable`]) || truthy(labels[prefix]);

  // Group labels by route index. The un-indexed labels form route "".
  const groups = new Map<string, Record<string, string>>();
  for (const [key, value] of relevant) {
    const rest = key.slice(p.length); // e.g. "hostname" or "0.hostname" or "access.group"
    const m = /^(\d+)\.(.+)$/.exec(rest);
    const idx = m ? m[1]! : "";
    const sub = m ? m[2]! : rest;
    if (sub === "enable") continue;
    let bag = groups.get(idx);
    if (!bag) {
      bag = {};
      groups.set(idx, bag);
    }
    bag[sub] = value;
  }

  const routes: CloudflareRoute[] = [];
  for (const [, bag] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (!bag.hostname && !bag.service && !bag.path) continue;
    const access =
      bag["access.group"] || bag["access.policy"] || bag["access.email"] || bag["access.emails"]
        ? {
            group: bag["access.group"],
            policy: bag["access.policy"],
            emails: splitList(bag["access.email"] ?? bag["access.emails"]),
          }
        : undefined;
    routes.push({
      hostname: bag.hostname ?? "",
      service: bag.service ?? "",
      path: bag.path,
      access,
      noTlsVerify: truthy(bag["no-tls-verify"]),
      raw: bag,
    });
  }

  // If enabled but no explicit route bag captured a hostname, still surface it.
  if (routes.length === 0 && enabled && labels[`${p}hostname`]) {
    routes.push({
      hostname: labels[`${p}hostname`]!,
      service: labels[`${p}service`] ?? "",
      path: labels[`${p}path`],
      raw: {},
    });
  }
  return routes;
}

function truthy(v: string | undefined): boolean {
  return v === "true" || v === "1" || v === "yes" || v === "on";
}

function splitList(v: string | undefined): string[] | undefined {
  if (!v) return undefined;
  return v
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
