import type { CloudflareRoute } from "../model/types.js";

/**
 * Extract DockFlare Cloudflare-tunnel routes from a service's labels.
 *
 * Supports the flat form:
 *   dockflare.enable=true
 *   dockflare.hostname=app.example.com
 *   dockflare.service=http://app:8080
 *   dockflare.path=/foo
 *   dockflare.access.group=<access-group>
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

  // An explicit `dockflare.enable=false` means DockFlare skips this service, so
  // the remaining labels describe a route that is not actually published. Treat
  // it as having no Cloudflare ingress at all — otherwise the service is
  // classified as public and can be reported as "exposed without auth" when it
  // is not reachable from the internet in the first place. An absent `enable`
  // label is left alone: the other labels are the only signal we have.
  // Only an explicit falsy value disables; an unrecognised value is left to the
  // normal path rather than silently hiding a route.
  const enableLabel = labels[`${p}enable`] ?? labels[prefix];
  if (enableLabel !== undefined && falsy(enableLabel)) return [];
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
  const s = v?.trim().toLowerCase();
  return s === "true" || s === "1" || s === "yes" || s === "on";
}

function falsy(v: string | undefined): boolean {
  const s = v?.trim().toLowerCase();
  return s === "false" || s === "0" || s === "no" || s === "off";
}

function splitList(v: string | undefined): string[] | undefined {
  if (!v) return undefined;
  return v
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
