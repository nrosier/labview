/**
 * What moved between two scans, and how to say it.
 *
 * A rescan that reports nothing is indistinguishable from a rescan that never happened,
 * which is the whole reason this module exists. It answers one question — *what changed
 * in the configuration since the last scan* — for the server log and the web UI from one
 * implementation, so the log line and the topbar can never describe the same rescan
 * differently.
 *
 * Pure, and free of node imports on purpose: `web/model.ts` re-exports it into the
 * browser bundle. The comparison is over canonical strings rather than a hash — both
 * payloads are already in memory, so an exact comparison costs little and needs no story
 * about collisions.
 *
 * Nothing here reaches a filesystem. A "changed compose file" means a file whose *parsed*
 * content differs, which is the question an operator actually has: did my edit take
 * effect. A comment-only edit is therefore not a change, and neither is a rewrite that
 * produces the same document.
 */
import type { AppStack, Service } from "./types.js";
import { plural } from "./connections.js";

/** What moved inside one stack that exists in both scans. */
export interface StackChange {
  id: string;
  servicesAdded: string[];
  servicesRemoved: string[];
  servicesChanged: string[];
  /**
   * The stack's own configuration moved rather than a service's: its compose filename,
   * project name, declared networks or volumes, or its parse warnings.
   */
  stackChanged: boolean;
}

export interface ScanDiff {
  added: Array<{ id: string; services: number }>;
  removed: Array<{ id: string; services: number }>;
  changed: StackChange[];
  /** Totals after this scan, for the line that reports no change at all. */
  stacks: number;
  services: number;
  unchanged: boolean;
}

/**
 * Fields excluded from the comparison, because they move without anyone editing a file.
 *
 * A container restarting, an API that answered this time and not last time, a new
 * container IP — none of those are configuration changes, and including them would make
 * every rescan report everything, which is the noise that made `read` a non-member of
 * `changedConnections`'s signature for the same reason.
 *
 *  - `docker` is live Engine state: status, health, addresses, restart count.
 *  - `authentik` and `traefikLive` are live API matches, present only when those reads
 *    worked.
 *  - `ingress`, `auth` and `notes` are derived, and `auth` is deliberately *downgraded by
 *    live truth* — so a Traefik read that succeeds this time would otherwise read as an
 *    edit to a file nobody touched.
 *  - `cloudflare` is label-derived, but each route's `origin` is resolved against the
 *    fleet index, whose container-address table exists only when Docker is readable. The
 *    hostname edits it would have caught are caught anyway: they are in `labels`.
 *
 * A deny-list rather than an allow-list, deliberately. Forgetting to exclude a new
 * *derived* field produces a spurious "changed" line — loud, and fixed the first time
 * anyone sees it. Forgetting to include a new field parsed from the compose document
 * produces an edit that is silently never reported, which is the failure this exists to
 * prevent. So the default for anything new is "compared".
 */
const VOLATILE_SERVICE_FIELDS: readonly string[] = [
  "docker",
  "authentik",
  "traefikLive",
  "ingress",
  "auth",
  "notes",
  "cloudflare",
];

/** Everything about a service that came out of the compose document, as one string. */
function serviceConfig(svc: Service): string {
  const view: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(svc)) {
    if (VOLATILE_SERVICE_FIELDS.includes(key)) continue;
    view[key] = value;
  }
  return stableStringify(view);
}

/** The stack's own configuration, without its services — those are compared by name. */
function stackConfig(stack: AppStack): string {
  const view: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(stack)) {
    if (key === "services") continue;
    view[key] = value;
  }
  return stableStringify(view);
}

/**
 * Sorted-key JSON, so two documents that differ only in key order are equal.
 *
 * `undefined` members are dropped rather than serialized, which matches `JSON.stringify`
 * and keeps an optional field that is absent equal to one that is explicitly undefined.
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const body = Object.keys(obj)
    .sort()
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`)
    .join(",");
  return `{${body}}`;
}

/**
 * Which stacks and services differ between two scans.
 *
 * Service tallies count only stacks present in both scans: the services of a stack that
 * was just added are already accounted for by the stack itself, and counting them twice
 * would overstate what happened.
 */
export function diffStacks(prev: AppStack[], next: AppStack[]): ScanDiff {
  const before = new Map(prev.map((s) => [s.id, s]));
  const after = new Map(next.map((s) => [s.id, s]));

  const added = next.filter((s) => !before.has(s.id)).map((s) => ({ id: s.id, services: s.services.length }));
  const removed = prev.filter((s) => !after.has(s.id)).map((s) => ({ id: s.id, services: s.services.length }));

  const changed: StackChange[] = [];
  for (const stack of next) {
    const old = before.get(stack.id);
    if (!old) continue;
    const oldServices = new Map(old.services.map((s) => [s.name, serviceConfig(s)]));
    const newServices = new Map(stack.services.map((s) => [s.name, serviceConfig(s)]));

    const servicesAdded = [...newServices.keys()].filter((n) => !oldServices.has(n));
    const servicesRemoved = [...oldServices.keys()].filter((n) => !newServices.has(n));
    const servicesChanged = [...newServices.entries()]
      .filter(([name, cfg]) => oldServices.has(name) && oldServices.get(name) !== cfg)
      .map(([name]) => name);
    const stackChanged = stackConfig(old) !== stackConfig(stack);

    if (servicesAdded.length || servicesRemoved.length || servicesChanged.length || stackChanged) {
      changed.push({ id: stack.id, servicesAdded, servicesRemoved, servicesChanged, stackChanged });
    }
  }

  return {
    added,
    removed,
    changed,
    stacks: next.length,
    services: next.reduce((n, s) => n + s.services.length, 0),
    unchanged: added.length === 0 && removed.length === 0 && changed.length === 0,
  };
}

/**
 * The short form: what the topbar shows and the log line leads with.
 *
 * Says something in every case, including the common one. "No config changes" is the
 * answer an operator pressing Rescan most often needs, and leaving it unsaid is what
 * made the button feel inert.
 */
export function scanDiffText(d: ScanDiff): string {
  if (d.unchanged) return "no config changes";
  const parts: string[] = [];
  if (d.added.length) parts.push(`+${plural(d.added.length, "stack")}`);
  if (d.removed.length) parts.push(`-${plural(d.removed.length, "stack")}`);
  if (d.changed.length) parts.push(`${plural(d.changed.length, "stack")} changed`);

  const tally = (pick: (c: StackChange) => string[]) => d.changed.reduce((n, c) => n + pick(c).length, 0);
  const svcAdded = tally((c) => c.servicesAdded);
  const svcRemoved = tally((c) => c.servicesRemoved);
  const svcChanged = tally((c) => c.servicesChanged);
  if (svcAdded) parts.push(`+${plural(svcAdded, "service")}`);
  if (svcRemoved) parts.push(`-${plural(svcRemoved, "service")}`);
  if (svcChanged) parts.push(`${plural(svcChanged, "service")} changed`);
  return parts.join(", ");
}

/** Beyond this many stacks the list is truncated — with the remainder stated, never silently. */
const MAX_DETAIL_LINES = 12;

/**
 * One line per stack that moved, naming what moved in it.
 *
 * The same lines serve the log and the topbar tooltip. Stack and service names are the
 * operator's own, which is the only way the line is actionable; the truncation is
 * announced so a long list never reads as a complete one.
 */
export function scanDiffDetails(d: ScanDiff): string[] {
  const lines: string[] = [];
  for (const s of d.added) lines.push(`· added: ${s.id} (${plural(s.services, "service")})`);
  for (const s of d.removed) lines.push(`· removed: ${s.id} (${plural(s.services, "service")})`);
  for (const c of d.changed) {
    const what: string[] = [];
    if (c.servicesAdded.length) what.push(`services added: ${c.servicesAdded.join(", ")}`);
    if (c.servicesRemoved.length) what.push(`services removed: ${c.servicesRemoved.join(", ")}`);
    if (c.servicesChanged.length) what.push(`services changed: ${c.servicesChanged.join(", ")}`);
    // Last, so the specific service names lead when there are any — this clause carries
    // the changes no service explains: compose filename, project name, declared networks
    // or volumes, parse warnings.
    if (c.stackChanged) what.push("stack configuration changed");
    lines.push(`· changed: ${c.id} — ${what.join("; ")}`);
  }
  if (lines.length <= MAX_DETAIL_LINES) return lines;
  const kept = lines.slice(0, MAX_DETAIL_LINES);
  kept.push(`· … and ${plural(lines.length - MAX_DETAIL_LINES, "more stack")}`);
  return kept;
}

/**
 * The log lines for a rescan: the summary, then the detail.
 *
 * Shaped after `formatConnection` so the server's output reads as one story — the same
 * `LabView …` opening, the same indented continuation lines.
 */
export function formatScanDiff(appsRoot: string, d: ScanDiff): string[] {
  const totals = `${plural(d.stacks, "stack")}, ${plural(d.services, "service")}`;
  const lines = [`LabView rescanned ${appsRoot} — ${scanDiffText(d)} (${totals})`];
  for (const line of scanDiffDetails(d)) lines.push(`  ${line}`);
  return lines;
}

/** The first scan has nothing to compare against, so it states the baseline instead. */
export function formatScanTotals(appsRoot: string, stacks: AppStack[]): string {
  const services = stacks.reduce((n, s) => n + s.services.length, 0);
  return `LabView read ${plural(stacks.length, "stack")}, ${plural(services, "service")} from ${appsRoot}`;
}
