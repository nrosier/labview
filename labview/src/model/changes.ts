/**
 * What moved between two scans, and how to say it.
 *
 * A rescan that reports nothing is indistinguishable from a rescan that never happened,
 * which is the whole reason this module exists. It answers two questions — *what changed
 * in the configuration since the last scan*, and *what the integration reads came back
 * with* — for the server log and the web UI from one implementation, so the log line and
 * the topbar can never describe the same rescan differently.
 *
 * The two are kept **separate structures**, reported side by side. A container that
 * restarted and an API that answered differently are not edits, and folding them into the
 * configuration diff would make "changed" mean two things at once. But they are not
 * nothing either: a rescan that re-read Authentik and says only "no config changes" reads
 * as a rescan that never touched Authentik, which is the gap `diffIntegrations` closes.
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
import type {
  AppStack,
  AuthentikSummary,
  Overview,
  Service,
  ServiceDeclaration,
  TraefikSummary,
} from "./types.js";
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

/**
 * Members of a `declared` block the *analyzer* writes, which must be excluded for the
 * same reason as the volatile fields above.
 *
 * A declaration is parsed from a file, so it belongs in the comparison — an edited
 * sidecar is exactly the kind of change this is here to report. But `drift` and
 * `authAgreement` are conclusions about the scan that happen to be stored on the
 * declaration, so a service whose *detected* posture moved would otherwise be reported
 * as an edited file, which is the one thing the deny-list above exists to prevent.
 */
const DERIVED_DECLARATION_FIELDS: readonly string[] = ["drift", "authAgreement"];

/** Everything about a service that came out of the compose document, as one string. */
function serviceConfig(svc: Service): string {
  const view: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(svc)) {
    if (VOLATILE_SERVICE_FIELDS.includes(key) || key === "declared") continue;
    view[key] = value;
  }
  if (svc.declared) view.declared = declarationConfig(svc.declared);
  return stableStringify(view);
}

/** The sidecar as it was written, without what the analyzer added to it. */
function declarationConfig(declared: ServiceDeclaration): Record<string, unknown> {
  const view: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(declared)) {
    if (DERIVED_DECLARATION_FIELDS.includes(key)) continue;
    view[key] = value;
  }
  return view;
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

/** What one integration's read came back with, compared against the previous scan. */
export interface IntegrationChange {
  target: "authentik" | "traefik";
  /**
   * The read itself, decided before any count is compared.
   *
   * `started` and `stopped` are about the *read*, not about the integration's contents:
   * they say a comparison was not possible, which is why their `counts` are empty.
   */
  state: "unchanged" | "moved" | "started" | "stopped";
  /** Signed count deltas, `moved` only — e.g. `["+3 applications", "-2 withheld"]`. */
  counts: string[];
  /** Records that appeared and disappeared: application slugs, router names. Sorted. */
  appeared: string[];
  disappeared: string[];
}

export interface IntegrationDiff {
  /** One entry per target read in either scan, in the order LabView reads them. */
  changes: IntegrationChange[];
  unchanged: boolean;
}

/**
 * One comparable number on a summary.
 *
 * `noun` is a countable thing and goes through `plural` (`+3 applications`); `label` is a
 * modifier of those same things and reads identically in both directions (`-3 withheld`,
 * `+1 matched`). Two renderings rather than one because `+3 withhelds` is not English and
 * `-3 withheld applications` claims applications were lost when the opposite happened.
 */
interface Metric<S> {
  pick: (s: S) => number | undefined;
  noun?: string;
  label?: string;
}

/**
 * In the order the panel presents them, so the log and the drawer read alike.
 *
 * `applicationsConfigured` is a *label* on purpose: after the `authentik ` prefix a second
 * "applications" would repeat the first delta's noun, and the number it moves is Authentik's
 * own total rather than what LabView holds.
 */
const AUTHENTIK_METRICS: readonly Metric<AuthentikSummary>[] = [
  { pick: (s) => s.applications, noun: "application" },
  { pick: (s) => s.applicationsConfigured, label: "in its own total" },
  { pick: (s) => s.applicationsWithheld, label: "withheld" },
  { pick: (s) => s.applicationsRecovered, label: "recovered" },
  { pick: (s) => s.providers, noun: "provider" },
  { pick: (s) => s.outposts, noun: "outpost" },
  { pick: (s) => s.matchedServices, label: "matched" },
  { pick: (s) => s.unmatchedApplications.length, label: "unmatched" },
];

/** `services` is rendered "live service": a Traefik service is not a fleet service. */
const TRAEFIK_METRICS: readonly Metric<TraefikSummary>[] = [
  { pick: (s) => s.routers, noun: "router" },
  { pick: (s) => s.middlewares, noun: "middleware" },
  { pick: (s) => s.services, noun: "live service" },
  { pick: (s) => s.matchedServices, label: "matched" },
  { pick: (s) => s.unmatchedRouters.length, label: "unmatched" },
];

/** What a record is called when a whole one was replaced. */
const RECORD_NOUN: Record<IntegrationChange["target"], string> = {
  authentik: "application",
  traefik: "router",
};

function delta<S>(n: number, m: Metric<S>): string {
  const sign = n > 0 ? "+" : "-";
  const abs = Math.abs(n);
  return m.noun ? `${sign}${plural(abs, m.noun)}` : `${sign}${abs} ${m.label}`;
}

/**
 * Every metric both summaries report a value for.
 *
 * A field one side does not have is skipped rather than defaulted to zero (**I4**): an
 * older payload without `applicationsConfigured` must degrade to saying nothing about it,
 * not to claiming Authentik's total fell to nothing.
 */
function countDeltas<S>(before: S, after: S, metrics: readonly Metric<S>[]): string[] {
  const out: string[] = [];
  for (const m of metrics) {
    const was = m.pick(before);
    const is = m.pick(after);
    if (was === undefined || is === undefined || was === is) continue;
    out.push(delta(is - was, m));
  }
  return out;
}

/**
 * One target's entry — and the rule that keeps every number in it honest.
 *
 * **Reachability is decided first.** A read that failed reports zeros, so comparing counts
 * across it would announce `-40 applications`: a statement about Authentik's contents that
 * LabView has no evidence for, and precisely the **I1** failure this codebase exists to
 * avoid. So a scan pair that does not have two successful reads produces no deltas at all,
 * only the fact that the read started or stopped.
 *
 * Neither side readable yields *no entry*. A persistent failure is already stated, loudly
 * and continuously, by the banner and the connection line; repeating it on every rescan as
 * a change would make it look like news.
 */
function integrationChange<S extends { reachable: boolean }>(
  target: IntegrationChange["target"],
  before: S | undefined,
  after: S | undefined,
  metrics: readonly Metric<S>[],
  names: (which: "before" | "after") => Set<string>,
): IntegrationChange | undefined {
  const was = before?.reachable === true ? before : undefined;
  const is = after?.reachable === true ? after : undefined;
  if (!was && !is) return undefined;
  if (!was || !is) {
    return { target, state: is ? "started" : "stopped", counts: [], appeared: [], disappeared: [] };
  }

  const counts = countDeltas(was, is, metrics);
  const had = names("before");
  const has = names("after");
  const appeared = [...has].filter((n) => !had.has(n)).sort();
  const disappeared = [...had].filter((n) => !has.has(n)).sort();
  const moved = counts.length > 0 || appeared.length > 0 || disappeared.length > 0;
  return { target, state: moved ? "moved" : "unchanged", counts, appeared, disappeared };
}

/**
 * Every Authentik application this scan holds, matched or not.
 *
 * Read back off the payload rather than kept as a separate list, so what the diff names is
 * exactly what the UI shows. Matched applications live on the services, unmatched ones in
 * the summary, and a slug can be on more than one service — hence a set.
 */
function applicationSlugs(ov: Overview): Set<string> {
  const out = new Set<string>();
  for (const stack of ov.stacks) {
    for (const svc of stack.services) {
      for (const app of svc.authentik?.applications ?? []) out.add(app.slug);
    }
  }
  for (const u of ov.meta.authentik?.unmatchedApplications ?? []) out.add(u.application.slug);
  return out;
}

/** Every live router this scan holds, matched or not. See {@link applicationSlugs}. */
function routerNames(ov: Overview): Set<string> {
  const out = new Set<string>();
  for (const stack of ov.stacks) {
    for (const svc of stack.services) {
      for (const r of svc.traefikLive ?? []) out.add(r.router);
    }
  }
  for (const u of ov.meta.traefik?.unmatchedRouters ?? []) out.add(u.router.router);
  return out;
}

/**
 * What the integration reads came back with, compared across two scans.
 *
 * Deliberately a second structure beside {@link ScanDiff} rather than part of it. An API
 * that answers differently is not an edit to a file, and folding the two together would
 * make "changed" mean two things at once — the property `VOLATILE_SERVICE_FIELDS` exists
 * to protect. Reported side by side, each labelled.
 */
export function diffIntegrations(prev: Overview, next: Overview): IntegrationDiff {
  const changes: IntegrationChange[] = [];

  const authentik = integrationChange(
    "authentik",
    prev.meta.authentik,
    next.meta.authentik,
    AUTHENTIK_METRICS,
    (which) => applicationSlugs(which === "before" ? prev : next),
  );
  if (authentik) changes.push(authentik);

  const traefik = integrationChange("traefik", prev.meta.traefik, next.meta.traefik, TRAEFIK_METRICS, (which) =>
    routerNames(which === "before" ? prev : next),
  );
  if (traefik) changes.push(traefik);

  return { changes, unchanged: changes.every((c) => c.state === "unchanged") };
}

function joinAnd(items: string[]): string {
  if (items.length <= 1) return items.at(0) ?? "";
  return `${items.slice(0, -1).join(", ")} and ${items.at(-1) ?? ""}`;
}

/**
 * The short form: what the topbar shows beside the configuration note.
 *
 * `""` when no integration was read in either scan, so a config-only fleet's note is
 * untouched. Otherwise it says something in every case, including — especially — the
 * common one, because `authentik and traefik unchanged` is the answer to *did the rescan
 * look at them at all*, and that question is the reason this function exists.
 */
export function integrationDiffText(d: IntegrationDiff): string {
  if (!d.changes.length) return "";
  if (d.unchanged) return `${joinAnd(d.changes.map((c) => c.target))} unchanged`;

  const parts: string[] = [];
  for (const c of d.changes) {
    if (c.state === "started") {
      parts.push(`${c.target} now readable`);
    } else if (c.state === "stopped") {
      parts.push(`${c.target} not read`);
    } else if (c.state === "unchanged") {
      parts.push(`${c.target} unchanged`);
    } else {
      // Every count equal while the records themselves changed: one replaced another, and
      // saying "unchanged" would deny it happened.
      const said = c.counts.length
        ? c.counts
        : [`${plural(Math.max(c.appeared.length, c.disappeared.length), RECORD_NOUN[c.target])} replaced`];
      parts.push(`${c.target} ${said.join(", ")}`);
    }
  }
  return parts.join("; ");
}

/**
 * Beyond this many names one line states the remainder instead of listing it.
 *
 * A count, not a line count: each target contributes at most three lines, so the
 * `MAX_DETAIL_LINES` ceiling could never be reached here — while a fleet with forty
 * applications would still put forty names in one of them.
 */
const MAX_NAMES = 12;

function nameList(names: string[]): string {
  if (names.length <= MAX_NAMES) return names.join(", ");
  return `${names.slice(0, MAX_NAMES).join(", ")} … and ${names.length - MAX_NAMES} more`;
}

/**
 * One line per integration that moved, naming the records that moved in it.
 *
 * Nothing for `unchanged` — the summary already said it, and a detail line that repeats
 * the summary trains the reader to skip both. `started` and `stopped` state why they carry
 * no numbers, so an empty delta list never reads as "nothing changed over there".
 */
export function integrationDiffDetails(d: IntegrationDiff): string[] {
  const lines: string[] = [];
  for (const c of d.changes) {
    if (c.state === "started") {
      lines.push(`· ${c.target}: readable again — nothing is compared across a failed read`);
    } else if (c.state === "stopped") {
      lines.push(`· ${c.target}: not read this scan — nothing is compared across a failed read`);
    } else if (c.state === "moved") {
      if (c.counts.length) lines.push(`· ${c.target}: ${c.counts.join(", ")}`);
      if (c.appeared.length) lines.push(`· ${c.target} appeared: ${nameList(c.appeared)}`);
      if (c.disappeared.length) lines.push(`· ${c.target} disappeared: ${nameList(c.disappeared)}`);
    }
  }
  return lines;
}

/**
 * The log lines for a rescan: the summary, then the detail.
 *
 * Shaped after `formatConnection` so the server's output reads as one story — the same
 * `LabView …` opening, the same indented continuation lines. `extra` is appended to the
 * summary when the caller has a second thing to say about the same rescan; omitting it
 * produces exactly the configuration-only line this function has always produced.
 */
export function formatScanDiff(appsRoot: string, d: ScanDiff, extra?: string): string[] {
  const totals = `${plural(d.stacks, "stack")}, ${plural(d.services, "service")}`;
  const summary = [scanDiffText(d), extra].filter((s) => s).join("; ");
  const lines = [`LabView rescanned ${appsRoot} — ${summary} (${totals})`];
  for (const line of scanDiffDetails(d)) lines.push(`  ${line}`);
  return lines;
}

/**
 * Both diffs as one log block, and the rule for when a rescan speaks at all.
 *
 * The cadence lives here rather than in the server so it can be asserted: a change always
 * speaks, an operator who pressed the button gets an answer even when nothing moved, and
 * only a quiet timer rebuild stays silent. Quiet means *both* diffs — a rescan that found
 * new applications is not quiet just because no file was edited, which was the whole gap.
 */
export function formatRescan(appsRoot: string, d: ScanDiff, i: IntegrationDiff, forced: boolean): string[] {
  if (!forced && d.unchanged && i.unchanged) return [];
  const lines = formatScanDiff(appsRoot, d, integrationDiffText(i));
  for (const line of integrationDiffDetails(i)) lines.push(`  ${line}`);
  return lines;
}

/** The first scan has nothing to compare against, so it states the baseline instead. */
export function formatScanTotals(appsRoot: string, stacks: AppStack[]): string {
  const services = stacks.reduce((n, s) => n + s.services.length, 0);
  return `LabView read ${plural(stacks.length, "stack")}, ${plural(services, "service")} from ${appsRoot}`;
}
