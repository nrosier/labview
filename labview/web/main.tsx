import { render } from "preact";
import { useEffect, useMemo, useState } from "preact/hooks";
import type {
  AppStack,
  AuthentikSummary,
  ConnectionReport,
  IngressKind,
  Overview,
  Service,
  TraefikSummary,
} from "./model";
import { phaseText, shouldBanner } from "./model";
import {
  diffIntegrations,
  diffStacks,
  integrationDiffDetails,
  integrationDiffText,
  scanDiffDetails,
  scanDiffText,
  type IntegrationDiff,
  type ScanDiff,
} from "./model";
import { fetchOverview, rescan } from "./api";
import { AUTH_META, INGRESS_META } from "./lib/palette";
import { fmtTime, ingressSummary, qualifyRouter, serviceKey } from "./lib/format";
import { StatTile, DistributionBar, type DistSegment } from "./components/stats";
import { StackCard } from "./components/StackCard";
import { AppDetail } from "./components/AppDetail";
import { AuthentikDetail, TraefikDetail } from "./components/ApiDetail";
import { GraphView } from "./components/GraphView";

type Theme = "light" | "dark" | "auto";
const THEME_KEY = "labview-theme";

interface Flat {
  stack: AppStack;
  svc: Service;
  key: string;
}

/** A stack together with the services of it that survived the filters. */
interface StackGroup {
  stack: AppStack;
  services: Service[];
}

/**
 * Every service, paired with its stack.
 *
 * Filtering stays service-level even though the view is stack-level — "public" is
 * a property of a service, not of a directory — so the flat list remains the thing
 * the predicate runs over, and the stack grouping is applied to its results.
 */
function flatten(ov: Overview): Flat[] {
  const out: Flat[] = [];
  for (const stack of ov.stacks) {
    for (const svc of stack.services) {
      out.push({ stack, svc, key: serviceKey(stack.id, svc.name) });
    }
  }
  out.sort((a, b) => a.stack.name.localeCompare(b.stack.name) || a.svc.name.localeCompare(b.svc.name));
  return out;
}

/**
 * Tooltip for the Authentik status: the endpoint, how it was arrived at, and what was
 * read. Applications the scan could not tie to a service are named because that gap
 * is LabView's to explain — an unmatched application is a service it failed to
 * identify, not a misconfiguration on the provider's side.
 */
function authentikTitle(ak: AuthentikSummary): string {
  const configured = ak.applicationsConfigured ?? ak.applications;
  const bits = [
    `${ak.endpoint ?? "unknown endpoint"} (${ak.endpointSource ?? "unknown"})`,
    `${ak.applicationsWithheld ? `${ak.applications} of ${configured}` : ak.applications} applications, ${ak.providers} providers, ${ak.outposts} outposts`,
    `${ak.matchedServices} services matched`,
  ];
  // The endpoint filters its own list by what this token's user may launch, so the gap
  // between the two numbers above is a limit on every conclusion below them.
  if (ak.applicationsWithheld) {
    const unaccounted = Math.max(0, ak.applicationsWithheld - ak.applicationsRecovered);
    bits.push(
      `${ak.applicationsWithheld} withheld by the applications endpoint: ` +
        `${ak.applicationsRecovered} rebuilt from providers, ${unaccounted} not readable`,
    );
  }
  if (ak.unmatchedApplications.length) {
    bits.push(
      `not matched to any service: ${ak.unmatchedApplications
        .map((u) => u.application.slug)
        .join(", ")}`,
    );
  }
  bits.push("click for the matched and unmatched detail");
  if (ak.error) bits.push(ak.error);
  return bits.join("\n");
}

/**
 * Tooltip for the proxy status: which endpoint answered, what it needed to let LabView
 * in, and what was read. Routers no service could be identified for are named for the
 * same reason unmatched applications are — ingress LabView could not attribute is its
 * own reporting gap, and it is also the only place file-provider routes show up.
 */
function traefikTitle(tf: TraefikSummary): string {
  const bits = [
    `${tf.endpoint ?? "unknown endpoint"} (${tf.endpointSource ?? "unknown"})`,
    tf.version ? `Traefik ${tf.version}` : "version not reported",
    tf.credential === "none"
      ? "answered without a credential — the API is open to anything that can reach it"
      : "answered after HTTP Basic authentication",
    `${tf.routers} routers, ${tf.middlewares} middlewares, ${tf.services} services`,
    `${tf.matchedServices} services matched`,
  ];
  if (!tf.entrypointsRead) {
    bits.push("entrypoint middlewares were not read, so a gate attached there is not accounted for");
  }
  if (tf.unmatchedRouters.length) {
    bits.push(
      `not matched to any service: ${tf.unmatchedRouters.map((u) => qualifyRouter(u.router)).join(", ")}`,
    );
  }
  bits.push("click for the matched and unmatched detail");
  if (tf.error) bits.push(tf.error);
  return bits.join("\n");
}

/**
 * Why a connection failed, said where the reader already is.
 *
 * The status pills stay compact counts and keep their tooltips, but a tooltip is a
 * place a reason goes to be missed — `authentik: unreachable` with the explanation
 * behind a hover is the complaint this exists to answer. One row per target that is
 * worth mentioning (`shouldBanner`), each naming the stage, the address, what happened
 * and what to change. Candidate rows follow on a discovery failure, because "nothing
 * answered" is unactionable and three addresses with a phase each is not.
 *
 * Reuses `.banner` and its warning colour: the red of `--c8` is reserved for the
 * exposure warning, and a diagnostic is not the same class of problem.
 */
/**
 * The long form for a pill's tooltip, for a target that did not connect.
 *
 * The banner says the reason once; this repeats it where the reader's pointer already
 * is, and adds the candidate list, which is too long for a banner row but is exactly
 * what a discovery failure needs.
 */
function connTitle(r: ConnectionReport | undefined, fallback: string | undefined): string {
  if (!r) return fallback ?? "";
  const bits = [`${r.endpoint ?? "no endpoint"} — ${phaseText(r.phase)}`];
  if (r.detail) bits.push(r.detail);
  if (r.hint) bits.push(r.hint);
  for (const a of r.attempts) bits.push(`tried ${a.endpoint} (${a.why}) — ${a.phase}: ${a.detail}`);
  return bits.join("\n");
}

function ConnectionBanner({ reports }: { reports: ConnectionReport[] | undefined }) {
  const shown = (reports ?? []).filter(shouldBanner);
  if (!shown.length) return null;
  return (
    <div class="banner">
      {shown.map((r) => (
        <div class="conn" key={r.target}>
          <div>
            <strong>{r.target}</strong>
            {r.endpoint && <span class="mono"> {r.endpoint}</span>}
            {" — "}
            {phaseText(r.phase)}
            {r.code && ` (${r.code})`}
            {r.detail && <>: {r.detail}</>}
          </div>
          {r.hint && <div class="conn-hint">{r.hint}</div>}
          {!r.ok && r.attempts.length > 0 && (
            <ul class="conn-tried">
              {r.attempts.map((a) => (
                <li key={a.endpoint}>
                  <span class="mono">{a.endpoint}</span> ({a.why}) — {a.phase}: {a.detail}
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

function applyTheme(theme: Theme) {
  const el = document.documentElement;
  if (theme === "auto") el.removeAttribute("data-theme");
  else el.setAttribute("data-theme", theme);
}

function App() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // What the last rescan found, held until the next one. The initial load has nothing to
  // compare against, so both stay null and the notes are absent rather than empty.
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  /** The other half of the same rescan: what the Authentik and Traefik reads came back with. */
  const [apiDiff, setApiDiff] = useState<IntegrationDiff | null>(null);
  const [tab, setTab] = useState<"overview" | "graph">("overview");
  const [theme, setTheme] = useState<Theme>((localStorage.getItem(THEME_KEY) as Theme) || "auto");

  // Filters
  const [search, setSearch] = useState("");
  const [ingressFilter, setIngressFilter] = useState<Set<string>>(new Set());
  const [authFilter, setAuthFilter] = useState<Set<string>>(new Set());
  const [exposedOnly, setExposedOnly] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  /**
   * Which integration's detail panel is open, if any.
   *
   * Separate from `selected` rather than folded into one "what is in the drawer" state:
   * the two are opened from different places and closed in a defined order, and a single
   * union would have to be unpacked at every use to say which of the two it is.
   */
  const [apiPanel, setApiPanel] = useState<"authentik" | "traefik" | null>(null);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    fetchOverview()
      .then(setOv)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // One layer at a time, topmost first. Opening a service from a panel closes the
      // panel, so the two are not normally both open — but the order is defined here
      // rather than relying on that, since the cost of being wrong is a key that looks
      // dead because it dismissed something behind what the reader was looking at.
      if (apiPanel) setApiPanel(null);
      else setSelected(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [apiPanel]);

  async function doRescan() {
    setBusy(true);
    setError(null);
    // Captured before the request: the payload on screen is the one the operator wants
    // the new scan compared against, and it is about to be replaced.
    const before = ov;
    try {
      const next = await rescan();
      setOv(next);
      setDiff(before ? diffStacks(before.stacks, next.stacks) : null);
      setApiDiff(before ? diffIntegrations(before, next) : null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const flat = useMemo(() => (ov ? flatten(ov) : []), [ov]);
  // Empty when no integration was read in either scan, which is what keeps the note
  // unchanged for a fleet that has neither switched on.
  const apiDiffText = apiDiff ? integrationDiffText(apiDiff) : "";

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return flat.filter(({ stack, svc }) => {
      if (ingressFilter.size && !ingressFilter.has(svc.ingress)) return false;
      if (authFilter.size && !authFilter.has(svc.auth.method)) return false;
      if (exposedOnly && !svc.auth.exposedWithoutAuth) return false;
      if (q) {
        const hay = [
          svc.name,
          stack.name,
          svc.image ?? "",
          svc.containerName,
          ingressSummary(svc),
        ]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [flat, search, ingressFilter, authFilter, exposedOnly]);

  // Group the surviving services back under their stacks. `filtered` is already
  // ordered by stack then service, and a Map keeps insertion order, so the stacks
  // come out sorted without a second sort.
  const groups = useMemo<StackGroup[]>(() => {
    const byStack = new Map<string, StackGroup>();
    for (const { stack, svc } of filtered) {
      const g = byStack.get(stack.id);
      if (g) g.services.push(svc);
      else byStack.set(stack.id, { stack, services: [svc] });
    }
    return [...byStack.values()];
  }, [filtered]);

  const filtering = search.trim() !== "" || ingressFilter.size > 0 || authFilter.size > 0 || exposedOnly;

  // A match must never hide behind a click, so an active filter opens the stacks it
  // matched, and clearing the filter collapses them again. Keyed on the filter
  // inputs rather than on the results, so toggling a stack does not re-trigger it.
  useEffect(() => {
    setExpanded(filtering ? new Set(groups.map((g) => g.stack.id)) : new Set());
  }, [search, ingressFilter, authFilter, exposedOnly]);

  const ingressSegments = useMemo<DistSegment[]>(() => {
    const counts = new Map<IngressKind, number>();
    for (const { svc } of flat) counts.set(svc.ingress, (counts.get(svc.ingress) ?? 0) + 1);
    return INGRESS_META.map((m) => ({ key: m.key, label: m.label, cssVar: m.cssVar, count: counts.get(m.key) ?? 0 }));
  }, [flat]);

  const authSegments = useMemo<DistSegment[]>(() => {
    const counts = ov?.stats.byAuthMethod ?? {};
    return AUTH_META.map((m) => ({ key: m.key, label: m.label, cssVar: m.cssVar, count: counts[m.key] ?? 0 }));
  }, [ov]);

  function toggle(set: Set<string>, setter: (s: Set<string>) => void, key: string) {
    const next = new Set(set);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setter(next);
  }

  const selectedFlat = selected ? flat.find((f) => f.key === selected) : undefined;

  function openService(stackId: string, serviceName: string) {
    setSelected(serviceKey(stackId, serviceName));
    // A service can be reached from inside an integration panel. Two stacked drawers
    // would leave the reader closing one to find another underneath, so the panel that
    // sent them here gets out of the way.
    setApiPanel(null);
  }

  function toggleStack(stackId: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(stackId)) next.delete(stackId);
      else next.add(stackId);
      return next;
    });
  }

  if (error && !ov) {
    return (
      <div class="shell">
        <div class="center-msg">
          <p>Could not load overview.</p>
          <p class="mono">{error}</p>
          <button class="btn" onClick={() => location.reload()}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!ov) {
    return (
      <div class="shell">
        <div class="center-msg">
          <span class="spinner" /> Loading fleet…
        </div>
      </div>
    );
  }

  const allOpen = groups.length > 0 && expanded.size === groups.length;
  /** The report for one target, for the pill tooltips beside the banner. */
  const conn = (target: string) => ov.meta.connections?.find((c) => c.target === target);
  const nextTheme: Record<Theme, Theme> = { auto: "light", light: "dark", dark: "auto" };
  const themeIcon: Record<Theme, string> = { auto: "◐ Auto", light: "☀ Light", dark: "☾ Dark" };

  return (
    <div class="shell">
      <header class="topbar">
        <div class="brand">
          <span class="dot">●</span>
          <h1>LabView</h1>
        </div>
        <div class="meta">
          <span class="mono">{ov.meta.appsRoot}</span>
          <span>
            scanned {fmtTime(ov.meta.scannedAt)}
            {/* The proof the click did something. "No config changes" is as much an
                answer as a list of changes, and its absence is what made the button
                feel inert — so it is shown too, only quieter. */}
            {diff && (
              <span
                class={diff.unchanged ? "rescan-note" : "rescan-note moved"}
                title={
                  diff.unchanged
                    ? `Re-read ${ov.meta.appsRoot}: nothing in the parsed configuration differs from the previous scan.`
                    : scanDiffDetails(diff).join("\n")
                }
              >
                {" · "}
                {scanDiffText(diff)}
              </span>
            )}
            {/* The same proof for the other half of a rescan: both API exchanges are
                re-run every time, and until this said so, an Authentik that gained
                twenty applications still reported "no config changes". A second span
                rather than a longer string, so each half highlights on its own — and
                absent entirely when no integration was read in either scan. */}
            {apiDiff && apiDiffText && (
              <span
                class={apiDiff.unchanged ? "rescan-note" : "rescan-note moved"}
                title={
                  apiDiff.unchanged
                    ? "Re-read on this rescan, including the credentials: every count came back the same."
                    : integrationDiffDetails(apiDiff).join("\n")
                }
              >
                {" · "}
                {apiDiffText}
              </span>
            )}
          </span>
          <span>
            docker:{" "}
            {ov.meta.dockerAvailable ? (
              "connected"
            ) : (
              <span title={connTitle(conn("docker"), ov.meta.dockerError)}>config-only</span>
            )}
          </span>
          {/* Only shown once a token exists: an unconfigured optional integration is
              not a status worth a permanent line in the header. */}
          {ov.meta.authentik?.configured && (
            <span>
              authentik:{" "}
              {/* The count is the way in to the detail behind it: which application was
                  tied to which service and on what evidence, and why the rest were not.
                  The tooltip keeps the summary — hover for the gist, click for the case. */}
              {ov.meta.authentik.reachable ? (
                <button
                  class="linkbtn"
                  aria-expanded={apiPanel === "authentik"}
                  onClick={() => setApiPanel("authentik")}
                  title={[authentikTitle(ov.meta.authentik), conn("authentik")?.hint]
                    .filter(Boolean)
                    .join("\n")}
                >
                  {/* Two numbers whenever the endpoint kept some back, because one of
                      them would be a filtered count presented as a complete one. */}
                  {ov.meta.authentik.applicationsWithheld > 0
                    ? `${ov.meta.authentik.applications} of ${
                        ov.meta.authentik.applicationsConfigured ?? ov.meta.authentik.applications
                      } apps`
                    : `${ov.meta.authentik.applications} app${ov.meta.authentik.applications === 1 ? "" : "s"}`}
                  {ov.meta.authentik.matchedServices > 0 &&
                    ` · ${ov.meta.authentik.matchedServices} matched`}
                </button>
              ) : (
                /* Clickable in this state too: the pill shows a phase instead of a count,
                   and the stage that failed with every candidate tried is worth more than
                   one word of it. */
                <button
                  class="linkbtn"
                  aria-expanded={apiPanel === "authentik"}
                  onClick={() => setApiPanel("authentik")}
                  title={connTitle(conn("authentik"), ov.meta.authentik.error)}
                >
                  {conn("authentik")?.phase ?? "unreachable"}
                </button>
              )}
            </span>
          )}
          {/* Same rule for the proxy's API. Its credential state is part of the status
              rather than a tooltip detail: a proxy API that answered unauthenticated is
              readable by anything that can reach it, which is worth seeing at a glance. */}
          {ov.meta.traefik?.configured && (
            <span>
              traefik:{" "}
              {ov.meta.traefik.reachable ? (
                <button
                  class="linkbtn"
                  aria-expanded={apiPanel === "traefik"}
                  onClick={() => setApiPanel("traefik")}
                  title={[traefikTitle(ov.meta.traefik), conn("traefik")?.hint]
                    .filter(Boolean)
                    .join("\n")}
                >
                  {ov.meta.traefik.routers} router
                  {ov.meta.traefik.routers === 1 ? "" : "s"}
                  {ov.meta.traefik.matchedServices > 0 && ` · ${ov.meta.traefik.matchedServices} matched`}
                  {ov.meta.traefik.credential === "none" && " · no credential"}
                </button>
              ) : (
                <button
                  class="linkbtn"
                  aria-expanded={apiPanel === "traefik"}
                  onClick={() => setApiPanel("traefik")}
                  title={connTitle(conn("traefik"), ov.meta.traefik.error)}
                >
                  {conn("traefik")?.phase ?? "unreachable"}
                </button>
              )}
            </span>
          )}
        </div>
        <div class="spacer" />
        <button
          class="btn"
          onClick={() => {
            const t = nextTheme[theme];
            setTheme(t);
            localStorage.setItem(THEME_KEY, t);
          }}
          title="Toggle theme"
        >
          {themeIcon[theme]}
        </button>
        <button class="btn" onClick={doRescan} disabled={busy}>
          {busy ? <span class="spinner" /> : "↻"} Rescan
        </button>
      </header>

      <ConnectionBanner reports={ov.meta.connections} />
      {ov.meta.warnings.length > 0 && (
        <div class="banner">
          {ov.meta.warnings.length} scan warning(s): {ov.meta.warnings.slice(0, 3).join("; ")}
          {ov.meta.warnings.length > 3 ? " …" : ""}
        </div>
      )}
      {!ov.meta.dockerAvailable && (
        <div class="banner">
          Docker socket not available — showing configuration only. Live status, health and IPs are hidden.
        </div>
      )}

      <div class="kpis">
        <StatTile label="Stacks" value={ov.stats.stacks} />
        <StatTile
          label="Services"
          value={ov.stats.services}
          sub={ov.meta.dockerAvailable ? `${ov.stats.running} running` : undefined}
        />
        {/* Subtitles name the mechanism, not a vendor: which tunnel or proxy is in
            front is the routes' business, and a fleet using neither should not be
            told otherwise by a hard-coded caption. */}
        <StatTile label="Public" value={ov.stats.publicServices} sub="tunnel route" />
        <StatTile label="Local only" value={ov.stats.localOnlyServices} sub="proxy route" />
        <StatTile
          label="Host port only"
          value={ov.stats.hostPortServices}
          sub="no proxy in front"
          alert={ov.stats.hostPortServices > 0}
        />
        <StatTile label="Auth-protected" value={ov.stats.authProtected} />
        <StatTile
          label="Exposed, no auth"
          value={ov.stats.exposedWithoutAuth}
          alert={ov.stats.exposedWithoutAuth > 0}
          sub={ov.stats.exposedWithoutAuth > 0 ? "⚠ review" : "none"}
        />
      </div>

      <div class="dists">
        <DistributionBar
          title="Ingress exposure"
          segments={ingressSegments}
          active={ingressFilter}
          onToggle={(k) => toggle(ingressFilter, setIngressFilter, k)}
        />
        <DistributionBar
          title="Authentication method"
          segments={authSegments}
          active={authFilter}
          onToggle={(k) => toggle(authFilter, setAuthFilter, k)}
        />
      </div>

      <nav class="tabs">
        <button class={`tab${tab === "overview" ? " active" : ""}`} onClick={() => setTab("overview")}>
          Stacks ({ov.stats.stacks})
        </button>
        <button class={`tab${tab === "graph" ? " active" : ""}`} onClick={() => setTab("graph")}>
          Relationship graph
        </button>
      </nav>

      {tab === "overview" && (
        <>
          <div class="filters">
            <input
              type="search"
              placeholder="Search apps, images, hostnames…"
              value={search}
              onInput={(e) => setSearch((e.target as HTMLInputElement).value)}
            />
            <button
              class="chip"
              aria-pressed={exposedOnly}
              onClick={() => setExposedOnly((v) => !v)}
            >
              ⚠ Exposed, no auth
            </button>
            {filtering && (
              <button
                class="chip"
                onClick={() => {
                  setSearch("");
                  setIngressFilter(new Set());
                  setAuthFilter(new Set());
                  setExposedOnly(false);
                }}
              >
                Clear filters
              </button>
            )}
            <button
              class="chip"
              disabled={groups.length === 0}
              onClick={() => setExpanded(allOpen ? new Set() : new Set(groups.map((g) => g.stack.id)))}
            >
              {allOpen ? "Collapse all" : "Expand all"}
            </button>
            <span class="result-count">
              {filtering
                ? `${groups.length} of ${ov.stats.stacks} stacks · ${filtered.length} of ${flat.length} services`
                : `${groups.length} stacks · ${flat.length} services`}
            </span>
          </div>

          {groups.length === 0 ? (
            <div class="center-msg">No services match the current filters.</div>
          ) : (
            <div class="stack-list">
              {groups.map((g) => (
                <StackCard
                  key={g.stack.id}
                  stack={g.stack}
                  services={g.services}
                  expanded={expanded.has(g.stack.id)}
                  onToggle={() => toggleStack(g.stack.id)}
                  onOpenService={(svc) => setSelected(serviceKey(g.stack.id, svc.name))}
                />
              ))}
            </div>
          )}
        </>
      )}

      {tab === "graph" && (
        <GraphView graph={ov.graph} themeKey={theme} onOpenService={openService} />
      )}

      {selectedFlat && (
        <AppDetail stack={selectedFlat.stack} svc={selectedFlat.svc} onClose={() => setSelected(null)} />
      )}

      {/* The integration panels read the payload already in memory — `ov.stacks` for the
          matched pairs, the summary for the unplaced ones — so opening one costs no
          request and can never disagree with the drawer behind it. */}
      {apiPanel === "authentik" && ov.meta.authentik && (
        <AuthentikDetail
          summary={ov.meta.authentik}
          stacks={ov.stacks}
          conn={conn("authentik")}
          onClose={() => setApiPanel(null)}
          onOpenService={openService}
        />
      )}
      {apiPanel === "traefik" && ov.meta.traefik && (
        <TraefikDetail
          summary={ov.meta.traefik}
          stacks={ov.stacks}
          conn={conn("traefik")}
          onClose={() => setApiPanel(null)}
          onOpenService={openService}
        />
      )}
    </div>
  );
}

const root = document.getElementById("app");
if (root) render(<App />, root);
