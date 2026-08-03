import { render } from "preact";
import { useEffect, useMemo, useState } from "preact/hooks";
// The stylesheet is a dependency of the app, not a file that happens to sit beside
// it: importing it here is what puts it in the graph, so Vite minifies it, hashes
// nothing it does not have to, and injects the <link> itself (§3.9).
import "./styles.css";
import type {
  AppStack,
  AuthMethod,
  AuthentikSummary,
  ConnectionReport,
  IngressKind,
  LoginFailureReason,
  Overview,
  Service,
  SessionInfo,
  TagFilter,
  TraefikSummary,
} from "./model";
import {
  collectDeclarationDrift,
  declaredAuthLabel,
  driftSummaryText,
  formatExposureCount,
  parseLoginFailure,
  phaseText,
  shouldBanner,
} from "./model";
import {
  EMPTY_TAG_FILTER,
  cycleTag,
  describeTagFilter,
  matchesTagFilter,
  tagFilterActive,
} from "./model";
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
import { UnauthorizedError, fetchOverview, fetchSession, logout, rescan } from "./api";
import { Login } from "./components/Login";
import { AUTH_META, INGRESS_META, authLabel, ingressLabel } from "./lib/palette";
import { fmtTime, ingressSummary, qualifyRouter, serviceKey } from "./lib/format";
import { StatTile, DistributionBar, TagBars, type DistSegment } from "./components/stats";
import { StackCard } from "./components/StackCard";
import { AppDetail } from "./components/AppDetail";
import { AuthentikDetail, TraefikDetail } from "./components/ApiDetail";
import { DriftDetail } from "./components/DriftDetail";
import { GraphView } from "./components/GraphView";
import { NetworksSection } from "./components/NetworksSection";

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

/**
 * The failure code a redirect left in the address bar, taken once and removed.
 *
 * The OIDC routes can only report a failure by redirecting, so `?login_error=…` is how
 * that arrives. Validated through `parseLoginFailure` because the value is
 * attacker-supplied by definition, and stripped with `replaceState` so a reload or a
 * shared link does not resurrect an error about an attempt that is long over.
 */
function readLoginError(): LoginFailureReason | undefined {
  const params = new URLSearchParams(location.search);
  const reason = parseLoginFailure(params.get("login_error"));
  if (params.has("login_error")) {
    params.delete("login_error");
    const query = params.toString();
    history.replaceState(null, "", `${location.pathname}${query ? `?${query}` : ""}${location.hash}`);
  }
  return reason;
}

function applyTheme(theme: Theme) {
  const el = document.documentElement;
  if (theme === "auto") el.removeAttribute("data-theme");
  else el.setAttribute("data-theme", theme);
}

function App() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  /**
   * Who may read this LabView, from `/api/session` — the one API route a visitor may
   * read. `null` until it answers, which is why the overview fetch waits on it: when
   * LabView is enforcing there is no overview to fetch yet, and asking first would put a
   * 401 in the console of every cold load.
   */
  const [session, setSession] = useState<SessionInfo | null>(null);
  /** A failure code from a redirect or from a session that ran out mid-visit. */
  const [loginError, setLoginError] = useState<LoginFailureReason | undefined>(readLoginError);
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
  /**
   * Tri-state, because ingress is multi-valued: a chip is included, excluded, or
   * neither, and the included set is combined with `Any` (OR) or `All` (AND). The
   * semantics live in `model/filter.ts` — this holds only the state.
   */
  const [ingressFilter, setIngressFilter] = useState<TagFilter>(EMPTY_TAG_FILTER);
  /** The same three states for auth, which stays on `any`: `auth.method` is one value. */
  const [authFilter, setAuthFilter] = useState<TagFilter>(EMPTY_TAG_FILTER);
  const [exposedOnly, setExposedOnly] = useState(false);
  /**
   * Put the exposures someone has signed off on out of the way, so the list can be read
   * down to zero. Off by default and offered only when there is something to hide — an
   * acceptance is a decision to be able to see, not a way to make the count look better.
   */
  const [hideAccepted, setHideAccepted] = useState(false);
  /** The other direction: only the services whose `.labview` disagrees with the scan. */
  const [driftOnly, setDriftOnly] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  /**
   * The network whose row to open at, set by tapping a network node in the graph.
   *
   * A network node cannot show its own members — its spokes are capped — so tapping one
   * has to hand the reader over to the list that can, which lives on the other tab.
   */
  const [network, setNetwork] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  /**
   * Which side panel is open, if any: an integration's detail, or the declaration drift.
   *
   * One state for all three rather than one flag each, so opening a panel closes whichever
   * was open and the Escape order below has a single thing to dismiss — two panels stacked
   * on one scrim is a reader closing one to find another underneath.
   *
   * Separate from `selected` rather than folded into it: the two are opened from different
   * places and closed in a defined order, and a single union would have to be unpacked at
   * every use to say which of the two it is.
   */
  const [panel, setPanel] = useState<"authentik" | "traefik" | "drift" | null>(null);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  /**
   * Whether the fleet may be read: either nothing is enforced — the default, and how
   * LabView behaved before it had a login — or there is a session.
   */
  const mayRead = session !== null && (!session.enforced || session.user !== undefined);

  useEffect(() => {
    fetchSession()
      .then(setSession)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  // Second, and only once reading is allowed. Signing in flips `mayRead` and this fires,
  // so the card hands straight over to the overview without a reload.
  useEffect(() => {
    if (!mayRead) return;
    fetchOverview().then(setOv).catch(loadFailed);
  }, [mayRead]);

  /**
   * A failed read of the fleet.
   *
   * A 401 is not an error to report — it means the session went away (expired, revoked, or
   * a restart with a generated secret), so the fleet comes off the screen and the card
   * comes back saying which. Anything else is the red box it always was.
   *
   * A session re-read that itself fails keeps the previous snapshot rather than raising:
   * the visitor needs the card, and the card's own submit path is what reports an
   * unreachable server, in the words of the thing they just tried to do.
   */
  function loadFailed(e: unknown): void {
    if (e instanceof UnauthorizedError) {
      setOv(null);
      setLoginError("session-expired");
      fetchSession()
        .then(setSession)
        .catch(() => undefined);
      return;
    }
    setError(e instanceof Error ? e.message : String(e));
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // One layer at a time, topmost first. Opening a service from a panel closes the
      // panel, so the two are not normally both open — but the order is defined here
      // rather than relying on that, since the cost of being wrong is a key that looks
      // dead because it dismissed something behind what the reader was looking at.
      if (panel) setPanel(null);
      else setSelected(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [panel]);

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
      loadFailed(e);
    } finally {
      setBusy(false);
    }
  }

  /**
   * Sign out, then reload.
   *
   * The reload is the point, not a shortcut: an open drawer, a filter and a selected
   * service all describe a fleet this browser may no longer read, and clearing them one
   * by one is a list that grows every time the UI does. Coming back through a cold load
   * shows whatever the server now says, which after a successful sign-out is the card.
   */
  async function doSignOut() {
    setBusy(true);
    try {
      await logout();
    } finally {
      location.reload();
    }
  }

  const flat = useMemo(() => (ov ? flatten(ov) : []), [ov]);
  // Empty when no integration was read in either scan, which is what keeps the note
  // unchanged for a fleet that has neither switched on.
  const apiDiffText = apiDiff ? integrationDiffText(apiDiff) : "";

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return flat.filter(({ stack, svc }) => {
      // Evaluated per service, against that service's own kinds. A stack survives when
      // at least one of its services does, and shows only those — which is what makes
      // "All: Public + LAN" mean one service carrying both, not a stack that has one of
      // each.
      if (!matchesTagFilter(svc.ingress, ingressFilter)) return false;
      if (!matchesTagFilter([svc.auth.method], authFilter)) return false;
      if (exposedOnly && !svc.auth.exposedWithoutAuth) return false;
      if (hideAccepted && svc.declared?.unauthenticatedAccepted) return false;
      if (driftOnly && !svc.declared?.drift.length) return false;
      if (q) {
        // Declared prose is searchable too: "who owns this" and "which of these is the
        // media stack" are questions the sidecar answers and the compose file does not.
        const declared = svc.declared;
        const hay = [
          svc.name,
          stack.name,
          svc.image ?? "",
          svc.containerName,
          ingressSummary(svc),
          declared?.description ?? stack.declared?.description ?? "",
          declared?.owner ?? stack.declared?.owner ?? "",
          declared?.criticality ?? stack.declared?.criticality ?? "",
          declared?.auth.map((a) => `${a.mechanism} ${declaredAuthLabel(a.mechanism)}`).join(" ") ?? "",
        ]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [flat, search, ingressFilter, authFilter, exposedOnly, hideAccepted, driftOnly]);

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

  const filtering =
    search.trim() !== "" ||
    tagFilterActive(ingressFilter) ||
    tagFilterActive(authFilter) ||
    exposedOnly ||
    hideAccepted ||
    driftOnly;

  // A match must never hide behind a click, so an active filter opens the stacks it
  // matched, and clearing the filter collapses them again. Keyed on the filter
  // inputs rather than on the results, so toggling a stack does not re-trigger it.
  useEffect(() => {
    setExpanded(filtering ? new Set(groups.map((g) => g.stack.id)) : new Set());
  }, [search, ingressFilter, authFilter, exposedOnly]);

  // One count per kind, each counted independently — a service tunnelled and proxied
  // adds to both, so these overlap and do not sum to the number of services. `TagBars`
  // draws them as separate gauges against the service count for exactly that reason.
  const ingressSegments = useMemo<DistSegment[]>(() => {
    const counts = new Map<IngressKind, number>();
    for (const { svc } of flat) {
      for (const k of svc.ingress) counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    return INGRESS_META.map((m) => ({ key: m.key, label: m.label, cssVar: m.cssVar, count: counts.get(m.key) ?? 0 }));
  }, [flat]);

  const authSegments = useMemo<DistSegment[]>(() => {
    const counts = ov?.stats.byAuthMethod ?? {};
    return AUTH_META.map((m) => ({ key: m.key, label: m.label, cssVar: m.cssVar, count: counts[m.key] ?? 0 }));
  }, [ov]);

  // Every `.labview` disagreement, grouped by stack. One report, read by the tile's
  // tooltip and by the panel it opens, so the number on the front and the list behind it
  // are the same object rather than two counts of one fleet.
  const drift = useMemo(() => collectDeclarationDrift(ov?.stacks ?? []), [ov]);


  const selectedFlat = selected ? flat.find((f) => f.key === selected) : undefined;

  function openService(stackId: string, serviceName: string) {
    setSelected(serviceKey(stackId, serviceName));
    // A service can be reached from inside a panel — an integration's matched row, or a
    // drifting service. Two stacked drawers would leave the reader closing one to find
    // another underneath, so the panel that sent them here gets out of the way.
    setPanel(null);
  }

  function toggleStack(stackId: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(stackId)) next.delete(stackId);
      else next.add(stackId);
      return next;
    });
  }

  // Before the error box on purpose: a visitor who has to sign in is shown how to, even
  // if a read failed on the way here — the card carries the reason, and its own submit
  // path is what reports a server that cannot be reached.
  if (session && session.enforced && !session.user) {
    return (
      <Login
        info={session}
        initialError={loginError}
        onSignedIn={() => {
          setLoginError(undefined);
          setError(null);
          fetchSession()
            .then(setSession)
            .catch((e) => setError(e instanceof Error ? e.message : String(e)));
        }}
      />
    );
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
                  aria-expanded={panel === "authentik"}
                  onClick={() => setPanel("authentik")}
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
                  aria-expanded={panel === "authentik"}
                  onClick={() => setPanel("authentik")}
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
                  aria-expanded={panel === "traefik"}
                  onClick={() => setPanel("traefik")}
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
                  aria-expanded={panel === "traefik"}
                  onClick={() => setPanel("traefik")}
                  title={connTitle(conn("traefik"), ov.meta.traefik.error)}
                >
                  {conn("traefik")?.phase ?? "unreachable"}
                </button>
              )}
            </span>
          )}
        </div>
        <div class="spacer" />
        {/* Only while enforcing — with nothing configured there is no session to name and
            no way to end one, and a "signed in as" line would be a fiction. */}
        {session?.user && (
          <span class="who">
            signed in as <strong>{session.user.name}</strong>
            {" · "}
            <button class="linkbtn" onClick={doSignOut} disabled={busy}>
              Sign out
            </button>
          </span>
        )}
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
        {/* Subtitles name the mechanism the routes describe, so a tile still reads
            correctly for a fleet whose tunnel or proxy is a different product. */}
        <StatTile label="Public" value={ov.stats.publicServices} sub="tunnel route" />
        <StatTile label="Traefik" value={ov.stats.traefikServices} sub="proxy route" />
        {/* Every service with a published port, whether or not a proxy also fronts it —
            the port answers on the LAN either way, which is the thing worth counting.
            The tiles overlap by construction now: a tunnelled, proxied, port-publishing
            service is in three of them. */}
        <StatTile
          label="LAN"
          value={ov.stats.lanServices}
          sub="published port"
          alert={ov.stats.lanServices > 0}
        />
        {/* The complement, and the only tile here that is exclusive: nothing reaches
            these, not even another container. */}
        <StatTile label="No ingress" value={ov.stats.noIngressServices} sub="nothing reaches it" />
        <StatTile label="Auth-protected" value={ov.stats.authProtected} />
        {/* `23/28` — needing attention over found. The denominator is what the scan
            found and does not move when an exposure is accepted; the numerator is what
            nobody has looked at yet, and drives the alarm. So a fleet where every
            exposure has been reviewed stops shouting without ever understating what is
            reachable, and the five that were reviewed stay countable. */}
        <StatTile
          label="Exposed, no auth"
          value={formatExposureCount(ov.stats.exposedWithoutAuth, ov.stats.exposureAccepted)}
          alert={ov.stats.exposedWithoutAuth - ov.stats.exposureAccepted > 0}
          sub={
            ov.stats.exposedWithoutAuth === 0
              ? "none"
              : ov.stats.exposureAccepted > 0
                ? `${ov.stats.exposureAccepted} accepted in .labview`
                : "⚠ review"
          }
        />
        {/* Only when there is something to report: a fleet with no sidecar anywhere sees
            the same tiles it always did. */}
        {ov.stats.declaredAuth > 0 && (
          <StatTile
            label="Declared auth"
            value={ov.stats.declaredAuth}
            sub="from .labview"
          />
        )}
        {/* The services that left the tile above on the strength of a declaration. Its
            own tile precisely so that number is never absorbed into "Auth-protected",
            which means *proven* protected — these rest on a statement instead. */}
        {ov.stats.declaredAuthProtected > 0 && (
          <StatTile
            label="Protected — declared"
            value={ov.stats.declaredAuthProtected}
            sub="unverified"
          />
        )}
        {/* The one tile whose number stands for a set of sentences rather than a
            measurement, so it is the one tile that opens: a count of stale declarations
            is unactionable until it says which file, about which service, and in which
            direction — all of which the analyzer already wrote. */}
        {ov.stats.declarationDrift > 0 && (
          <StatTile
            label="Declaration drift"
            value={ov.stats.declarationDrift}
            alert
            sub="⚠ stale .labview"
            title={`${driftSummaryText(drift)}\nclick for the service-by-service detail`}
            onClick={() => setPanel("drift")}
          />
        )}
      </div>

      <div class="dists">
        <TagBars
          title="Ingress exposure"
          segments={ingressSegments}
          total={ov.stats.services}
          filter={ingressFilter}
          onCycle={(k) => setIngressFilter((f) => cycleTag(f, k))}
          onMode={(mode) => setIngressFilter((f) => ({ ...f, mode }))}
        />
        <DistributionBar
          title="Authentication method"
          segments={authSegments}
          filter={authFilter}
          onCycle={(k) => setAuthFilter((f) => cycleTag(f, k))}
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
            {ov.stats.exposureAccepted > 0 && (
              <button
                class="chip"
                aria-pressed={hideAccepted}
                title="Hide the exposures declared intentional in a .labview file"
                onClick={() => setHideAccepted((v) => !v)}
              >
                Hide accepted ({ov.stats.exposureAccepted})
              </button>
            )}
            {ov.stats.declarationDrift > 0 && (
              <button
                class="chip"
                aria-pressed={driftOnly}
                title="Only services whose .labview declaration disagrees with the scan"
                onClick={() => setDriftOnly((v) => !v)}
              >
                ⚠ Declaration drift ({ov.stats.declarationDrift})
              </button>
            )}
            {filtering && (
              <button
                class="chip"
                onClick={() => {
                  setSearch("");
                  // All three parts of each expression, mode included: a cleared filter
                  // that silently kept `All` would behave differently the next time a
                  // second chip was clicked.
                  setIngressFilter(EMPTY_TAG_FILTER);
                  setAuthFilter(EMPTY_TAG_FILTER);
                  setExposedOnly(false);
                  setHideAccepted(false);
                  setDriftOnly(false);
                }}
              >
                Clear filters
              </button>
            )}
            {/* The expression in words. Three parts — a set, a mode and an exclusion —
                cannot be read reliably off which chips look bright, and a filter a reader
                misreads is a conclusion they draw wrongly. */}
            {(tagFilterActive(ingressFilter) || tagFilterActive(authFilter)) && (
              <span class="filter-readout">
                {[
                  tagFilterActive(ingressFilter)
                    ? `ingress: ${describeTagFilter(ingressFilter, (k) => ingressLabel(k as IngressKind))}`
                    : "",
                  tagFilterActive(authFilter)
                    ? `auth: ${describeTagFilter(authFilter, (m) => authLabel(m as AuthMethod))}`
                    : "",
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
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

          {/* Outside the filtered list on purpose: a network is a fleet-wide fact about
              which services can reach each other, and answering "who else is on this"
              with a set narrowed by the search box would be answering a different
              question. */}
          <NetworksSection
            graph={ov.graph}
            soloLocalNetworks={ov.stats.soloLocalNetworks}
            highlight={network}
            onOpenService={openService}
          />

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
        <GraphView
          graph={ov.graph}
          themeKey={theme}
          onOpenService={openService}
          onOpenNetwork={(name) => {
            setNetwork(name);
            setTab("overview");
          }}
        />
      )}

      {selectedFlat && (
        <AppDetail
          stack={selectedFlat.stack}
          svc={selectedFlat.svc}
          graph={ov.graph}
          onClose={() => setSelected(null)}
          onOpenService={openService}
          /* The same landing as a tap on a network node in the graph, plus the drawer
             closing: the list this points at sits behind the drawer's scrim, so leaving it
             open would scroll a row into view under a sheet of dark. */
          onOpenNetwork={(name) => {
            setNetwork(name);
            setTab("overview");
            setSelected(null);
          }}
        />
      )}

      {/* The integration panels read the payload already in memory — `ov.stacks` for the
          matched pairs, the summary for the unplaced ones — so opening one costs no
          request and can never disagree with the drawer behind it. */}
      {panel === "authentik" && ov.meta.authentik && (
        <AuthentikDetail
          summary={ov.meta.authentik}
          stacks={ov.stacks}
          conn={conn("authentik")}
          onClose={() => setPanel(null)}
          onOpenService={openService}
        />
      )}
      {panel === "traefik" && ov.meta.traefik && (
        <TraefikDetail
          summary={ov.meta.traefik}
          stacks={ov.stacks}
          conn={conn("traefik")}
          onClose={() => setPanel(null)}
          onOpenService={openService}
        />
      )}
      {/* Same shell, same source: the drift panel reads the report built from `ov.stacks`
          above, so it can no more disagree with the tile that opened it than the
          integration panels can with the drawer behind them. */}
      {panel === "drift" && (
        <DriftDetail report={drift} onClose={() => setPanel(null)} onOpenService={openService} />
      )}
    </div>
  );
}

const root = document.getElementById("app");
if (root) render(<App />, root);
