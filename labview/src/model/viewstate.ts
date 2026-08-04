/**
 * What the reader is looking at, as a query string.
 *
 * Every part of the dashboard's view state — which tab, which filters, which service's
 * drawer, which panel — lived only in `main.tsx`'s `useState`, which meant none of it
 * survived a reload and none of it could be sent to anybody. For a tool whose entire output
 * is *look at this service*, that is the gap: the answer to "which one?" was a screenshot or
 * a sentence, never a link. It also meant the browser's Back button did nothing to a drawer,
 * which on a phone is the first gesture anybody tries to close one.
 *
 * Pure, and here rather than in `web/`, for the reason {@link ./filter.ts} states: the web
 * bundle is never rendered by the smoke pass, so anything that decides what a reader sees
 * has to live in a module the smoke test can call directly. `main.tsx` owns the state and
 * the `history` calls; this owns the grammar, and the round trip is asserted.
 *
 * **Everything read out of a URL is attacker-supplied**, on the same footing as
 * `parseLoginFailure`: a link is the one input a visitor can be handed by somebody else. So
 * the enumerations are checked against their literals, the tag lists are checked against
 * what the legend can actually draw, and every free string is length-capped. The failure
 * mode being defended against is not injection — Preact escapes — but a view a reader cannot
 * get out of: a filter for a tag that has no chip is a filter with no way to clear it.
 */
import type { TagFilter, TagMode } from "./filter.js";
import { EMPTY_TAG_FILTER } from "./filter.js";

export type ViewTab = "overview" | "graph";
export type ViewPanel = "authentik" | "traefik" | "drift" | "unconfirmed" | "probe";

const VIEW_TABS: readonly ViewTab[] = ["overview", "graph"];
const VIEW_PANELS: readonly ViewPanel[] = ["authentik", "traefik", "drift", "unconfirmed", "probe"];

/**
 * A free-text value's cap. Long enough for the longest thing anybody searches for — a
 * fully-qualified image reference — and short enough that a hostile link cannot arrive with
 * a megabyte in it.
 */
const MAX_TEXT = 200;

export interface ViewState {
  tab: ViewTab;
  search: string;
  ingress: TagFilter;
  auth: TagFilter;
  exposedOnly: boolean;
  hideAccepted: boolean;
  driftOnly: boolean;
  /** `serviceKey` — `${stackId}/${serviceName}` — carried opaquely, matched by the caller. */
  service?: string;
  panel?: ViewPanel;
  /** A docker network name, to open the fleet-wide Networks list at that row. */
  network?: string;
}

export const DEFAULT_VIEW_STATE: ViewState = {
  tab: "overview",
  search: "",
  ingress: EMPTY_TAG_FILTER,
  auth: EMPTY_TAG_FILTER,
  exposedOnly: false,
  hideAccepted: false,
  driftOnly: false,
};

/** Which tag values each dimension's legend can draw, so a filter always has a chip. */
export interface ViewVocabulary {
  ingress: readonly string[];
  auth: readonly string[];
}

/**
 * A tri-state filter as one value: `all:public,lan,-internal`.
 *
 * One parameter rather than three, because the three parts are one expression and a URL
 * carrying `ingress=public&ingress-not=internal&ingress-mode=all` invites a link with two of
 * them. `-` prefixes an exclusion, and the `all:`/`any:` prefix is the mode — omitted when
 * it is `any`, which is the default and by far the common case.
 */
function writeFilter(f: TagFilter): string {
  const parts = [...f.include, ...f.exclude.map((t) => `-${t}`)];
  if (!parts.length) return "";
  return `${f.mode === "all" ? "all:" : ""}${parts.join(",")}`;
}

function readFilter(raw: string | null, allow: readonly string[]): TagFilter {
  if (!raw) return EMPTY_TAG_FILTER;
  let rest = raw;
  let mode: TagMode = "any";
  // Both spellings accepted on the way in, only one written on the way out: `any:` is what
  // somebody hand-editing a link will reach for, and rejecting it would be a puzzle.
  if (rest.startsWith("all:")) {
    mode = "all";
    rest = rest.slice(4);
  } else if (rest.startsWith("any:")) {
    rest = rest.slice(4);
  }
  const include: string[] = [];
  const exclude: string[] = [];
  for (const token of rest.split(",")) {
    const negated = token.startsWith("-");
    const tag = negated ? token.slice(1) : token;
    // Unknown tags are dropped, not carried: `matchesTagFilter` would happily filter every
    // service out on a tag no chip can clear, which is a view with no way back.
    if (!allow.includes(tag)) continue;
    const into = negated ? exclude : include;
    if (!into.includes(tag)) into.push(tag);
  }
  if (!include.length && !exclude.length) return EMPTY_TAG_FILTER;
  return { include, exclude, mode };
}

/**
 * Drop C0 control characters and DEL.
 *
 * A code-point test rather than a regex character class: the class is three escape sequences
 * that no reader can check by eye, and the range is the entire point — everything below the
 * space, plus DEL. Nothing above that is touched, so a search for a container named in
 * Cyrillic or an emoji in a compose label survives intact.
 */
function stripControls(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) continue;
    out += s.charAt(i);
  }
  return out;
}

function readText(raw: string | null): string {
  if (!raw) return "";
  // Control characters stripped rather than the value rejected: a stray newline in a pasted
  // link should cost the newline, not the search term it was pasted with.
  return stripControls(raw).slice(0, MAX_TEXT);
}

function readFlag(raw: string | null): boolean {
  return raw === "1";
}

/**
 * Read a view out of a query string.
 *
 * Anything absent, unrecognised or malformed falls back to the field's default, so a
 * truncated or hand-mangled link opens the dashboard rather than an error — there is no
 * such thing as an invalid LabView URL, only one that describes less than it meant to.
 */
export function readViewState(query: string, vocab: ViewVocabulary): ViewState {
  const p = new URLSearchParams(query);
  const tab = p.get("tab");
  const panel = p.get("panel");
  const service = readText(p.get("svc"));
  const network = readText(p.get("net"));
  return {
    tab: VIEW_TABS.includes(tab as ViewTab) ? (tab as ViewTab) : "overview",
    search: readText(p.get("q")),
    ingress: readFilter(p.get("ingress"), vocab.ingress),
    auth: readFilter(p.get("auth"), vocab.auth),
    exposedOnly: readFlag(p.get("exposed")),
    hideAccepted: readFlag(p.get("accepted")),
    driftOnly: readFlag(p.get("drift")),
    ...(service ? { service } : {}),
    ...(VIEW_PANELS.includes(panel as ViewPanel) ? { panel: panel as ViewPanel } : {}),
    ...(network ? { network } : {}),
  };
}

/**
 * Write a view as a query string, without the `?`.
 *
 * **Defaults are omitted.** The dashboard as it opens has an empty query, so the address bar
 * stays clean until the reader has actually done something — and "is anything filtered?" is
 * answerable by looking at the URL, which is the property that makes a pasted link
 * trustworthy. Key order is fixed rather than insertion-dependent so that the same view
 * always spells the same string, which is what lets the caller compare the result against
 * the current URL and skip a history write that would change nothing.
 */
export function writeViewState(s: ViewState): string {
  const p = new URLSearchParams();
  if (s.tab !== "overview") p.set("tab", s.tab);
  if (s.search) p.set("q", s.search);
  const ing = writeFilter(s.ingress);
  if (ing) p.set("ingress", ing);
  const auth = writeFilter(s.auth);
  if (auth) p.set("auth", auth);
  if (s.exposedOnly) p.set("exposed", "1");
  if (s.hideAccepted) p.set("accepted", "1");
  if (s.driftOnly) p.set("drift", "1");
  if (s.network) p.set("net", s.network);
  if (s.panel) p.set("panel", s.panel);
  if (s.service) p.set("svc", s.service);
  return p.toString();
}

/**
 * Whether moving between two views is *navigation* rather than tuning.
 *
 * A drawer or a panel opening and closing is something Back should undo; a keystroke in the
 * search box is not, and a history entry per keystroke would bury the entry the reader
 * actually wants to get back to. One predicate rather than the condition inlined at the
 * `history` call, so the rule is stated once and can be asserted.
 */
export function isViewNavigation(prev: ViewState, next: ViewState): boolean {
  return prev.service !== next.service || prev.panel !== next.panel;
}
