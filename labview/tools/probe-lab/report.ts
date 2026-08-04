/**
 * What LabView's login rule saw at one address, and what it would take to see more.
 *
 * The pure half of the probe lab, split from `cli.ts` the way `resolveBuildStamp` is split
 * from `buildStamp` and `parsePasswd` from `readPasswd`: everything here is a function of an
 * observation record, so the whole report is assertable by the smoke pass against the canned
 * bodies already in `scripts/smoke.ts` — no network, no temporary files, no server.
 *
 * **The verdict is the pipeline's verdict, by construction.** Every rule this file reaches for
 * is imported from `src/model/probe.ts` — `readGate` for the answer, `readRedirect`,
 * `readRefresh`, `readMediaType`, `isHtmlMediaType` and `readLoginForm` for the facts it read,
 * `probeOutcome` and `probeReasonText` for how a result is worded, and the four clause
 * predicates for the per-signal rows. Nothing is reimplemented, because a report that described
 * a decision LabView would not make is worse than no report: it would send somebody to change
 * a rule that was never the problem.
 *
 * **What it is for.** A service that comes back `open` in a real fleet is one of two things: a
 * genuinely unprotected application, or a login page this rule cannot see. Those are the same
 * row on the dashboard and completely different facts, and until now there was no way to look
 * at the page and find out which. So section 2 lists every signal *and why it did not fire*,
 * section 3 dumps the evidence no signal reads yet, and section 4 says what the next signal
 * would have to be. Fine-tuning happens against sections 3 and 4 — the eighth clause LabView
 * ships was designed from exactly those two sections of five real reports.
 *
 * **Two of those sections are about addresses `/` cannot answer for**, because the two ways a
 * login page hides from a body-reading rule are both about *where* rather than *what*. A
 * same-origin redirect chain can end at a sign-in screen three responses past the one the scan
 * reads ({@link ChainStep}). A client-rendered shell has no sign-in screen in its markup at any
 * depth, but the application behind it still refuses an anonymous caller somewhere, and that
 * somewhere is an address ({@link AUTH_STATE_PATHS}).
 *
 * The scan has since learned to ask four of those addresses itself, so the two are no longer
 * symmetrical: **the chain cannot move the verdict and the sweep can**, for the four paths the
 * pipeline shares and under the pipeline's own eligibility test. That is not this tool acquiring a
 * rule of its own — it is the same construction as before, following a rule that moved. See
 * {@link buildReport} and {@link pipelineState}, which is where the eight addresses this tool asks
 * are narrowed to the four a scan would have.
 *
 * **Nothing here decides anything about a fleet.** This is a diagnostic; it writes files a
 * person reads. It is not imported by `src/`, it is not in the image, and no scan consults it.
 */
import {
  LOGIN_LABEL_MAX,
  LOGIN_PATHS,
  PROBE_GATES,
  STATE_PATHS,
  drawnMarkup,
  hasPasswordField,
  hasSamlField,
  isHtmlMediaType,
  isLoginPath,
  pointsAtLogin,
  probeGateText,
  probeOutcome,
  probeReasonText,
  readAnonAccess,
  readGate,
  readLoginForm,
  readMediaType,
  readRedirect,
  readRefresh,
  readState,
  readStateGate,
  saysLogin,
  saysLogout,
  servedAnonContent,
  visibleText,
  wantsStateProbe,
  type StateAnswer,
} from "../../src/model/probe.js";
import type {
  ConnectionPhase,
  LoginFormShape,
  ProbeAnon,
  ProbeGate,
  ProbeRedirect,
  ProbeState,
  ServiceProbe,
} from "../../src/model/types.js";

/**
 * One request as the caller saw it, with no judgement in it at all.
 *
 * Deliberately not a `Response`, and for the reason `ProbeResponse` is not one: a plain record
 * is the only shape a test can hand over. It carries more than `ProbeResponse` does — every
 * header, the body size whether or not the body was kept — because the questions this tool
 * exists to answer are mostly about the parts the rule never looked at.
 */
export interface ProbeLabObservation {
  /** The URL that was requested. A `Location` is resolved against it, as in the pipeline. */
  requestUrl: string;
  /** Present when an HTTP response arrived, whatever its status. */
  status?: number;
  /**
   * Every response header, name lowercased. Values are whatever the caller chose to put here —
   * `redactHeaders` is applied by `cli.ts` *before* this record is built, so a report can never
   * carry a value the tool decided not to keep.
   */
  headers: Record<string, string>;
  /**
   * The body — kept **only** when the media type was HTML, which is the pipeline's own rule
   * (`getResponse` does not read a non-HTML body at all). Present is therefore itself the
   * evidence that HTML answered, exactly as on `ProbeResponse`.
   */
  body?: string;
  /** Whether the body read stopped at the cap rather than at the end of the page. */
  truncated?: boolean;
  /** Bytes read for the body, whether or not it was kept. */
  bodyBytes?: number;
  /** Why nothing arrived. Present only when `status` is absent. */
  error?: string;
  /** Which transport stage failed. `connected` whenever a response arrived. */
  phase?: ConnectionPhase;
  /** Wall-clock for the request. Stamped by the caller, since a pure function cannot. */
  elapsedMs?: number;
}

/** One of the eight clauses, and what it turned on for this page. */
export interface SignalRow {
  gate: ProbeGate;
  /** What a reader sees this signal called, from `probeGateText` — never a second wording. */
  label: string;
  /** Whether *this clause* is satisfied, independent of whether a stronger one also is. */
  fired: boolean;
  /** The fact that decided it, in both directions. This is the fine-tuning surface. */
  because: string;
}

/** One `<form>`, dumped rather than ranked. `readLoginForm` reads these and reports one shape. */
export interface FormDump {
  action?: string;
  method?: string;
  id?: string;
  inputs: InputDump[];
  /** The text of every `<button>` and `<input type=submit|button>` value in the form. */
  buttons: string[];
}

/** One `<input>`, with every attribute a login-detection rule could ever want. */
export interface InputDump {
  type?: string;
  name?: string;
  id?: string;
  placeholder?: string;
  autocomplete?: string;
  ariaLabel?: string;
  required: boolean;
}

/** A `<script src>` or `<link rel=… href>` — the only clue an SPA shell leaves in its markup. */
export interface AssetRef {
  kind: "script" | "link";
  /** `rel`, for a `<link>`. */
  rel?: string;
  href: string;
}

/**
 * One `<a href>`, and what the pipeline's own predicates make of it.
 *
 * **The field this whole section was added for.** Eight reports against a live fleet each said
 * "no `<form>` element in the served markup" about pages carrying fifteen to twenty-four
 * kilobytes of finished HTML — and the proof the operator could see in a browser was a plain
 * `<a href="/login">Sign in</a>` that nothing here had ever read. A form is one of four ways a
 * page offers a login and it is the least common of them on a prerendered page.
 *
 * The three booleans are the pipeline's answers, not the lab's: `isLoginPath`, `saysLogin` and
 * `saysLogout` as `src/model/probe.ts` exports them. Recording them per anchor is the
 * fine-tuning surface — a reader who disagrees with a verdict can see which anchor the rule
 * matched and on which of the two halves.
 */
export interface AnchorRef {
  /** The `href` as written, so a relative link is visible as one. */
  href: string;
  /** Resolved against the request URL, query dropped — `readRedirect`'s own reading. */
  path?: string;
  crossOrigin?: boolean;
  /** Visible text, tags stripped and whitespace collapsed. Capped, since prose can be an anchor. */
  text?: string;
  ariaLabel?: string;
  rel?: string;
  /** `isLoginPath(path)` — set only when true, so a dump of fifty anchors stays readable. */
  loginPath?: boolean;
  /** `saysLogin(label)`. */
  loginLabel?: boolean;
  /** `saysLogout(label)` — the one that stops the two above from meaning what they look like. */
  logoutLabel?: boolean;
  /**
   * Served, but not drawn: this anchor is inside a `<template>`, `<noscript>`, `<script>` or
   * `<svg>`, so no visitor was shown it.
   *
   * Kept rather than dropped, because a framework that routes in the browser ships its sign-in
   * screen in a `<template>` and finding it there is *worth knowing* — it says the application has
   * a login, which is what `login-route` says. It is simply not evidence about what this response
   * showed anybody, so a finding built on one is graded down to `weak` and points at
   * `look-closer`. `readAnonAccess` does not see these at all: `drawnMarkup` removes them before
   * it counts anything.
   */
  hidden?: boolean;
}

/**
 * One control that is not inside a `<form>` — the sign-in of an application that has no form.
 *
 * A single-page application renders `<button>Sign in</button>` with nothing around it and wires
 * it up in JavaScript, so `readLoginForm` has nothing to rank and `hasPasswordField` has nothing
 * to find. Only controls outside every `<form>` are here: one inside a form was already read by
 * the pipeline's own form rules, and dumping it twice would make section 3 argue with section 2.
 */
export interface ControlRef {
  /** Which shape it was found in — a `<button>`, an `<input>`, or a `role="button"` element. */
  kind: "button" | "input" | "role";
  label?: string;
  type?: string;
  id?: string;
  ariaLabel?: string;
  loginLabel?: boolean;
}

/** A `<meta name|property>` and its content — where a vendor names itself when `generator` does not. */
export interface MetaRef {
  name: string;
  content: string;
}

/**
 * A mount point: a custom element, or the `<div>` a framework hands its bundle.
 *
 * The shell's fingerprint. `<div id="root">` is Vite or Create React App, `<div id="__next">` is
 * Next.js, `<home-assistant>` is a custom element that names its own product — and a shell whose
 * mount point is called `login-app` has said what it is about to draw.
 */
export interface RootRef {
  tag: string;
  id?: string;
  className?: string;
}

/**
 * An inline `<script>`, described rather than dumped.
 *
 * **Never its source.** An anonymous page's bootstrap script is where a client keeps its route
 * table, and one of the reports that prompted this section listed a `/__config.js` — so what is
 * kept is a size, a type, the login-shaped path literals in it and the names of the globals it
 * assigns. That is everything a rule could be built on and none of what would make a report
 * unsafe to paste into an issue (**I6**).
 */
export interface InlineScript {
  type?: string;
  id?: string;
  bytes: number;
  /** Quoted path literals in it that `isLoginPath` matches — the client's own route table. */
  loginPaths: string[];
  /** Globals it assigns (`__NEXT_DATA__`, `window.__NUXT__`) — names only, never values. */
  bootstrapKeys: string[];
}

/**
 * What a reader would have read, and a sample of it.
 *
 * `chars` is `read.anon.textChars` — the pipeline's own count, from the pipeline's own
 * `visibleText`, because a second extractor here would print a number the rule did not decide
 * on. The sample is capped and exists for one reason: to show the words "Sign in" sitting in
 * their context, which is what tells a reader whether a hit is a control or a sentence.
 */
export interface PageText {
  chars: number;
  sample: string;
  /** Characters of visible text past the sample cap. `0` when the whole of it is above. */
  omitted: number;
}

/**
 * One thing the page proves about itself, and which way it points.
 *
 * Section 3a, and the part of a report that answers the question an operator actually asked:
 * *this service has a sign-in page — why does the tool say it found nothing?* The signal table
 * above can only say which of eight clauses failed. This says what the page showed.
 *
 * **`direction` has no `"gated"` member, and that is the type doing the work.** A finding here
 * can point at *open*, at *open with an optional account*, or at *worth another look*; it can
 * never conclude that a gate exists, because concluding that is `readGate`'s job and `readGate`
 * cannot see any of this. So the worst a detector can be wrong about is a paragraph in a
 * diagnostic file — never a service's place in the exposed count (**I1**). `buildReport` puts
 * the verdict together before this function is called, and the smoke pass asserts that a report
 * with findings has the same `verdict.gate` as `readGate` alone.
 */
export interface EvidenceFinding {
  kind:
    | "login-link"
    | "login-control"
    | "login-route"
    | "login-heading"
    | "session-cookie"
    | "content-served";
  direction: "open-with-login" | "open" | "look-closer";
  /** How much the fact carries: `proof` is what a page did, `weak` is what a word suggested. */
  strength: "proof" | "strong" | "weak";
  /** Quoted from the page, so a reader checks the finding rather than believing it. */
  fact: string;
  /** Why that fact points where `direction` says. */
  because: string;
}

/**
 * One hop of a redirect chain the tool walked past the first response.
 *
 * **The scan does not walk this.** `getResponse` sends `redirect: "manual"` and `readGate` reads
 * one response, so a chain is not evidence LabView could act on — it is evidence about *why* the
 * one response LabView reads said what it said. A service can hand out three same-origin 3xx in a
 * row and land on its sign-in screen, and all the scan gets is the first `Location`. Recording
 * the hops is how a reader sees the difference between "no gate" and "the gate is further down a
 * chain nobody followed", which are the same row on the dashboard.
 */
export interface ChainStep {
  /** The address asked at this hop. */
  url: string;
  status?: number;
  /** The raw `Location`, and where it resolved to — the same reading `readRedirect` does. */
  location?: string;
  to?: string;
  crossOrigin?: boolean;
  contentType?: string;
  /** `<title>`, when HTML came back. Often the only thing naming what the page is. */
  title?: string;
  bodyBytes?: number;
  error?: string;
  /**
   * What `readGate` would find *at this hop*, applied to the hop's own response.
   *
   * The load-bearing field. A gate here and none on the first response is the finding: the
   * service is gated and the scan cannot see it from where it looks.
   */
  gate?: ProbeGate;
}

/**
 * One address from {@link AUTH_STATE_PATHS}, and what it answered.
 *
 * The evidence a client-rendered login leaves at the HTTP level. A shell's markup carries no
 * gate by construction, but the application behind it still has to refuse an anonymous caller
 * somewhere — and where it does that is an address, which can be asked.
 */
export interface SweepStep {
  /** The path, as it appears in {@link AUTH_STATE_PATHS}. */
  path: string;
  url: string;
  status?: number;
  contentType?: string;
  /** Kept verbatim, for `challenge`'s reason: a challenge is evidence, not a secret. */
  wwwAuthenticate?: string;
  bodyBytes?: number;
  error?: string;
  /**
   * Whether the body was byte-identical to the one served at the target address.
   *
   * The tell for a catch-all: a single-page application whose server answers every unmatched
   * path with the same shell will return 200 here, and that 200 means *nothing was matched*
   * rather than *an anonymous caller was served*. Without this, a catch-all reads as an open
   * endpoint, which is the one wrong conclusion this whole section could produce.
   */
  sameAsRoot?: boolean;
}

/**
 * One address from the pipeline's own {@link LOGIN_PATHS}, asked on purpose, and what it answered.
 *
 * **Opt-in, `--try-login-paths`, and off by default.** The other two extra-request sections exist
 * because a service *told* the tool where to look — a `Location` header, or a convention the
 * pipeline already trusts enough to send a scan's second request at. This one guesses, and a guess
 * at ten addresses on somebody's service is a different kind of act, so it happens only when
 * somebody typed the flag.
 *
 * Three readings, and each is worth having:
 *
 *  - **A login page.** `gate` is the real `readGate` run on that answer, so this says the
 *    application has a sign-in screen at a path the pipeline already trusts by name — and the
 *    change that would let a scan find it is *one more address in a list*, which is a sized,
 *    reviewable commit rather than a loosened clause.
 *  - **The same bytes as the root.** A catch-all router, which is proof the login is drawn in the
 *    browser — the blind spot named, rather than guessed at. Same `sameAsRoot` reasoning as
 *    {@link SweepStep}, and it matters more here: every path below is *expected* to 404 on a
 *    service that has no login, so a 200 that is really the shell would otherwise read as a hit.
 *  - **A 404.** The path is ruled out, which is the answer that keeps a reader from going looking.
 *
 * **None of it can move the verdict**, and here that is a plain statement rather than a
 * construction: the scan asks none of these addresses, so a gate found at one is a gate LabView
 * does not have. {@link nextSteps} is where it lands, in the register the sweep's own
 * fourth-address finding already uses.
 */
export interface LoginPathStep {
  /** The path, as it appears in `LOGIN_PATHS`. */
  path: string;
  url: string;
  status?: number;
  contentType?: string;
  wwwAuthenticate?: string;
  bodyBytes?: number;
  error?: string;
  /** The same catch-all tell {@link SweepStep.sameAsRoot} is, and load-bearing for the same reason. */
  sameAsRoot?: boolean;
  /** `readGate` on this answer — the pipeline's rule at an address the pipeline does not ask. */
  gate?: ProbeGate;
  /** `readLoginForm`, so a reader sees *what* made it a login page and not only that it did. */
  form?: LoginFormShape;
  /** The page's own name for itself, which is how a reader recognises a sign-in screen. */
  title?: string;
}

/** The whole report for one address. `renderMarkdown`/`renderJson` are views of this. */
export interface ProbeLabReport {
  url: string;
  /** 1 — what LabView would conclude, and what that would do to the exposed count. */
  verdict: {
    gate?: ProbeGate;
    /** `probeOutcome().label` — the same words the dashboard uses. */
    label: string;
    /** `probeReasonText()` — the fact the verdict rested on. */
    reason: string;
    /**
     * Whether this answer would take a service out of the exposed count. True exactly when a
     * gate fired: `hasEdgeAuth` is `configuredEdgeAuth || probeGate`, and this tool is pointed
     * at services with no configured gate, so the probe term is the only one in play.
     */
    withdrawsExposure: boolean;
  };
  /** 2 — what the rule read, and one row per signal. */
  read: {
    status?: number;
    phase?: ConnectionPhase;
    error?: string;
    elapsedMs?: number;
    contentType?: string;
    mediaType?: string;
    /** Whether the media type is one the rule reads a body from at all. */
    html: boolean;
    location?: string;
    redirect?: ProbeRedirect;
    refresh?: ProbeRedirect;
    /** Present or not is the whole of what the `challenge` clause asks of it. */
    wwwAuthenticate?: string;
    bodyBytes?: number;
    truncated: boolean;
    /** What `readLoginForm` reduced the page to — the one form the rule ranked highest. */
    form?: LoginFormShape;
    /**
     * What `readAnonAccess` made of the same body, read the other way round.
     *
     * In `read` rather than `unread` because the pipeline reads it now: the scan puts this record
     * on `ServiceProbe.anon` and `probeReasonText` words a sentence from it. Present exactly when
     * a body was read at all.
     */
    anon?: ProbeAnon;
    signals: SignalRow[];
  };
  /**
   * 2b — every hop past the first, when the first was a 3xx and carried no gate.
   *
   * Empty when nothing was followed, which is also what it is for every response the scan itself
   * could have judged. Reported beside section 2 rather than in it, because none of it is what
   * the rule read.
   */
  chain: ChainStep[];
  /**
   * 3b — what {@link AUTH_STATE_PATHS} answered, when the served page carried nothing.
   *
   * Empty unless the sweep ran. See {@link wantsSweep} for when that is.
   */
  sweep: SweepStep[];
  /**
   * 3c — what the pipeline's own {@link LOGIN_PATHS} answered, when somebody asked for it.
   *
   * Empty unless `--try-login-paths` was given and the target was the shape {@link wantsSweep}
   * describes. See {@link LoginPathStep} for why this one is opt-in where the other two are not.
   */
  loginPaths: LoginPathStep[];
  /**
   * 3a — what the page proves about itself, in the order worth reading.
   *
   * Above the dumps because it is the actionable part, and separate from `verdict` because it is
   * structurally incapable of being one. Empty when nothing answered, or when a gate fired and
   * there is nothing left to argue about.
   */
  evidence: EvidenceFinding[];
  /** 3 — the evidence no signal reads yet, which is what an eighth one would be built from. */
  unread: {
    title?: string;
    h1?: string;
    lang?: string;
    generator?: string;
    forms: FormDump[];
    assets: AssetRef[];
    /**
     * Every `<a href>` on the page, with the pipeline's own reading of each.
     *
     * Capped at {@link MAX_ANCHORS}, login-shaped ones kept first and drawn ones ahead of undrawn
     * — a navigation menu is fifty anchors and the one that matters is not reliably among the
     * first fifty in document order.
     */
    anchors: AnchorRef[];
    anchorsOmitted: number;
    /** Controls **outside** every `<form>`, capped at {@link MAX_CONTROLS}. */
    controls: ControlRef[];
    controlsOmitted: number;
    /** Every `<meta name|property>`, capped at {@link MAX_METAS}. */
    metas: MetaRef[];
    metasOmitted: number;
    /** Mount points and custom elements, capped at {@link MAX_ROOTS}. */
    roots: RootRef[];
    rootsOmitted: number;
    /** Inline scripts described, never dumped. Capped at {@link MAX_INLINE_SCRIPTS}. */
    inlineScripts: InlineScript[];
    inlineScriptsOmitted: number;
    /** `<noscript>` contents — the server's own fallback, which sometimes names the login. */
    noscript: string[];
    /** What a reader would have read, and a capped sample of it. */
    text: PageText;
    /** Every response header that survived redaction, in the order they were given. */
    headers: [string, string][];
    /** `Set-Cookie` reduced to names. A session cookie name is a strong vendor marker. */
    cookieNames: string[];
  };
  /** 4 — one line per signal that did not fire, saying what would have to be true. */
  next: string[];
}

/* -------------------------------------------------------------------------- */
/* How much of a page a report is allowed to carry                            */
/* -------------------------------------------------------------------------- */

/*
 * A report is a file a person reads, and the pages this tool is pointed at run to twenty-four
 * kilobytes. Every dump below is therefore bounded, and every bound is reported as an `…Omitted`
 * count rather than applied in silence — a truncated list that does not say it was truncated is
 * how a reader concludes a page had no sign-in link when what happened is that the report stopped
 * before it.
 *
 * The numbers are deliberately generous. Nothing here can move a verdict, so the only cost of a
 * bound set too high is a long file, and the only cost of one set too low is the exact failure
 * this whole change exists to fix.
 */
const MAX_ANCHORS = 60;
const MAX_CONTROLS = 30;
const MAX_METAS = 40;
const MAX_ROOTS = 20;
const MAX_INLINE_SCRIPTS = 20;
/** How much visible text {@link PageText.sample} keeps. Roughly a screenful and a half. */
const MAX_TEXT_SAMPLE = 2000;
/** How much of one anchor's text is kept. Prose can be an anchor; a label is short. */
const MAX_ANCHOR_TEXT = 120;
/** How many login-shaped path literals one inline script contributes. */
const MAX_SCRIPT_PATHS = 8;
/** How many bootstrap global names one inline script contributes. */
const MAX_SCRIPT_KEYS = 8;
/** How many `<noscript>` blocks are kept, and how much of each. */
const MAX_NOSCRIPT = 4;
const MAX_NOSCRIPT_TEXT = 400;

/* -------------------------------------------------------------------------- */
/* The addresses the rule never asks                                          */
/* -------------------------------------------------------------------------- */

/**
 * Where an application is asked whether it knows who is calling, when its markup will not say.
 *
 * The blind spot this exists for: a 200 whose body is a script tag and an empty `<div>` is not a
 * page without a login form, it is a page whose login form has not been drawn yet — and **no
 * amount of reading that body can tell the difference.** The information is not in the markup at
 * any depth, and it is not in a redirect either, because there is no redirect: the application
 * serves its shell at every path and routes in the browser.
 *
 * But the shell is only the front. Whatever it draws has to fetch state, and the fetch has to be
 * refused when nobody is signed in. So there is an HTTP-level gate; it is simply at a different
 * address than the one the scan asks. These are the addresses that refusal is conventionally at:
 * an `/api` root, and a current-user or session resource under nothing, one path segment, or a
 * version segment. Nothing here is any product's endpoint — it is the shape the convention takes,
 * and the reason the list can be short is that the convention is narrow.
 *
 * **Bounds, because this is the one place the tool asks for more than it was given** (I8):
 *
 *  - **Fixed.** Nothing derived from a fetched page, no pattern expansion, no crawl. Eight
 *    addresses, the same eight every run, and adding one is a commit somebody reviews.
 *  - **Only where reading failed.** {@link wantsSweep} restricts it to the case above — a page
 *    served, no gate found, no `<form>` in the markup. A response the rule could judge is never
 *    swept, because the answer could not change anything.
 *  - **`GET`, no credential.** Which is the whole point: a 401 here is what an anonymous visitor
 *    gets, and a credential would turn the one useful answer into a useless one.
 *
 * **The pipeline's four come first, and they come from the pipeline.** `STATE_PATHS` is spread in
 * rather than retyped, so this list is a superset of what a scan asks by construction and not by
 * an assertion somebody has to keep true. That matters because {@link buildReport} reconstructs
 * the scan's own walk from these answers: a path the scan asks and this sweep does not would
 * silently truncate that reconstruction, and the report would understate the verdict rather than
 * fail. The order puts them first for the same reason — those are the four that can move a
 * verdict, and the four after them are evidence only.
 */
export const AUTH_STATE_PATHS: readonly string[] = [
  ...STATE_PATHS,
  "/api/user",
  "/api/session",
  "/api/auth/session",
  "/api/v1/users/me",
];

/**
 * Whether asking {@link AUTH_STATE_PATHS} could tell this target's reader anything.
 *
 * True for exactly one shape: a page was served, the rule found no gate in it, and there is no
 * `<form>` in the markup at all. That is the client-rendered shell — the only case where the
 * served body is known to be silent rather than known to be negative.
 *
 * False for everything else, and each exclusion is deliberate. A gate that fired needs no further
 * evidence. A 3xx has a `Location`, which is evidence, and following it is the chain's job. A
 * non-HTML answer says the address is not a UI. A page *with* forms said something the reader can
 * act on, so section 3's dump is the next thing to look at rather than eight more requests.
 *
 * **Not the same test as `wantsStateProbe`, and deliberately looser.** The pipeline's test asks
 * whether *any* `<form` appears in the markup; this one asks whether the report's form dump came
 * out empty, which is a parse and can be empty where the regex would have matched. The difference
 * only ever makes this tool ask more — it is a diagnostic, so a wasted eight requests against a
 * page the reader pointed it at costs nothing but time. It must never make the *verdict* wider,
 * and it cannot: {@link buildReport} consults `wantsStateProbe` before it lets a swept answer near
 * the gate.
 */
export function wantsSweep(report: ProbeLabReport): boolean {
  return (
    report.verdict.gate === undefined &&
    report.read.status === 200 &&
    report.read.html &&
    report.unread.forms.length === 0
  );
}

/* -------------------------------------------------------------------------- */
/* The report                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Build the whole report for one observation.
 *
 * The order below is the order the sections are read in, and it is not arbitrary: the verdict
 * comes from the rule first, so everything after it is an account of a decision already made
 * rather than a second derivation that could disagree with it.
 *
 * `extra` is what the caller went on to ask after the first answer — hops of a redirect chain,
 * and the auth-state sweep. **The chain cannot move the verdict.** A chain that ends at a login
 * page still reports "no login page", because that is what LabView would conclude from the same
 * first response, and a report whose verdict improved on the pipeline's would be describing a
 * dashboard nobody has.
 *
 * **The sweep can**, and that is not an exception to the rule above — it is the same rule, applied
 * after the pipeline learned to send a second request of its own. `readStateGate` is now part of a
 * scan's verdict, so a report that withheld it would be the thing this file exists to prevent: a
 * verdict LabView does not share. What keeps it honest is that only the pipeline's own four
 * addresses are consulted, in the pipeline's order, truncated at the pipeline's short-circuit, and
 * only where the pipeline's own eligibility test says the request would have been sent at all — see
 * {@link pipelineState}. This tool asks eight addresses; four of them are evidence for a reader and
 * cannot appear in a verdict.
 *
 * **`loginPaths` cannot, and needs no argument at all.** The pipeline has no code path that sends a
 * request to `/login`, so there is no reading of those answers that a scan could reproduce. They
 * are read by the pipeline's rules — `readGate`, `readLoginForm` — for the reader's benefit, and
 * they land in `next` as a sized change, the same way the sweep's fourth address does.
 */
export function buildReport(
  obs: ProbeLabObservation,
  extra: {
    chain?: readonly ProbeLabObservation[];
    sweep?: readonly ProbeLabObservation[];
    loginPaths?: readonly ProbeLabObservation[];
  } = {},
): ProbeLabReport {
  const contentType = obs.headers["content-type"];
  const mediaType = readMediaType(contentType);
  const location = obs.headers["location"];
  const wwwAuthenticate = obs.headers["www-authenticate"];

  // The exact record the pipeline would have handed `readGate`. Built once and reused for the
  // verdict, the reason and every signal row, so the three cannot describe different responses.
  const res = asProbeResponse(obs);
  const answered = obs.status !== undefined;
  const firstGate = answered ? readGate(res) : undefined;

  // The scan's walk, reconstructed — but only if the scan would have walked. `wantsSweep` is this
  // tool's looser test and may well have run the sweep on a page the pipeline would never have
  // asked a second question about; reading a gate out of those answers would put a verdict in the
  // report that no scan can reach.
  const state =
    answered &&
    extra.sweep?.length &&
    wantsStateProbe({ gate: firstGate, status: obs.status!, mediaType, body: obs.body })
      ? pipelineState(extra.sweep)
      : undefined;
  const gate = firstGate ?? (state ? readStateGate(state) : undefined);

  const redirect = location ? readRedirect(location.trim(), obs.requestUrl) : undefined;
  const refresh = obs.body ? readRefresh(obs.body, obs.requestUrl) : undefined;
  const form = obs.body ? readLoginForm(obs.body, obs.requestUrl) : undefined;
  // Computed here and put on `asProbe` below, not read out of the extraction pass: this is the
  // record the *scan* would hold, so the sentence in section 1 of this report is the sentence in
  // the dashboard drawer. Section 3a's detectors read the same one — a report where the reason
  // said "a sign-in link to /login" and the evidence list disagreed would be worse than either.
  const anon = obs.body ? readAnonAccess(obs.body, obs.requestUrl) : undefined;

  // `probeOutcome` and `probeReasonText` take a `ServiceProbe`-shaped record. Assembling one
  // here rather than wording anything locally is what keeps this report saying what the
  // dashboard says about the same answer — the type is the pipeline's, so a field the wording
  // rules start reading is a field this has to start providing.
  const asProbe: Pick<
    ServiceProbe,
    | "phase"
    | "status"
    | "gate"
    | "form"
    | "mediaType"
    | "redirect"
    | "refresh"
    | "state"
    | "anon"
    | "truncated"
    | "detail"
  > = {
    phase: answered ? "connected" : (obs.phase ?? "connect"),
    ...(obs.status !== undefined ? { status: obs.status } : {}),
    ...(gate ? { gate } : {}),
    ...(form ? { form } : {}),
    ...(mediaType ? { mediaType } : {}),
    ...(redirect ? { redirect } : {}),
    ...(refresh ? { refresh } : {}),
    ...(state ? { state } : {}),
    ...(anon ? { anon } : {}),
    ...(obs.truncated ? { truncated: true } : {}),
    detail: obs.error ?? `HTTP ${obs.status}`,
  };

  const signals = signalRows(obs, { mediaType, redirect, refresh, form, wwwAuthenticate, state });
  const chain = buildChain(extra.chain ?? []);
  const sweep = buildSweep(extra.sweep ?? [], obs.body);
  const loginPaths = buildLoginPaths(extra.loginPaths ?? [], obs.body);
  const unread = readUnread(obs, anon);
  return {
    url: obs.requestUrl,
    verdict: {
      ...(gate ? { gate } : {}),
      label: probeOutcome(asProbe).label,
      reason: probeReasonText(asProbe),
      withdrawsExposure: gate !== undefined,
    },
    read: {
      ...(obs.status !== undefined ? { status: obs.status } : {}),
      ...(obs.phase ? { phase: obs.phase } : {}),
      ...(obs.error ? { error: obs.error } : {}),
      ...(obs.elapsedMs !== undefined ? { elapsedMs: obs.elapsedMs } : {}),
      ...(contentType ? { contentType } : {}),
      ...(mediaType ? { mediaType } : {}),
      html: isHtmlMediaType(mediaType),
      ...(location ? { location } : {}),
      ...(redirect ? { redirect } : {}),
      ...(refresh ? { refresh } : {}),
      ...(wwwAuthenticate ? { wwwAuthenticate } : {}),
      ...(obs.bodyBytes !== undefined ? { bodyBytes: obs.bodyBytes } : {}),
      truncated: obs.truncated === true,
      ...(form ? { form } : {}),
      ...(anon ? { anon } : {}),
      signals,
    },
    chain,
    sweep,
    loginPaths,
    // After the verdict, and taking it as an argument rather than deciding anything about it. The
    // gate is already fixed by the time this runs, which is the I1 argument in the one place it
    // has to hold: a detector cannot reach `gate` because `gate` is a `const` above it.
    evidence: readEvidence(unread, { answered, gate, anon }),
    unread,
    next: nextSteps(obs, signals, { mediaType, form, redirect, refresh, chain, sweep, loginPaths }),
  };
}

/**
 * One observation as the record `readGate` takes.
 *
 * Shared by the verdict and by every hop of a chain, so a hop is judged by exactly the rule the
 * target was judged by. `status ?? 0` is how "nothing answered" reaches a rule that requires a
 * number; every clause tests the status against something, and 0 matches none of them.
 */
function asProbeResponse(obs: ProbeLabObservation) {
  const location = obs.headers["location"];
  const wwwAuthenticate = obs.headers["www-authenticate"];
  return {
    requestUrl: obs.requestUrl,
    status: obs.status ?? 0,
    ...(location ? { location } : {}),
    ...(wwwAuthenticate ? { wwwAuthenticate } : {}),
    ...(obs.body ? { body: obs.body } : {}),
  };
}

/**
 * Each followed hop, read by the same rule the target was read by.
 *
 * `gate` is the reason this function exists. Applying `readGate` to a hop answers the question a
 * chain raises — *would the scan have found something if it looked here?* — with the pipeline's
 * own rule rather than an impression, so the answer is comparable to the verdict it sits beside.
 */
export function buildChain(observations: readonly ProbeLabObservation[]): ChainStep[] {
  return observations.map((o) => {
    const location = o.headers["location"];
    const redirect = location ? readRedirect(location.trim(), o.requestUrl) : undefined;
    const gate = o.status !== undefined ? readGate(asProbeResponse(o)) : undefined;
    return {
      url: o.requestUrl,
      ...(o.status !== undefined ? { status: o.status } : {}),
      ...(location ? { location } : {}),
      ...(redirect ? { to: redirect.to, crossOrigin: redirect.crossOrigin } : {}),
      ...(o.headers["content-type"] ? { contentType: o.headers["content-type"] } : {}),
      ...(o.body ? { title: tagText(o.body, "title") } : {}),
      ...(o.bodyBytes !== undefined ? { bodyBytes: o.bodyBytes } : {}),
      ...(o.error ? { error: o.error } : {}),
      ...(gate ? { gate } : {}),
    };
  });
}

/**
 * Each swept address, and whether its answer is the shell again.
 *
 * `rootBody` is the target's own body, and comparing against it is not an optimisation — a
 * catch-all router answers 200 with the same shell at every unmatched path, and a 200 read as "an
 * anonymous caller was served" when it means "nothing matched" is the one way this section could
 * mislead somebody into calling a gated service open.
 */
export function buildSweep(
  observations: readonly ProbeLabObservation[],
  rootBody?: string,
): SweepStep[] {
  return observations.map((o) => {
    const same = rootBody !== undefined && o.body !== undefined && o.body === rootBody;
    return {
      path: pathOf(o.requestUrl),
      url: o.requestUrl,
      ...(o.status !== undefined ? { status: o.status } : {}),
      ...(o.headers["content-type"] ? { contentType: o.headers["content-type"] } : {}),
      ...(o.headers["www-authenticate"] ? { wwwAuthenticate: o.headers["www-authenticate"] } : {}),
      ...(o.bodyBytes !== undefined ? { bodyBytes: o.bodyBytes } : {}),
      ...(o.error ? { error: o.error } : {}),
      ...(same ? { sameAsRoot: true } : {}),
    };
  });
}

/**
 * Each guessed login address, read by the pipeline's own rule.
 *
 * The same three fields `buildChain` adds to a hop, for the same reason: the question is *would
 * the scan have found something if it looked here*, and only `readGate` can answer that in a way
 * comparable to the verdict beside it. `sameAsRoot` comes first in a reader's eye though, because
 * on a catch-all every one of these is a 200 and none of them is a page.
 */
export function buildLoginPaths(
  observations: readonly ProbeLabObservation[],
  rootBody?: string,
): LoginPathStep[] {
  return observations.map((o) => {
    const same = rootBody !== undefined && o.body !== undefined && o.body === rootBody;
    // A catch-all's answer is the target's own page, which was already judged in section 1 — so
    // judging it again under a different address would put the same reading in the report twice,
    // once as a verdict and once as a discovery.
    const gate = o.status !== undefined && !same ? readGate(asProbeResponse(o)) : undefined;
    const form = !same && o.body ? readLoginForm(o.body, o.requestUrl) : undefined;
    return {
      path: pathOf(o.requestUrl),
      url: o.requestUrl,
      ...(o.status !== undefined ? { status: o.status } : {}),
      ...(o.headers["content-type"] ? { contentType: o.headers["content-type"] } : {}),
      ...(o.headers["www-authenticate"] ? { wwwAuthenticate: o.headers["www-authenticate"] } : {}),
      ...(o.bodyBytes !== undefined ? { bodyBytes: o.bodyBytes } : {}),
      ...(o.error ? { error: o.error } : {}),
      ...(same ? { sameAsRoot: true } : {}),
      ...(gate ? { gate } : {}),
      ...(form ? { form } : {}),
      ...(!same && o.body ? { title: tagText(o.body, "title") } : {}),
    };
  });
}

/**
 * The first guessed address that turned out to be a login page, if any.
 *
 * `gate` and not a status: a 200 at `/login` is a page, and whether it is a *login* page is
 * `readGate`'s to say. Used by the index and the closing lines, so a run over twenty services
 * names the ones worth opening.
 */
export function firstLoginPage(steps: readonly LoginPathStep[]): LoginPathStep | undefined {
  return steps.find((s) => s.gate !== undefined);
}

/**
 * The first swept address that refused an anonymous caller, if any.
 *
 * **401 and 407, not 403.** The same two statuses `readState` treats as a refusal, and the reason
 * is in its doc comment: a plain file server 403s a directory it will not list, so 403 would make a
 * static site refuse. Exported so `cli.ts`'s index row, its per-target line and its closing summary
 * all mean the same thing by "refused" as the rule does — four wordings of one test is four chances
 * for the tool to describe a finding the report it links to does not have.
 */
export function firstRefusal(sweep: readonly SweepStep[]): SweepStep | undefined {
  return sweep.find((s) => s.status === 401 || s.status === 407);
}

/**
 * Whether a refusal is one a *scan* would have found, rather than one only this tool asked for.
 *
 * Both halves are the difference between a verdict and a note. The path has to be one of the four
 * `STATE_PATHS` a scan sends, and the refusal has to have named a scheme — see `ProbeGate`'s
 * `state-challenge` for why a bare 401 at a deliberately chosen API path is weaker evidence than a
 * bare 401 at `/` rather than stronger.
 */
export function refusalIsPipelineGate(step: SweepStep): boolean {
  return STATE_PATHS.includes(step.path) && Boolean(step.wwwAuthenticate?.trim());
}

/**
 * The scan's own state walk, reconstructed from a sweep that asked more than the scan would.
 *
 * Three things make this a reconstruction rather than a re-reading, and all three are what let the
 * result be put in a verdict:
 *
 *  - **`STATE_PATHS`' order, not the sweep's.** The walk is ordered, because it stops early, so
 *    which address refused first is part of the answer.
 *  - **Only `STATE_PATHS`.** The four extra addresses this tool asks are for a reader deciding
 *    whether the list should grow. A refusal at `/api/session` is a good argument for a commit; it
 *    is not something a scan would have found.
 *  - **`readState` does the truncating.** Not a loop here — the same function the scan calls, so
 *    `asked` counts what a scan would have sent and the tool cannot claim a cheaper or dearer walk
 *    than the real one.
 *
 * A missing path stops the reconstruction where it stops. That cannot happen while
 * {@link AUTH_STATE_PATHS} spreads `STATE_PATHS` in, and it is handled rather than asserted because
 * the failure mode is worth being boring: a short prefix understates the walk, which at worst
 * withholds a gate. It can never invent one.
 */
function pipelineState(sweep: readonly ProbeLabObservation[]): ProbeState {
  const byPath = new Map<string, ProbeLabObservation>();
  for (const o of sweep) byPath.set(pathOf(o.requestUrl), o);

  const answers: StateAnswer[] = [];
  for (const path of STATE_PATHS) {
    const o = byPath.get(path);
    if (!o) break;
    const header = o.headers["www-authenticate"];
    answers.push({
      path,
      ...(o.status !== undefined ? { status: o.status } : {}),
      ...(header ? { wwwAuthenticate: header } : {}),
    });
  }
  return readState(answers);
}

/** The path of an address, or the whole address if it will not parse. */
function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

/** What each clause turned on, whether or not it fired. Facts derived once and passed in. */
function signalRows(
  obs: ProbeLabObservation,
  ctx: {
    mediaType?: string;
    redirect?: ProbeRedirect;
    refresh?: ProbeRedirect;
    form?: LoginFormShape;
    wwwAuthenticate?: string;
    /** The reconstructed walk, when there was one. `undefined` is "the scan would not have asked". */
    state?: ProbeState;
  },
): SignalRow[] {
  const status = obs.status;
  const body = obs.body;
  const redirecting = status !== undefined && status >= 300 && status < 400;
  const served = status === 200 && body !== undefined;
  // Why a body-reading clause could not even be attempted, said once. Every one of the four
  // shares it, and it is the single most common answer this tool gives.
  const noPage = !served
    ? status === undefined
      ? "nothing answered, so there was no page to read"
      : status !== 200
        ? `the answer was HTTP ${status}, not a page served`
        : ctx.mediaType
          ? `the answer was ${ctx.mediaType}, so no body was read as HTML`
          : "the answer carried no content type, so no body was read as HTML"
    : undefined;

  const rows: Record<ProbeGate, Omit<SignalRow, "gate" | "label">> = {
    challenge: {
      fired: (status === 401 || status === 407) && Boolean(ctx.wwwAuthenticate?.trim()),
      because:
        status === 401 || status === 407
          ? ctx.wwwAuthenticate?.trim()
            ? `HTTP ${status} with WWW-Authenticate: ${ctx.wwwAuthenticate}`
            : `HTTP ${status} with no WWW-Authenticate header — a bare ${status} is also what an API answers a call it will not serve`
          : `the status was ${status ?? "absent"}, not 401 or 407`,
    },
    "redirect-origin": {
      fired: redirecting && ctx.redirect?.crossOrigin === true,
      because: !redirecting
        ? `the status was ${status ?? "absent"}, not a 3xx`
        : !ctx.redirect
          ? "the Location header was absent or would not parse, so where it pointed cannot be judged"
          : ctx.redirect.crossOrigin
            ? `Location resolved to ${ctx.redirect.to}, off this origin`
            : `Location resolved to ${ctx.redirect.to}, which stayed on this origin`,
    },
    "redirect-login": {
      fired: redirecting && ctx.redirect?.crossOrigin === false && isLoginPath(ctx.redirect.to),
      because: !redirecting
        ? `the status was ${status ?? "absent"}, not a 3xx`
        : !ctx.redirect
          ? "the Location header was absent or would not parse"
          : ctx.redirect.crossOrigin
            ? `Location left the origin, which is redirect-origin's clause rather than this one`
            : isLoginPath(ctx.redirect.to)
              ? `Location resolved to ${ctx.redirect.to}, a known login path`
              : `Location resolved to ${ctx.redirect.to}, which is not a known login path — routing, not a gate`,
    },
    "meta-refresh-login": {
      fired: served && ctx.refresh !== undefined && pointsAtLogin(ctx.refresh),
      because:
        noPage ??
        (!ctx.refresh
          ? "the page carries no <meta http-equiv=refresh> with a url= in it"
          : pointsAtLogin(ctx.refresh)
            ? `its <meta refresh> points at ${ctx.refresh.to}, which is a login`
            : `its <meta refresh> points at ${ctx.refresh.to}, which is neither off the origin nor a login path`),
    },
    "sso-form": {
      fired: served && hasSamlField(body!),
      because:
        noPage ??
        (hasSamlField(body!)
          ? "the page carries a SAMLRequest or SAMLResponse input — the SAML POST binding, which nothing else emits"
          : "no SAMLRequest or SAMLResponse input is in the markup"),
    },
    "password-form": {
      fired: served && hasPasswordField(body!),
      because:
        noPage ??
        (hasPasswordField(body!)
          ? "the page carries an input of type=password or autocomplete=current-password"
          : "no input of type=password or autocomplete=current-password is in the markup"),
    },
    "credential-form": {
      fired:
        served &&
        ctx.form?.username === true &&
        ctx.form.submit &&
        (ctx.form.action !== undefined || ctx.form.otp),
      because:
        noPage ??
        (!ctx.form
          ? "no form on the page carries any of the parts a login form is made of"
          : (shortfall(ctx.form) ?? `one form carries ${markers(ctx.form)}`)),
    },
    // The only row whose fact came from a request the other seven know nothing about, so it is
    // the only one that has to say whether that request went out at all. Three answers, and the
    // first is the common one: the page was readable, so no second question was warranted.
    "state-challenge": {
      fired: ctx.state !== undefined && readStateGate(ctx.state) !== undefined,
      because: !ctx.state
        ? "the served page was readable — a second request is only sent for a 200 of HTML with no <form> anywhere on it, and only when nothing else fired"
        : ctx.state.refusedAt === undefined
          ? `none of the ${ctx.state.asked} current-user addresses refused an anonymous request`
          : ctx.state.challenge
            ? `${ctx.state.refusedAt} answered HTTP ${ctx.state.status} and named an authentication scheme`
            : `${ctx.state.refusedAt} answered a bare HTTP ${ctx.state.status} with no WWW-Authenticate — which is also what an API with optional accounts answers while its pages serve everybody, so it is evidence and not a gate`,
    },
  };
  // In `PROBE_GATES`' order — `readGate`'s precedence for its seven, with `readStateGate`'s one
  // after them — so the first firing row is the one that decided the verdict, and a reader can
  // see what it beat.
  return PROBE_GATES.map((gate) => ({ gate, label: probeGateText(gate).label, ...rows[gate] }));
}

/** Which part of a passwordless login the highest-ranked form did not have, if any. */
function shortfall(form: LoginFormShape): string | undefined {
  const missing: string[] = [];
  if (!form.username) missing.push("no username field");
  if (!form.submit) missing.push("no submit control");
  if (form.action === undefined && !form.otp) {
    missing.push("no login intent — its action is not a login path and it asks for no one-time code");
  }
  return missing.length ? `the strongest form on the page has ${missing.join(", ")}` : undefined;
}

/** The three facts the `credential-form` clause rests on, when it has them. */
function markers(form: LoginFormShape): string {
  const intent = form.otp ? "a one-time-code field" : `an action of ${form.action}`;
  return `a username field, a submit control and ${intent}`;
}

/* -------------------------------------------------------------------------- */
/* Section 3 — what no rule reads yet                                         */
/* -------------------------------------------------------------------------- */

/**
 * Everything on the page that no signal consults, dumped rather than ranked.
 *
 * This is the section a new rule gets designed from, so nothing here is filtered by whether it
 * looks relevant — that judgement is exactly what is being worked out. The `<script src>` list
 * was the known blind spot for a shell; the anchor list is the one that turned out to matter more
 * often, because a page can be finished and still hold its whole login story in one `<a>`.
 *
 * `anon` is passed in rather than recomputed. Everything the pipeline decided about this body is
 * decided once, in {@link buildReport}, and read from there — so `text.chars` is the number the
 * scan's own sentence quotes and not a second count that could differ from it by a space.
 */
function readUnread(obs: ProbeLabObservation, anon: ProbeAnon | undefined): ProbeLabReport["unread"] {
  const body = obs.body ?? "";
  // Forms first, because the control dump is defined as *what is not in one* and needs the same
  // markup with them removed. `formDumps` reads the originals; `outsideForms` is only for controls.
  const forms = formDumps(body);
  const anchors = anchorRefs(body, obs.requestUrl);
  const controls = controlRefs(outsideForms(drawnMarkup(body)));
  const metas = metaRefs(body);
  const roots = rootRefs(body);
  const scripts = inlineScripts(body);
  const text = pageText(body, anon);
  return {
    title: tagText(body, "title"),
    h1: tagText(body, "h1"),
    lang: attrOf(/<html\b[^>]*>/i.exec(body)?.[0] ?? "", "lang"),
    generator: metaContent(body, "generator"),
    forms,
    assets: assetRefs(body),
    anchors: anchors.slice(0, MAX_ANCHORS),
    anchorsOmitted: Math.max(0, anchors.length - MAX_ANCHORS),
    controls: controls.slice(0, MAX_CONTROLS),
    controlsOmitted: Math.max(0, controls.length - MAX_CONTROLS),
    metas: metas.slice(0, MAX_METAS),
    metasOmitted: Math.max(0, metas.length - MAX_METAS),
    roots: roots.slice(0, MAX_ROOTS),
    rootsOmitted: Math.max(0, roots.length - MAX_ROOTS),
    inlineScripts: scripts.slice(0, MAX_INLINE_SCRIPTS),
    inlineScriptsOmitted: Math.max(0, scripts.length - MAX_INLINE_SCRIPTS),
    noscript: noscriptText(body),
    text,
    // `set-cookie` is dropped here rather than filtered downstream: its names are reported
    // separately and its values are credentials, so the value never enters the record at all.
    headers: Object.entries(obs.headers).filter(([name]) => name !== "set-cookie"),
    cookieNames: cookieNames(obs.headers["set-cookie"]),
  };
}

/**
 * Every anchor, login-shaped ones first.
 *
 * **The ordering is load-bearing, not cosmetic.** A finished page's navigation is thirty to fifty
 * anchors and the sign-in link is conventionally last in document order, in a header bar rendered
 * after the content or in a footer. Capping in document order would therefore drop exactly the
 * anchor the cap exists to make room for. So anything the pipeline's predicates found interesting
 * — a login path, a login label, or a logout label, since the logout one is what explains a
 * *rejected* candidate — sorts ahead of the rest, and document order is preserved within each
 * group.
 *
 * The three booleans are `isLoginPath`, `saysLogin` and `saysLogout` as `src/model/probe.ts`
 * exports them. Not reimplemented, and not approximated: a reader disagreeing with the reason
 * sentence in section 1 needs to see the same answers it was built from.
 */
function anchorRefs(body: string, requestUrl: string): AnchorRef[] {
  const shown: AnchorRef[] = [];
  const undrawn: AnchorRef[] = [];
  const rest: AnchorRef[] = [];
  // Which anchors a visitor was actually shown, decided by the pipeline's own `drawnMarkup` and
  // then asked as a set membership. Matching the drawn string separately would give no way to
  // relate one list to the other; the whole body is walked once and each anchor is asked whether
  // it survived the reduction.
  const drawn = new Set(drawnMarkup(body).match(ANCHOR_TAGS) ?? []);
  for (const tag of body.match(ANCHOR_TAGS) ?? []) {
    const href = attrOf(tag, "href")?.trim();
    if (!href) continue;
    const hidden = !drawn.has(tag);
    const text = clip(innerText(tag), MAX_ANCHOR_TEXT);
    const ariaLabel = attrOf(tag, "aria-label");
    const rel = attrOf(tag, "rel");
    // The label the predicates are asked about, which is the same fallback chain `readAnonAccess`
    // uses: visible text if there is any, otherwise what the tag says about itself.
    const label = text || ariaLabel || attrOf(tag, "title") || "";
    // Resolved with the pipeline's own resolver, so `path` is the string `isLoginPath` is asked
    // about and a reader can check the answer against it. Skipped for a fragment or a scheme
    // that never leaves the page — those are in the dump, just without a resolved path.
    const to = /^(?:#|javascript:|mailto:|tel:|data:|blob:)/i.test(href)
      ? undefined
      : readRedirect(href, requestUrl);
    const loginPath = to !== undefined && !to.crossOrigin && isLoginPath(to.to);
    const loginLabel = label.length > 0 && saysLogin(label);
    const logoutLabel = label.length > 0 && saysLogout(label);
    const ref: AnchorRef = {
      href: clip(href, MAX_ANCHOR_TEXT),
      ...(to ? { path: to.to, ...(to.crossOrigin ? { crossOrigin: true } : {}) } : {}),
      ...(text ? { text } : {}),
      ...(ariaLabel ? { ariaLabel } : {}),
      ...(rel ? { rel } : {}),
      ...(loginPath ? { loginPath: true } : {}),
      ...(loginLabel ? { loginLabel: true } : {}),
      ...(logoutLabel ? { logoutLabel: true } : {}),
      ...(hidden ? { hidden: true } : {}),
    };
    // Three groups, not two, and the split between the first two is what stops a `<noscript>`
    // copy of the sign-in link from standing in for the real one: `readEvidence` reports one
    // finding per resolved path, so whichever row comes first is the row that speaks for that
    // path — and it has to be the one a visitor could click.
    (loginPath || loginLabel || logoutLabel ? (hidden ? undrawn : shown) : rest).push(ref);
  }
  return [...shown, ...undrawn, ...rest];
}

/**
 * `<a>` elements with their contents. The pipeline's own pattern, for the reason it has one.
 *
 * Kept here rather than imported because `ANCHOR_TAG` is private in `src/model/probe.ts` — the
 * discipline that section follows is that *the questions are shared and the patterns are not*, and
 * a lenient dump is exactly the case that discipline exists to allow. The three alternatives at the
 * end are the same reasoning: stop at a close tag, at the next anchor, or at a truncated body.
 */
const ANCHOR_TAGS = /<a\b[^>]*>[\s\S]*?(?:<\/a>|(?=<a\b)|$)/gi;

/**
 * The markup with every `<form>` block removed.
 *
 * So that a control dump means what its doc comment says: *outside any form*. A `<button>Sign
 * in</button>` inside a form was already read by `readLoginForm` and ranked in section 2, and
 * repeating it here would make section 3 look like a second, unranked opinion about the same
 * element. An unclosed `<form>` swallows the rest of the page, which is the conservative
 * direction — it can only ever produce fewer form-less controls, never a spurious one.
 */
function outsideForms(body: string): string {
  return body.replace(/<form\b[^>]*>[\s\S]*?(?:<\/form\s*>|$)/gi, " ");
}

/**
 * Every control that is not in a form: `<button>`, `role="button"`, and submit-ish `<input>`.
 *
 * The shape three of the reports that prompted this section had. A single-page application draws
 * `<button>Sign in</button>` and attaches a click handler in JavaScript; there is no form, so
 * `readLoginForm` has nothing to rank and `hasPasswordField` nothing to find, and the page reports
 * as having no login affordance at all while showing one to every visitor.
 *
 * Called on the *drawn* markup with forms removed, which makes this list exactly the set
 * `readAnonAccess` scanned for its `loginLabel` — so a report cannot show a control the reason
 * sentence did not consider. A `<template>`'s undrawn button is therefore absent here; the anchor
 * dump keeps its hidden rows precisely because an `<a href>` has a target worth naming and a
 * button does not.
 */
function controlRefs(markup: string): ControlRef[] {
  const out: ControlRef[] = [];
  const push = (kind: ControlRef["kind"], tag: string, label: string) => {
    const type = attrOf(tag, "type");
    const id = attrOf(tag, "id");
    const ariaLabel = attrOf(tag, "aria-label");
    const text = clip(label, MAX_ANCHOR_TEXT);
    const asked = text || ariaLabel || attrOf(tag, "title") || attrOf(tag, "value") || "";
    out.push({
      kind,
      ...(text ? { label: text } : {}),
      ...(type ? { type } : {}),
      ...(id ? { id } : {}),
      ...(ariaLabel ? { ariaLabel } : {}),
      ...(asked.length > 0 && saysLogin(asked) ? { loginLabel: true } : {}),
    });
  };
  for (const m of markup.matchAll(/<button\b[^>]*>([\s\S]*?)(?:<\/button\s*>|$)/gi)) {
    push("button", m[0].replace(/>[\s\S]*$/, ">"), plainish(m[1] ?? ""));
  }
  for (const tag of markup.match(/<input\b[^>]*>/gi) ?? []) {
    const type = (attrOf(tag, "type") ?? "").toLowerCase();
    if (type !== "submit" && type !== "button" && type !== "image") continue;
    push("input", tag, attrOf(tag, "value") ?? "");
  }
  for (const m of markup.matchAll(
    /<([a-z][a-z0-9-]*)\b[^>]*\brole\s*=\s*["']?button\b[^>]*>([\s\S]*?)(?:<\/\1\s*>|$)/gi,
  )) {
    // `<button role="button">` exists in real markup; counting it twice would make a report
    // claim two sign-in controls where a visitor sees one.
    if ((m[1] ?? "").toLowerCase() === "button") continue;
    push("role", m[0].replace(/>[\s\S]*$/, ">"), plainish(m[2] ?? ""));
  }
  return out;
}

/**
 * Every `<meta>` that names something, `name` or `property`.
 *
 * `metaContent` above reads exactly one of these, for `generator`. This reads all of them,
 * because `application-name`, `og:site_name` and `apple-mobile-web-app-title` name a vendor on
 * pages where `generator` is absent — and a vendor name is what turns "some 200 with no form"
 * into a product whose auth model can be looked up.
 */
function metaRefs(body: string): MetaRef[] {
  const out: MetaRef[] = [];
  for (const tag of body.match(/<meta\b[^>]*>/gi) ?? []) {
    const name = (attrOf(tag, "name") ?? attrOf(tag, "property") ?? "").trim();
    const content = attrOf(tag, "content");
    if (!name || content === undefined) continue;
    out.push({ name, content: clip(content, MAX_ANCHOR_TEXT) });
  }
  return out;
}

/**
 * Mount points: hyphenated custom elements, and the `<div>` a bundle is handed.
 *
 * A shell's whole markup is often one of these and one `<script src>`. Which one it is names the
 * framework — `__next`, `root`, `app`, `q-app` — and a mount point named for a screen rather than
 * for a framework has said what the bundle is about to draw, which is the only thing in a shell's
 * markup that ever points at a login.
 */
function rootRefs(body: string): RootRef[] {
  const out: RootRef[] = [];
  const seen = new Set<string>();
  const push = (tag: string, name: string) => {
    const id = attrOf(tag, "id");
    const className = attrOf(tag, "class");
    const key = `${name}#${id ?? ""}.${className ?? ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      tag: name,
      ...(id ? { id } : {}),
      ...(className ? { className: clip(className, MAX_ANCHOR_TEXT) } : {}),
    });
  };
  for (const m of body.matchAll(/<([a-z][a-z0-9]*-[a-z0-9-]*)\b[^>]*>/gi)) {
    push(m[0], (m[1] ?? "").toLowerCase());
  }
  for (const m of body.matchAll(/<(div|main|section)\b[^>]*>/gi)) {
    if (!MOUNT_ID.test((attrOf(m[0], "id") ?? "").toLowerCase())) continue;
    push(m[0], (m[1] ?? "").toLowerCase());
  }
  return out;
}

/** The `id` values a framework hands its bundle. Anchored, so `login-container` is not one. */
const MOUNT_ID = /^(?:__\w+|mount|main|\w*app|\w*root)$/;

/**
 * Every inline `<script>`, described. **Never its source.**
 *
 * The one dump in this file that is deliberately lossy, and invariant **I6** is why: a report is a
 * file somebody pastes into an issue, and an anonymous page's bootstrap script is where a client
 * keeps its configuration. One of the reports that prompted this work listed a `/__config.js`;
 * another was a Home Assistant page whose entire routing lived in an inline block. Dumping those
 * would make the report the least safe artifact the tool produces.
 *
 * What is kept is what a *rule* could be built on and nothing else: how big it was, the quoted
 * path literals in it that the pipeline's own `isLoginPath` matches — which is the client's route
 * table, and the closest thing a shell has to a sign-in link — and the *names* of the globals it
 * assigns. Names, never values: `__NEXT_DATA__` says Next.js, and its contents say who is
 * signed in.
 */
function inlineScripts(body: string): InlineScript[] {
  const out: InlineScript[] = [];
  for (const m of body.matchAll(/<script\b([^>]*)>([\s\S]*?)(?:<\/script\s*>|$)/gi)) {
    const attrs = m[1] ?? "";
    const source = m[2] ?? "";
    // A `src` script has no inline source to describe, and is already in `assets`.
    if (attrOf(attrs, "src") !== undefined) continue;
    if (!source.trim()) continue;
    const type = attrOf(attrs, "type");
    const id = attrOf(attrs, "id");
    const paths = new Set<string>();
    for (const q of source.matchAll(/["'`](\/[A-Za-z0-9._~\-/]{1,60})["'`]/g)) {
      const path = q[1]!;
      if (isLoginPath(path)) paths.add(path);
      if (paths.size >= MAX_SCRIPT_PATHS) break;
    }
    const keys = new Set<string>();
    for (const k of source.matchAll(
      /(?:window|globalThis|self)\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["']([^"']{1,60})["']\s*\])\s*=|\b(?:var|let|const)\s+(__[\w$]+)\s*=/g,
    )) {
      const name = k[1] ?? k[2] ?? k[3];
      if (name) keys.add(name);
      if (keys.size >= MAX_SCRIPT_KEYS) break;
    }
    out.push({
      ...(type ? { type } : {}),
      ...(id ? { id } : {}),
      bytes: Buffer.byteLength(source, "utf8"),
      loginPaths: [...paths],
      bootstrapKeys: [...keys],
    });
  }
  return out;
}

/**
 * Each `<noscript>` block's text.
 *
 * The server's own account of the page, written for a reader who will not run the bundle — so on
 * exactly the shells whose markup says nothing, it is sometimes the one place the word "sign in"
 * appears in what was served.
 */
function noscriptText(body: string): string[] {
  const out: string[] = [];
  for (const m of body.matchAll(/<noscript\b[^>]*>([\s\S]*?)(?:<\/noscript\s*>|$)/gi)) {
    const text = clip(plainish(m[1] ?? ""), MAX_NOSCRIPT_TEXT);
    if (text) out.push(text);
    if (out.length >= MAX_NOSCRIPT) break;
  }
  return out;
}

/**
 * What a reader would have read, and a capped sample of it.
 *
 * `chars` comes from `anon.textChars` whenever a body was read, which is the pipeline's own count
 * from the pipeline's own `visibleText` — because the sentence in section 1 quotes that number,
 * and a section 3 that printed a different one would be an argument between two halves of the
 * same report about the same page. The sample is this file's, and it is the same extraction: one
 * `visibleText` call, sliced.
 */
function pageText(body: string, anon: ProbeAnon | undefined): PageText {
  const text = body ? visibleText(body) : "";
  const chars = anon?.textChars ?? text.length;
  return {
    chars,
    sample: text.slice(0, MAX_TEXT_SAMPLE),
    omitted: Math.max(0, text.length - MAX_TEXT_SAMPLE),
  };
}

/** A tag's inner markup as text: `<a href=…><span>Sign in</span></a>` -> `Sign in`. */
function innerText(tag: string): string {
  return plainish(tag.replace(/^<[^>]*>/, "").replace(/<\/[a-z][a-z0-9-]*\s*>\s*$/i, ""));
}

/**
 * Tags out, entities to a space, whitespace collapsed.
 *
 * The lab's own reduction, lenient where the pipeline's cannot be — it feeds a dump a person
 * reads. Where a *predicate* is asked about a label, it is the pipeline's predicate that is
 * asked, on whatever this produced.
 */
function plainish(html: string): string {
  return html
    .replace(/<[^>]*>/g, " ")
    .replace(/&(?:#\d+|#x[0-9a-f]+|[a-z]+);/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** `text` with an ellipsis if it had to be shortened. Bounds a dump, never a decision. */
function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/* -------------------------------------------------------------------------- */
/* Section 3a — what a visitor was shown                                      */
/* -------------------------------------------------------------------------- */

/**
 * Cookie names that suggest a session, on a request that carried no credential.
 *
 * The lab's own vocabulary and not the pipeline's, because nothing decides on it — no clause reads
 * a cookie, and a finding built from this one cannot move a count. Lenient on purpose: the point is
 * to put the name in front of a reader who knows what their fleet runs, which `authentik_session`,
 * `JSESSIONID` and `_forward_auth` all reward.
 */
const SESSION_COOKIE = /sess|\bsid\b|_sid|auth|token|jwt|csrf|xsrf|remember|identity/i;

/** How many findings one report carries. A page with forty anchors can produce a lot of them. */
const MAX_EVIDENCE = 12;
/** How many anchors and controls each contribute, strongest first. */
const MAX_LINK_FINDINGS = 3;
const MAX_CONTROL_FINDINGS = 2;

/**
 * What this page proves about itself, strongest first.
 *
 * **The section the operator's question is actually about.** Section 2 can say which of eight
 * clauses failed; only this can say *the page served you four kilobytes of content and a link
 * reading "Sign in", so there is nothing in front of it.* That is the first positive evidence of
 * openness the tool has ever produced — until now `open` was an absence, and an absence is what a
 * reader discounts.
 *
 * **Everything here is downstream of the verdict and cannot reach it.** `gate` arrives as a
 * parameter, already decided; `EvidenceFinding["direction"]` has no `"gated"` member; and no caller
 * writes any of this back. So the worst a detector below can be is wrong in a paragraph — never
 * wrong about a service's place in the exposed count (**I1**).
 *
 * Nothing is emitted when a gate fired, for the same reason section 4 is empty then: the rule
 * already read this page and reached a conclusion, and a list of open-pointing facts printed
 * beside a `gated` verdict would read as the report disagreeing with itself.
 *
 * **The pivot is `content-served`.** A sign-in link on a page that served content is proof of an
 * application with an optional account. The same link on an empty shell is a login page whose form
 * has not been drawn — the opposite conclusion from the same anchor. So every login finding takes
 * its `direction` from whether content came with it, rather than each detector deciding for itself.
 */
function readEvidence(
  unread: ProbeLabReport["unread"],
  ctx: { answered: boolean; gate?: ProbeGate; anon?: ProbeAnon },
): EvidenceFinding[] {
  if (!ctx.answered || ctx.gate) return [];
  const out: EvidenceFinding[] = [];
  const anon = ctx.anon;
  const served = anon !== undefined && servedAnonContent(anon);
  // Where a login affordance points when content came with it, and where it points when it did
  // not. One decision, made once, so five detectors cannot answer it five ways.
  const withContent: EvidenceFinding["direction"] = served ? "open-with-login" : "look-closer";

  if (served && anon) {
    out.push({
      kind: "content-served",
      direction: "open",
      strength: "proof",
      fact: `${anon.textChars} characters of visible text and ${anon.links} same-origin ${anon.links === 1 ? "link" : "links"} were served to a caller carrying no credential`,
      because:
        "a gate answers an anonymous request with a challenge, a redirect or a login form — not with the application's own content. This is what a visitor sees, which makes it evidence that the service is open rather than an absence of evidence that it is closed.",
    });
  }

  // `login-link` — the headline gap, and the whole proof for three of the reports this was built
  // from. Graded by which half of the question the anchor answered: a login *path* is the
  // pipeline's own vocabulary and worth more than a label, and a long label is worth least of all
  // because prose contains the words ("How to log in to your router" is a real article title).
  let links = 0;
  // One finding per resolved target, and the anchors arrive login-shaped-first, so the first row
  // for a path is the one that says the most about it. A header bar and a mobile menu are the same
  // sign-in link twice, and reporting it twice would read as two independent facts.
  const reported = new Set<string>();
  for (const a of unread.anchors) {
    if (links >= MAX_LINK_FINDINGS) break;
    if (a.logoutLabel || !(a.loginPath || a.loginLabel)) continue;
    const target = a.path ?? a.href;
    if (reported.has(target)) continue;
    reported.add(target);
    const short = (a.text ?? a.ariaLabel ?? "").length <= LOGIN_LABEL_MAX;
    const both = a.loginPath === true && a.loginLabel === true && short;
    // A hidden anchor cannot be `proof` of anything a visitor was shown, whatever it says: it is
    // markup the client had and did not draw. Graded to the same `weak` a route literal gets,
    // because that is what it is — a route the bundle knows about.
    const strength: EvidenceFinding["strength"] = a.hidden
      ? "weak"
      : both
        ? "proof"
        : a.loginPath || short
          ? "strong"
          : "weak";
    const quoted = a.text
      ? `reading "${a.text}", `
      : a.ariaLabel
        ? `labelled "${a.ariaLabel}", `
        : "";
    out.push({
      kind: "login-link",
      direction: strength === "weak" ? "look-closer" : withContent,
      strength,
      fact: `<a href="${a.href}">, ${quoted}resolving to ${a.path ?? "no same-origin path"}${a.hidden ? " — inside a template, noscript or script, so not drawn" : ""}`,
      because: a.hidden
        ? "the markup was served but not shown: it sits inside a `<template>`, `<noscript>`, `<script>` or `<svg>`, so no visitor was offered it. What it does say is that the client knows this route — the same thing `login-route` says, and worth the same `--try-login-paths` run."
        : a.loginPath
          ? `\`isLoginPath\` matches ${a.path} — the same vocabulary the \`redirect-login\` clause trusts when a 302 points there${a.loginLabel ? ", and the label says so too" : ", though the label does not say so"}. ${served ? "The page it sits on served content, so this is an account a visitor may choose to use." : "Nothing else was served with it, so this may equally be a login page whose form is drawn in the browser."}`
          : short
            ? `the label is a sign-in label by itself, which is how an application with no login \`<form>\` still offers one. ${served ? "It sits on a page that served content." : "Nothing else was served with it, so the page may be the login screen."}`
            : "the words appear, but in a label too long to be a control — this is far more likely prose about signing in than an offer to do it. Read the text sample before acting on it.",
    });
    links++;
  }

  // `login-control` — the same offer with no anchor around it. Exactly the shape of the target the
  // operator described as "has a 'Sign in' on the page which I have to click".
  let controls = 0;
  for (const c of unread.controls) {
    if (controls >= MAX_CONTROL_FINDINGS) break;
    if (!c.loginLabel) continue;
    const label = c.label ?? c.ariaLabel ?? "";
    const short = label.length <= LOGIN_LABEL_MAX;
    out.push({
      kind: "login-control",
      direction: short ? withContent : "look-closer",
      strength: short ? "strong" : "weak",
      fact: `a <${c.kind === "role" ? "* role=button" : c.kind}> outside every form, labelled "${label}"${c.id ? ` (id="${c.id}")` : ""}`,
      because: short
        ? `no \`<form>\` contains it, so \`readLoginForm\` has nothing to rank and \`hasPasswordField\` nothing to find — the sign-in is wired up in JavaScript. ${served ? "The page around it served content, so the account is a feature rather than a gate." : "The page around it served little else, so this may be the login screen itself."}`
        : "the words appear in a label too long to be a control, so this is probably text rather than an offer.",
    });
    controls++;
  }

  // `login-heading` — the candidate ninth signal, and the only finding here that would move a
  // count if it were ever promoted. So it is stated as a question rather than an answer, and
  // `nextSteps` is where the sized change belongs.
  const heading = [unread.title, unread.h1].find((t) => t !== undefined && saysLogin(t));
  if (heading && unread.forms.length === 0 && unread.assets.length > 0) {
    out.push({
      kind: "login-heading",
      direction: "look-closer",
      strength: "strong",
      fact: `the page names itself "${clip(heading, MAX_ANCHOR_TEXT)}", carries no <form>, and ships ${unread.assets.length} ${unread.assets.length === 1 ? "script or stylesheet" : "scripts or stylesheets"}`,
      because:
        "a page that calls itself a sign-in page and has no form is a login screen whose form is drawn in the browser. Nothing in the served bytes proves it, which is why this is a proposal for a ninth clause and not a verdict — see section 4.",
    });
  }

  // `login-route` — the shell's route table. Proves the application *has* a sign-in screen, which
  // is not the same as proving a visitor was made to use one, so it is `weak` however many hits
  // there are.
  const routes = new Set<string>();
  for (const s of unread.inlineScripts) for (const p of s.loginPaths) routes.add(p);
  for (const a of unread.assets) {
    const path = a.href.startsWith("/") ? a.href.split(/[?#]/)[0]! : undefined;
    if (path && isLoginPath(path)) routes.add(path);
  }
  if (routes.size) {
    out.push({
      kind: "login-route",
      direction: "look-closer",
      strength: "weak",
      fact: `the client's own bytes name ${[...routes].slice(0, MAX_SCRIPT_PATHS).map((p) => `\`${p}\``).join(", ")}`,
      because:
        "a login-shaped path in a bundle or an inline script says the application has a sign-in screen somewhere, not that this response was one. Worth an `--try-login-paths` run, which asks those addresses directly.",
    });
  }

  // `session-cookie` — weak in both directions on purpose. A session handed to a caller who sent
  // nothing is either an application tracking anonymous visitors, or a login page issuing a CSRF
  // token, and the served bytes cannot say which.
  const sessions = unread.cookieNames.filter((n) => SESSION_COOKIE.test(n));
  if (sessions.length) {
    out.push({
      kind: "session-cookie",
      direction: "look-closer",
      strength: "weak",
      fact: `Set-Cookie named ${sessions.map((n) => `\`${n}\``).join(", ")} on a request that sent no credential`,
      because:
        "the name says the application keeps server-side state for anonymous callers. That is what an app with optional accounts does and also what a login form issuing a CSRF token does — the name is a vendor clue, not a verdict.",
    });
  }

  const rank = { proof: 0, strong: 1, weak: 2 };
  // Stable, so within one strength the order above survives: content, then links, then controls.
  return out.sort((a, b) => rank[a.strength] - rank[b.strength]).slice(0, MAX_EVIDENCE);
}

/** `<title>Sign in</title>` -> `Sign in`. Whitespace collapsed; nothing else touched. */
function tagText(body: string, tag: string): string | undefined {
  const m = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, "i").exec(body);
  const text = m?.[1]?.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
  return text || undefined;
}

/** The `content` of a `<meta name="…">`, which is where a vendor names itself. */
function metaContent(body: string, name: string): string | undefined {
  for (const tag of body.match(/<meta\b[^>]*>/gi) ?? []) {
    if ((attrOf(tag, "name") ?? "").trim().toLowerCase() === name) return attrOf(tag, "content");
  }
  return undefined;
}

/**
 * Every `<form>` on the page, with every input in it.
 *
 * `readLoginForm` reads the same markup and returns one ranked shape; this returns all of it
 * unranked, because the question here is what a *different* ranking could have seen. The
 * regexes are the lab's own — a lenient dump for a person to read, not a rule anything decides
 * on, which is why they may be lenient where the pipeline's cannot be.
 */
function formDumps(body: string): FormDump[] {
  const out: FormDump[] = [];
  const re = /<form\b([^>]*)>([\s\S]*?)(?:<\/form\s*>|$)/gi;
  for (const m of body.matchAll(re)) {
    const attrs = m[1] ?? "";
    const inner = m[2] ?? "";
    out.push({
      action: attrOf(attrs, "action"),
      method: attrOf(attrs, "method"),
      id: attrOf(attrs, "id"),
      inputs: (inner.match(/<input\b[^>]*>/gi) ?? []).map((tag) => ({
        type: attrOf(tag, "type"),
        name: attrOf(tag, "name"),
        id: attrOf(tag, "id"),
        placeholder: attrOf(tag, "placeholder"),
        autocomplete: attrOf(tag, "autocomplete"),
        ariaLabel: attrOf(tag, "aria-label"),
        required: /\brequired\b/i.test(tag),
      })),
      buttons: buttonLabels(inner),
    });
  }
  return out;
}

/** Every button's visible text, and every submit input's `value`. */
function buttonLabels(inner: string): string[] {
  const out: string[] = [];
  for (const m of inner.matchAll(/<button\b[^>]*>([\s\S]*?)<\/button>/gi)) {
    const text = (m[1] ?? "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
    if (text) out.push(text);
  }
  for (const tag of inner.match(/<input\b[^>]*>/gi) ?? []) {
    const type = (attrOf(tag, "type") ?? "").toLowerCase();
    if (type !== "submit" && type !== "button") continue;
    const value = attrOf(tag, "value");
    if (value) out.push(value);
  }
  return out;
}

/**
 * Every `<script src>` and `<link rel>` on the page.
 *
 * The one piece of evidence a client-rendered login leaves behind. A 200 whose markup is an
 * empty `<div id="root">` and one bundle is not a page with no login form on it — it is a page
 * whose login form has not been drawn yet, and no rule that reads served HTML can tell the
 * difference. Section 4 says so in those words when it applies.
 */
function assetRefs(body: string): AssetRef[] {
  const out: AssetRef[] = [];
  for (const tag of body.match(/<script\b[^>]*>/gi) ?? []) {
    const href = attrOf(tag, "src");
    if (href) out.push({ kind: "script", href });
  }
  for (const tag of body.match(/<link\b[^>]*>/gi) ?? []) {
    const href = attrOf(tag, "href");
    if (!href) continue;
    const rel = attrOf(tag, "rel");
    out.push({ kind: "link", ...(rel ? { rel } : {}), href });
  }
  return out;
}

/**
 * Cookie *names* from a `Set-Cookie`, never values.
 *
 * A report is a file somebody will paste into an issue, and a session cookie's value is a
 * credential. The name is the whole of what is diagnostic — `authentik_session`, `JSESSIONID`
 * and `_forward_auth` each name their vendor — so the value is not read at all rather than
 * masked, which is invariant **I6** applied to a tool that writes files.
 */
function cookieNames(setCookie: string | undefined): string[] {
  if (!setCookie) return [];
  const attributes = new Set([
    "expires",
    "max-age",
    "domain",
    "path",
    "samesite",
    "secure",
    "httponly",
    "version",
    "priority",
    "partitioned",
  ]);
  const out: string[] = [];
  for (const token of setCookie.split(/[;,]/)) {
    const eq = token.indexOf("=");
    if (eq <= 0) continue;
    const name = token.slice(0, eq).trim();
    if (!name || attributes.has(name.toLowerCase()) || out.includes(name)) continue;
    out.push(name);
  }
  return out;
}

/** One attribute's value out of a tag or an attribute string. Quoted or bare. */
function attrOf(tag: string, name: string): string | undefined {
  const re = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, "i");
  const m = re.exec(tag);
  if (!m) return undefined;
  return m[1] ?? m[2] ?? m[3];
}

/* -------------------------------------------------------------------------- */
/* Section 4 — what would have to change                                      */
/* -------------------------------------------------------------------------- */

/**
 * One line per thing standing between this page and a verdict, in the order worth acting on.
 *
 * Mechanical on purpose. Each line names a fact about *this* response and what a rule would
 * have to read to get past it — never a suggestion to loosen a clause, because every clause
 * here is tight for a reason and the two fixtures in `fixtures/probe` that exist to catch
 * word-matching are what a loosened one breaks.
 *
 * Empty when a gate fired: there is nothing to change about a page the rule already reads.
 */
function nextSteps(
  obs: ProbeLabObservation,
  signals: SignalRow[],
  ctx: {
    mediaType?: string;
    form?: LoginFormShape;
    redirect?: ProbeRedirect;
    refresh?: ProbeRedirect;
    chain: ChainStep[];
    sweep: SweepStep[];
    loginPaths: LoginPathStep[];
  },
): string[] {
  if (signals.some((s) => s.fired)) return [];
  const out: string[] = [];

  if (obs.status === undefined) {
    out.push(
      `Nothing answered (${obs.phase ?? "transport failure"}: ${obs.error ?? "no detail"}). There is no page to read yet — fix the address or the reachability first, then re-run.`,
    );
    return out;
  }
  // A 3xx that stayed on the origin. The single most actionable case in this whole tool: the
  // service did not serve the request, so *something* stands in front of it, and whether that
  // something is a gate turns entirely on one path name.
  if (obs.status >= 300 && obs.status < 400) {
    const ahead = chainLines(ctx.chain);
    // A gate further down the chain outranks the path observation, because it settles what the
    // path observation only raises: there *is* a sign-in screen, and the scan looked one response
    // too early to see it. Where no hop gated, the path is still the whole of the evidence and
    // goes first.
    const gatedAhead = ctx.chain.some((h) => h.gate !== undefined);
    if (gatedAhead) out.push(...ahead);
    out.push(
      ctx.redirect
        ? `The redirect stayed on this origin and went to ${ctx.redirect.to}, which is not a login path — so LabView read it as routing. If that path *is* this service's sign-in screen under a name the login-path list does not have, adding the name is the smallest possible change and needs a fixture; if it is not, then ${ctx.redirect.to} is the address worth asking, and --paths will ask it.`
        : `A ${obs.status} whose Location could not be read, so where the service was sending the request is unknown. Nothing can be concluded from a redirect whose target is unavailable — check the raw header in section 3.`,
    );
    if (!gatedAhead) out.push(...ahead);
    return out;
  }
  // Before anything about the markup, because it is about something stronger than markup: an
  // address that refused an anonymous caller is a gate that exists, whatever the page said.
  out.push(...sweepLines(ctx.sweep));
  out.push(...loginPathLines(ctx.loginPaths));
  if (obs.status !== 200 && obs.status !== 401 && obs.status !== 407) {
    out.push(
      `HTTP ${obs.status} is none of the three shapes a gate is recognised in — a credential request, a redirect, or a page served. If this status is how the service refuses an anonymous visitor, that is a new clause and it needs a fact beyond the number: a WWW-Authenticate header, a body, or a redirect.`,
    );
  }
  if (obs.status === 401 || obs.status === 407) {
    out.push(
      `A bare ${obs.status} with no WWW-Authenticate header. This is deliberately not a gate — an API answering a call it will not serve looks identical, while its UI serves the whole application. If this service is genuinely gated, the evidence has to come from somewhere else on the response.`,
    );
  }
  if (obs.status === 200 && !isHtmlMediaType(ctx.mediaType)) {
    out.push(
      `The answer was ${ctx.mediaType ?? "sent with no content type"} rather than HTML, so no body was read at all. No body-reading signal can ever fire here. If this address is the application's API and its UI is elsewhere, the UI's address is the one worth asking.`,
    );
  }
  if (obs.body !== undefined) {
    const scripts = assetRefs(obs.body).filter((a) => a.kind === "script");
    const forms = formDumps(obs.body);
    if (ctx.refresh) {
      out.push(
        `The page sends the browser to ${ctx.refresh.to} by <meta refresh>, which is neither off the origin nor a login path — so it was read as a page that reloads or forwards rather than as a gate. If that target is the sign-in screen, this is the same one-word change a same-origin redirect would need; if it is not, ${ctx.refresh.to} is the address worth asking.`,
      );
    }
    if (!forms.length && scripts.length) {
      out.push(
        `HTML came back with no <form> in it and ${scripts.length} script${scripts.length === 1 ? "" : "s"} to load (${scripts.map((s) => s.href).slice(0, 3).join(", ")}). This is the known blind spot: a login screen drawn by JavaScript is not in the served markup, so **no body-only signal can see it** — recognising it needs either a rendered page or a marker the shell itself carries, such as a session cookie name or a vendor header.`,
      );
    }
    if (forms.length && !ctx.form) {
      out.push(
        `${forms.length} form${forms.length === 1 ? " was" : "s were"} found, and none carries any part a login form is recognised by. Section 3 lists their inputs — if one of them is a login field under a name the vocabulary does not have, the fix is a word in USERNAME_WORDS, not a looser clause.`,
      );
    }
    if (ctx.form) {
      const missing = shortfall(ctx.form);
      if (missing) {
        out.push(
          `A form was read but ${missing}. The composite needs all three at once, because a username field and a button alone are a newsletter box — which is what fixtures/probe/passwordless/news exists to keep out. Look at the action in section 3 before changing anything.`,
        );
      }
    }
    if (obs.truncated) {
      out.push(
        `The body read stopped at the cap, so "not in the markup" means "not in the part that was read". A password field is in the first few kilobytes of every page that has one, so this is usually not the reason — but it is worth ruling out.`,
      );
    }
    const cookies = cookieNames(obs.headers["set-cookie"]);
    if (cookies.length) {
      out.push(
        `The response set ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} (${cookies.join(", ")}). A cookie name is the strongest vendor marker on an unauthenticated response and no signal reads one today — if these names identify a proxy or an SSO product, that is an eighth signal with a fact behind it.`,
      );
    }
  }
  if (!out.length) {
    out.push(
      "Nothing in this response is close to a signal, and nothing here suggests a rule that would find one. This looks like a service that is genuinely reachable without authenticating.",
    );
  }
  return out;
}

/**
 * What a followed chain adds, in one or two lines.
 *
 * The line worth writing this function for is the first one. A same-origin 3xx to a path the list
 * does not have, followed twice more, ending on a page that carries a password field — that is a
 * gated service the dashboard shows as exposed, and the distance between the two is *the number
 * of responses the scan reads*. Saying so is the point.
 *
 * What it deliberately does not say is "follow redirects in the scan". Following is a second
 * request per service and a second address to be wrong about, and the chain's own evidence is
 * cheaper: the first `Location` is a string the scan already has, so recognising the sign-in
 * screen by its path costs nothing and needs no extra request.
 */
function chainLines(chain: ChainStep[]): string[] {
  if (!chain.length) return [];
  const out: string[] = [];
  const hops = chain.length;
  const plural = hops === 1 ? "hop" : "hops";
  const gated = chain.find((h) => h.gate !== undefined);
  const last = chain[chain.length - 1]!;

  if (gated) {
    const at = chain.indexOf(gated) + 1;
    out.push(
      `**Following the chain finds \`${gated.gate}\` at ${gated.url}**, ${at} ${at === 1 ? "hop" : "hops"} on. The service is gated and the scan cannot see it: \`getResponse\` sends \`redirect: "manual"\` and \`readGate\` reads one response, so everything past the first is invisible by design. The cheap fix is not to follow — it is that the *first* Location already pointed here, so a rule recognising that path would reach the same conclusion with the request it already makes.`,
    );
  }
  if (last.status !== undefined && last.status >= 300 && last.status < 400) {
    out.push(
      `The chain was still redirecting after ${hops} ${plural} (${last.url} → ${last.to ?? last.location ?? "unread Location"}), so where it ends is unknown — raise \`--max-hops\` to find out.`,
    );
  } else if (last.status === undefined) {
    out.push(
      `The chain ran ${hops} ${plural} and then nothing answered at ${last.url} (${last.error ?? "no detail"}). A service that redirects an anonymous visitor to an address that does not answer is worth knowing about on its own.`,
    );
  } else if (!gated) {
    out.push(
      `The chain ended after ${hops} ${plural} at ${last.url} — HTTP ${last.status}${last.title ? `, titled “${last.title}”` : ""} — and no hop carried a signal either. That address is a target in its own right and has its own report; if a sign-in screen is there, it is drawn after the markup arrives, which is the blind spot rather than a rule to widen.`,
    );
  }
  return out;
}

/**
 * What the auth-state sweep adds, once the scan asks these addresses itself.
 *
 * **This function is only ever reached when the eighth signal did not fire.** `nextSteps` returns
 * early on any firing signal, and `state-challenge` is one of them now — so the case this used to
 * be written for, a refusal that named its scheme at one of the scan's own four addresses, no
 * longer arrives here. It is a verdict, in section 1, and there is nothing to propose about it.
 *
 * What is left is the three near misses, and each implies a different size of change:
 *
 *  - **A refusal with a scheme, at one of the four addresses the scan does *not* ask.** The
 *    smallest change in this whole tool: one entry in `STATE_PATHS`. The clause already exists and
 *    the request budget already exists; the list is simply one path short. Worth a commit and a
 *    fixture, and nothing else.
 *  - **A bare refusal, at any address.** Deliberately not a gate, and the line has to say why
 *    rather than read as an oversight — a public application with optional accounts answers exactly
 *    this while serving everybody, so reading it as a gate would take a genuinely open service out
 *    of the count. It is the one direction this file must never be wrong in.
 *  - **A 403.** Excluded for the same reason and a sharper one: a plain file server 403s a
 *    directory it will not list, so a static site with no API at all would refuse by that test.
 *
 * **No refusal anywhere is also a finding**, and the more common one worth trusting. If nothing
 * near a current-user endpoint refuses an anonymous caller, the shell is not hiding a gate — and a
 * reader who came here suspecting a false positive can stop.
 */
function sweepLines(sweep: SweepStep[]): string[] {
  if (!sweep.length) return [];
  const refused = sweep.filter((s) => s.status === 401 || s.status === 407);
  const forbidden = sweep.filter((s) => s.status === 403);
  if (!refused.length && !forbidden.length) {
    const answered = sweep.filter((s) => s.status !== undefined);
    const shells = sweep.filter((s) => s.sameAsRoot).length;
    return [
      `None of the ${sweep.length} auth-state addresses refused an anonymous caller (${
        answered.length
          ? answered.map((s) => `${s.path} → ${s.status}`).join(", ")
          : "none of them answered at all"
      }${shells ? `; ${shells} answered with the same bytes as the page itself, which is a catch-all rather than an endpoint` : ""}). So there is no gate hiding behind this shell at any address this tool knows to ask, and on the evidence available the service is reachable without authenticating.`,
    ];
  }
  const out: string[] = [];
  // The one actionable case, and it is actionable precisely because it is small. Ordered first:
  // a reader with a one-line change available should not have to read past two paragraphs of why
  // the other refusals are not gates to find it.
  const growList = refused.find((s) => s.wwwAuthenticate?.trim() && !STATE_PATHS.includes(s.path));
  if (growList) {
    out.push(
      `**${growList.path} answered ${growState(growList)} while the page answered 200**, and \`${growList.path}\` is not one of the ${STATE_PATHS.length} addresses a scan asks. This is the smallest change this tool can recommend: add the path to \`STATE_PATHS\` in \`src/model/probe.ts\`. The clause that reads it (\`state-challenge\`) already exists and already ships — the list is one entry short, which is a commit with a fixture and no new rule at all.`,
    );
  }
  const bare = refused.filter((s) => !s.wwwAuthenticate?.trim());
  if (bare.length) {
    out.push(
      `${bare.map((s) => `${s.path} → ${s.status}`).join(", ")} refused an anonymous request but named no authentication scheme. **This is deliberately not a gate.** A public application with optional accounts answers a bare 401 at its current-user endpoint while serving its pages to everybody — an anonymous-enabled Grafana and a public Gitea both do — so reading it as one would take a genuinely open service out of the exposed count, which is the only direction this rule must never be wrong in. Only a server that wants a *browser* to prompt sends the header. So this is a place to look and not a finding, and the exposure stands.`,
    );
  }
  if (forbidden.length) {
    out.push(
      `${forbidden.map((s) => `${s.path} → 403`).join(", ")} — a 403 is not read as a refusal either, and this exclusion is load-bearing rather than cautious: nginx answers 403 for a directory with no index, so a static site with no API whatsoever would "refuse" at \`/api/\` and be called gated. If this service's real gate answers 403, the evidence has to come from somewhere else on the response.`,
    );
  }
  return out;
}

/** `401` or `401 with WWW-Authenticate: Basic`, for a line that has room to name the scheme. */
function growState(step: SweepStep): string {
  const scheme = step.wwwAuthenticate?.trim();
  return scheme ? `${step.status} with \`WWW-Authenticate: ${scheme}\`` : String(step.status);
}

/**
 * What guessing the login addresses adds — and what it costs, which is the part that matters.
 *
 * Every other line in section 4 proposes a change to a *rule*. This one is the only one that
 * proposes a change to the **request budget**, and the two are not comparable sizes: a word in
 * `USERNAME_WORDS` is free at scan time, while asking `/login` is one more request per service
 * per scan sent to an address no label mentioned, which is exactly what invariant **I8** is a
 * budget for. So each line below states the finding and then states the cost, and none of them
 * says "add these to the scan" — a reader with a real fleet is the one who can weigh ten paths
 * against twenty-five services, and this tool cannot.
 *
 * Three findings, in descending order of what they settle:
 *
 *  - **A login page at a guessed address.** The service has a sign-in screen; the scan looked at
 *    the wrong address. `readGate` said so, so the finding is the pipeline's own reading and not
 *    this file's.
 *  - **The same bytes as the page itself, everywhere.** A catch-all router, and therefore proof
 *    the sign-in screen is drawn in the browser. That closes the blind-spot question rather than
 *    leaving it open: no path is worth adding, because no path would return anything different.
 *  - **Nothing at any of them.** The ten names are ruled out, which is worth one line — it is the
 *    result that stops a reader guessing an eleventh.
 */
function loginPathLines(steps: LoginPathStep[]): string[] {
  if (!steps.length) return [];
  const found = steps.filter((s) => s.gate !== undefined);
  const shells = steps.filter((s) => s.sameAsRoot);
  const answered = steps.filter((s) => s.status !== undefined && s.status < 400);
  if (found.length) {
    const first = found[0]!;
    const gate = probeGateText(first.gate!);
    return [
      `**${first.path} is a login page** — HTTP ${first.status}${
        first.title ? `, titled “${first.title}”` : ""
      }, read by \`readGate\` as ${lower(gate.label)}${
        first.form ? ` (${markers(first.form)})` : ""
      }${
        found.length > 1
          ? `, and so ${found.length === 2 ? "is" : "are"} ${found
              .slice(1)
              .map((s) => s.path)
              .join(", ")}`
          : ""
      }. This service is gated and the scan is looking at the wrong address — but note what would have to change for it to see this: **a scan asks none of these paths.** Reading a login page here costs one request per service per scan at an address no label mentioned, which is a request-budget change and not a rule change. The cheaper version of the same finding is a redirect: if this service sends an anonymous *browser* to ${first.path}, then the root response carries the evidence already and section 1 would have it.`,
    ];
  }
  if (shells.length && shells.length === answered.length) {
    return [
      `All ${shells.length} of the ${steps.length} guessed login addresses that answered returned the same bytes as the page itself (${shells
        .map((s) => s.path)
        .slice(0, 4)
        .join(", ")}${shells.length > 4 ? ", …" : ""}). That is a catch-all router, and it settles the blind-spot question rather than leaving it open: **there is no path worth adding to any list**, because every path returns this same shell and the sign-in screen — if there is one — is drawn in the browser afterwards. Recognising it needs a rendered page or a marker the shell itself carries, not another address.`,
    ];
  }
  const reached = steps.filter((s) => s.status !== undefined);
  return [
    `None of the ${steps.length} guessed login addresses is a login page (${
      reached.length
        ? reached
            .map((s) => `${s.path} → ${s.status}`)
            .slice(0, 6)
            .join(", ")
        : "none of them answered at all"
    }). So the ten names \`LOGIN_PATHS\` carries do not find this service's sign-in screen by guessing, and an eleventh name is unlikely to either. If this service has one, it is behind a name only the application knows — section 3's inline scripts and mount points are where that name shows up, if it shows up anywhere.`,
  ];
}

/** `Credential requested` → `credential requested`, for a label used mid-sentence. */
function lower(s: string): string {
  return s.charAt(0).toLowerCase() + s.slice(1);
}

/* -------------------------------------------------------------------------- */
/* Views                                                                      */
/* -------------------------------------------------------------------------- */

/** The report as JSON. The actual deliverable: a fixture a new rule can be replayed against. */
export function renderJson(report: ProbeLabReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

/**
 * The report as Markdown, for reading while changing `readGate`.
 *
 * Four sections in the order the docstring at the top gives, and the signal table is the middle
 * of it — eight rows of "why not" is the thing this tool exists to put in front of somebody.
 */
export function renderMarkdown(report: ProbeLabReport): string {
  const L: string[] = [];
  const r = report.read;

  L.push(`# ${report.url}`, "");
  L.push(`**${report.verdict.label}**${report.verdict.gate ? ` — \`${report.verdict.gate}\`` : ""}`, "");
  L.push(report.verdict.reason, "");
  // Three sentences for three outcomes, and the third is not a weaker version of the second:
  // a service nothing answered for was not measured at all, and a line letting that read as
  // "no login page found" would be the one conclusion this whole stage must never reach by
  // accident. Same split `probeOutcome` makes, for the same reason.
  L.push(
    report.verdict.withdrawsExposure
      ? "This answer would take the service **out** of the exposed count."
      : r.status === undefined
        ? "Nothing was measured, so nothing is withdrawn: the service's posture rests on its configuration alone."
        : "This answer withdraws nothing: the service stays in the exposed count.",
    "",
  );

  L.push("## What the rule read", "");
  const facts: [string, string | undefined][] = [
    ["Status", r.status === undefined ? `— (${r.phase ?? "no answer"}: ${r.error ?? "no detail"})` : String(r.status)],
    ["Elapsed", r.elapsedMs === undefined ? undefined : `${r.elapsedMs} ms`],
    ["Content-Type", r.contentType],
    ["Media type", r.mediaType ? `${r.mediaType} (${r.html ? "read as HTML" : "not HTML — no body read"})` : undefined],
    ["Location", r.location ? `${r.location} → ${r.redirect ? `${r.redirect.to}${r.redirect.crossOrigin ? " (off origin)" : " (same origin)"}` : "would not parse"}` : undefined],
    ["Meta refresh", r.refresh ? `${r.refresh.to}${r.refresh.crossOrigin ? " (off origin)" : " (same origin)"}` : undefined],
    // `absent` only where a response arrived. On a transport failure there was no header set
    // to be absent from, and the row would read as a response that came back without one.
    ["WWW-Authenticate", r.status === undefined ? undefined : (r.wwwAuthenticate ?? "absent")],
    ["Body", r.bodyBytes === undefined ? undefined : `${r.bodyBytes} bytes${r.truncated ? " (truncated at the cap)" : ""}`],
    [
      "Strongest form",
      r.form
        ? `password=${r.form.password} username=${r.form.username} submit=${r.form.submit} otp=${r.form.otp} action=${r.form.action ?? "—"}`
        : // `none` only where markup was read. Where none was, there was no page to find a
          // form on, and the row would read as a page that had none.
          r.html && r.status !== undefined
          ? "none"
          : undefined,
    ],
  ];
  for (const [name, value] of facts) if (value !== undefined) L.push(`- **${name}**: ${value}`);
  L.push("");
  L.push("| Signal | Fired | Because |", "| --- | --- | --- |");
  for (const s of r.signals) {
    // Several clauses can fire on one page — a login form satisfies `password-form` and
    // `credential-form` both — and only the first of them decided anything. Marking it is how
    // a reader sees that the table is a precedence order rather than a list of votes.
    const fired = !s.fired ? "no" : s.gate === report.verdict.gate ? "**yes** ← the verdict" : "yes";
    L.push(`| \`${s.gate}\` | ${fired} | ${cell(s.because)} |`);
  }
  L.push("");

  // Its own section rather than part of section 2, because none of it is what the rule read — and
  // the heading has to say so before the first row, or a hop that gated reads as a verdict.
  if (report.chain.length) {
    L.push("## Where the chain went", "");
    L.push(
      `**LabView reads the first response and stops.** These ${report.chain.length} hop${
        report.chain.length === 1 ? "" : "s"
      } are this tool's, followed because the answer above was a redirect the rule found nothing in. A signal on any row below is a signal the scan does not see.`,
      "",
    );
    L.push("| Hop | Address | Status | Location → resolved | Signal there |", "| --- | --- | --- | --- | --- |");
    report.chain.forEach((h, i) => {
      const where = h.location
        ? `${h.location} → ${h.to ? `${h.to}${h.crossOrigin ? " (off origin)" : " (same origin)"}` : "would not parse"}`
        : "—";
      const status = h.status === undefined ? `— (${h.error ?? "no answer"})` : String(h.status);
      L.push(`| ${i + 1} | ${h.url} | ${status} | ${cell(where)} | ${h.gate ? `\`${h.gate}\`` : "—"} |`);
    });
    L.push("");
    for (const h of report.chain) {
      if (h.title === undefined && h.contentType === undefined) continue;
      L.push(
        `- ${h.url} — ${[h.title ? `titled “${h.title}”` : undefined, h.contentType, h.bodyBytes === undefined ? undefined : `${h.bodyBytes} bytes`].filter(Boolean).join(", ")}`,
      );
    }
    if (report.chain.some((h) => h.title !== undefined || h.contentType !== undefined)) L.push("");
  }

  // Above the dumps, because it is the part somebody can act on. The preamble states the one thing
  // a reader has to hold on to before the first row: none of this moved the verdict, and none of it
  // can — a `look-closer` row beside a "No login page" verdict is not the report contradicting
  // itself, it is the report saying what a rule change would have to be built from.
  if (report.evidence.length) {
    L.push("## What a visitor was shown", "");
    L.push(
      `${report.evidence.length} finding${report.evidence.length === 1 ? "" : "s"} read off the same response as the verdict above, and **none of them changed it** — a finding here can point at *open*, at *open with an optional account*, or at *worth another look*, and never at a gate. Deciding a gate is \`readGate\`'s, and \`readGate\` cannot see any of this.`,
      "",
    );
    L.push("| Points at | Strength | What the page did | Why that means it |", "| --- | --- | --- | --- |");
    for (const f of report.evidence) {
      L.push(
        `| \`${f.kind}\` → **${EVIDENCE_DIRECTION[f.direction]}** | ${f.strength} | ${cell(f.fact)} | ${cell(f.because)} |`,
      );
    }
    L.push("");
  }

  L.push("## What the rule did not consider", "");
  const u = report.unread;
  const notes: string[] = [];
  for (const [name, value] of [
    ["Title", u.title],
    ["First h1", u.h1],
    ["Lang", u.lang],
    ["Generator", u.generator],
  ] as [string, string | undefined][]) {
    if (value !== undefined) notes.push(`- **${name}**: ${value}`);
  }
  if (u.cookieNames.length) notes.push(`- **Set-Cookie names**: ${u.cookieNames.join(", ")}`);
  if (notes.length) L.push(...notes, "");
  if (u.forms.length) {
    L.push("### Forms", "");
    u.forms.forEach((f, i) => {
      L.push(`**Form ${i + 1}** — action=\`${f.action ?? "—"}\` method=\`${f.method ?? "—"}\` id=\`${f.id ?? "—"}\``);
      for (const input of f.inputs) {
        L.push(
          `  - \`type=${input.type ?? "—"}\` name=\`${input.name ?? "—"}\` id=\`${input.id ?? "—"}\` autocomplete=\`${input.autocomplete ?? "—"}\` placeholder=\`${input.placeholder ?? "—"}\` aria-label=\`${input.ariaLabel ?? "—"}\`${input.required ? " required" : ""}`,
        );
      }
      if (f.buttons.length) L.push(`  - buttons: ${f.buttons.map((b) => `“${b}”`).join(", ")}`);
      L.push("");
    });
  } else {
    L.push(
      r.status === undefined
        ? "_Nothing answered, so there was no page to read._"
        : r.html
          ? "_No `<form>` element in the served markup._"
          : "_The answer was not HTML, so no markup was read at all._",
      "",
    );
  }
  // Anchors first among the new dumps, and with a preamble, because this is the section that was
  // missing: eight reports said "no `<form>` in the served markup" about pages whose entire login
  // story was one of these rows.
  if (u.anchors.length) {
    L.push("### Links", "");
    L.push(
      `Login-shaped rows first, then document order${u.anchorsOmitted ? `; ${u.anchorsOmitted} more not shown` : ""}. The three flags are the pipeline's own predicates — \`isLoginPath\`, \`saysLogin\`, \`saysLogout\` — so a finding above can be checked against the row it came from.`,
      "",
    );
    L.push("| href | Resolves to | Text | Login path | Login label | Logout label |", "| --- | --- | --- | --- | --- | --- |");
    for (const a of u.anchors) {
      L.push(
        `| ${cell(a.href)} | ${a.path ? `${a.path}${a.crossOrigin ? " (off origin)" : ""}` : "—"} | ${
          cell(a.text ?? a.ariaLabel ?? "—")
        } | ${a.loginPath ? "**yes**" : "no"} | ${a.loginLabel ? "**yes**" : "no"} | ${a.logoutLabel ? "**yes**" : "no"} |`,
      );
    }
    L.push("");
  }
  if (u.controls.length) {
    L.push("### Controls outside every form", "");
    L.push(
      `A sign-in that is a \`<button>\` with no \`<form>\` around it is invisible to \`readLoginForm\`, which is why these are listed apart from section 2's ranking${u.controlsOmitted ? `. ${u.controlsOmitted} more not shown` : ""}.`,
      "",
    );
    for (const c of u.controls) {
      L.push(
        `- \`${c.kind}\`${c.type ? ` type=${c.type}` : ""}${c.id ? ` id=${c.id}` : ""}: “${c.label ?? c.ariaLabel ?? "—"}”${c.loginLabel ? " — **login label**" : ""}`,
      );
    }
    L.push("");
  }
  if (u.assets.length) {
    L.push("### Scripts and links", "");
    for (const a of u.assets) L.push(`- \`${a.kind}\`${a.rel ? ` rel=${a.rel}` : ""}: ${a.href}`);
    L.push("");
  }
  // Described, never dumped — the heading says so, because a reader who wanted the source will
  // otherwise assume the tool failed to capture it rather than declined to (**I6**).
  if (u.inlineScripts.length) {
    L.push("### Inline scripts", "");
    L.push(
      `Sizes, login-shaped path literals and the *names* of the globals each assigns. **The source is not kept**: an anonymous page's bootstrap script carries configuration, and this file is meant to be safe to paste into an issue${u.inlineScriptsOmitted ? `. ${u.inlineScriptsOmitted} more not shown` : ""}.`,
      "",
    );
    u.inlineScripts.forEach((s, i) => {
      L.push(
        `- **${i + 1}** — ${s.bytes} bytes${s.type ? `, type=\`${s.type}\`` : ""}${s.id ? `, id=\`${s.id}\`` : ""}${
          s.loginPaths.length ? `, login-shaped paths: ${s.loginPaths.map((p) => `\`${p}\``).join(", ")}` : ""
        }${s.bootstrapKeys.length ? `, assigns: ${s.bootstrapKeys.map((k) => `\`${k}\``).join(", ")}` : ""}`,
      );
    });
    L.push("");
  }
  if (u.roots.length) {
    L.push("### Mount points", "");
    for (const m of u.roots) {
      L.push(`- \`<${m.tag}>\`${m.id ? ` id=\`${m.id}\`` : ""}${m.className ? ` class=\`${m.className}\`` : ""}`);
    }
    if (u.rootsOmitted) L.push(`- _${u.rootsOmitted} more not shown._`);
    L.push("");
  }
  if (u.metas.length) {
    L.push("### Meta", "");
    for (const m of u.metas) L.push(`- \`${m.name}\`: ${m.content}`);
    if (u.metasOmitted) L.push(`- _${u.metasOmitted} more not shown._`);
    L.push("");
  }
  if (u.noscript.length) {
    L.push("### Noscript", "");
    for (const n of u.noscript) L.push(`- ${n}`);
    L.push("");
  }
  // Last of the markup dumps and deliberately so: it is the longest, and it is the one a reader
  // goes to in order to settle a `weak` finding — “Sign in” in a nav bar reads differently from
  // “sign in” in the middle of a sentence, and only the surrounding words say which happened.
  if (u.text.chars > 0) {
    L.push("### Visible text", "");
    L.push(
      `${u.text.chars} characters after scripts, styles, comments and tags were removed${u.text.omitted ? `; the first ${u.text.sample.length} are below` : ""}.`,
      "",
      "```",
      u.text.sample,
      "```",
      "",
    );
  }
  if (u.headers.length) {
    L.push("### Response headers", "");
    for (const [name, value] of u.headers) L.push(`- \`${name}\`: ${value}`);
    L.push("");
  }
  // Last in the section, and inside it rather than above it: this is evidence no clause reads,
  // which is what section 3 is. The heading names the credential situation because a reader
  // seeing 401s in a report needs to know immediately that nothing was ever sent to earn them.
  if (report.sweep.length) {
    L.push("### Auth-state addresses", "");
    L.push(
      `The served markup carried no gate, so a fixed list of current-user addresses was asked too — \`GET\`, **no credential on any of them**. A refusal below is an application declining an anonymous caller at an address the scan does not ask.`,
      "",
    );
    L.push("| Path | Status | Content-Type | WWW-Authenticate | Body |", "| --- | --- | --- | --- | --- |");
    for (const s of report.sweep) {
      L.push(
        `| \`${s.path}\` | ${s.status === undefined ? `— (${s.error ?? "no answer"})` : String(s.status)} | ${
          s.contentType ?? "—"
        } | ${s.wwwAuthenticate ? cell(s.wwwAuthenticate) : "—"} | ${
          s.sameAsRoot
            ? "the same bytes as the page — a catch-all, not an endpoint"
            : s.bodyBytes !== undefined
              ? `${s.bodyBytes} bytes`
              : s.status === undefined
                ? "—"
                : // The pipeline's own rule, and worth saying rather than dashing: a body is read
                  // only when the media type is HTML, so an API's answer is a status and headers.
                  "not read (not HTML)"
        } |`,
      );
    }
    L.push("");
  }
  // After the sweep, and the last thing in the section, because it is the only part of the report
  // that exists because somebody passed a flag. The preamble has to say that before the first row:
  // a reader comparing two reports of the same service needs to know why one has this table.
  if (report.loginPaths.length) {
    L.push("### Guessed login addresses", "");
    L.push(
      `\`--try-login-paths\` was passed, so each of the ${report.loginPaths.length} name${
        report.loginPaths.length === 1 ? "" : "s"
      } in the pipeline's own \`LOGIN_PATHS\` was asked as well — \`GET\`, **no credential on any of them**, sequential. **A scan asks none of these addresses**, so nothing below is or could become the verdict above; the \`Read as\` column is \`readGate\` run on that answer, which is what makes a row comparable to section 1 rather than a second opinion about it.`,
      "",
    );
    L.push("| Path | Status | Read as | Title | Body |", "| --- | --- | --- | --- | --- |");
    for (const s of report.loginPaths) {
      L.push(
        `| \`${s.path}\` | ${s.status === undefined ? `— (${s.error ?? "no answer"})` : String(s.status)} | ${
          s.gate ? `\`${s.gate}\`` : s.sameAsRoot ? "not read — the page itself" : "—"
        } | ${s.title ? cell(s.title) : "—"} | ${
          s.sameAsRoot
            ? "the same bytes as the page — a catch-all, not a page of its own"
            : s.bodyBytes !== undefined
              ? `${s.bodyBytes} bytes${s.form ? `, ${markers(s.form)}` : ""}`
              : s.status === undefined
                ? "—"
                : "not read (not HTML)"
        } |`,
      );
    }
    L.push("");
  }

  L.push("## What would have to change", "");
  if (!report.next.length) {
    L.push("_A signal fired — the rule already reads this page._", "");
  } else {
    for (const line of report.next) L.push(`- ${line}`);
    L.push("");
  }
  return `${L.join("\n")}\n`;
}

/**
 * What each direction is called in a report.
 *
 * Prose rather than the identifier, because the identifier is a discriminant and the words are the
 * conclusion. `look-closer` reads as an instruction on purpose: it is the only one of the three
 * that is not an answer, and a reader must not be able to mistake it for one.
 */
const EVIDENCE_DIRECTION: Record<EvidenceFinding["direction"], string> = {
  "open-with-login": "open, with an optional account",
  open: "open",
  "look-closer": "worth another look",
};

/** A table cell: pipes escaped, newlines flattened. Nothing else altered. */
function cell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");
}
