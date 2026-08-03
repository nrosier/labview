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
 * section 3 dumps the evidence no signal reads yet, and section 4 says what an eighth signal
 * would have to be. Fine-tuning happens against sections 3 and 4.
 *
 * **Nothing here decides anything about a fleet.** This is a diagnostic; it writes files a
 * person reads. It is not imported by `src/`, it is not in the image, and no scan consults it.
 */
import {
  PROBE_GATES,
  hasPasswordField,
  hasSamlField,
  isHtmlMediaType,
  isLoginPath,
  pointsAtLogin,
  probeGateText,
  probeOutcome,
  probeReasonText,
  readGate,
  readLoginForm,
  readMediaType,
  readRedirect,
  readRefresh,
} from "../../src/model/probe.js";
import type {
  ConnectionPhase,
  LoginFormShape,
  ProbeGate,
  ProbeRedirect,
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

/** One of the seven clauses, and what it turned on for this page. */
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
    signals: SignalRow[];
  };
  /** 3 — the evidence no signal reads yet, which is what an eighth one would be built from. */
  unread: {
    title?: string;
    h1?: string;
    lang?: string;
    generator?: string;
    forms: FormDump[];
    assets: AssetRef[];
    /** Every response header that survived redaction, in the order they were given. */
    headers: [string, string][];
    /** `Set-Cookie` reduced to names. A session cookie name is a strong vendor marker. */
    cookieNames: string[];
  };
  /** 4 — one line per signal that did not fire, saying what would have to be true. */
  next: string[];
}

/* -------------------------------------------------------------------------- */
/* The report                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Build the whole report for one observation.
 *
 * The order below is the order the sections are read in, and it is not arbitrary: the verdict
 * comes from `readGate` first, so everything after it is an account of a decision already made
 * rather than a second derivation that could disagree with it.
 */
export function buildReport(obs: ProbeLabObservation): ProbeLabReport {
  const contentType = obs.headers["content-type"];
  const mediaType = readMediaType(contentType);
  const location = obs.headers["location"];
  const wwwAuthenticate = obs.headers["www-authenticate"];

  // The exact record the pipeline would have handed `readGate`. Built once and reused for the
  // verdict, the reason and every signal row, so the three cannot describe different responses.
  const res = {
    requestUrl: obs.requestUrl,
    status: obs.status ?? 0,
    ...(location ? { location } : {}),
    ...(wwwAuthenticate ? { wwwAuthenticate } : {}),
    ...(obs.body ? { body: obs.body } : {}),
  };
  const answered = obs.status !== undefined;
  const gate = answered ? readGate(res) : undefined;

  const redirect = location ? readRedirect(location.trim(), obs.requestUrl) : undefined;
  const refresh = obs.body ? readRefresh(obs.body, obs.requestUrl) : undefined;
  const form = obs.body ? readLoginForm(obs.body, obs.requestUrl) : undefined;

  // `probeOutcome` and `probeReasonText` take a `ServiceProbe`-shaped record. Assembling one
  // here rather than wording anything locally is what keeps this report saying what the
  // dashboard says about the same answer — the type is the pipeline's, so a field the wording
  // rules start reading is a field this has to start providing.
  const asProbe: Pick<
    ServiceProbe,
    "phase" | "status" | "gate" | "form" | "mediaType" | "redirect" | "refresh" | "truncated" | "detail"
  > = {
    phase: answered ? "connected" : (obs.phase ?? "connect"),
    ...(obs.status !== undefined ? { status: obs.status } : {}),
    ...(gate ? { gate } : {}),
    ...(form ? { form } : {}),
    ...(mediaType ? { mediaType } : {}),
    ...(redirect ? { redirect } : {}),
    ...(refresh ? { refresh } : {}),
    ...(obs.truncated ? { truncated: true } : {}),
    detail: obs.error ?? `HTTP ${obs.status}`,
  };

  const signals = signalRows(obs, { mediaType, redirect, refresh, form, wwwAuthenticate });
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
      signals,
    },
    unread: readUnread(obs),
    next: nextSteps(obs, signals, { mediaType, form, redirect, refresh }),
  };
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
  };
  // In `PROBE_GATES`' order, which is `readGate`'s precedence — so the first firing row is the
  // one that decided the verdict, and a reader can see what it beat.
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
 * matters most and is the known blind spot: a login screen rendered by JavaScript leaves
 * nothing in the served markup except the bundle that will draw it.
 */
function readUnread(obs: ProbeLabObservation): ProbeLabReport["unread"] {
  const body = obs.body ?? "";
  return {
    title: tagText(body, "title"),
    h1: tagText(body, "h1"),
    lang: attrOf(/<html\b[^>]*>/i.exec(body)?.[0] ?? "", "lang"),
    generator: metaContent(body, "generator"),
    forms: formDumps(body),
    assets: assetRefs(body),
    // `set-cookie` is dropped here rather than filtered downstream: its names are reported
    // separately and its values are credentials, so the value never enters the record at all.
    headers: Object.entries(obs.headers).filter(([name]) => name !== "set-cookie"),
    cookieNames: cookieNames(obs.headers["set-cookie"]),
  };
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
  ctx: { mediaType?: string; form?: LoginFormShape; redirect?: ProbeRedirect; refresh?: ProbeRedirect },
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
    out.push(
      ctx.redirect
        ? `The redirect stayed on this origin and went to ${ctx.redirect.to}, which is not a login path — so LabView read it as routing. If that path *is* this service's sign-in screen under a name the login-path list does not have, adding the name is the smallest possible change and needs a fixture; if it is not, then ${ctx.redirect.to} is the address worth asking, and --paths will ask it.`
        : `A ${obs.status} whose Location could not be read, so where the service was sending the request is unknown. Nothing can be concluded from a redirect whose target is unavailable — check the raw header in section 3.`,
    );
    return out;
  }
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
 * of it — seven rows of "why not" is the thing this tool exists to put in front of somebody.
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
  if (u.assets.length) {
    L.push("### Scripts and links", "");
    for (const a of u.assets) L.push(`- \`${a.kind}\`${a.rel ? ` rel=${a.rel}` : ""}: ${a.href}`);
    L.push("");
  }
  if (u.headers.length) {
    L.push("### Response headers", "");
    for (const [name, value] of u.headers) L.push(`- \`${name}\`: ${value}`);
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

/** A table cell: pipes escaped, newlines flattened. Nothing else altered. */
function cell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");
}
