import type {
  AppStack,
  CloudflareRoute,
  LoginFormShape,
  ProbeGate,
  ProbeRedirect,
  ProbeState,
  ProbeVantage,
  Service,
  ServiceProbe,
  TraefikRoute,
} from "./types.js";
import { phaseText } from "./connections.js";
import { publishedHostPort } from "./ports.js";

/**
 * The rules of the active probe: which addresses a service may be asked at, and what
 * counts as a login page answering.
 *
 * Every other source LabView reads says what a service *is configured* to do. This one
 * says what it *answers*, which is the only way to see the largest class of real-world
 * protection there is: an application with its own login page, carrying no label, no env
 * key and no entry in anybody's API. Until now the only way to keep such a service out
 * of the exposed count was a `.labview` declaration, which is unverifiable by
 * construction — so the count was either wrong or resting on a claim.
 *
 * A probe result is evidence in the sense invariant I1 means it: LabView made the
 * request and read the answer. But it names **no mechanism** — an HTML form with a
 * password field could be local accounts, OIDC or SAML, and the response cannot tell
 * them apart — so nothing here may become an `AuthMethod` (I3). It is reported as its
 * own reason and counted in its own statistic, exactly as an unnamed gate found through
 * Authentik's API already is.
 *
 * Four rules, and all of them live here rather than in the client that does the
 * fetching, because a rule in an I/O module can only be tested by mocking the I/O:
 *
 *  - **{@link probeTargets}** — eligibility and try-order. Only where HTTP is
 *    *observable*, never from a port number and never from an image name, which is what
 *    keeps the probe off a database (I2/I3).
 *  - **{@link readGate}** — what counts as a login page. Strict on purpose: everything
 *    it does not recognise reads as "answered, no gate observed", which leaves the
 *    exposure finding standing. A finding a reader dismisses costs them a look; false
 *    comfort is the thing this project exists to remove.
 *  - **{@link wantsStateProbe} / {@link readState} / {@link readStateGate}** — the eighth
 *    signal, and the only one that needs a **second request**. A login screen drawn by
 *    JavaScript is not in the served markup, so the seven above cannot see it at any body
 *    size; what is observable is that the address the page's own client fetches the signed-in
 *    user from refuses a caller with no credential. Three functions rather than one because
 *    they answer three separable questions — may a second request be sent, what did it find,
 *    and is what it found a gate — and only the last is allowed to move a verdict.
 *  - **{@link readLoginForm}** — what a form on the page was *made of*, which is
 *    reported whether or not it cleared anything. A verdict a reader cannot inspect is
 *    one they have to take on trust, and this is the part they can check.
 *  - **{@link probeReasonText}** — which fact decided the verdict. The other half of the
 *    same argument: `readGate` may only recognise facts, so a reader is owed the fact,
 *    especially for the answer that leaves a service in the exposed count.
 *
 * `readRedirect`, `readRefresh` and `readMediaType` are exported alongside them because
 * `enrich/probe.ts` records what they read onto the {@link ServiceProbe} — the same reading
 * the gate rule judges, so a verdict and its stated reason can never be about different
 * observations.
 */

/**
 * Every vantage, in try-order — {@link ProbeVantage} as an array.
 *
 * Typed by the union, exactly as `INGRESS_KINDS` and `DECLARED_AUTH_MECHANISMS` are, so
 * adding a vantage without ordering it is a compile error rather than a silent omission.
 */
export const PROBE_VANTAGES: readonly ProbeVantage[] = ["public", "traefik", "lan"];

/** One address worth asking, and why it is worth asking. */
export interface ProbeTarget {
  /** Absolute URL, always with a path of `/`. Carries no credential and no query. */
  url: string;
  vantage: ProbeVantage;
  /** How this candidate was arrived at, for the attempt line when it fails. */
  why: string;
}

/**
 * What the gate rule needs of a response, and deliberately not a `Response`.
 *
 * A plain record rather than the live object so {@link readGate} can be asserted with
 * no network, no stub and no fetch: the recognition rule is the part of this feature
 * most worth pinning, and it is testable here as a table of literals.
 */
export interface ProbeResponse {
  /** The URL that was requested, so a `Location` can be resolved against it. */
  requestUrl: string;
  status: number;
  location?: string;
  wwwAuthenticate?: string;
  /**
   * The response body, present **only** when it was HTML and under the size cap —
   * `getResponse` never reads a JSON or binary body at all. So a body being here is
   * itself the evidence that HTML answered.
   */
  body?: string;
}

/**
 * How many addresses one service may be asked at.
 *
 * Bounded for the same reason `discoverTraefikEndpoints` bounds its candidates: the
 * list is built from scanned documents, and a compose file with thirty published ports
 * must not turn one scan into thirty outbound requests for one service.
 */
export const MAX_PROBE_TARGETS = 4;

/**
 * Paths that are a login page by name.
 *
 * Ten entries and no convention-guessing beyond them. Every one is either a path the OAuth
 * and SSO ecosystem standardised on, a spelling of one of those that real applications
 * redirect to, or a path a named product publishes. Matched as a prefix so `/login.php` and
 * `/oauth2/start` both count, which is what real applications redirect to.
 *
 * This list only ever *adds* a gate to a redirect that stayed on the same origin. A
 * cross-origin redirect is already `redirect-origin` without consulting it, so a
 * hand-rolled login path that is missing here costs a gate — never a false one. Which is
 * also the direction the risk runs in: a **wrong** entry takes a service out of the exposed
 * count on the strength of a path name, so every entry has to be a name that means "sign in
 * here" and nothing else. That is why `/flows/-/` carries its odd-looking `-/` and `/auth/`
 * carries its trailing slash — see below.
 *
 *  - `/login`, `/signin`, `/sso`, `/oauth2` — the four the ecosystem settled on.
 *  - `/sign-in`, `/users/sign_in` — the same two words hyphenated and underscored. Not new
 *    conventions: the first is what a great many applications spell `/signin` as, and the
 *    second is Devise's own path, which every Rails application using it redirects to.
 *  - `/auth/` — the fourth ecosystem convention, and the one that needs its slash. `/auth`
 *    as a bare prefix would match `/authors` and `/author/jane`, which is a blog routing to
 *    content; with the slash it matches `/auth/login`, `/auth/realms/…` (Keycloak) and
 *    `/auth/authorize`, and matches no word that merely starts with those four letters.
 *  - `/outpost.goauthentik.io`, `/if/flow/`, `/flows/-/` — Authentik's three published
 *    paths: the outpost endpoint, the flow interface a browser is sent to, and the flow
 *    executor. `/flows/-/` keeps the `-` because that segment is Authentik's own placeholder
 *    for "any brand", and a bare `/flows` prefix would read an application routing to its own
 *    list of flows as a login page — which is what `authentik-flow/pipeline` exists to catch.
 *
 * Exported for one reason: so `scripts/smoke.ts` can assert that every entry has a row of its
 * own there, with a path it matches and a near miss it does not. An entry nothing pins is an
 * entry that can take a service out of the exposed count for a reason nobody wrote down.
 */
export const LOGIN_PATHS: readonly string[] = [
  "/login",
  "/signin",
  "/sign-in",
  "/users/sign_in",
  "/sso",
  "/oauth2",
  "/auth/",
  "/outpost.goauthentik.io",
  "/if/flow/",
  "/flows/-/",
];

/**
 * Words that name a username field, matched against `name`, `id` and `autocomplete`.
 *
 * A closed vocabulary, and the reason the {@link LoginFormShape} `username` flag can be
 * read off a text input at all: `type="text"` says nothing by itself, and a search box is
 * the same element. `q`, `search` and `query` are absent on purpose — matching them is
 * how a site search becomes a login form.
 */
const USERNAME_WORDS: readonly string[] = [
  "username",
  "user",
  "uname",
  "userid",
  "uid",
  "login",
  "email",
  "e-mail",
  "identifier",
  "account",
];

/**
 * `<meta http-equiv="refresh">`, which is a redirect the HTTP layer cannot see.
 *
 * A 200 carrying one has not served the reader anything — it has told the browser to go
 * somewhere else — so where it points is read by exactly the rule that reads a `Location`,
 * and a refresh onto `/dashboard` is routing and is not a gate.
 */
const META_TAG = /<meta\b[^>]*>/gi;

/**
 * The SAML POST binding: the hidden field an identity provider hand-off is carried in.
 *
 * `SAMLRequest` and `SAMLResponse` are the parameter names the SAML 2.0 binding
 * specifies, so a page carrying one *is* a hand-off — there is no second thing that
 * emits it. Matched case-insensitively because the attribute is HTML, even though every
 * real implementation writes the spec's own casing.
 */
const SAML_FIELD = /<input\b[^>]*\bname\s*=\s*["']?saml(?:request|response)\b/i;

/**
 * A password field, in either of the two spellings that mean "type your password here".
 *
 * `type="password"` is the field itself. `autocomplete="current-password"` is the WHATWG
 * token for the same thing and is what a page using a custom widget writes; it is matched
 * for the same reason, and `new-password` is deliberately *not* — that is a signup or a
 * password change, neither of which is a gate standing in front of an application.
 *
 * Read across the whole page rather than per form, unlike {@link readLoginForm}. A
 * password input is unambiguous on its own, so it needs no company to be believed, and a
 * client-rendered login screen frequently has no `<form>` element around it at all.
 */
const PASSWORD_INPUT =
  /<input\b[^>]*(?:\btype\s*=\s*["']?password\b|\bautocomplete\s*=\s*["']?current-password\b)/i;

/**
 * Whether a tunnel origin addresses an HTTP service.
 *
 * The eligibility rule the request rests on — "http/https services, not databases" —
 * and it is decided from the operator's own `service:` value rather than from a port
 * number: `tcp://db:5432` and `ssh://host:22` are tunnel routes to something that is
 * not HTTP, and LabView must not send a byte at them.
 *
 * A missing scheme reads as HTTP, on the same convention `parseOrigin` in
 * `analyze/origins.ts` already applies to a bare `host:port` — and so does a route with
 * no declared service at all, since a tunnel ingress with none is HTTP by default.
 * Neither is a guess about *what* the service is; both only decide whether one GET is
 * allowed to leave.
 *
 * Reads `CloudflareRoute.service` — the operator's own value — rather than the resolved
 * `origin.address` it is copied into. The two are the same string, and taking the raw one
 * keeps this rule independent of whether `resolveOrigins` has run, so it holds wherever
 * in the pipeline the probe ends up and can be asserted on a route built by hand.
 */
export function isHttpOrigin(address: string | undefined): boolean {
  const raw = (address ?? "").trim();
  if (!raw) return true;
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(raw)?.[1]?.toLowerCase();
  if (!scheme) return true;
  return scheme === "http" || scheme === "https";
}

/**
 * Every address this service may be probed at, in try-order, deduped and capped.
 *
 * Pure, and the whole of the eligibility rule. Three vantages, each resting on evidence
 * that is already on the service:
 *
 *  - `public` — a tunnel route with a resolved hostname whose origin is HTTP. `https`,
 *    always: the tunnel terminates TLS at Cloudflare's edge, so there is no other
 *    scheme a public hostname could be asked on.
 *  - `traefik` — a proxy route's own hostname, on `https` when the router declares TLS
 *    and `http` otherwise. `parseTraefik` reads only `traefik.http.routers.*`, so a
 *    non-empty route list *is* the evidence that this is an HTTP service — no port and
 *    no image is consulted to establish it.
 *  - `lan` — `http://<lanHost>:<published port>/`, and only for a service one of the two
 *    above already found HTTP. Plain HTTP because a published container port is normally
 *    not where TLS is terminated; a port that only speaks TLS answers with a `tls` or
 *    `protocol` attempt, which is recorded rather than guessed around.
 *
 * **A service with `ports:` and no route of either kind yields nothing.** That single
 * line is what keeps the probe away from a database: LabView has observed no HTTP there,
 * so it asks nothing. What it costs is a LAN-only web UI, which stays inferred from its
 * configuration rather than measured — the honest trade, and the one the docs state.
 *
 * `lanHost` is the operator's answer to a question LabView cannot answer for itself: it
 * runs in a container and cannot see its host's LAN address. Empty means no LAN vantage,
 * not a guessed one.
 */
export function probeTargets(
  svc: Pick<Service, "cloudflare" | "traefik" | "ports">,
  lanHost: string,
): ProbeTarget[] {
  const out: ProbeTarget[] = [];
  const seen = new Set<string>();
  const push = (url: string, vantage: ProbeVantage, why: string): void => {
    if (seen.has(url)) return;
    seen.add(url);
    out.push({ url, vantage, why });
  };

  for (const route of svc.cloudflare) {
    if (!route.hostname || !isHttpOrigin(route.service)) continue;
    push(`https://${route.hostname}/`, "public", `${route.hostname} is a tunnel hostname for this service`);
  }
  for (const route of svc.traefik) {
    for (const host of route.hosts) {
      const scheme = route.tls ? "https" : "http";
      push(
        `${scheme}://${host}/`,
        "traefik",
        `${host} is served by this service's own Traefik router \`${route.router}\``,
      );
    }
  }
  // The LAN address is a fallback for a service already known to speak HTTP, never a
  // reason to probe one. Ordered last for the same reason `internal` is withheld beside
  // an external kind: what an outsider gets is the answer worth having, and a published
  // port answering says nothing about what the edge in front of it would have done.
  if (lanHost.trim() && isHttpObservable(svc)) {
    for (const port of svc.ports) {
      const published = publishedHostPort(port);
      if (!published) continue;
      // A port bound to one interface does not answer on another, which is the same
      // evidence `bindReachableFrom` reads in the other direction when it rules a
      // service out as a tunnel's target. Dialling it anyway would report a connection
      // failure as though the service were down.
      if (!bindAnswersAt(published.bindIp, lanHost.trim())) continue;
      push(
        `http://${lanHost.trim()}:${published.port}/`,
        "lan",
        `host port ${published.port} is published by this service`,
      );
    }
  }
  return out.slice(0, MAX_PROBE_TARGETS);
}

/**
 * Whether anything in the scan shows this service speaks HTTP.
 *
 * The `traefik` half is deliberately the same test `classifyIngress` uses for the
 * `traefik` ingress kind — hosts or a rule — so a service the dashboard tags as proxied
 * is exactly a service the probe considers HTTP. A router label carrying only, say, a
 * middleware list serves nothing and proves nothing.
 */
function isHttpObservable(svc: Pick<Service, "cloudflare" | "traefik">): boolean {
  const tunnelled = svc.cloudflare.some((r: CloudflareRoute) => r.hostname && isHttpOrigin(r.service));
  return tunnelled || svc.traefik.some((r: TraefikRoute) => r.hosts.length > 0 || Boolean(r.rule));
}

/** Whether a published port's bind address answers at `host`. Wildcards answer anywhere. */
function bindAnswersAt(bindIp: string | undefined, host: string): boolean {
  if (!bindIp) return true;
  if (bindIp === "0.0.0.0" || bindIp === "::" || bindIp === "*") return true;
  return bindIp === host;
}

/**
 * The gate rule: which of the seven signals a *single* response carries, or none.
 *
 * Ordered strongest first. Every clause but the last is one observable fact:
 *
 *  1. **`challenge`** — 401/407 *with* a `WWW-Authenticate` header. The header is
 *     required: a bare 401 is an application saying "not signed in" through its API,
 *     which is not a login page, and a great many REST endpoints answer that way to an
 *     unauthenticated GET while their UI happily serves the whole app.
 *  2. **`redirect-origin`** — a 3xx leaving the origin. Whatever is at the other end,
 *     this origin declined to serve the request itself, which is the shape of every
 *     external SSO hand-off there is.
 *  3. **`redirect-login`** — a 3xx that stayed on the origin and landed on a
 *     {@link LOGIN_PATHS} path. A same-origin redirect to `/dashboard` is an
 *     application routing, not a gate, and is not one.
 *  4. **`meta-refresh-login`** — a 200 whose HTML sends the browser somewhere else by
 *     `<meta http-equiv="refresh">`, judged by exactly the rule that judges a
 *     `Location`. A page that has told the browser to leave has served nothing, so the
 *     status code being 200 is an accident of how it chose to redirect.
 *  5. **`sso-form`** — a 200 carrying a `SAMLRequest`/`SAMLResponse` input. That field
 *     *is* the SAML POST binding; nothing else emits it.
 *  6. **`password-form`** — a 200 whose HTML carries a password input, anywhere on the
 *     page. Sufficient alone, which is why it outranks the composite below.
 *  7. **`credential-form`** — a 200 with a passwordless login form. The one clause that
 *     holds several facts together, because passwordless sign-in cannot be seen any other
 *     way; see {@link ProbeGate} for why it is worth the exception and
 *     {@link readLoginForm} for what it rests on.
 *
 * Clauses 4–7 read a 200's HTML, which is the only condition under which a body was kept
 * at all — so `res.body` being present is itself the evidence that HTML answered.
 *
 * Everything else — a bare 401, a 403, a same-origin redirect anywhere else, a 200 with
 * the words "Sign in" and no form to go with them, an empty body — returns `undefined`,
 * and `undefined` means *the exposure finding stands*. That asymmetry is the design: this
 * function can only ever take a service out of the exposed count, so every clause in it
 * has to be a fact rather than a likelihood.
 *
 * There is an eighth signal, and it is deliberately not decided here: `state-challenge`
 * rests on a **second request** and so cannot be read off the one response this function is
 * given. {@link wantsStateProbe} decides whether that request may be sent — only where this
 * function found nothing — and {@link readStateGate} judges the answer. Keeping the two
 * apart is what lets a reader see that no clause above was loosened to accommodate it.
 */
export function readGate(res: ProbeResponse): ProbeGate | undefined {
  if ((res.status === 401 || res.status === 407) && res.wwwAuthenticate?.trim()) return "challenge";

  if (res.status >= 300 && res.status < 400 && res.location?.trim()) {
    const to = readRedirect(res.location.trim(), res.requestUrl);
    // A `Location` that will not parse is not evidence of anything.
    if (!to) return undefined;
    if (to.crossOrigin) return "redirect-origin";
    if (isLoginPath(to.to)) return "redirect-login";
    return undefined;
  }

  if (res.status !== 200 || !res.body) return undefined;

  // The two signals that do not need a form at all: a redirect wearing a 200, and a
  // hand-off whose entire purpose is to be POSTed onward by script.
  const refresh = readRefresh(res.body, res.requestUrl);
  if (refresh && pointsAtLogin(refresh)) return "meta-refresh-login";
  if (hasSamlField(res.body)) return "sso-form";

  if (hasPasswordField(res.body)) return "password-form";

  // Passwordless. All three parts are required and they must be on **one** form: a
  // username field and a button with no login intent behind them is a signup box or a
  // site search, which is what the `news` service in `fixtures/probe/passwordless`
  // exists to keep out.
  const form = readLoginForm(res.body, res.requestUrl);
  if (form?.username && form.submit && (form.action !== undefined || form.otp)) return "credential-form";
  return undefined;
}

/**
 * The current-user addresses, and the whole of the second request's eligibility.
 *
 * Four paths, the same four every scan, reviewed here rather than derived at runtime. Every
 * one is a published convention for "who am I": `/api/` is the root a great many
 * applications mount their API at and refuse wholesale, and the other three are the shapes
 * `me`/`user` endpoints are actually spelled in. Nothing is guessed from a page — see
 * {@link stateTargets}.
 *
 * The list length *is* the request budget, and the walk stops at the first refusal
 * ({@link readState}), so the ordinary cost is one extra request and the worst case is four —
 * for the subset of services that answered 200 with form-less HTML and gated nothing. A
 * service that answered anything else is never asked (**I8**).
 */
export const STATE_PATHS: readonly string[] = ["/api/", "/api/me", "/api/v1/me", "/api/v1/user"];

/** Whether the page carries a `<form>` at all — the precondition, not a login test. */
function hasAnyForm(body: string): boolean {
  return /<form\b/i.test(body);
}

/**
 * Whether this answer is the one case a second request can settle: a form-less HTML shell.
 *
 * All four conditions do work, and the third and fourth are what keep the second request off
 * services it could tell nothing about:
 *
 *  - **No gate.** A service already known to be gated has nothing left to ask about, and
 *    asking would be a request that cannot change a verdict — the same argument
 *    `hasDetectedAuth` rests on, one stage further in.
 *  - **200, and HTML.** An API answering JSON was never a page, and a redirect's evidence is
 *    where it pointed.
 *  - **No `<form>` anywhere on it.** The line between "this rule cannot see the login" and
 *    "there was no login to see". A page with any form on it was read by clauses 5–7 with
 *    everything they need; a page with none either has no login screen or draws it in the
 *    browser, and those two are indistinguishable in served markup at any body size.
 *
 * A body of `undefined` under an HTML content type is an empty page, which is form-less by
 * the same test and is asked about for the same reason.
 */
export function wantsStateProbe(read: {
  gate: ProbeGate | undefined;
  status: number;
  mediaType: string | undefined;
  body: string | undefined;
}): boolean {
  if (read.gate !== undefined || read.status !== 200) return false;
  if (!isHtmlMediaType(read.mediaType)) return false;
  return !hasAnyForm(read.body ?? "");
}

/**
 * {@link STATE_PATHS} as absolute addresses on the origin that answered, in order.
 *
 * Resolved against the origin rather than against the path that was asked, so a service
 * answering at `/en` is still asked at `/api/` and not at `/en/api/`. Built from a constant in
 * this file and a URL LabView already sent a request to — **nothing here is parsed out of a
 * page**, which is the containment rule that matters: the served markup of an application
 * LabView did not write must never be able to name an address LabView then dials.
 *
 * Empty for a request URL that will not parse, which cannot happen for a URL that answered.
 */
export function stateTargets(requestUrl: string): string[] {
  try {
    const origin = new URL(requestUrl).origin;
    return STATE_PATHS.map((p) => new URL(p, origin).toString());
  } catch {
    return [];
  }
}

/** One current-user address's answer. No body and no header value — see {@link ProbeState}. */
export interface StateAnswer {
  /** The path asked, as it appears in {@link STATE_PATHS}. */
  path: string;
  /**
   * Absent when the address was asked and nothing came back.
   *
   * A sentinel would have done the same arithmetic, and would have put a status on the record
   * that no server ever sent. Optional instead: an entry with no status is one LabView asked
   * and got no answer to, which is not a refusal but is also not an address it skipped — so it
   * counts toward `asked` and toward nothing else.
   */
  status?: number;
  wwwAuthenticate?: string;
}

/**
 * What the walk found, and where it stopped.
 *
 * **401 and 407 are a refusal and 403 is not**, which is the one line here worth arguing.
 * A 403 is what a plain file server returns for a directory it will not list, so a static
 * site with no `/api/` at all would refuse by that test and be read as gated — a false gate
 * on a genuinely open service, which is the only direction this file must never be wrong in.
 * A 401 is the HTTP layer saying *you are not authenticated*, and nothing emits one by
 * accident.
 *
 * The walk ends at the first refusal, so `asked` is what LabView sent rather than what it was
 * offered — the truncation is here, in the pure rule, so the count on the payload and the
 * requests on the wire cannot come apart however the caller loops.
 */
export function readState(answers: readonly StateAnswer[]): ProbeState {
  for (const [i, a] of answers.entries()) {
    if (a.status !== 401 && a.status !== 407) continue;
    return {
      asked: i + 1,
      refusedAt: a.path,
      status: a.status,
      challenge: Boolean(a.wwwAuthenticate?.trim()),
    };
  }
  return { asked: answers.length };
}

/**
 * The eighth signal: a refusal that named a scheme, at an address the page's client asks.
 *
 * `challenge` one address over, and the header is required for the same reason it is there —
 * see {@link ProbeGate}'s `state-challenge` for why a bare 401 here is weaker evidence than a
 * bare 401 at `/` rather than stronger, and stays out of the verdict.
 *
 * A separate function from {@link readGate} because it answers a question about a *different
 * request*, and keeping them apart is what lets a reader see that no clause of the first was
 * loosened to accommodate the second.
 */
export function readStateGate(state: ProbeState): ProbeGate | undefined {
  return state.challenge ? "state-challenge" : undefined;
}

/**
 * Where a page's `<meta http-equiv="refresh">` sends the browser, if anywhere.
 *
 * Reported rather than judged, which is the difference between this and the predicate it
 * replaced: {@link readGate} asks {@link pointsAtLogin} about the answer and
 * {@link probeReasonText} names it, so the verdict and the reason rest on one reading of one
 * tag and cannot describe different tags. A refresh with no `url=` is a page reloading itself
 * on a timer — a live dashboard, not a gate — and is skipped rather than returned, so a page
 * that reloads itself *and* refreshes elsewhere is read by the second tag.
 *
 * **The first parseable target wins**, because that is the one a browser honours. A page with
 * two of them is contrived, and reading all of them would let a gate fire on a target the
 * payload does not name — a reason that contradicts its own verdict, which is worse than the
 * gate that first-tag semantics can only ever decline to give.
 */
export function readRefresh(body: string, requestUrl: string): ProbeRedirect | undefined {
  for (const tag of body.match(META_TAG) ?? []) {
    if ((attrOf(tag, "http-equiv") ?? "").trim().toLowerCase() !== "refresh") continue;
    // `content` is `<seconds>` or `<seconds>; url=<target>`.
    const url = /\burl\s*=\s*["']?([^"';]+)/i.exec(attrOf(tag, "content") ?? "")?.[1]?.trim();
    if (!url) continue;
    const to = readRedirect(url, requestUrl);
    if (to) return to;
  }
  return undefined;
}

/**
 * Where a `Location` points, relative to the URL that was asked — resolved once, for both the
 * verdict and the record of it.
 *
 * `to` is deliberately not the header. Query and fragment are dropped, because a redirect to
 * an identity provider carries `state`, `code` and `redirect_uri`, a redirect to a login page
 * carries `?next=`, and any of them can carry a session token that invariant **I6** keeps out
 * of the API — while none of them changes whether this is a gate. The origin is kept only
 * when the redirect left it, so the value reads as the fact it is: `/dashboard` went nowhere,
 * `https://sso.example.com/application/o/crm/` went to somebody else.
 *
 * Returns nothing for a `Location` that will not parse, which is not evidence of anything.
 */
export function readRedirect(location: string, requestUrl: string): ProbeRedirect | undefined {
  try {
    const from = new URL(requestUrl);
    const to = new URL(location, from);
    const crossOrigin = to.origin !== from.origin;
    return { to: crossOrigin ? `${to.origin}${to.pathname}` : to.pathname, crossOrigin };
  } catch {
    return undefined;
  }
}

/**
 * The media type alone — `text/html; charset=utf-8` becomes `text/html`.
 *
 * The parameters are dropped because none of them says anything about whether a page could be
 * a login page, and a charset in the payload is a detail a reader has to look past to find
 * the fact: an answer of `application/json` was never read as HTML at all, so no signal could
 * have been found in it however hard the rule looked.
 */
export function readMediaType(contentType: string | undefined): string | undefined {
  const type = contentType?.split(";")[0]?.trim().toLowerCase();
  return type || undefined;
}

/**
 * Whether a media type is HTML — `text/html` and `application/xhtml+xml`, nothing else.
 *
 * Here rather than beside the fetch that acts on it, because two copies of this test could
 * disagree: `getResponse` uses it to decide whether to read a body at all, and
 * {@link probeReasonText} uses it to explain a 200 that carried no login page *because it was
 * never a page*. Those two answers must be the same answer.
 */
export function isHtmlMediaType(mediaType: string | undefined): boolean {
  return mediaType === "text/html" || mediaType === "application/xhtml+xml";
}

/*
 * The four clause predicates, exported for one reason.
 *
 * `readGate` returns the *strongest* signal it found, which is what a verdict needs and is not
 * what somebody trying to improve the rule needs: they want to know which of the seven clauses
 * fired, which came close, and on what fact each one turned. `tools/probe-lab` answers that a
 * clause at a time, and it has to be able to ask each question the way `readGate` asks it —
 * a report that restated these tests could describe a decision LabView would never make, which
 * would make it worse than no report at all.
 *
 * So the tests are named and shared rather than copied. The regexes and the path list stay
 * private: what is exported is the question, never the pattern that answers it.
 */

/** Whether a same-origin path is a login page by name. Cross-origin never reaches here. */
export function isLoginPath(path: string): boolean {
  const lower = path.toLowerCase();
  return LOGIN_PATHS.some((p) => lower.startsWith(p));
}

/**
 * Whether a resolved target is a login: off the origin, or onto a {@link LOGIN_PATHS} path.
 *
 * One predicate for both ways of redirecting — a `Location` and a `<meta refresh>` — so the
 * two cannot disagree about what counts, and so `probeReasonText` explains a near-miss in the
 * terms this function actually failed on.
 */
export function pointsAtLogin(to: ProbeRedirect): boolean {
  return to.crossOrigin || isLoginPath(to.to);
}

/** Whether the page carries a password field, in either spelling. See {@link PASSWORD_INPUT}. */
export function hasPasswordField(body: string): boolean {
  return PASSWORD_INPUT.test(body);
}

/** Whether the page carries the SAML POST binding's own field. See {@link SAML_FIELD}. */
export function hasSamlField(body: string): boolean {
  return SAML_FIELD.test(body);
}

/**
 * What the most login-like form on a page is made of, or nothing if no form has any of
 * the parts a login form is made of.
 *
 * The answer to the plainest question about a 200: *is there a username field, a password
 * field and a login button?* Two things about how it answers are the whole point:
 *
 * **Per form, never page-wide.** A footer search box and a nav "Sign in" link are each
 * real, and a page-wide scan would hold them up together as a login form that does not
 * exist. Every flag here is read inside one `<form>` element, and only a form that has
 * several of them at once can mean anything.
 *
 * **Reported whether or not it gated.** {@link readGate} consults this for exactly one of
 * its clauses, but the shape goes onto the {@link ServiceProbe} either way — including for
 * a page that cleared nothing. A verdict a reader cannot inspect is one they have to take
 * on trust; this is the part they can check, and a form of `username + submit` with no
 * intent marker is precisely the case where they will want to.
 *
 * When several forms qualify the strongest wins, and the first of equals — so one page
 * yields one answer, and the same page yields the same answer twice (**I7**).
 */
export function readLoginForm(body: string, requestUrl: string): LoginFormShape | undefined {
  let best: LoginFormShape | undefined;
  let bestRank = 0;
  for (const form of formBlocks(body)) {
    const shape = shapeOf(form, requestUrl);
    const rank = rankShape(shape);
    if (rank > bestRank) {
      best = shape;
      bestRank = rank;
    }
  }
  return best;
}

/** One `<form>`: its attributes, and the markup between its tags. */
interface FormBlock {
  attrs: string;
  inner: string;
}

/**
 * Every `<form>` on the page, and the tail of a truncated one.
 *
 * The fallback is not defensive tidiness: bodies are read only to `MAX_BODY_BYTES`, so a
 * login page whose markup is larger than the cap arrives with its `<form>` opened and
 * never closed. Reading the tail as the form is the difference between measuring a
 * truncated login page and reporting that it had no form at all — and reporting that
 * would remove a gate, which is the one direction this file must not be wrong in.
 */
function formBlocks(body: string): FormBlock[] {
  const out: FormBlock[] = [];
  const re = /<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi;
  for (let m = re.exec(body); m; m = re.exec(body)) {
    out.push({ attrs: m[1] ?? "", inner: m[2] ?? "" });
  }
  if (out.length) return out;
  const open = /<form\b([^>]*)>/i.exec(body);
  if (!open) return out;
  out.push({ attrs: open[1] ?? "", inner: body.slice(open.index + open[0].length) });
  return out;
}

/** What one form is made of. */
function shapeOf(form: FormBlock, requestUrl: string): LoginFormShape {
  let password = false;
  let username = false;
  let submit = false;
  let otp = false;

  for (const tag of form.inner.match(/<input\b[^>]*>/gi) ?? []) {
    // An `<input>` with no `type` is a text field — the HTML default, not a guess.
    const type = (attrOf(tag, "type") ?? "text").trim().toLowerCase();
    const auto = (attrOf(tag, "autocomplete") ?? "").trim().toLowerCase();
    if (type === "password" || auto === "current-password") password = true;
    if (auto === "one-time-code") otp = true;
    if (type === "submit" || type === "image") submit = true;
    if (type === "email" || ((type === "text" || type === "tel") && namesAUser(tag, auto))) username = true;
  }
  // A `<button>` with no `type` submits its form, again by the HTML default — so the
  // absence of the attribute counts, and only `button` and `reset` do not.
  for (const tag of form.inner.match(/<button\b[^>]*>/gi) ?? []) {
    if ((attrOf(tag, "type") ?? "submit").trim().toLowerCase() === "submit") submit = true;
  }

  const action = loginAction(form.attrs, requestUrl);
  return { password, username, submit, otp, ...(action ? { action } : {}) };
}

/**
 * Whether a field is named like a username, by `name`, `id` or `autocomplete`.
 *
 * Substring matching against the closed {@link USERNAME_WORDS} list, because real markup
 * writes `login_email`, `user-id` and `signInName`. That it is loose is affordable only
 * because it is never sufficient on its own: `credential-form` also demands a submit
 * control and a login intent marker, so a search box named `account_query` costs nothing.
 */
function namesAUser(tag: string, autocomplete: string): boolean {
  for (const value of [attrOf(tag, "name"), attrOf(tag, "id"), autocomplete]) {
    const s = (value ?? "").trim().toLowerCase();
    if (s && USERNAME_WORDS.some((w) => s.includes(w))) return true;
  }
  return false;
}

/**
 * The form's `action`, but only when it submits to a login path on this origin.
 *
 * A **cross-origin** action is rejected rather than treated as a hand-off, which is the
 * one place this rule is deliberately narrower than the redirect rules above. Hosted
 * newsletter signup is a form posting an email address to somebody else's domain — the
 * shape is identical to a hosted login and the meaning is the opposite — so an off-origin
 * action is not evidence, and reading it as one would clear an exposure for every site
 * with a Mailchimp box in the footer.
 */
function loginAction(attrs: string, requestUrl: string): string | undefined {
  const raw = attrOf(attrs, "action")?.trim();
  if (!raw) return undefined;
  const to = readRedirect(raw, requestUrl);
  if (!to || to.crossOrigin) return undefined;
  return isLoginPath(to.to) ? to.to : undefined;
}

/**
 * How login-like one form is, for picking between several on a page.
 *
 * Ordering only — no threshold is read off it, and nothing gates on a total. A password
 * field outweighs everything because it is the one part that means something alone.
 */
function rankShape(s: LoginFormShape): number {
  return (
    (s.password ? 8 : 0) + (s.otp ? 4 : 0) + (s.username ? 2 : 0) + (s.submit ? 1 : 0) + (s.action ? 1 : 0)
  );
}

/**
 * One attribute out of a tag's source, quoted or bare.
 *
 * Enough HTML parsing for the job and no more, in the same spirit as the label readers:
 * the input is a document LabView did not write, the questions asked of it are five fixed
 * attribute names, and a real parser would be a dependency for no gain in what can be
 * concluded. A tag this fails to read yields a flag of `false`, which leaves the exposure
 * finding standing (**I4**).
 */
function attrOf(tag: string, name: string): string | undefined {
  const m = new RegExp(`\\b${name}\\s*=\\s*("[^"]*"|'[^']*'|[^\\s>]+)`, "i").exec(tag);
  const raw = m?.[1];
  if (!raw) return undefined;
  const quoted = raw.startsWith('"') || raw.startsWith("'");
  return quoted ? raw.slice(1, -1) : raw;
}

/** A short answer and the sentence behind it, matching `NoAuthText`'s shape. */
export interface ProbeGateText {
  label: string;
  title: string;
}

const GATE_TEXT: Record<ProbeGate, ProbeGateText> = {
  challenge: {
    label: "Credential requested",
    title:
      "The service answered 401/407 with a WWW-Authenticate header, so it asked for a credential before serving anything.",
  },
  "redirect-origin": {
    label: "Redirected off-site",
    title:
      "The service redirected the request to a different origin without serving it — the shape of a hand-off to an identity provider.",
  },
  "redirect-login": {
    label: "Redirected to a login path",
    title: "The service redirected the request to a login path of its own instead of serving it.",
  },
  "meta-refresh-login": {
    label: "Page redirects to a login",
    title:
      "The service answered with an HTML page that immediately sends the browser to a login path or off the origin, so it served no content of its own.",
  },
  "sso-form": {
    label: "Identity provider hand-off",
    title:
      "The service answered with a SAML POST binding — a form carrying a SAMLRequest or SAMLResponse — which hands the browser to an identity provider.",
  },
  "password-form": {
    label: "Login form served",
    title: "The service answered with an HTML page carrying a password field, i.e. its own login form.",
  },
  "credential-form": {
    label: "Passwordless login form",
    title:
      "The service answered with a form asking for a username or a one-time code and submitting it to a login path — a magic-link or passkey sign-in, which has no password field to find.",
  },
  "state-challenge": {
    label: "Credential requested behind the page",
    title:
      "The service answered with a page carrying no form at all — a login screen drawn in the browser is not in the served markup — and the address its own client fetches the signed-in user from asked for a credential, with a WWW-Authenticate header, from a request that carried none.",
  },
};

/** The wording for a signal. One place, so the drawer and a note cannot drift. */
export function probeGateText(gate: ProbeGate): ProbeGateText {
  return GATE_TEXT[gate];
}

/**
 * Every signal, strongest first — the precedence {@link readGate} applies for its seven, with
 * {@link readStateGate}'s one after them. A consumer can enumerate them rather than restate the
 * union, and the order a reader sees is the order that decides.
 */
export const PROBE_GATES: readonly ProbeGate[] = [
  "challenge",
  "redirect-origin",
  "redirect-login",
  "meta-refresh-login",
  "sso-form",
  "password-form",
  "credential-form",
  // Last, because it is the only one that needs a second request — and the second request is
  // sent only where all seven above already found nothing. Ordering it anywhere else would
  // suggest a page could satisfy it *instead* of one of them, and none can.
  "state-challenge",
];

/**
 * What asking at this vantage was worth, which is not the same at all three.
 *
 * The address decides how much an answer means, and a reader has to be told which one
 * was used before they can judge the result. A public hostname answering without a login
 * page is the strong case: the request went out of the fleet and back through the very
 * edge a visitor's would. A published host port answering the same way says only that the
 * port is open — which is a real finding, and a different one.
 */
const VANTAGE_TEXT: Record<ProbeVantage, string> = {
  public: "asked at its public hostname, so the request left the fleet and returned through the edge",
  traefik: "asked at the hostname its own proxy router serves",
  lan: "asked straight at a published host port, which nothing at the edge stands in front of",
};

export function probeVantageText(vantage: ProbeVantage): string {
  return VANTAGE_TEXT[vantage];
}

/**
 * What {@link readLoginForm} found, as a sentence.
 *
 * The inspectable half of a probe verdict. A gate label says *what LabView concluded*; this
 * says what it saw, and the two are shown together so a reader can disagree with the first
 * on the strength of the second — a form of a username field and a button, with no action
 * on a login path, is exactly the case where they might, and it is reported for precisely
 * that reason rather than hidden because it cleared nothing.
 *
 * The action is named when there is one because it is the marker the `credential-form`
 * verdict rests on, and a reader who can see which path a form posts to can check the
 * conclusion instead of accepting it.
 */
export function probeFormText(form: LoginFormShape): string {
  const parts: string[] = [];
  if (form.password) parts.push("a password field");
  if (form.username) parts.push("a username field");
  if (form.otp) parts.push("a one-time-code field");
  if (form.submit) parts.push("a submit button");
  if (form.action) parts.push(`an action of ${form.action}`);
  const last = parts.pop();
  if (!last) return "The page carried a form with none of the parts a login form is made of.";
  const made = parts.length ? `${parts.join(", ")} and ${last}` : last;
  return `The page carried a form with ${made}.`;
}

/**
 * What the login-probe switch says when a reader hovers it.
 *
 * Here rather than in the component, on the same reasoning as every other wording rule in
 * this file: a component cannot be asserted by the smoke pass, and this text carries three
 * facts a reader cannot get anywhere else — that flipping it makes a scan send requests at
 * the fleet, that it outranks the configured value, and that it does so for exactly one
 * scan. A switch whose scope is not stated is a switch that looks broken the first time a
 * cache expiry moves it.
 *
 * Ends with what the payload on screen actually did, rather than with what the switch is
 * set to. The two differ for as long as it takes to press Rescan, and that gap is where a
 * reader would otherwise read an unprobed scan as "no login page found".
 */
export function probeToggleText(run: { enabled: boolean; source: "config" | "request" }): string {
  const did = run.enabled ? "probed" : "did not probe";
  const why =
    run.source === "request"
      ? "because this switch asked it to"
      : run.enabled
        ? "because the configuration has probing on"
        : "and the configuration has probing off";
  return [
    "Ask each HTTP service what it answers, and read a login page as evidence — this is the only stage that sends requests to the scanned services, and for a service behind a public hostname those requests leave the fleet.",
    "Only services this scan found no authentication for are asked: where a gate is already detected the answer could not change the verdict, so no request is sent.",
    "One address each, at /, except for a page that came back with no form on it at all — a login screen drawn in the browser is invisible in served markup, so up to four fixed current-user addresses are asked as well, stopping at the first that refuses.",
    "It applies to the next Rescan and to nothing else: a refresh after the cache expires has no request behind it and goes back to the configured value.",
    `The scan on screen ${did} ${why}.`,
  ].join(" ");
}

/** One probe's result as a reader sees it: a short answer, the sentence, and a severity. */
export interface ProbeOutcome {
  label: string;
  title: string;
  /** Whether this is a finding rather than a reassurance — an open service, not a gate. */
  critical: boolean;
}

/**
 * How one probe result is worded, wherever it is shown.
 *
 * Here rather than in the drawer for the reason every wording rule in this codebase is in
 * `src/model/`: a component cannot be asserted by the smoke pass, and the three outcomes
 * have to stay told apart. In particular the third is neither of the other two —
 * a service that did not answer had nothing measured about it, and a UI that let that
 * read as "no login page" would be inventing the one conclusion this stage must never
 * reach by accident.
 */
export function probeOutcome(
  probe: Pick<ServiceProbe, "phase" | "status" | "gate" | "detail">,
): ProbeOutcome {
  if (probe.gate) {
    const text = probeGateText(probe.gate);
    return { label: text.label, title: text.title, critical: false };
  }
  if (probe.phase === "connected") {
    return {
      label: "No login page",
      title: `The service answered${probe.status ? ` (HTTP ${probe.status})` : ""} carrying none of the signals a login page carries, so whatever the section above says is what LabView could observe.`,
      critical: true,
    };
  }
  return {
    label: "No answer",
    title: `Nothing was measured for this service — ${phaseText(probe.phase)}: ${probe.detail}. Its posture rests on configuration alone.`,
    critical: false,
  };
}

/** Everything {@link probeReasonText} reads. Spelled out so the rule cannot quietly grow. */
type ProbeReasonInput = Pick<
  ServiceProbe,
  | "phase"
  | "status"
  | "gate"
  | "form"
  | "mediaType"
  | "redirect"
  | "refresh"
  | "truncated"
  | "state"
  | "detail"
>;

/**
 * Which fact decided a probe's verdict — the checkable half of a probe result.
 *
 * {@link probeOutcome} says what LabView concluded. This says what it saw and which clause
 * of {@link readGate} that satisfied or fell short of, so a reader can disagree with the
 * conclusion on the strength of the observation instead of taking it on trust.
 *
 * **The negative verdict is the one this exists for.** A gate takes a service out of the
 * exposed count, so a reader who doubts one can go and look; `gate: undefined` *leaves* a
 * service in the count, and until now the record of that was `HTTP 302 — answered with no
 * login page` — a conclusion with the fact behind it thrown away. A 302 to `/dashboard` and a
 * 302 to `/login` are the same sentence there. So for a service that answered and did not
 * gate, this names the clause that came closest and what it lacked: the header a bare 401
 * did not carry, the origin a redirect did not leave, the page an `application/json` answer
 * never was, the login intent a signup form does not have.
 *
 * Pure, and therefore assertable — which is the whole reason it is here and not written in
 * `enrich/probe.ts` where the response is in hand. A sentence composed at probe time can only
 * be tested by mocking the network, and the two fixtures that exist to catch word-matching
 * (`meta-refresh/home`, `passwordless/news`) are pinned by *what this says about them*.
 */
export function probeReasonText(probe: ProbeReasonInput): string {
  if (probe.phase !== "connected") {
    return `Nothing answered, so nothing about this service was measured: ${probe.detail}.`;
  }
  const at = probe.status === undefined ? "It answered" : `It answered HTTP ${probe.status}`;
  if (probe.gate) return GATE_REASON[probe.gate](probe, at);
  // The caveat rides only on a negative verdict. On a gate it would read as doubt about a
  // verdict that is not in doubt — the signal was found in what *was* read.
  const caveat = probe.truncated
    ? " The read stopped at the probe's body cap before the end of the page, so a login form below that point was never searched for."
    : "";
  return openReason(probe, at) + caveat;
}

/**
 * One sentence per signal, naming the fact that fired rather than restating the label.
 *
 * A `Record<ProbeGate, …>` for the same reason `GATE_TEXT` is one: a new member of the union
 * is a compile error here until it has been explained, so a signal can never ship with its
 * reason left as the generic case.
 */
const GATE_REASON: Record<ProbeGate, (p: ProbeReasonInput, at: string) => string> = {
  challenge: (_p, at) =>
    `${at} with a WWW-Authenticate header, so a credential was asked for before anything was served.`,
  "redirect-origin": (p, at) =>
    `${at} and sent the request to ${p.redirect?.to ?? "another origin"}, which is off its own origin — the shape of a hand-off to an identity provider.`,
  "redirect-login": (p, at) =>
    `${at} and sent the request to ${p.redirect?.to ?? "a login path"}, a login path on its own origin, instead of serving it.`,
  "meta-refresh-login": (p, at) =>
    `${at} with a page whose <meta refresh> sends the browser to ${p.refresh?.to ?? "a login"} instead of serving any content of its own.`,
  "sso-form": (_p, at) =>
    `${at} with a form carrying a SAMLRequest or SAMLResponse field, which is the SAML POST binding — nothing else emits one.`,
  "password-form": (_p, at) => `${at} with an HTML page carrying a password field.`,
  "credential-form": (p, at) =>
    `${at} with one form carrying ${credentialMarkers(p.form)}, and no password field — a magic-link or passkey sign-in.`,
  "state-challenge": (p, at) =>
    `${at} with a page carrying no form at all, so nothing in the markup could be read as a login — and then ${p.state?.refusedAt ?? "a current-user address"} answered ${p.state?.status ?? 401} with a WWW-Authenticate header to a request carrying no credential. The login screen is drawn by this service's own client, and the gate is at the address that client asks.`,
};

/** The three facts `credential-form` rests on, in the words of the form they were read from. */
function credentialMarkers(form: LoginFormShape | undefined): string {
  if (!form) return "a username field and a submit button";
  const intent = form.otp ? "a one-time-code field" : `an action of ${form.action}`;
  return `a username field, a submit button and ${intent}`;
}

/**
 * Why the answer that arrived was not a login page — the clause that came closest, and what
 * it lacked.
 *
 * Ordered by status the way {@link readGate} is, so the near-miss named is the one the rule
 * actually got furthest through rather than the first thing that happened to be absent.
 */
function openReason(probe: ProbeReasonInput, at: string): string {
  const status = probe.status ?? 0;
  if (status === 401 || status === 407) {
    return `${at} but sent no WWW-Authenticate header, so nothing asked for a credential — a bare ${status} is also what an API returns to a call it will not serve.`;
  }
  if (status >= 300 && status < 400) {
    return probe.redirect
      ? `${at} and sent the request to ${probe.redirect.to}, which is on its own origin and is not a login path — routing rather than a gate.`
      : `${at} with no Location that could be read, so where it was sending the request cannot be judged.`;
  }
  if (status !== 200) {
    return `${at}, which is neither a credential request, a redirect, nor a page served — there is nothing in it that a login page is recognised by.`;
  }
  if (!isHtmlMediaType(probe.mediaType)) {
    const was = probe.mediaType ? `a body of ${probe.mediaType}` : "no content type at all";
    return `${at} with ${was} rather than an HTML page, so it was never read as one — an application answering its API cannot be shown to have a login page in front of it.`;
  }
  // HTML came back and nothing in it fired. Name whatever came nearest, because a page with a
  // form on it and a page with nothing on it are both "no signals found" and only one of them
  // is worth a second look.
  const near = [
    probe.refresh
      ? `its <meta refresh> points at ${probe.refresh.to}, which is neither off the origin nor a login path`
      : undefined,
    probe.form ? formShortfall(probe.form) : undefined,
  ].filter((s): s is string => s !== undefined);
  const closest = near.length ? ` The nearest thing to a signal on it: ${joinAnd(near)}.` : "";
  return `${at} and served an HTML page carrying none of the signals — no password field, no SAML hand-off, no refresh to a login and no form with login intent.${closest}${stateShortfall(probe.state)}`;
}

/**
 * What the second request found, for the page it did not clear — the sentence this whole
 * feature is honest in.
 *
 * Two outcomes, and the first is the one that costs something to report this way. A **bare**
 * 401 at a current-user address is the shape three services in four wear in a real fleet, and
 * it is exactly as consistent with a fully gated application as with a public one that has
 * optional accounts. Naming it while *leaving the finding standing* is the whole of the
 * compromise: a reader is told where to look, and the count is not moved on a maybe.
 *
 * The second outcome is a reassurance and is worth as much. A form-less shell is the one page
 * this rule cannot read, so "and nothing behind it refused an anonymous caller either" is what
 * turns "no signals found" from a limit of the rule into a finding about the service.
 *
 * Empty when no second request was sent, which is every service that answered anything but a
 * form-less HTML 200.
 */
function stateShortfall(state: ProbeState | undefined): string {
  if (!state) return "";
  const plural = (n: number) => `${n} current-user address${n === 1 ? "" : "es"}`;
  if (state.refusedAt === undefined) {
    return ` None of the ${plural(state.asked)} it was asked at refused an anonymous request either, so nothing behind the page contradicts what the page itself served.`;
  }
  // A refusal that gated would have been reported by `GATE_REASON` and never reach here, so
  // this arm is only ever the bare one — but the condition is stated rather than assumed,
  // because a future clause that gates on something else must not silently land in this
  // sentence and describe itself as evidence that changed nothing.
  if (state.challenge) return "";
  return ` Its ${state.refusedAt} did answer ${state.status} to a request carrying no credential, which is an application saying nobody is signed in — but it named no authentication scheme, and a public application with optional accounts answers exactly the same way while serving everybody. So it is a place to look and not a gate, and the finding stands.`;
}

/**
 * Which part of a passwordless login the form on the page did not have.
 *
 * Nothing when it had all of them, which cannot happen for a page that reached here — the
 * `credential-form` clause reads the same {@link readLoginForm} answer — so rather than emit a
 * sentence contradicting its own verdict, the clause is left out.
 */
function formShortfall(form: LoginFormShape): string | undefined {
  const missing: string[] = [];
  if (!form.username) missing.push("no username field");
  if (!form.submit) missing.push("no submit control");
  if (form.action === undefined && !form.otp) {
    missing.push("no login intent, since its action is not a login path and it asks for no one-time code");
  }
  return missing.length ? `a form was read with ${joinAnd(missing)}` : undefined;
}

/** `a, b and c`. Used only where the parts are already worded. */
function joinAnd(parts: readonly string[]): string {
  if (parts.length <= 1) return parts[0] ?? "";
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

/** One probed service, with enough of its identity to be found again. */
export interface ProbeReportEntry {
  stackId: string;
  stackName: string;
  service: string;
  probe: ServiceProbe;
}

/**
 * Every probe result in the fleet, split by the three outcomes that must never be conflated.
 *
 * The order of the fields is the order the panel shows them, and it is the answers that
 * cleared nothing first: `open` is the half of the measurement that left every finding
 * standing and is the reason to open the panel at all, `gated` is the half that withdrew one,
 * and `silent` is neither — a service nothing was measured about, which a UI must not let
 * read as "no login page found".
 *
 * `open` is **not** a list of exposures, on `OverviewStats.probeOpen`'s own terms: a service
 * whose `.labview` file declares a mechanism is in here too, since a declaration is a claim
 * rather than detection and so does not withhold the question. What every entry has in common
 * is that asking withdrew nothing, not that anything is wrong.
 */
export interface ProbeReport {
  /** Answered, and no signal fired — so nothing was taken out of the exposed count. */
  open: ProbeReportEntry[];
  /** Answered with a login page, by one of the eight signals in `PROBE_GATES`. */
  gated: ProbeReportEntry[];
  /** Nothing answered, so nothing was measured. */
  silent: ProbeReportEntry[];
  /** Every service asked — the three lists' total, and what the tile counts. */
  probed: number;
  /**
   * Services with an HTTP address that were deliberately not asked, because authentication
   * had already been detected in front of them — `ProbeRun.skipped`, carried in so the tile
   * and the panel can say it.
   *
   * A number rather than a fourth list, and that is a limit worth naming: nothing on
   * `svc.probe` records a service that was never asked, so there is nothing to list. What
   * the count buys is that `probed` reading lower than the fleet's HTTP services has a
   * stated reason instead of looking like results went missing.
   */
  notAsked: number;
}

/**
 * Collect what the probe found, for a reader who has counts and wants the cases.
 *
 * Derived from `stacks` rather than carried in `ScanMeta`, exactly as
 * `collectDeclarationDrift` is and for the same reason: the results are already on
 * `svc.probe`, and a second copy in the payload would be a second thing to keep in step with
 * the first. Nothing is re-worded here either — `probeOutcome` and {@link probeReasonText} own
 * what a result says, so the panel and the service drawer give one fact one voice.
 *
 * In `src/model/` rather than in the component that renders it so it can be asserted: smoke
 * never mounts a DOM, and "the panel lists exactly the services the tile counted" — that
 * `gated.length` and `open.length` equal `OverviewStats.probeGated` and `.probeOpen` — is
 * precisely the claim worth pinning.
 *
 * Sorted by stack name then service name, matching the fleet list, so a reader arriving from
 * it finds a service where they left it and the same scan produces the same panel twice (I7).
 *
 * @param notAsked `ScanMeta.probe.skipped`. The one thing here that cannot be derived from
 * `stacks`, because a service that was never asked leaves nothing behind on itself to derive
 * it from. Defaults to 0 so a caller holding only a fleet — a test, the CLI — still gets a
 * report, on the understanding that 0 then means "not stated" rather than "none withheld".
 */
export function collectProbeReport(stacks: readonly AppStack[], notAsked = 0): ProbeReport {
  const open: ProbeReportEntry[] = [];
  const gated: ProbeReportEntry[] = [];
  const silent: ProbeReportEntry[] = [];
  for (const stack of [...stacks].sort((a, b) => a.name.localeCompare(b.name))) {
    for (const svc of [...stack.services].sort((a, b) => a.name.localeCompare(b.name))) {
      const probe = svc.probe;
      if (!probe) continue;
      const entry: ProbeReportEntry = {
        stackId: stack.id,
        stackName: stack.name,
        service: svc.name,
        probe,
      };
      // The same three-way split `enrichWithProbe` counts by, and in the same order of tests:
      // a transport failure first, because `gate` is necessarily absent on one and reading it
      // as "answered, no gate" is the one mistake this stage must never make by accident.
      if (probe.phase !== "connected") silent.push(entry);
      else if (probe.gate) gated.push(entry);
      else open.push(entry);
    }
  }
  return { open, gated, silent, probed: open.length + gated.length + silent.length, notAsked };
}

/**
 * The report as one line — `5 services asked · 3 gated · 2 answered with no login page`.
 *
 * Shared by the tile's tooltip and the panel's subtitle so the two cannot count the same fleet
 * differently. `did not answer` and `not asked` appear only when some service was, because a
 * zero there is a fact about nothing and every fleet on a good day would carry it.
 *
 * A fleet where *everything* eligible was already authenticated is the one case with a count
 * and no services in it, and it gets its own sentence: `no service was asked` alone would be
 * true and would read as though the stage had not run.
 */
export function probeReportSummaryText(report: ProbeReport): string {
  const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? "" : "s"}`;
  const notAsked = report.notAsked
    ? `${plural(report.notAsked, "service")} not asked (authentication already detected)`
    : "";
  if (report.probed === 0) return notAsked || "no service was asked";
  return [
    `${plural(report.probed, "service")} asked`,
    `${report.gated.length} gated`,
    `${report.open.length} answered with no login page`,
    ...(report.silent.length ? [`${report.silent.length} did not answer`] : []),
    ...(notAsked ? [notAsked] : []),
  ].join(" · ");
}
