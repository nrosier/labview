import type {
  CloudflareRoute,
  LoginFormShape,
  ProbeGate,
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
 * Three rules, and all of them live here rather than in the client that does the
 * fetching, because a rule in an I/O module can only be tested by mocking the I/O:
 *
 *  - **{@link probeTargets}** — eligibility and try-order. Only where HTTP is
 *    *observable*, never from a port number and never from an image name, which is what
 *    keeps the probe off a database (I2/I3).
 *  - **{@link readGate}** — what counts as a login page. Strict on purpose: everything
 *    it does not recognise reads as "answered, no gate observed", which leaves the
 *    exposure finding standing. A finding a reader dismisses costs them a look; false
 *    comfort is the thing this project exists to remove.
 *  - **{@link readLoginForm}** — what a form on the page was *made of*, which is
 *    reported whether or not it cleared anything. A verdict a reader cannot inspect is
 *    one they have to take on trust, and this is the part they can check.
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
 * Five entries and no convention-guessing beyond them. Four are the paths the OAuth and
 * SSO ecosystem standardised on; `/outpost.goauthentik.io` is Authentik's own outpost
 * path, which is published rather than inferred. Matched as a prefix so `/login.php` and
 * `/oauth2/start` both count, which is what real applications redirect to.
 *
 * This list only ever *adds* a gate to a redirect that stayed on the same origin. A
 * cross-origin redirect is already `redirect-origin` without consulting it, so a
 * hand-rolled login path that is missing here costs a gate — never a false one.
 */
const LOGIN_PATHS: readonly string[] = ["/login", "/signin", "/sso", "/oauth2", "/outpost.goauthentik.io"];

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
 * The gate rule: which of the seven signals a response carries, or none.
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
 */
export function readGate(res: ProbeResponse): ProbeGate | undefined {
  if ((res.status === 401 || res.status === 407) && res.wwwAuthenticate?.trim()) return "challenge";

  if (res.status >= 300 && res.status < 400 && res.location?.trim()) {
    const to = resolveLocation(res.location.trim(), res.requestUrl);
    // A `Location` that will not parse is not evidence of anything.
    if (!to) return undefined;
    if (to.crossOrigin) return "redirect-origin";
    const path = to.pathname.toLowerCase();
    if (LOGIN_PATHS.some((p) => path.startsWith(p))) return "redirect-login";
    return undefined;
  }

  if (res.status !== 200 || !res.body) return undefined;

  // The two signals that do not need a form at all: a redirect wearing a 200, and a
  // hand-off whose entire purpose is to be POSTed onward by script.
  if (sendsBrowserToLogin(res.body, res.requestUrl)) return "meta-refresh-login";
  if (SAML_FIELD.test(res.body)) return "sso-form";

  if (PASSWORD_INPUT.test(res.body)) return "password-form";

  // Passwordless. All three parts are required and they must be on **one** form: a
  // username field and a button with no login intent behind them is a signup box or a
  // site search, which is what the `news` service in `fixtures/probe/passwordless`
  // exists to keep out.
  const form = readLoginForm(res.body, res.requestUrl);
  if (form?.username && form.submit && (form.action !== undefined || form.otp)) return "credential-form";
  return undefined;
}

/**
 * Whether a page's `<meta http-equiv="refresh">` points at a login.
 *
 * The judgement is deliberately the same one the 3xx arm makes — off the origin, or onto a
 * {@link LOGIN_PATHS} path — so the two ways of redirecting cannot disagree about what
 * counts. A refresh with no `url=` is a page reloading itself on a timer, which is a live
 * dashboard and not a gate; a refresh to `/dashboard` is routing, and the `home` service in
 * `fixtures/probe/meta-refresh` is there to hold that line.
 */
function sendsBrowserToLogin(body: string, requestUrl: string): boolean {
  for (const tag of body.match(META_TAG) ?? []) {
    if ((attrOf(tag, "http-equiv") ?? "").trim().toLowerCase() !== "refresh") continue;
    // `content` is `<seconds>` or `<seconds>; url=<target>`.
    const url = /\burl\s*=\s*["']?([^"';]+)/i.exec(attrOf(tag, "content") ?? "")?.[1]?.trim();
    if (!url) continue;
    const to = resolveLocation(url, requestUrl);
    if (!to) continue;
    if (to.crossOrigin) return true;
    const path = to.pathname.toLowerCase();
    if (LOGIN_PATHS.some((p) => path.startsWith(p))) return true;
  }
  return false;
}

/** Where a `Location` points, relative to the URL that was asked. */
function resolveLocation(
  location: string,
  requestUrl: string,
): { crossOrigin: boolean; pathname: string } | undefined {
  try {
    const from = new URL(requestUrl);
    const to = new URL(location, from);
    return { crossOrigin: to.origin !== from.origin, pathname: to.pathname };
  } catch {
    return undefined;
  }
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
  const to = resolveLocation(raw, requestUrl);
  if (!to || to.crossOrigin) return undefined;
  const path = to.pathname.toLowerCase();
  return LOGIN_PATHS.some((p) => path.startsWith(p)) ? to.pathname : undefined;
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
};

/** The wording for a signal. One place, so the drawer and a note cannot drift. */
export function probeGateText(gate: ProbeGate): ProbeGateText {
  return GATE_TEXT[gate];
}

/**
 * Every signal, in the precedence {@link readGate} applies — so a consumer can enumerate
 * them rather than restate the union, and the order a reader sees is the order that decides.
 */
export const PROBE_GATES: readonly ProbeGate[] = [
  "challenge",
  "redirect-origin",
  "redirect-login",
  "meta-refresh-login",
  "sso-form",
  "password-form",
  "credential-form",
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
