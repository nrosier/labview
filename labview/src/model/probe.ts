import type {
  CloudflareRoute,
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
 * Two rules, and both of them live here rather than in the client that does the
 * fetching, because a rule in an I/O module can only be tested by mocking the I/O:
 *
 *  - **{@link probeTargets}** — eligibility and try-order. Only where HTTP is
 *    *observable*, never from a port number and never from an image name, which is what
 *    keeps the probe off a database (I2/I3).
 *  - **{@link readGate}** — what counts as a login page. Strict on purpose: everything
 *    that is not one of three specific signals reads as "answered, no gate observed",
 *    which leaves the exposure finding standing. A finding a reader dismisses costs
 *    them a look; false comfort is the thing this project exists to remove.
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

/** An `<input type="password">`, in any of the spellings HTML permits. */
const PASSWORD_INPUT = /<input[^>]*\btype\s*=\s*["']?password\b/i;

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
 * The gate rule: which of the four signals a response carries, or none.
 *
 * Ordered strongest first, and each clause is one fact:
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
 *  4. **`password-form`** — a 200 whose HTML carries a password input. Only on 200 and
 *     only from HTML, because those are the terms on which the body was read at all.
 *
 * Everything else — a bare 401, a 403, a same-origin redirect anywhere else, a 200 with
 * the words "Sign in" and no password field, an empty body — returns `undefined`, and
 * `undefined` means *the exposure finding stands*. That asymmetry is the design: this
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

  if (res.status === 200 && res.body && PASSWORD_INPUT.test(res.body)) return "password-form";
  return undefined;
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
  "password-form": {
    label: "Login form served",
    title: "The service answered with an HTML page carrying a password field, i.e. its own login form.",
  },
};

/** The wording for a signal. One place, so the drawer and a note cannot drift. */
export function probeGateText(gate: ProbeGate): ProbeGateText {
  return GATE_TEXT[gate];
}

/** Every signal, so a consumer can enumerate them rather than restate the union. */
export const PROBE_GATES: readonly ProbeGate[] = [
  "challenge",
  "redirect-origin",
  "redirect-login",
  "password-form",
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
