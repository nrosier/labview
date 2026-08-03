/**
 * LabView normalized model.
 *
 * These types are the single contract between the scanner/analyzer (backend) and
 * the web UI (frontend). The frontend imports this file directly, so keep it free
 * of any Node-only imports.
 */

/** One env var as parsed from a .env file or a service `environment` block. */
export interface EnvVar {
  key: string;
  /** Raw value after ${...} interpolation. `null` when masked as a secret. */
  value: string | null;
  masked: boolean;
  /** Where the value came from, for provenance in the UI. */
  source: "env_file" | "environment" | "shell-default";
}

/** A parsed port mapping (`8080:80/tcp`). */
export interface PortMapping {
  published?: string;
  target: string;
  protocol: string;
  raw: string;
}

/** A parsed volume/bind mount. */
export interface MountSpec {
  type: "bind" | "volume" | "tmpfs" | "npipe" | "unknown";
  /** Host path (bind) or named volume. */
  source?: string;
  /** Path inside the container. */
  target: string;
  readOnly: boolean;
  raw: string;
}

/**
 * What a tunnel origin address points at, resolved from observable evidence only.
 *
 * A tunnel does not usually terminate at the container it is declared on: the
 * origin points at a reverse proxy, which forwards to the container over a shared
 * network. Drawing the tunnel straight at the container would assert a topology
 * the configuration contradicts, so the origin is resolved instead of assumed.
 *
 * The evidence is the origin's **port**. Host ports are unique per host, so a
 * published port identifies exactly one service — which makes the match an
 * observation rather than an inference, and needs no image or vendor detection to
 * establish (invariants I1/I2 in IMPLEMENTATION.md).
 */
export interface OriginTarget {
  /** The raw origin address as declared (`dockflare.service`). */
  address: string;
  host: string;
  /** Explicit port, or the one implied by the scheme (443 for https, 80 for http). */
  port: string;
  kind: OriginKind;
  /** For `fleet-service`: `${stackId}/${serviceName}` of the resolved hop. */
  hopKey?: string;
  /** Why this conclusion was reached, in the spirit of `AuthPosture.evidence`. */
  evidence: string;
}

/**
 * How a tunnel origin resolved.
 *
 * Only `fleet-service` establishes a hop. The three others all mean "the tunnel
 * reaches this service directly", either because the config says so or because
 * nothing in the scan could prove otherwise — and an unproven hop is not drawn.
 */
export type OriginKind =
  /** Origin host is the service's own compose/container name — direct over a docker network. */
  | "self-network"
  /** Origin port is a port this very service publishes — direct at the host port. */
  | "self-host-port"
  /** Origin port is another scanned service's published port — that service is the hop. */
  | "fleet-service"
  /** Matched nothing published in the scanned stacks, or was ambiguous. */
  | "unresolved";

/** DockFlare-derived public ingress via a Cloudflare tunnel. */
export interface CloudflareRoute {
  hostname: string;
  service: string;
  path?: string;
  /** Cloudflare Access policy, if any (group / policy / emails). */
  access?: {
    group?: string;
    policy?: string;
    emails?: string[];
  };
  noTlsVerify?: boolean;
  raw: Record<string, string>;
  /** What `service` resolves to. Absent when no origin was declared. */
  origin?: OriginTarget;
}

/** Traefik-derived local ingress. */
export interface TraefikRoute {
  router: string;
  /** The full router rule (e.g. `Host(\`x.example.com\`)`). */
  rule?: string;
  /** Hostnames extracted from the rule. */
  hosts: string[];
  pathPrefixes: string[];
  entrypoints: string[];
  tls: boolean;
  certResolver?: string;
  middlewares: string[];
  /** loadbalancer target port, if declared. */
  servicePort?: string;
  /**
   * The Traefik service this router targets, verbatim, when the label names one.
   *
   * Usually the container's own load balancer, but it can also be one of Traefik's
   * built-ins — `api@internal` being the one that matters, since a router pointing at
   * it is the operator stating that this container serves the Traefik API.
   */
  service?: string;
}

/**
 * One entry of a router's middleware chain as Traefik itself resolved it.
 *
 * A label lists middleware *names*; only the proxy knows what those names resolve
 * to. `type` therefore comes from the definition Traefik holds — including for a
 * middleware declared in a file provider, which a compose scan cannot see at all.
 */
export interface TraefikLiveMiddleware {
  /** Traefik's own qualified name, `name@provider`. */
  name: string;
  /** Lowercased middleware type as Traefik keys it (`forwardauth`, `basicauth`, `chain`, …). */
  type: string;
  /** For a forward-auth: the address the proxy delegates the decision to. */
  address?: string;
  /** Errors Traefik reported for this middleware. Non-empty means it is not usable. */
  errors: string[];
  /** Name of the `chain` middleware this entry was reached through, when nested. */
  viaChain?: string;
  /**
   * True when the middleware is attached to the router's *entrypoint* rather than
   * named by the router. Such a gate is invisible in a router's own middleware
   * list, so it must be merged in before any conclusion about a missing gate.
   */
  viaEntrypoint?: boolean;
}

/** One backend Traefik forwards to, with the health it last observed for it. */
export interface TraefikLiveServer {
  url: string;
  /** Traefik's `serverStatus` for this URL (`UP` / `DOWN`), when it reported one. */
  status?: string;
}

/**
 * A router as the proxy is actually serving it, matched to a scanned service.
 *
 * This is the live counterpart of `TraefikRoute`: same subject, different source.
 * `TraefikRoute` is what the compose labels asked for; this is what Traefik built
 * from them — plus whatever it built from providers the scan cannot read.
 */
export interface TraefikLiveRouter {
  /** Router name without the provider suffix. */
  router: string;
  /** Provider Traefik loaded it from (`docker`, `file`, `kubernetes`, …). */
  provider: string;
  /** Traefik's own status, typically `enabled` or `disabled`. */
  status?: string;
  /** Errors Traefik reported for this router. Non-empty means it is not serving. */
  errors: string[];
  rule?: string;
  /** Hostnames extracted from `rule`. */
  hosts: string[];
  entryPoints: string[];
  /** The fully resolved chain: router middlewares, chains expanded, entrypoint ones merged. */
  middlewares: TraefikLiveMiddleware[];
  /** Traefik service name this router targets, `name@provider`. */
  service?: string;
  /** Backends of that service, when it is a load balancer. */
  servers: TraefikLiveServer[];
  tls: boolean;
  /** How this router was tied to this service, in the spirit of `AuthPosture.evidence`. */
  evidence: string[];
}

/**
 * The auth mechanism in front of a service.
 *
 * A provider is only named when something observable in the configuration says
 * so — a forward-auth address, an issuer URL, or an LDAP host that matches a
 * provider identity discovered elsewhere in the same fleet. Where the mechanism
 * is visible but the provider is not identifiable, the generic variant is used
 * (`forward-auth`, `other-oauth`, `ldap`) rather than guessing a vendor.
 */
export type AuthMethod =
  | "authentik-forward-auth"
  | "authentik-oauth"
  | "authentik-ldap"
  /** Forward-auth middleware observed, provider not identifiable from its address. */
  | "forward-auth"
  /** OAuth/OIDC wired through the environment, issuer not identifiably Authentik. */
  | "other-oauth"
  /** LDAP bind against a directory that is not identifiably Authentik. */
  | "ldap"
  | "basic-auth"
  | "none";

/** How firmly a conclusion is grounded in the scanned configuration. */
export type AuthConfidence =
  /**
   * The identity provider's own API states it. Stronger than `observed`: a compose
   * label says what the operator intended to configure, whereas the provider's
   * records say what it will actually enforce.
   */
  | "confirmed"
  /** A value in the config states it: a forwardauth address, an issuer, an LDAP host. */
  | "observed"
  /** Inferred from a name only — the referenced definition was never found. */
  | "inferred";

/**
 * What an Authentik provider does, normalized from the API's `component` /
 * `meta_model_name` / `verbose_name` fields.
 *
 * `other` covers a provider type this version does not model rather than being
 * dropped, so an unmodelled gate is still reported as existing.
 */
export type AuthentikProviderKind =
  | "proxy"
  | "oauth2"
  | "ldap"
  | "saml"
  | "radius"
  | "scim"
  | "other";

/** One provider backing an Authentik application. */
export interface AuthentikProvider {
  name: string;
  kind: AuthentikProviderKind;
  /** Verbatim provider type as the API reported it, for anything not modelled above. */
  rawKind: string;
  /** Proxy providers: `proxy`, `forward_single` or `forward_domain`. */
  mode?: string;
  /** Proxy providers: the address the outpost forwards authenticated traffic to. */
  internalHost?: string;
  /** Proxy providers: the public address the provider answers on. */
  externalHost?: string;
  /** OAuth2 providers: configured redirect URIs, a second source of the app's hostname. */
  redirectUris?: string[];
  /**
   * Whether the provider is attached as a backchannel provider. LDAP and SCIM are
   * always backchannel, so reading only the primary provider would miss them.
   */
  backchannel: boolean;
  /**
   * Names of the outposts serving this provider. Empty is meaningful: a proxy or
   * LDAP provider that no outpost serves is configured but not deployed, so it
   * enforces nothing.
   */
  outposts: string[];
}

/** One application as Authentik records it. */
export interface AuthentikApplication {
  name: string;
  slug: string;
  group?: string;
  /** Resolved launch URL, when the API supplied a concrete one (not a template). */
  launchUrl?: string;
  providers: AuthentikProvider[];
  /**
   * Which read produced this application.
   *
   * `list` is the applications endpoint. `provider` means the endpoint withheld it —
   * it filters its answer by what the token's user may launch — and it was rebuilt
   * from a provider that names it. A rebuilt record is narrower: no launch URL, no
   * group, and only the providers this token may read. Reported rather than smoothed
   * over, because a match made on less evidence should look like one.
   */
  discoveredVia: "list" | "provider";
}

/**
 * How firmly an Authentik application was tied to a service.
 *
 * The distinction is load-bearing rather than cosmetic. An **address** is the
 * provider pointing at the service — a proxy provider's internal host, or the host
 * inside a URL the provider sends a browser or a token to. A **hostname** is one
 * name both sides declare independently. A **name** is only that the operator chose
 * similar words on each side, which is a good guess and nothing more. The reported
 * confidence follows this, because a posture resting on a name should not read the
 * same as one resting on a resolved address.
 */
export type AuthentikMatchStrength = "address" | "hostname" | "name";

/**
 * The Authentik applications tied to one service, and how the tie was established.
 *
 * A match is only recorded when something identifies the same thing from both sides:
 * an address resolving to this service, a hostname this service is configured to
 * serve, or a name equal to its stack/service/container name. A candidate that could
 * refer to more than one service is discarded rather than arbitrated, the same
 * discipline `origins.ts` applies to a tunnel origin.
 *
 * The three arrays are parallel — index `i` of each describes the same match.
 */
export interface AuthentikMatch {
  applications: AuthentikApplication[];
  /** Why each application was tied to this service. */
  evidence: string[];
  /** What kind of thing established each tie. */
  strength: AuthentikMatchStrength[];
}

/**
 * Which stage of an outbound connection failed.
 *
 * One vocabulary for every system LabView reads — the Docker endpoint, Authentik's
 * API, the proxy's API, and whatever is added next. The point of naming the stage
 * rather than passing an error message through is that each stage has a different
 * fix, and "unreachable" hides all of them behind one word: a name that does not
 * resolve is a wrong hostname or a network LabView is not on, a refused connection is
 * nothing listening, a 401 is a missing credential, a 403 is a credential that is not
 * allowed here, and a 200 carrying HTML is an SSO login page answering instead of the
 * API. `authenticate` and `authorize` are deliberately separate for that reason: on a
 * socket proxy with the endpoint switched off, the second is the likeliest cause of
 * all and the first would send the operator looking at credentials.
 */
export type ConnectionPhase =
  /** Switched off in configuration. Not a fault. */
  | "disabled"
  /** Nothing was asked for: no credential and no endpoint. Not a fault either. */
  | "not-configured"
  /**
   * Asked for, but there was nowhere to send the request — nothing was configured and
   * discovery identified no candidate. Distinct from `not-configured`: a half-finished
   * configuration will never work and is worth saying so.
   */
  | "not-found"
  /**
   * A credential was asked for and arrived empty — its variable is set in the environment
   * and carries nothing, which is a half-finished configuration rather than an absent one.
   */
  | "credential"
  /** The name does not exist (`ENOTFOUND`, `EAI_AGAIN`). */
  | "resolve"
  /** Nothing is listening, or the socket is not there (`ECONNREFUSED`, `ENOENT`, …). */
  | "connect"
  /** The certificate was not trusted. */
  | "tls"
  /** Accepted the connection and never answered. */
  | "timeout"
  /** HTTP 401 — a credential is missing or wrong. */
  | "authenticate"
  /** HTTP 403 — the identity was accepted and the access denied. */
  | "authorize"
  /** HTTP 404/405 — nothing of this kind is served at this address. */
  | "path"
  /** Any other error status; the status itself is in the detail. */
  | "status"
  /** Answered, but not with this API's payload — HTML, or JSON of the wrong shape. */
  | "protocol"
  /** Connected, and part of what was wanted could not be read. */
  | "partial"
  /** Worked. */
  | "connected";

/** One candidate endpoint that was tried, and what came back. */
export interface ConnectionAttempt {
  /** Origin only, credential-free. */
  endpoint: string;
  /** Why this candidate was tried, in discovery's own words. */
  why: string;
  phase: ConnectionPhase;
  /**
   * The libuv/TLS code or HTTP status behind the phase, when there was one. A
   * constant like `ENOTFOUND` or `403` — never an address and never a credential.
   */
  code?: string;
  detail: string;
}

/**
 * What happened when LabView tried to reach one other system.
 *
 * Built by the enrichment client that made the attempt, carried out through
 * `ScanMeta` rather than logged in place: `buildOverview` takes no logger and must
 * stay deterministic (**I7**), so the server and the CLI are what turn these into
 * lines. `src/model/connections.ts` holds the formatting.
 */
export interface ConnectionReport {
  /** The system, as logged and displayed: `docker`, `authentik`, `traefik`. */
  target: string;
  ok: boolean;
  phase: ConnectionPhase;
  /** Address reached or attempted, credential-free. */
  endpoint?: string;
  /** How that address was arrived at. */
  source?: "config" | "discovered" | "default";
  /** What happened, in one line, with no credential in the text. */
  detail?: string;
  /**
   * The transport code or HTTP status behind the phase, when there was one — a
   * constant like `ENOTFOUND` or `403`, never an address. Kept next to the phase it
   * produced so a reader can tell an inferred phase from a reported one.
   */
  code?: string;
  /** What to change. Absent when there is nothing useful to say. */
  hint?: string;
  /** What was read, when it worked: `86 containers`, `10 routers, 5 middlewares`. */
  read?: string;
  /** Every candidate tried and rejected, in the order tried. */
  attempts: ConnectionAttempt[];
}

/**
 * Why an application or router could not be tied to exactly one service.
 *
 * The distinction is the point. `ambiguous` means the evidence pointed at more than
 * one service and was discarded rather than arbitrated — the operator can fix that by
 * making one name distinct. `no-candidate` means nothing pointed anywhere, which is
 * usually LabView's to explain. Reporting both as "unmatched" hides the actionable one.
 * `internal` is defensive: a matcher named a service key the scan does not hold.
 */
export type UnmatchedReason = "ambiguous" | "no-candidate" | "internal";

/** One Authentik application no scanned service could be matched to, and why. */
export interface UnmatchedApplication {
  /** The application itself, so the UI can show what was on offer. */
  application: AuthentikApplication;
  reason: UnmatchedReason;
  /** One line naming what stopped the match. */
  detail: string;
  /**
   * One line per matching rule tried and what it produced, in the order tried — the
   * same evidence discipline as `AuthPosture.evidence`, for the case that failed.
   * Carries only what the payload already holds: slugs, provider and service names,
   * hostnames. Never an env value.
   */
  considered: string[];
}

/** Outcome of the Authentik API exchange, for the scan metadata. */
export interface AuthentikSummary {
  /** Whether the integration is switched on at all. */
  enabled: boolean;
  /** Whether an endpoint and a token were both available to try. */
  configured: boolean;
  /** Whether an endpoint answered as Authentik and accepted the token. */
  reachable: boolean;
  /** Endpoint used, origin only — never a path, query or credential. */
  endpoint?: string;
  /** Whether the endpoint was configured or discovered from the fleet. */
  endpointSource?: "config" | "discovered";
  /** Why the exchange did not complete, with no credential in the text. */
  error?: string;
  /** Applications LabView knows about: those listed, plus those rebuilt from providers. */
  applications: number;
  /**
   * Applications Authentik says exist, from the list endpoint's own `pagination.count`.
   *
   * It counts records before the policy filter, because that endpoint paginates first
   * and filters the page afterwards. Absent only if the API reported no count.
   */
  applicationsConfigured?: number;
  /** Configured minus listed: applications the endpoint did not return to this token. */
  applicationsWithheld: number;
  /** Of the withheld ones, how many a readable provider let LabView rebuild. */
  applicationsRecovered: number;
  providers: number;
  outposts: number;
  /** Services that matched at least one application. */
  matchedServices: number;
  /** Applications no scanned service could be matched to, each with its reason. */
  unmatchedApplications: UnmatchedApplication[];
}

/** One live router no scanned service could be identified for, and why. */
export interface UnmatchedRouter {
  /** The router itself: rule, hosts, entrypoints, chain, backends, status. */
  router: TraefikLiveRouter;
  reason: UnmatchedReason;
  /** One line naming what stopped the match. */
  detail: string;
  /** One line per matching rule tried, as on {@link UnmatchedApplication}. */
  considered: string[];
}

/** Outcome of the Traefik API exchange, for the scan metadata. */
export interface TraefikSummary {
  /** Whether the integration is switched on at all. */
  enabled: boolean;
  /** Whether there was at least one endpoint to try. */
  configured: boolean;
  /** Whether an endpoint answered as a Traefik API and its runtime config was read. */
  reachable: boolean;
  /** Endpoint used, origin only — never a path, query or credential. */
  endpoint?: string;
  /** Whether the endpoint was configured or discovered from the fleet. */
  endpointSource?: "config" | "discovered";
  /**
   * Which credential the successful read needed. `none` means the API answered
   * unauthenticated, which is the direct evidence that `api.insecure` is on.
   */
  credential: "none" | "basic";
  /** Traefik's reported version, when it supplied one. */
  version?: string;
  /**
   * Whether `/api/entrypoints` was read. An entrypoint can carry auth middlewares
   * that no router lists, so without this a missing gate cannot be distinguished
   * from a gate attached one level up — which is why the downgrade requires it.
   */
  entrypointsRead: boolean;
  /** Why the exchange did not complete, with no credential in the text. */
  error?: string;
  routers: number;
  middlewares: number;
  services: number;
  /** Services that matched at least one live router. */
  matchedServices: number;
  /** Live routers no scanned service could be identified for, each with its reason. */
  unmatchedRouters: UnmatchedRouter[];
}

/**
 * Derived authentication posture for a service.
 *
 * Two kinds of thing are recorded here and they must not be conflated. `method`,
 * `detail`, `evidence` and `confidence` describe *a mechanism LabView identified* —
 * something it can name, from a middleware, an env key or an API read.
 * `exposedWithoutAuth` is the verdict that follows, and it takes in evidence that names
 * no mechanism at all: a SAML application behind an Authentik gate, a Cloudflare Access
 * policy, an operator's declaration, a login page the probe was answered with.
 *
 * So a new source of protection extends the *verdict* and never the *method*. An
 * {@link ServiceProbe} answering with a login page is real evidence — LabView made the
 * request — but a password field cannot tell local accounts from OIDC from SAML, so
 * turning it into an `AuthMethod` or a fourth `AuthConfidence` would put a name on
 * something unnamed (invariant I3). It clears `exposedWithoutAuth`, is reported through
 * its own `NoAuthReason`, and is counted in its own statistic.
 */
export interface AuthPosture {
  method: AuthMethod;
  /** Human-readable, e.g. "Authentik forward-auth via `authentik@docker`". */
  detail: string;
  /** The middleware / env keys / hints that led to this conclusion. */
  evidence: string[];
  /**
   * Whether `method` rests on a value read from the config or only on a name.
   * Surfaced so a reader can tell a fact from a guess without re-deriving it.
   */
  confidence: AuthConfidence;
  /** True when the service is publicly reachable but has no detected auth. */
  exposedWithoutAuth: boolean;
}

/* -------------------------------------------------------------------------- */
/* The active probe (`src/model/probe.ts`, `src/enrich/probe.ts`)             */
/* -------------------------------------------------------------------------- */

/**
 * Which of a service's own addresses answered the probe.
 *
 * The three names are {@link IngressKind}'s three external kinds, and the order they
 * are declared in is the order they are tried: the public hostname first, because that
 * is the vantage point an outsider actually has, and the LAN address last, because
 * reaching a published port says nothing about what the edge in front of it would do.
 *
 * `probeTargets` in `model/probe.ts` builds the candidates; `PROBE_VANTAGES` there is
 * this union as an array.
 */
export type ProbeVantage = "public" | "traefik" | "lan";

/**
 * Why a probe response was read as a login page — the strongest signal that fired.
 *
 * Six of the seven are a single observable fact about one response, which is the bar this
 * union was built to: a gate can only ever take a service *out* of the exposed count, so
 * a member that is merely likely buys false comfort at the price of the finding.
 *
 * `credential-form` is the deliberate exception, and it is worth saying why rather than
 * leaving the asymmetry to be discovered. Passwordless sign-in — a magic link, a passkey,
 * an emailed code — serves a login page with no password field on it, so the one-fact
 * rule cannot see it at all, and the class is growing. It therefore reads three facts
 * about *one form* held together, and every one of them is required. What keeps that from
 * becoming word-matching is the intent marker: without it a newsletter signup would
 * qualify, which is exactly the mistake `fixtures/probe/signup-form` exists to catch.
 *
 * `readGate` in `model/probe.ts` is the whole rule, and everything it does not recognise
 * leaves the exposure finding standing.
 */
export type ProbeGate =
  /** 401 or 407 *with* a `WWW-Authenticate` header: a credential was asked for. */
  | "challenge"
  /** A redirect to a different origin — the shape of every external SSO hand-off. */
  | "redirect-origin"
  /** A redirect to a login path on the same origin, i.e. the app's own sign-in page. */
  | "redirect-login"
  /**
   * A 200 whose HTML sends the browser to a login path or off the origin by
   * `<meta http-equiv="refresh">` — a redirect by another means.
   */
  | "meta-refresh-login"
  /**
   * A 200 carrying a `SAMLRequest`/`SAMLResponse` hidden input: the SAML POST binding,
   * which is a hand-off to an identity provider and nothing else.
   */
  | "sso-form"
  /** A 200 whose HTML carries a password field. The application's own login form. */
  | "password-form"
  /**
   * A 200 with a passwordless login form: a username field, a submit control and a
   * login intent marker on one form, with no password input. See the note above.
   */
  | "credential-form";

/**
 * What one HTML `<form>` on a probed page is made of.
 *
 * The composition is reported separately from the verdict because the two answer
 * different questions. `ProbeGate` says whether the exposure finding stands;
 * this says what LabView actually saw on the page, which is what a reader needs in
 * order to disagree with it — a form with a username field and a submit button and no
 * password field is a fact worth showing whether or not it cleared anything.
 *
 * Read per form rather than per page (`readLoginForm` in `model/probe.ts`). A footer
 * search box and a nav "Sign in" link are each real, and a page-wide scan would hold
 * them up together as a login form that does not exist.
 */
export interface LoginFormShape {
  /** An `<input type="password">`, or an `autocomplete="current-password"` field. */
  password: boolean;
  /** An email input, or a text input named like a username. */
  username: boolean;
  /** A submit control: `<input type="submit">`, or a `<button>` in the form. */
  submit: boolean;
  /** An `autocomplete="one-time-code"` field — a page asking for a second factor. */
  otp: boolean;
  /** The form's `action`, when it pointed at a login path. Absent when it did not. */
  action?: string;
}

/**
 * What one service's active probe observed.
 *
 * Evidence, in the sense invariant I1 means it — LabView sent the request and read the
 * answer — and *not* a mechanism: see {@link AuthPosture} for why nothing here may
 * become an `AuthMethod`. Beside `authentik` and `traefikLive` on {@link Service}
 * rather than inside `auth`, the same placement `declared` has and for a related
 * reason: this is a source, and `auth` is the conclusion drawn from every source.
 *
 * Present only when the service was eligible and the stage was enabled. A service that
 * was probed and could not be reached still gets a record — `phase` says which stage
 * failed and `gate` is absent, so "nothing answered" stays distinguishable from
 * "answered, and served the page".
 */
export interface ServiceProbe {
  /** The address that produced `phase`, origin only and credential-free. */
  endpoint: string;
  /** Which of the service's addresses that was. */
  vantage: ProbeVantage;
  /**
   * How far the request got, on the same scale every other connection uses — but read
   * differently, because a probe wants a different thing than an API client does.
   *
   * `connected` means *an HTTP response arrived*, whatever its status. A 401 is a failure
   * for the Authentik client and the best possible outcome here, so mapping status codes
   * to `authenticate` / `authorize` / `path` the way `phaseForStatus` does would leave
   * "did this service answer at all" with no single test. Every other value is a
   * transport failure — `resolve`, `connect`, `tls`, `timeout` — and means nothing
   * answered, at which point `gate` is necessarily absent and the service counts in
   * neither `OverviewStats.probeGated` nor `.probeOpen`. The status is in `status`.
   */
  phase: ConnectionPhase;
  /** The HTTP status, when one came back. */
  status?: number;
  /** Which signal fired. Absent means no gate was observed, not that none exists. */
  gate?: ProbeGate;
  /**
   * What the most login-like form on the answering page was made of, when HTML came back
   * carrying one.
   *
   * Independent of `gate`: a page can show a form that cleared nothing (a signup form),
   * and a page can be gated with no form at all (a challenge header, a redirect). Present
   * means a form was read, and the reader can see which parts of one were there.
   */
  form?: LoginFormShape;
  /** What happened, in one line, with no credential in the text. */
  detail: string;
  /** Every address tried, in vantage order, whether it answered or not. */
  attempts: ConnectionAttempt[];
}

/* -------------------------------------------------------------------------- */
/* Operator declarations (the `.labview` sidecar)                             */
/* -------------------------------------------------------------------------- */

/**
 * Authentication a *service* performs for itself, which no scan can observe: a
 * built-in user database, a directory bind the application makes on its own, a
 * client-certificate requirement, a network restriction enforced somewhere LabView
 * cannot see.
 *
 * **A declaration is a second source, not stronger evidence.** It lives here, in
 * its own field, precisely so it can never be mistaken for something the scan
 * proved: `AuthPosture.method`, `.detail`, `.evidence` and `.confidence` are derived
 * only from observable config and API state (invariant I1) and are left untouched by
 * everything in this section, as are `OverviewStats.authProtected` and
 * `.byAuthMethod`. A future change must not "simplify" this by folding a declared
 * mechanism into `AuthPosture.method` or by adding a `declared` value to
 * `AuthConfidence` — confidence measures how strong the *evidence* is, and there is
 * no evidence here.
 *
 * The one field a declaration does reach is `AuthPosture.exposedWithoutAuth`, which
 * is not a measurement but a *verdict* — "does a reader need to act on this" — and
 * the operator's statement is an answer to that question. It is reported as its own
 * outcome (`DeclaredAuthAgreement.supplies`) and counted in its own statistic, so the
 * services resting on an unverifiable claim stay separable from the ones the scan
 * proved.
 *
 * Named by mechanism and never by product (invariant I3): the same fleet may run
 * any application, and `app-local-accounts` is true of a hundred of them.
 */
export type DeclaredAuthMechanism =
  /** The application has its own user database. */
  | "app-local-accounts"
  /** The application binds a directory itself. */
  | "app-ldap"
  /** The application performs its own OIDC/OAuth login. */
  | "app-oidc"
  /** The application performs its own SAML login. */
  | "app-saml"
  /** An API token or key is required. */
  | "app-token"
  /** Client certificates are required. */
  | "mtls"
  /** Reachable only from restricted networks (VPN, VLAN, firewall). */
  | "network-restricted"
  /** An authenticating proxy outside the scanned fleet. */
  | "external-proxy"
  /** Anything else; `detail` then carries the explanation. */
  | "other";

/** One declared authentication mechanism. */
export interface DeclaredAuth {
  mechanism: DeclaredAuthMechanism;
  /** The operator's own words. Required for `other`, optional otherwise. */
  detail?: string;
}

/**
 * A mechanism both vocabularies can name — the only ground on which a declaration and
 * a detection can be compared at all.
 *
 * `DeclaredAuthMechanism` has nine members and `AuthMethod` eight, but they meet in
 * three places; everything else one side can say, the other cannot. Deliberately not a
 * superset of either: a family exists so two statements can be checked against each
 * other, and where that check is impossible there must be no family to imply otherwise.
 */
export type AuthFamily = "oidc" | "ldap" | "proxy";

/** How a declared mechanism stands relative to what the scan detected. */
export type DeclaredAuthAgreement =
  /**
   * The scan found nothing and the service answers from outside: the declaration is
   * the only reason it is not flagged. Reported in its own right, because the verdict
   * now rests on a statement no scan can check.
   */
  | "supplies"
  /** The scan detected the same family. Shown nowhere — it would repeat the scan. */
  | "redundant"
  /**
   * Both sides name a mechanism at the same tier of the request path and they name
   * different ones. One of the two is out of date; which one, only the operator knows.
   */
  | "conflicts"
  /**
   * Anything else: a mechanism the scan cannot observe, sitting alongside or behind
   * whatever it did observe. The ordinary case for a layered setup, and not a warning.
   */
  | "supplements";

/** A named URL from the sidecar (admin UI, upstream docs, a ticket). */
export interface DeclaredLink {
  label: string;
  url: string;
}

/** Something the service depends on that LabView cannot see at all. */
export interface DeclaredDependency {
  name: string;
  detail?: string;
}

/**
 * A dependency on another **scanned** service, as the sidecar wrote it.
 *
 * The counterpart to {@link DeclaredDependency}, and deliberately a different type: that
 * one is prose about something off the fleet, this one is a reference that has to resolve
 * to a service in the scan, and is reported when it does not.
 *
 * It exists because compose cannot express this relation at all. `depends_on` names a
 * service in the same project, so a database and the service that backs it up — two
 * stacks, one shared network — have no way to say they are related. The operator is the
 * only one who knows, and says it once, on the dependent: the target's own view of the
 * relation is derived, so a backup service needs no sidecar of its own however many
 * databases point at it.
 *
 * Stored exactly as written and never resolved in place. The parser cannot see the other
 * stacks, and the analyzer must not write the resolved target back here — that would make
 * a rename in an unrelated stack read as an edited sidecar on the next rescan (§3.11). A
 * reference that stops resolving becomes a `drift` entry instead.
 */
export interface DeclaredServiceDependency {
  /** The reference as written: `stack/service`, or a bare service name. */
  ref: string;
  detail?: string;
}

/**
 * Fields a `.labview` file may declare at either level. Everything is optional:
 * an absent or empty sidecar changes nothing about a scan.
 */
export interface Declaration {
  /** Filename the declarations were read from, e.g. `.labview`. Never a full path. */
  file: string;
  description?: string;
  owner?: string;
  criticality?: string;
  notes?: string;
  /** Prose about what persists where, and what is backed up. */
  data?: string;
  links: DeclaredLink[];
  dependencies: DeclaredDependency[];
}

/** A declaration attached to one service, with the service-only fields. */
export interface ServiceDeclaration extends Declaration {
  auth: DeclaredAuth[];
  /**
   * Dependencies on other scanned services, as written. Service level only: a
   * stack-level entry could not say *which* of the stack's services depends on the
   * target, so the key is refused there with a warning that says so.
   */
  dependsOn: DeclaredServiceDependency[];
  /**
   * Present only when the sidecar said `intentional: true` **and** gave a reason.
   * An acceptance with no reason is indistinguishable from a typo, so it is refused
   * with a warning rather than honoured.
   *
   * This never clears `AuthPosture.exposedWithoutAuth`: the service is still
   * reachable without authentication, which stays a fact. It records that the fact
   * was reviewed — which is why the dashboard reads `23/28` rather than `23`: the
   * finding is still counted, and separately shown to have been accepted.
   *
   * Note the difference from a declared *mechanism*, which does clear the flag: this
   * says "nothing authenticates it and that is fine", so there is a finding to accept.
   * That says "something authenticates it that you cannot see", so there is not.
   */
  unauthenticatedAccepted?: { reason: string };
  /**
   * Declared expectation, compared against `Service.ingress` as a set — never an
   * override. A list because the thing it is compared against is one: expecting
   * `[public, traefik]` and finding `[public, lan]` is a disagreement about the
   * proxy, and reporting it as "expected public, got public" would hide that.
   */
  expectedIngress?: IngressKind[];
  /**
   * Where this declaration and the scan disagree, in the operator's terms. Filled
   * by the analyzer, one entry per disagreement.
   */
  drift: string[];
  /**
   * How `auth` above stands relative to the detected posture. Filled by the analyzer;
   * absent when nothing was declared, so `auth.length` and this are set together.
   *
   * Derived rather than parsed, which is why {@link Service} comparisons must ignore
   * it: a change here means the *scan* moved, not that anyone edited the sidecar.
   */
  authAgreement?: DeclaredAuthAgreement;
}

/** Live data merged from the Docker Engine (present only when the socket works). */
export interface DockerState {
  id: string;
  name: string;
  image: string;
  imageDigest?: string;
  state: string; // running, exited, ...
  status: string; // "Up 3 days (healthy)"
  health?: "healthy" | "unhealthy" | "starting" | "none";
  running: boolean;
  restartCount?: number;
  createdAt?: string;
  startedAt?: string;
  networks: string[];
  ipAddresses: Record<string, string>;
  publishedPorts: PortMapping[];
}

/** A single compose service, fully analyzed. */
export interface Service {
  /** Service key in the compose file. */
  name: string;
  /** Resolved container_name or `${project}-${name}`. */
  containerName: string;
  image?: string;
  restart?: string;
  command?: string;
  dependsOn: string[];
  networks: string[];
  ports: PortMapping[];
  /**
   * `expose:` entries verbatim (`"9000"`, `"9000/udp"`, a range). Container ports
   * declared for other containers and *not* published to the host — which is what
   * distinguishes them from `ports:`, and what makes them evidence of `internal`
   * ingress rather than of exposure.
   */
  expose: string[];
  mounts: MountSpec[];
  env: EnvVar[];
  labels: Record<string, string>;
  cloudflare: CloudflareRoute[];
  traefik: TraefikRoute[];
  /**
   * Every way this service was found to be reachable, from the tunnel routes, the
   * proxy routes, `ports:`, `expose:` and shared networks. Never empty — see
   * {@link IngressKind}.
   */
  ingress: IngressKind[];
  auth: AuthPosture;
  docker?: DockerState;
  /** Authentik applications this service was matched to, when the API was readable. */
  authentik?: AuthentikMatch;
  /** Live routers this service was matched to, when the Traefik API was readable. */
  traefikLive?: TraefikLiveRouter[];
  /**
   * What the operator declared about this service in the stack's `.labview` file.
   * Deliberately beside `auth` rather than inside it — see `DeclaredAuthMechanism`.
   */
  declared?: ServiceDeclaration;
  /**
   * What answered when LabView asked this service's own address, when the probe stage
   * was enabled and the service was eligible for it. See {@link ServiceProbe}.
   */
  probe?: ServiceProbe;
  /** Notes/warnings surfaced during analysis. */
  notes: string[];
}

/** One stack = one directory under appsRoot with a compose file. */
export interface AppStack {
  /** Directory name; also the default compose project name. */
  id: string;
  name: string;
  dir: string;
  composeFile: string;
  hasEnvFile: boolean;
  projectName: string;
  services: Service[];
  /** Networks declared at the top level of the compose file. */
  declaredNetworks: NetworkDecl[];
  /** Volumes declared at the top level of the compose file. */
  declaredVolumes: VolumeDecl[];
  /**
   * What the operator declared about the stack as a whole in its `.labview` file.
   * Absent when there is no sidecar, or when it declared nothing at this level.
   */
  declared?: Declaration;
  /** Parse-level warnings for this stack. */
  warnings: string[];
}

export interface NetworkDecl {
  name: string;
  external: boolean;
  driver?: string;
}

/**
 * Who owns a real docker network, which is what decides whether it can join two
 * stacks at all.
 *
 *  - `stack-local` — the name is `${projectName}_${key}` of exactly one scanned
 *    stack, so compose created it for that stack and nothing outside it is on it.
 *    This is the network a multi-service stack talks to itself over.
 *  - `external` — everything else: a network declared `external:` (used verbatim, so
 *    several stacks can name the same one), or a live name no scanned project owns.
 *
 * The second case is why this is about *ownership* rather than about the `external:`
 * keyword. A network attached in live docker state that no scanned compose file
 * declares is, from the fleet's point of view, exactly as external as a declared
 * one: something this scan cannot see may be on it. Reporting it as stack-local
 * would claim the opposite.
 */
export type NetworkScope = "external" | "stack-local";

export interface VolumeDecl {
  name: string;
  external: boolean;
  driver?: string;
}

/** Nodes/edges for the interactive relationship graph. */
export interface GraphNode {
  id: string;
  label: string;
  kind: "service" | "network" | "volume" | "external";
  /** For services: the stack it belongs to. */
  stack?: string;
  /**
   * Auth/ingress used for coloring. Ingress is a single kind, not the service's whole
   * set: a node has one fill, so it carries `primaryIngress` — the most exposed kind
   * present. The full set is listed on the badges in the drawer.
   */
  auth?: AuthMethod;
  ingress?: IngressKind;
  running?: boolean;
  /**
   * Set on a service that another service's tunnel origin resolved to, i.e. one
   * observed to act as a reverse proxy. It stays an ordinary service node — this
   * only lets the UI style it as infrastructure.
   */
  role?: "proxy";
  /**
   * Network nodes only: who owns the network, and how much it joins. Set on every
   * network node, so a reader can tell a network that connects six stacks from one
   * that connects nothing without counting spokes.
   *
   * `memberCount` counts *scanned* services attached — never the containers on the
   * network that this scan cannot see. See {@link NetworkScope} for why an
   * unowned network reads as external.
   */
  scope?: NetworkScope;
  memberCount?: number;
  stackCount?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: "network" | "depends_on" | "volume" | "ingress" | "auth";
  label?: string;
  /**
   * On a `network` membership edge (`source` = service, `target` = network): where the
   * dependency arrowhead sits, so that following arrowheads reads dependent → network
   * → dependency and the network is drawn *in between* the two services.
   *
   *  - `to-network` — this service depends on something else on this network.
   *  - `to-service` — something else on this network depends on this service.
   *  - `both` — both are true.
   *
   * Absent on plain membership, which carries no arrowhead. One field on the
   * membership edge rather than a second edge beside it: a dependency and the
   * network it travels over are one relation, and drawing them as two was the thing
   * that made the graph unreadable.
   *
   * **Membership alone never sets this.** Two services on one network can reach each
   * other, which is not a dependency, so an arrowhead requires a dependency from one of
   * the two sources below.
   */
  flow?: "to-network" | "to-service" | "both";
  /**
   * On a `network` edge carrying {@link flow}: where the dependencies crossing it came
   * from — a compose file (`observed`), a `.labview` sidecar (`declared`), or both.
   *
   * Here so a view cannot present a declaration as a measurement (invariant I1). The
   * arrowhead is the same either way, because the operator's statement is the only thing
   * that could ever have said this; the *line* is what says which of the two it was.
   */
  flowSource?: "observed" | "declared" | "both";
  /**
   * On a `depends_on` edge: the sidecar that stated it, when the relation was declared
   * rather than read from a compose file. Absent on an observed dependency, so its
   * presence is the whole "declared" flag.
   *
   * Declared on the dependent only. The reverse direction — every service that declared a
   * dependency on *this* one — is read back off these same edges, which is what lets a
   * service everything points at carry no sidecar of its own.
   */
  declaredBy?: { file: string; detail?: string };
  /**
   * On a `depends_on` edge: every real network the two services share, in the
   * dependent's compose order — the dependency can travel over any of them, so all
   * of them carry its arrowheads rather than one being picked as the favourite.
   *
   * **Empty means they share none** — `depends_on` orders startup but grants no
   * connectivity, so such a pair is a real finding rather than a drawing detail, and
   * it is the one case a direct service→service edge is still rendered. See
   * `showsDirectDependency` in `model/networks.ts`.
   */
  via?: string[];
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * One way a service can be reached. A service carries a **set** of these, because
 * they are independent facts and several are routinely true at once:
 *
 *  - `public` — a tunnel publishes it to the internet.
 *  - `traefik` — the reverse proxy routes to it.
 *  - `lan` — a `ports:` entry publishes it at `hostIP:port`, answerable with no proxy
 *    and therefore no proxy-level SSO in the path.
 *  - `internal` — another container demonstrably can reach it (it declares `expose:`, or
 *    it shares a docker network with another scanned service) **and nothing else can**.
 *  - `none` — none of the above. A worker, a cron job, a one-shot init container.
 *
 * **Nothing here is combined and nothing is a fallback.** A proxied service that also
 * publishes a port is `traefik` *and* `lan`, and both are reported; `internal` is
 * positive evidence of container-network reachability rather than "whatever was left
 * over", which is what makes `none` a real, populated category worth filtering on.
 *
 * The three external kinds are independent of each other, and `internal` is the one
 * kind that yields: almost every service in a fleet shares a network with a neighbour,
 * so beside `public`, `traefik` or `lan` it is a tag true of nearly everything, and
 * `normalizeIngress` withholds it there. What is left is the useful set — the services
 * a neighbour and *only* a neighbour can reach.
 *
 * Build a set only through `normalizeIngress` (`model/ingress.ts`): deduped, in
 * canonical order, never empty, `internal` only when alone.
 */
export type IngressKind = "public" | "traefik" | "lan" | "internal" | "none";

/** Aggregate counters for the dashboard header. */
export interface OverviewStats {
  stacks: number;
  services: number;
  running: number;
  /**
   * The five ingress counters **overlap and do not sum to `services`**: one service
   * behind the tunnel, behind the proxy and on a published port is counted in three
   * of them, because all three are true of it. Anything presenting them as a
   * part-to-whole split would be presenting a number that is not there — the
   * dashboard draws them as five independent gauges for exactly this reason.
   *
   * The first three are what overlap. `internalServices` and `noIngressServices` are
   * each exclusive of every other counter, since a service only carries `internal` when
   * that is the only way in.
   */
  publicServices: number;
  traefikServices: number;
  lanServices: number;
  /** Services a neighbouring container can reach, and nothing outside the container network can. */
  internalServices: number;
  /** Services nothing was found to reach, inside the container network or out. */
  noIngressServices: number;
  authProtected: number;
  exposedWithoutAuth: number;
  byAuthMethod: Record<string, number>;
  /**
   * The four declaration counters. All of them count what the *operator* stated in a
   * `.labview` file. `authProtected` and `byAuthMethod` above stay derived from
   * evidence alone and none of these feeds them, so the "protected" figure keeps
   * meaning *proven* protected; a fleet with no sidecar anywhere reads exactly as it
   * did before the feature existed.
   */
  /** Services with at least one declared authentication mechanism. */
  declaredAuth: number;
  /**
   * Services that would be counted in `exposedWithoutAuth` but for a declared
   * mechanism — the one place a declaration changes a verdict, kept visible as its own
   * number so what left the exposed count can be found again.
   */
  declaredAuthProtected: number;
  /** Services that are `exposedWithoutAuth` **and** carry an accepted declaration. */
  exposureAccepted: number;
  /** Services whose declaration disagrees with what the scan found. */
  declarationDrift: number;
  /**
   * Dependencies on another scanned service declared in a sidecar and resolved to it.
   *
   * A fifth declaration counter, and a relation rather than a verdict: it changes none of
   * the four above and none of the evidence-derived counters. A reference that resolved to
   * nothing, or to more than one service, is not counted here — it is counted in
   * `declarationDrift`, which is what a statement the scan cannot confirm is.
   */
  declaredDependencies: number;
  /**
   * The two probe counters. Both count services LabView *asked* and got an answer from,
   * which is what separates them from every counter above: those are read from
   * configuration, these from a response.
   *
   * They are disjoint and together they are the services that answered — a service that
   * was probed and could not be reached is in neither. Like the declaration counters,
   * neither feeds `authProtected` or `byAuthMethod`, because a login page names no
   * mechanism; and `probeGated` is what keeps invariant I1's reconstructibility, since
   * subtracting it from `exposedWithoutAuth` gives the figure a scan with probing off
   * would report.
   */
  /**
   * Services that would be counted in `exposedWithoutAuth` but for a login page
   * answering the probe. Evidence rather than a claim, which is why this and
   * `declaredAuthProtected` are two numbers and not one.
   */
  probeGated: number;
  /**
   * Services that answered the probe with no gate observed.
   *
   * The other half of the value, and the reason the stage is worth running even where it
   * clears nothing: an exposure that was inferred from labels is now one LabView
   * measured. Not a subset of `exposedWithoutAuth` — a service behind a detected gate
   * that answers LabView from inside the fleet is counted here too, and the note on it
   * says so without touching its posture.
   */
  probeOpen: number;
  /**
   * The four network counters, over **real** docker network names — so an
   * `external:` network two stacks share is one network here, not two.
   *
   * `connectingNetworks` and `crossStackNetworks` nest (every cross-stack network
   * carries 2+ services), and `soloLocalNetworks` is disjoint from both. Together
   * with the external networks that carry a single service they sum to `networks`.
   *
   * `soloLocalNetworks` is exactly the set the fleet graph does not draw — a
   * stack-local network with one service on it connects nothing and cannot, since
   * nothing outside its own stack can join it. It is counted rather than dropped so
   * the graph can say how many nodes it left out.
   */
  networks: number;
  /** Networks carrying two or more scanned services, i.e. joining them. */
  connectingNetworks: number;
  /** Networks whose members span two or more stacks. */
  crossStackNetworks: number;
  /** Stack-local networks with exactly one scanned service attached. */
  soloLocalNetworks: number;
}

/** Metadata about the scan itself. */
export interface ScanMeta {
  scannedAt: string;
  appsRoot: string;
  dockerAvailable: boolean;
  dockerError?: string;
  /** Outcome of the optional Authentik API exchange. */
  authentik?: AuthentikSummary;
  /** Outcome of the optional Traefik API exchange. */
  traefik?: TraefikSummary;
  /**
   * One entry per system LabView tried to reach, whether it worked or not.
   *
   * The summaries above answer "what did that integration yield"; this answers "did
   * the connection work, and if not, which stage failed and what should change".
   * Always present, so a reader never has to infer silence.
   */
  connections: ConnectionReport[];
  /**
   * Whether the active probe ran for *this* build, and what decided that.
   *
   * Always present, on the same reasoning `connections` is: a reader must never have to
   * infer it from silence. It matters more here than for the other stages because the
   * answer can differ between two consecutive scans of an unedited fleet — `POST
   * /api/rescan` may carry a one-off override, and the rebuild after it falls back to
   * configuration. Without this field, probe results appearing and disappearing on their
   * own would be indistinguishable from a fleet that changed.
   */
  probe: ProbeRun;
  durationMs: number;
  warnings: string[];
  version: string;
}

/** Whether the probe stage ran, and on whose say-so. */
export interface ProbeRun {
  enabled: boolean;
  /**
   * `config` — `probe.enabled` from the config file or environment, which is what a
   * timer rebuild and the scan at boot always use. `request` — a one-off value on the
   * rescan that produced this build, which outranks the configured one for that build
   * and no other.
   */
  source: "config" | "request";
}

/** The full payload served at /api/overview. */
export interface Overview {
  meta: ScanMeta;
  stats: OverviewStats;
  stacks: AppStack[];
  graph: Graph;
}

/**
 * What a caller may decide about one scan — the optional body of `POST /api/rescan`.
 *
 * The only writable thing in LabView's API, and deliberately the smallest one that could
 * be: everything else about a scan comes from configuration, which no request can reach.
 * An empty object, an absent body and a body of nonsense all mean the same thing — use
 * configuration — so a client that sends nothing keeps working and one that sends rubbish
 * cannot make a scan do something unnamed here.
 *
 * The answer is not the echo. What the build actually did is on {@link ScanMeta.probe},
 * because a request can be coalesced onto a build that was already running under someone
 * else's terms.
 */
export interface ScanRequest {
  /**
   * Force the active probe on or off for this one build, whatever `probe.enabled` says.
   *
   * Absent means configuration decides, which is also what every rebuild after this one
   * will do — a TTL expiry has no request behind it to remember.
   */
  probe?: boolean;
}

/* ------------------------------------------------------------------------- *
 * LabView's own access control.
 *
 * A second contract with the UI, independent of `Overview`: the login screen has
 * to render before there is anything to scan, and after a 401 there is no
 * `Overview` at all.
 *
 * Nothing here is related to {@link AuthMethod}'s `basic-auth`, which says a
 * *scanned service* asks for HTTP Basic. This block is about who may read
 * LabView itself, and shares no vocabulary with it on purpose.
 * ------------------------------------------------------------------------- */

/**
 * A way of signing in to LabView.
 *
 *  - `passwd` — a login form checked against the `user:hash` file in
 *    `auth.passwd.file`, verified with bcrypt.
 *  - `oidc` — a redirect to an OpenID Connect provider (Authentik, in the fleet
 *    this was built against).
 *
 * Both are optional and independent; an operator may run either, both, or
 * neither.
 */
export type LoginMethod = "passwd" | "oidc";

/**
 * Why a sign-in attempt did not produce a session.
 *
 * A closed set of codes rather than a message, for two reasons. It crosses a
 * redirect — the OIDC callback can only hand the UI a query parameter — and a
 * message built at the failure site is exactly how a credential or an internal
 * URL ends up on someone's screen (**I6**). The wording lives in
 * `loginFailureText` and nowhere else.
 *
 * `credentials` deliberately covers *both* an unknown user and a wrong password.
 * Distinguishing them tells an attacker which usernames exist.
 */
export type LoginFailureReason =
  | "credentials"
  | "throttled"
  | "method-unavailable"
  | "session-expired"
  | "oidc-state"
  | "oidc-provider"
  | "oidc-token"
  | "oidc-identity";

/**
 * Which sign-in methods are live, and therefore whether the API is gated at all.
 *
 * Resolved by `resolveAccessMode` from configuration plus the state of the passwd
 * file — never from scanned data, so what LabView reads about the fleet can never
 * change who may read LabView (**I5**).
 */
export interface AccessMode {
  /**
   * Whether `/api/*` requires a session.
   *
   * False when nothing is configured, which is the default and is deliberate:
   * LabView behaves exactly as it did before it had a login, so pulling a new
   * image can never lock an operator out of a running deployment. It becomes
   * true the moment a method is usable.
   */
  enforced: boolean;
  /** The usable methods, in the order the login screen offers them. */
  methods: LoginMethod[];
  /**
   * A method that is switched on but not usable — an empty passwd file, an
   * issuer with no client id. One line each, for the log and the login screen.
   *
   * Never a filesystem path and never a count: this reaches an unauthenticated
   * visitor through {@link SessionInfo}.
   */
  notes: string[];
}

/** The payload served at /api/session — the one API route a visitor may read. */
export interface SessionInfo {
  /** See {@link AccessMode.enforced}. When false, everything is readable. */
  enforced: boolean;
  methods: LoginMethod[];
  notes: string[];
  /** Present only while signed in. */
  user?: { name: string; via: LoginMethod };
  /** What to label the OIDC button, when `methods` includes `oidc`. */
  oidcLabel?: string;
}
