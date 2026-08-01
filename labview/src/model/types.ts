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
  /** A configured credential could not be read — a missing or empty token file. */
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

/** Derived authentication posture for a service. */
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
  mounts: MountSpec[];
  env: EnvVar[];
  labels: Record<string, string>;
  cloudflare: CloudflareRoute[];
  traefik: TraefikRoute[];
  /** How this service is reachable, derived from cloudflare + traefik + ports. */
  ingress: IngressKind;
  auth: AuthPosture;
  docker?: DockerState;
  /** Authentik applications this service was matched to, when the API was readable. */
  authentik?: AuthentikMatch;
  /** Live routers this service was matched to, when the Traefik API was readable. */
  traefikLive?: TraefikLiveRouter[];
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
  /** Parse-level warnings for this stack. */
  warnings: string[];
}

export interface NetworkDecl {
  name: string;
  external: boolean;
  driver?: string;
}

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
  /** Auth/ingress used for coloring. */
  auth?: AuthMethod;
  ingress?: IngressKind;
  running?: boolean;
  /**
   * Set on a service that another service's tunnel origin resolved to, i.e. one
   * observed to act as a reverse proxy. It stays an ordinary service node — this
   * only lets the UI style it as infrastructure.
   */
  role?: "proxy";
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: "network" | "depends_on" | "volume" | "ingress" | "auth";
  label?: string;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * How a service can be reached, in the four situations a fleet distinguishes:
 * `public` through a tunnel, `lan` at a published host port, `traefik` through the
 * reverse proxy, `internal` on the container network only.
 *
 * **The kind names what is in *front* of the service, so a published host port is
 * named only when nothing proxies it.** `lan` is a service answerable directly at
 * `hostIP:port` with no proxy and therefore no proxy-level SSO in the path. A
 * proxied service that *also* publishes a port keeps its `traefik` /
 * `public+traefik` kind and gets a note instead — most services in a fleet publish
 * a port, so folding that into the kind would collapse the whole distribution into
 * one bucket.
 */
export type IngressKind =
  | "public"
  | "public+lan"
  | "public+traefik"
  | "traefik"
  | "lan"
  | "internal";

/** Aggregate counters for the dashboard header. */
export interface OverviewStats {
  stacks: number;
  services: number;
  running: number;
  publicServices: number;
  /** Reached through the reverse proxy, with no tunnel route. */
  traefikServices: number;
  /** Reachable only at a published host port (no proxy in front). */
  lanServices: number;
  internalServices: number;
  authProtected: number;
  exposedWithoutAuth: number;
  byAuthMethod: Record<string, number>;
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
  durationMs: number;
  warnings: string[];
  version: string;
}

/** The full payload served at /api/overview. */
export interface Overview {
  meta: ScanMeta;
  stats: OverviewStats;
  stacks: AppStack[];
  graph: Graph;
}
