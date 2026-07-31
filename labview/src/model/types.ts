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
}

/**
 * The Authentik applications tied to one service, and how the tie was established.
 *
 * A match is only recorded when something addresses the same thing from both sides:
 * a proxy provider's internal host resolving to this service, a URL whose hostname
 * this service serves, or an application slug equal to its stack/service/container
 * name. A candidate that could refer to more than one service is discarded rather
 * than arbitrated, the same discipline `origins.ts` applies to a tunnel origin.
 */
export interface AuthentikMatch {
  applications: AuthentikApplication[];
  /** Why each application was tied to this service. */
  evidence: string[];
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
  applications: number;
  providers: number;
  outposts: number;
  /** Services that matched at least one application. */
  matchedServices: number;
  /** Application slugs no scanned service could be matched to. */
  unmatchedApplications: string[];
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
 * How a service can be reached.
 *
 * `host-port` covers a service that publishes a port on the host but has no
 * Traefik router — it is reachable directly at `hostIP:port`, bypassing the
 * reverse proxy and therefore any proxy-level SSO. It is only reported when no
 * Traefik route exists: a proxied service that *also* publishes a port keeps its
 * `local` / `public+local` kind and gets a note instead, so the common case does
 * not collapse every service into one bucket.
 */
export type IngressKind =
  | "public"
  | "public+host-port"
  | "public+local"
  | "local"
  | "host-port"
  | "internal";

/** Aggregate counters for the dashboard header. */
export interface OverviewStats {
  stacks: number;
  services: number;
  running: number;
  publicServices: number;
  localOnlyServices: number;
  /** Reachable only via a published host port (no proxy in front). */
  hostPortServices: number;
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
