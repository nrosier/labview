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
  /** A value in the config states it: a forwardauth address, an issuer, an LDAP host. */
  | "observed"
  /** Inferred from a name only — the referenced definition was never found. */
  | "inferred";

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
