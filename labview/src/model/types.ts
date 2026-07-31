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

export type AuthMethod =
  | "authentik-forward-auth"
  | "authentik-oauth"
  | "authentik-ldap"
  | "basic-auth"
  | "other-oauth"
  | "none";

/** Derived authentication posture for a service. */
export interface AuthPosture {
  method: AuthMethod;
  /** Human-readable, e.g. "Authentik forward-auth via `authentik@docker`". */
  detail: string;
  /** The middleware / env keys / hints that led to this conclusion. */
  evidence: string[];
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

export type IngressKind = "public" | "local" | "public+local" | "internal";

/** Aggregate counters for the dashboard header. */
export interface OverviewStats {
  stacks: number;
  services: number;
  running: number;
  publicServices: number;
  localOnlyServices: number;
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
