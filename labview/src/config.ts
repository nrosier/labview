import { readFileSync, existsSync } from "node:fs";
import { parse as parseYaml } from "yaml";

export interface LabViewConfig {
  appsRoot: string;
  composeFilenames: string[];
  /**
   * Sidecar filenames to look for in a stack directory, in priority order. The
   * first one that exists is read; the rest are ignored, so two sidecars in one
   * directory can never half-apply.
   */
  sidecarFilenames: string[];
  docker: {
    enabled: boolean;
    /** When set, connect over TCP (the docker-socket-proxy). Takes precedence
     *  over socketPath. Empty string means "use the socket". */
    host: string;
    port: number;
    /** Local unix socket, used only when host is empty. */
    socketPath: string;
    /** Max concurrent `container inspect` calls per scan. */
    maxConcurrency: number;
    /**
     * Per-request timeout for the Docker endpoint.
     *
     * Socket inactivity, not total duration — it is reset whenever bytes arrive, so a
     * large fleet's container listing is unaffected while an endpoint that accepts the
     * connection and then says nothing is reported instead of hanging the scan.
     */
    timeoutMs: number;
  };
  secrets: {
    maskValues: boolean;
    keyPatterns: string[];
    keysAlways: string[];
    keysNever: string[];
    /** Also strip inline `scheme://user:password@host` passwords from any value,
     *  regardless of the key name (catches DATABASE_URL, REDIS_URL, …). */
    redactUriCredentials: boolean;
  };
  labels: {
    dockflare: { prefix: string };
    traefik: { prefix: string };
    authentik: {
      hostHints: string[];
      ldapEnvHints: string[];
      oauthEnvHints: string[];
    };
  };
  /**
   * Optional read-only Authentik API access. When a token is available, the
   * identity provider's own records replace guesswork about which services it
   * protects: applications, their providers, and the outposts serving them.
   *
   * Inert without a token — there is nothing useful to read anonymously — so the
   * feature costs nothing when unconfigured.
   */
  authentik: {
    enabled: boolean;
    /** Base URL of the Authentik instance. Empty = discover it from the fleet. */
    url: string;
    /** API token. Prefer `tokenFile` so the value never sits in the environment. */
    token: string;
    /** Path to a file holding the token (docker secret, mounted file). Wins over `token`. */
    tokenFile: string;
    /** Per-request timeout. The whole exchange is a handful of GETs. */
    timeoutMs: number;
    /** Hard cap on paginated pages per endpoint, so a huge instance cannot stall a scan. */
    maxPages: number;
  };
  /**
   * Optional read-only Traefik API access. Labels state which routers and
   * middlewares the operator *intended*; the API states what the proxy is
   * actually serving — including middlewares defined outside the scanned stacks,
   * which a compose scan can never see.
   *
   * Unlike Authentik's API, Traefik's is often reachable with no credential at
   * all (`api.insecure` on its own entrypoint), so this stage can do useful work
   * unconfigured. The credential fields exist only for an instance whose API is
   * reachable exclusively through an authenticating edge.
   */
  traefik: {
    enabled: boolean;
    /** Base URL of the Traefik API. Empty = discover it from the fleet. */
    url: string;
    /**
     * Username for HTTP Basic against a gated API. With an Authentik proxy
     * provider this is an Authentik user (or the reserved `goauthentik.io/token`).
     */
    username: string;
    /**
     * Password for HTTP Basic. Behind Authentik this must be an *app password* or
     * a token, not the account password. Prefer `passwordFile`.
     */
    password: string;
    /** Path to a file holding the password (docker secret, mounted file). Wins over `password`. */
    passwordFile: string;
    /** Per-request timeout. The whole exchange is three GETs. */
    timeoutMs: number;
  };
  cacheTtlSeconds: number;
  server: { host: string; port: number };
}

/**
 * The conventional Docker socket path.
 *
 * Exported because the enrichment layer has to tell "this is the default nobody chose"
 * from "the operator named this path" — a scan quietly using the built-in path when a
 * socket proxy was meant to be configured is a real mistake, and worth saying out loud.
 */
export const DEFAULT_DOCKER_SOCKET = "/var/run/docker.sock";

const DEFAULTS: LabViewConfig = {
  appsRoot: "/data/apps",
  composeFilenames: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"],
  // `.labview` first, since that is the documented name. The suffixed variants are
  // the same file under a name editors recognise as YAML.
  sidecarFilenames: [".labview", ".labview.yml", ".labview.yaml"],
  // Default to the conventional local socket, the one endpoint that needs no
  // naming assumption about the host. A TCP endpoint — typically a
  // docker-socket-proxy, as in compose.yml — is opted into by setting
  // `docker.host`, LABVIEW_DOCKER_HOST, or the standard DOCKER_HOST.
  docker: {
    enabled: true,
    host: "",
    port: 2375,
    socketPath: DEFAULT_DOCKER_SOCKET,
    maxConcurrency: 8,
    timeoutMs: 5000,
  },
  secrets: {
    maskValues: true,
    keyPatterns: ["PASS", "SECRET", "TOKEN", "KEY", "APIKEY", "CREDENTIAL", "PRIVATE", "SALT", "PEPPER", "DSN"],
    // LabView's own credentials are already caught by the TOKEN and PASS patterns,
    // but they are named explicitly so that editing keyPatterns cannot expose
    // them: a fleet that runs LabView from inside appsRoot scans its own stack.
    keysAlways: ["LABVIEW_AUTHENTIK_TOKEN", "LABVIEW_TRAEFIK_PASSWORD"],
    keysNever: ["PUBLIC_KEY_URL", "KEYCLOAK_REALM"],
    redactUriCredentials: true,
  },
  labels: {
    dockflare: { prefix: "dockflare" },
    traefik: { prefix: "traefik" },
    authentik: {
      // Markers that identify Authentik itself, all of them things Authentik
      // publishes: its project name and the outpost endpoint path its
      // forward-auth address always contains. Deliberately no host-naming
      // convention (`auth.`, `sso.`) — a convention is a guess about someone
      // else's DNS, and the real hostnames are discovered from the fleet at scan
      // time instead. Add your own only if your Authentik is outside appsRoot and
      // therefore cannot be discovered.
      hostHints: ["authentik", "goauthentik.io"],
      ldapEnvHints: ["LDAP_HOST", "LDAP_URI", "LDAP_SERVER", "LDAP_URL"],
      oauthEnvHints: ["OIDC", "OAUTH", "OPENID", "ISSUER", "CLIENT_ID", "CLIENT_SECRET", "SSO"],
    },
  },
  authentik: {
    enabled: true,
    url: "",
    token: "",
    tokenFile: "",
    timeoutMs: 5000,
    maxPages: 20,
  },
  traefik: {
    enabled: true,
    url: "",
    username: "",
    password: "",
    passwordFile: "",
    timeoutMs: 5000,
  },
  cacheTtlSeconds: 60,
  server: { host: "0.0.0.0", port: 8080 },
};

/**
 * Deep-merge a partial config onto defaults (arrays are replaced, not merged).
 * The result never aliases `base`: a spread would leave nested objects such as
 * `docker` shared with DEFAULTS, and `applyEnvOverrides` mutates them in place,
 * so a second `loadConfig()` would inherit the first call's overrides.
 */
function merge<T>(base: T, over: unknown): T {
  if (over === null || over === undefined) return clone(base);
  if (base === null || Array.isArray(base) || typeof base !== "object") return over as T;
  const out = clone(base) as Record<string, unknown>;
  for (const [k, v] of Object.entries(over as Record<string, unknown>)) {
    const cur = (base as Record<string, unknown>)[k];
    out[k] = cur !== undefined && cur !== null ? merge(cur as unknown, v) : v;
  }
  return out as T;
}

/** Structural copy of plain data (objects, arrays, primitives). */
function clone<T>(v: T): T {
  if (Array.isArray(v)) return v.map((x) => clone(x)) as unknown as T;
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = clone(val);
    return out as T;
  }
  return v;
}

/**
 * Parse a Docker endpoint given in `DOCKER_HOST` style. Accepts
 * `tcp://host:port`, `http://host:port`, `host:port`, a bare `host`,
 * `unix:///path` or an absolute `/path`. TCP forms set host/port; socket forms
 * set socketPath.
 */
function parseDockerTarget(value: string): { host?: string; port?: number; socketPath?: string } {
  const v = value.trim();
  if (!v) return {};
  if (v.startsWith("unix://")) return { socketPath: v.slice("unix://".length) };
  if (v.startsWith("/")) return { socketPath: v };
  const stripped = v.replace(/^tcp:\/\//i, "").replace(/^https?:\/\//i, "");
  const [host, port] = stripped.split(":");
  return { host, port: port ? Number(port) : 2375 };
}

function applyEnvOverrides(cfg: LabViewConfig): LabViewConfig {
  const env = process.env;
  if (env.LABVIEW_APPS_ROOT) cfg.appsRoot = env.LABVIEW_APPS_ROOT;
  if (env.LABVIEW_SIDECAR_FILENAMES) {
    const names = env.LABVIEW_SIDECAR_FILENAMES.split(",")
      .map((n) => n.trim())
      .filter(Boolean);
    if (names.length) cfg.sidecarFilenames = names;
  }
  // LABVIEW_DOCKER_HOST selects a TCP endpoint; a socket-style value clears host
  // so socketPath is used instead. DOCKER_HOST is the standard variable every
  // other Docker client already reads, so honour it too — LABVIEW_DOCKER_HOST
  // wins when both are set, since it is the more specific of the two.
  const dockerTarget = env.LABVIEW_DOCKER_HOST || env.DOCKER_HOST;
  if (dockerTarget) {
    const t = parseDockerTarget(dockerTarget);
    if (t.socketPath) {
      cfg.docker.socketPath = t.socketPath;
      cfg.docker.host = "";
    } else {
      if (t.host) cfg.docker.host = t.host;
      if (t.port) cfg.docker.port = t.port;
    }
  }
  if (env.LABVIEW_DOCKER_PORT) cfg.docker.port = Number(env.LABVIEW_DOCKER_PORT);
  // An explicit socket path always wins and disables the TCP host.
  if (env.LABVIEW_DOCKER_SOCKET) {
    cfg.docker.socketPath = env.LABVIEW_DOCKER_SOCKET;
    cfg.docker.host = "";
  }
  if (env.LABVIEW_DOCKER_ENABLED) cfg.docker.enabled = env.LABVIEW_DOCKER_ENABLED !== "false";
  if (env.LABVIEW_DOCKER_MAX_CONCURRENCY) {
    const n = Number(env.LABVIEW_DOCKER_MAX_CONCURRENCY);
    if (Number.isFinite(n) && n >= 1) cfg.docker.maxConcurrency = Math.floor(n);
  }
  if (env.LABVIEW_DOCKER_TIMEOUT) {
    const n = Number(env.LABVIEW_DOCKER_TIMEOUT);
    if (Number.isFinite(n) && n > 0) cfg.docker.timeoutMs = Math.floor(n);
  }
  if (env.LABVIEW_AUTHENTIK_ENABLED) cfg.authentik.enabled = env.LABVIEW_AUTHENTIK_ENABLED !== "false";
  if (env.LABVIEW_AUTHENTIK_URL) cfg.authentik.url = env.LABVIEW_AUTHENTIK_URL;
  if (env.LABVIEW_AUTHENTIK_TOKEN) cfg.authentik.token = env.LABVIEW_AUTHENTIK_TOKEN;
  if (env.LABVIEW_AUTHENTIK_TOKEN_FILE) cfg.authentik.tokenFile = env.LABVIEW_AUTHENTIK_TOKEN_FILE;
  if (env.LABVIEW_AUTHENTIK_TIMEOUT) {
    const n = Number(env.LABVIEW_AUTHENTIK_TIMEOUT);
    if (Number.isFinite(n) && n > 0) cfg.authentik.timeoutMs = Math.floor(n);
  }
  if (env.LABVIEW_TRAEFIK_ENABLED) cfg.traefik.enabled = env.LABVIEW_TRAEFIK_ENABLED !== "false";
  if (env.LABVIEW_TRAEFIK_URL) cfg.traefik.url = env.LABVIEW_TRAEFIK_URL;
  if (env.LABVIEW_TRAEFIK_USERNAME) cfg.traefik.username = env.LABVIEW_TRAEFIK_USERNAME;
  if (env.LABVIEW_TRAEFIK_PASSWORD) cfg.traefik.password = env.LABVIEW_TRAEFIK_PASSWORD;
  if (env.LABVIEW_TRAEFIK_PASSWORD_FILE) cfg.traefik.passwordFile = env.LABVIEW_TRAEFIK_PASSWORD_FILE;
  if (env.LABVIEW_TRAEFIK_TIMEOUT) {
    const n = Number(env.LABVIEW_TRAEFIK_TIMEOUT);
    if (Number.isFinite(n) && n > 0) cfg.traefik.timeoutMs = Math.floor(n);
  }
  if (env.LABVIEW_PORT) cfg.server.port = Number(env.LABVIEW_PORT);
  if (env.LABVIEW_HOST) cfg.server.host = env.LABVIEW_HOST;
  if (env.LABVIEW_CACHE_TTL) cfg.cacheTtlSeconds = Number(env.LABVIEW_CACHE_TTL);
  if (env.LABVIEW_MASK_SECRETS) cfg.secrets.maskValues = env.LABVIEW_MASK_SECRETS !== "false";
  return cfg;
}

export function loadConfig(): LabViewConfig {
  const path = process.env.LABVIEW_CONFIG ?? "config.yml";
  let cfg = merge(DEFAULTS, {}) as LabViewConfig;
  if (existsSync(path)) {
    try {
      const raw = parseYaml(readFileSync(path, "utf8")) ?? {};
      cfg = merge(DEFAULTS, raw);
    } catch (err) {
      console.error(`[config] failed to parse ${path}: ${(err as Error).message}; using defaults`);
    }
  }
  return applyEnvOverrides(cfg);
}
