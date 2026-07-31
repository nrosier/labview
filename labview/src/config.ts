import { readFileSync, existsSync } from "node:fs";
import { parse as parseYaml } from "yaml";

export interface FleetViewConfig {
  appsRoot: string;
  composeFilenames: string[];
  docker: {
    enabled: boolean;
    socketPath: string;
  };
  secrets: {
    maskValues: boolean;
    keyPatterns: string[];
    keysAlways: string[];
    keysNever: string[];
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
  cacheTtlSeconds: number;
  server: { host: string; port: number };
}

const DEFAULTS: FleetViewConfig = {
  appsRoot: "/data/apps",
  composeFilenames: ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"],
  docker: { enabled: true, socketPath: "/var/run/docker.sock" },
  secrets: {
    maskValues: true,
    keyPatterns: ["PASS", "SECRET", "TOKEN", "KEY", "APIKEY", "CREDENTIAL", "PRIVATE", "SALT", "PEPPER", "DSN"],
    keysAlways: [],
    keysNever: ["PUBLIC_KEY_URL", "KEYCLOAK_REALM"],
  },
  labels: {
    dockflare: { prefix: "dockflare" },
    traefik: { prefix: "traefik" },
    authentik: {
      hostHints: ["authentik", "auth.", "outpost.goauthentik.io"],
      ldapEnvHints: ["LDAP_HOST", "LDAP_URI", "LDAP_SERVER", "LDAP_URL"],
      oauthEnvHints: ["OIDC", "OAUTH", "OPENID", "ISSUER", "CLIENT_ID", "CLIENT_SECRET", "SSO"],
    },
  },
  cacheTtlSeconds: 60,
  server: { host: "0.0.0.0", port: 8080 },
};

/** Deep-merge a partial config onto defaults (arrays are replaced, not merged). */
function merge<T>(base: T, over: unknown): T {
  if (over === null || over === undefined) return base;
  if (Array.isArray(base) || typeof base !== "object") return over as T;
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [k, v] of Object.entries(over as Record<string, unknown>)) {
    const cur = (base as Record<string, unknown>)[k];
    out[k] = cur !== undefined && cur !== null ? merge(cur as unknown, v) : v;
  }
  return out as T;
}

function applyEnvOverrides(cfg: FleetViewConfig): FleetViewConfig {
  const env = process.env;
  if (env.FLEETVIEW_APPS_ROOT) cfg.appsRoot = env.FLEETVIEW_APPS_ROOT;
  if (env.FLEETVIEW_DOCKER_SOCKET) cfg.docker.socketPath = env.FLEETVIEW_DOCKER_SOCKET;
  if (env.FLEETVIEW_DOCKER_ENABLED) cfg.docker.enabled = env.FLEETVIEW_DOCKER_ENABLED !== "false";
  if (env.FLEETVIEW_PORT) cfg.server.port = Number(env.FLEETVIEW_PORT);
  if (env.FLEETVIEW_HOST) cfg.server.host = env.FLEETVIEW_HOST;
  if (env.FLEETVIEW_CACHE_TTL) cfg.cacheTtlSeconds = Number(env.FLEETVIEW_CACHE_TTL);
  if (env.FLEETVIEW_MASK_SECRETS) cfg.secrets.maskValues = env.FLEETVIEW_MASK_SECRETS !== "false";
  return cfg;
}

export function loadConfig(): FleetViewConfig {
  const path = process.env.FLEETVIEW_CONFIG ?? "config.yml";
  let cfg = merge(DEFAULTS, {}) as FleetViewConfig;
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
