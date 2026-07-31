import type { Service, AuthPosture, AuthMethod, EnvVar } from "../model/types.js";
import type { LabViewConfig } from "../config.js";
import type { MiddlewareRegistry } from "../analyze/middlewares.js";

interface Detection {
  method: AuthMethod;
  detail: string;
  evidence: string[];
}

/**
 * Derive the authentication posture of a service from its Traefik middlewares
 * (resolved against the global middleware registry), DockFlare Cloudflare Access
 * policy, and its environment (OIDC/OAuth/LDAP wired to Authentik).
 *
 * `exposedWithoutAuth` is left false here and finalized by the analyzer once the
 * ingress classification is known.
 */
export function deriveAuth(
  service: Service,
  cfg: LabViewConfig,
  registry: MiddlewareRegistry,
  hostHints: string[],
): AuthPosture {
  const a = cfg.labels.authentik;
  const evidence: string[] = [];
  const detections: Detection[] = [];

  const hintMatch = (s: string | undefined): string | undefined =>
    s ? hostHints.find((h) => s.toLowerCase().includes(h)) : undefined;

  // 1. Traefik middlewares referenced by this service's routers.
  const referenced = new Set(service.traefik.flatMap((r) => r.middlewares));
  for (const mw of referenced) {
    const bare = mw.replace(/@.*$/, "");
    const def = registry.get(bare);
    const type = def?.type;
    const addr = def?.address;

    if (type === "forwardauth" || (!def && /auth/i.test(bare) && !/header/i.test(bare))) {
      if (hintMatch(mw) || hintMatch(addr)) {
        detections.push({
          method: "authentik-forward-auth",
          detail: `Authentik forward-auth via Traefik middleware \`${mw}\``,
          evidence: [`middleware ${mw}`, ...(addr ? [`forwardauth -> ${addr}`] : [])],
        });
      } else {
        detections.push({
          method: "other-oauth",
          detail: `Forward-auth via \`${mw}\`${addr ? ` -> ${addr}` : ""}`,
          evidence: [`middleware ${mw}`],
        });
      }
    } else if (type === "basicauth" || type === "digestauth") {
      detections.push({
        method: "basic-auth",
        detail: `HTTP ${type === "digestauth" ? "digest" : "basic"} auth via \`${mw}\``,
        evidence: [`middleware ${mw}`],
      });
    }
    // headers / redirectscheme / compress / ratelimit / chain: not auth — ignored.
  }

  // 2. DockFlare Cloudflare Access policy on a public route.
  for (const route of service.cloudflare) {
    if (route.access && (route.access.policy || route.access.group || route.access.emails?.length)) {
      const bits = [
        route.access.policy && `policy=${route.access.policy}`,
        route.access.group && `group=${route.access.group}`,
        route.access.emails?.length && `emails=${route.access.emails.join(",")}`,
      ].filter(Boolean);
      detections.push({
        method: "other-oauth",
        detail: `Cloudflare Access on ${route.hostname}`,
        evidence: [`Cloudflare Access (${bits.join(", ")})`],
      });
    }
  }

  // 3. Env-derived OIDC/OAuth and LDAP (visible once .env / env_file is present).
  const oauth = detectEnv(service.env, a.oauthEnvHints);
  if (oauth.hit) {
    const authentik = oauth.matchedValues.some((v) => hintMatch(v)) || oauth.keys.some((k) => hintMatch(k));
    detections.push({
      method: authentik ? "authentik-oauth" : "other-oauth",
      detail: authentik ? "OAuth/OIDC SSO against Authentik" : "OAuth/OIDC SSO (issuer not obviously Authentik)",
      evidence: oauth.keys.map((k) => `env ${k}`),
    });
  }

  const ldap = detectEnv(service.env, a.ldapEnvHints);
  if (ldap.hit) {
    const authentik = ldap.matchedValues.some((v) => hintMatch(v));
    detections.push({
      method: "authentik-ldap",
      detail: authentik ? "LDAP bind against the Authentik LDAP outpost" : `LDAP authentication`,
      evidence: ldap.keys.map((k) => `env ${k}`),
    });
  }

  // Pick the primary method by precedence; keep everything as evidence.
  const order: AuthMethod[] = [
    "authentik-forward-auth",
    "authentik-oauth",
    "authentik-ldap",
    "other-oauth",
    "basic-auth",
  ];
  detections.sort((x, y) => order.indexOf(x.method) - order.indexOf(y.method));
  const primary = detections[0];
  const allEvidence = [...new Set([...detections.flatMap((d) => d.evidence), ...evidence])];

  if (!primary) {
    return {
      method: "none",
      detail: "No authentication detected",
      evidence: allEvidence,
      exposedWithoutAuth: false,
    };
  }

  const others = detections.slice(1).map((d) => d.detail);
  const detail = others.length ? `${primary.detail}; also: ${others.join("; ")}` : primary.detail;
  return { method: primary.method, detail, evidence: allEvidence, exposedWithoutAuth: false };
}

interface EnvHit {
  hit: boolean;
  keys: string[];
  matchedValues: string[];
}

function detectEnv(env: EnvVar[], hints: string[]): EnvHit {
  const upperHints = hints.map((h) => h.toUpperCase());
  const keys: string[] = [];
  const matchedValues: string[] = [];
  for (const e of env) {
    const K = e.key.toUpperCase();
    if (upperHints.some((h) => K.includes(h))) {
      keys.push(e.key);
      if (e.value) matchedValues.push(e.value);
    }
  }
  return { hit: keys.length > 0, keys, matchedValues };
}
