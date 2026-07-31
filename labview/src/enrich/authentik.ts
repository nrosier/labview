/**
 * Read the identity provider's own records over Authentik's REST API.
 *
 * Everywhere else LabView derives auth posture from compose labels and env, which
 * state what the operator *intended* to wire up. Authentik's API states what it
 * will actually enforce: which applications exist, which providers back them, and
 * which outposts serve those providers. That is strictly better evidence, and it
 * closes the two gaps labels cannot: a middleware defined in a Traefik file
 * provider (invisible to a compose scan) and a gate whose provider is configured
 * but deployed to no outpost.
 *
 * Three rules shape this module.
 *
 *  - **The token is only ever sent to a host confirmed to be Authentik.** An
 *    endpoint may be discovered from the fleet rather than configured, so each
 *    candidate is probed unauthenticated first — `/api/v3/root/config/` is
 *    `AllowAny` upstream — and the bearer token follows only once that answers.
 *    A wrong candidate therefore costs a 404, not a leaked credential.
 *  - **Read-only, always.** Only GETs are issued. Authentik has no read-only token
 *    type — a token carries its user's permissions — so the deployment docs call
 *    for a service account limited to `view_*`. That is the operator's half of the
 *    contract; issuing nothing but GETs is ours.
 *  - **Never throws, never blocks a scan** (invariant I4). Not configured,
 *    unreachable, unauthorized, rate-limited, serving unexpected JSON: every path
 *    returns a summary explaining itself and the scan continues on labels alone.
 */
import { readFileSync } from "node:fs";
import type {
  AppStack,
  AuthentikApplication,
  AuthentikProvider,
  AuthentikProviderKind,
  AuthentikSummary,
  Service,
} from "../model/types.js";
import type { LabViewConfig } from "../config.js";

/** Minimal shape of a `fetch` response, so a test can supply a stub. */
export interface HttpResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

/** The subset of `fetch` this module uses. The global `fetch` satisfies it. */
export type FetchLike = (
  url: string,
  init?: { headers?: Record<string, string>; signal?: AbortSignal },
) => Promise<HttpResponse>;

/** An Authentik base URL worth trying, and where the idea came from. */
export interface AuthentikEndpoint {
  url: string;
  source: "config" | "discovered";
  /** How this candidate was arrived at, for the error message when none works. */
  why: string;
}

export interface AuthentikSnapshot {
  summary: AuthentikSummary;
  applications: AuthentikApplication[];
}

/** Authentik's documented API root, relative to the instance base URL. */
const API = "/api/v3";

/** Page size for list endpoints; the cap on pages comes from config. */
const PAGE_SIZE = 100;

/**
 * Whether a service is Authentik itself.
 *
 * Both signals are things Authentik publishes about itself — its image name and
 * the outpost endpoint path its forward-auth address always contains — rather than
 * assumptions about how the operator named anything (invariant I2). Shared with the
 * hint discovery in the analyzer so there is one definition of "this is Authentik".
 */
export function isAuthentikService(svc: Service): boolean {
  if (/goauthentik|authentik/i.test(svc.image ?? "")) return true;
  return Object.entries(svc.labels).some(
    ([k, v]) => /forwardauth\.address$/i.test(k) && /goauthentik\.io/i.test(v),
  );
}

/**
 * Base URLs to try, in the order they are worth trying.
 *
 * The internal container address comes first on purpose. A discovered public
 * hostname is normally fronted by the tunnel and the proxy, which is exactly where
 * an edge access policy lives — probing it can return an SSO login page rather than
 * the API. The container address bypasses all of that and is what a sibling
 * container is meant to use.
 *
 * Ports come from the service's own declarations. Only when it declares none does
 * Authentik's documented listener port stand in, and even then the probe is what
 * decides: a candidate either answers as Authentik or it is discarded.
 */
export function discoverAuthentikEndpoints(stacks: AppStack[]): AuthentikEndpoint[] {
  const internal: AuthentikEndpoint[] = [];
  const external: AuthentikEndpoint[] = [];

  for (const stack of stacks) {
    for (const svc of stack.services) {
      if (!isAuthentikService(svc)) continue;
      const names = [svc.containerName, svc.name].filter(Boolean);
      // Container-internal traffic addresses the target port, not the host port.
      const targets = [...new Set(svc.ports.map((p) => p.target).filter((t) => /^\d+$/.test(t)))];
      // 9000 is Authentik's documented HTTP listener; prefer it when the service
      // declares it, since a stack commonly maps several ports.
      targets.sort((a, b) => Number(a === "9000" ? 0 : 1) - Number(b === "9000" ? 0 : 1));
      const ports = targets.length ? targets : ["9000"];
      for (const name of names) {
        for (const port of ports) {
          internal.push({
            url: `http://${name}:${port}`,
            source: "discovered",
            why: `container ${name} in stack ${stack.id} runs Authentik`,
          });
        }
      }
      const hosts = [
        ...new Set([
          ...svc.cloudflare.map((r) => r.hostname),
          ...svc.traefik.flatMap((r) => r.hosts),
        ]),
      ].filter(Boolean);
      for (const host of hosts) {
        external.push({
          url: `https://${host}`,
          source: "discovered",
          why: `Authentik answers on ${host}`,
        });
      }
    }
  }
  // Bounded: probing is cheap but not free, and a fleet can declare many hostnames.
  return dedupeByUrl([...internal, ...external]).slice(0, 6);
}

function dedupeByUrl(list: AuthentikEndpoint[]): AuthentikEndpoint[] {
  const seen = new Set<string>();
  return list.filter((e) => (seen.has(e.url) ? false : (seen.add(e.url), true)));
}

/**
 * Query Authentik and return everything needed to match applications to services.
 *
 * `candidates` is tried in order and the first one that both answers the
 * unauthenticated probe and accepts the token wins.
 */
export async function snapshotAuthentik(
  cfg: LabViewConfig,
  candidates: AuthentikEndpoint[],
  fetchImpl?: FetchLike,
): Promise<AuthentikSnapshot> {
  const empty = (over: Partial<AuthentikSummary>): AuthentikSnapshot => ({
    summary: {
      enabled: cfg.authentik.enabled,
      configured: false,
      reachable: false,
      applications: 0,
      providers: 0,
      outposts: 0,
      matchedServices: 0,
      unmatchedApplications: [],
      ...over,
    },
    applications: [],
  });

  if (!cfg.authentik.enabled) return empty({ error: "Authentik API lookup disabled in config" });

  const token = readToken(cfg);
  if (token.error) return empty({ error: token.error });
  // Nothing useful is readable anonymously, so an absent token means "feature off"
  // rather than "feature broken" — reported without an error so the UI stays quiet.
  if (!token.value) return empty({});
  if (!candidates.length) {
    return empty({
      error:
        "no Authentik endpoint: none configured, and no scanned service was identified as Authentik",
    });
  }

  const doFetch: FetchLike = fetchImpl ?? ((url, init) => fetch(url, init) as Promise<HttpResponse>);
  const attempts: string[] = [];

  for (const candidate of candidates) {
    const base = candidate.url.replace(/\/+$/, "");
    const origin = safeOrigin(base);

    // Probe unauthenticated: confirm this is Authentik before the token goes out.
    const probe = await getJson(doFetch, `${base}${API}/root/config/`, undefined, cfg);
    if (!probe.ok || !isObject(probe.body)) {
      attempts.push(`${origin} (${candidate.why}): ${probe.error ?? "not an Authentik API root"}`);
      continue;
    }

    const auth = { Authorization: `Bearer ${token.value}`, Accept: "application/json" };
    const apps = await getList(doFetch, base, "core/applications", auth, cfg);
    if (apps.error) {
      // A confirmed Authentik that refuses the token is a configuration problem
      // worth reporting rather than a candidate to skip past silently.
      return empty({
        configured: true,
        endpoint: origin,
        endpointSource: candidate.source,
        error: `Authentik at ${origin} rejected the API request: ${apps.error}`,
      });
    }

    const [proxies, oauth2, outposts] = await Promise.all([
      getList(doFetch, base, "providers/proxy", auth, cfg),
      getList(doFetch, base, "providers/oauth2", auth, cfg),
      getList(doFetch, base, "outposts/instances", auth, cfg),
    ]);

    const applications = buildApplications(apps.items, proxies.items, oauth2.items, outposts.items);
    const soft = [proxies.error, oauth2.error, outposts.error].filter(Boolean);
    return {
      summary: {
        enabled: true,
        configured: true,
        reachable: true,
        endpoint: origin,
        endpointSource: candidate.source,
        // A partial read still yields useful matches, so it is reported as reachable
        // with the gap stated rather than discarded wholesale.
        error: soft.length ? `some endpoints could not be read: ${soft.join("; ")}` : undefined,
        applications: applications.length,
        providers: applications.reduce((n, a) => n + a.providers.length, 0),
        outposts: outposts.items.length,
        matchedServices: 0,
        unmatchedApplications: [],
      },
      applications,
    };
  }

  return empty({
    configured: true,
    error: `no Authentik API endpoint answered — tried ${attempts.join("; ")}`,
  });
}

/** Resolve the token from a file when given one, else from config/env. */
function readToken(cfg: LabViewConfig): { value?: string; error?: string } {
  const file = cfg.authentik.tokenFile.trim();
  if (file) {
    try {
      const value = readFileSync(file, "utf8").trim();
      if (!value) return { error: `Authentik token file ${file} is empty` };
      return { value };
    } catch (err) {
      return { error: `Authentik token file ${file} could not be read: ${(err as Error).message}` };
    }
  }
  const value = cfg.authentik.token.trim();
  return value ? { value } : {};
}

interface ListResult {
  items: Record<string, unknown>[];
  error?: string;
}

/**
 * Read every page of a list endpoint.
 *
 * Authentik wraps list responses in its own envelope — `{pagination: {next, …},
 * results: []}`, where `next` is a page *number* and 0 means "no more" — but a
 * DRF-style `{next: <url>}` is accepted too, so a change in either direction
 * degrades to a first page rather than a failure. `maxPages` bounds a very large
 * instance so one scan cannot stall on pagination.
 */
async function getList(
  doFetch: FetchLike,
  base: string,
  path: string,
  headers: Record<string, string>,
  cfg: LabViewConfig,
): Promise<ListResult> {
  const items: Record<string, unknown>[] = [];
  for (let page = 1; page <= Math.max(1, cfg.authentik.maxPages); page++) {
    const url = `${base}${API}/${path}/?page=${page}&page_size=${PAGE_SIZE}`;
    const res = await getJson(doFetch, url, headers, cfg);
    if (!res.ok || !isObject(res.body)) {
      // A later page failing still leaves the earlier ones usable.
      if (items.length) return { items, error: `${path} page ${page}: ${res.error ?? "bad response"}` };
      return { items, error: `${path}: ${res.error ?? "unexpected response body"}` };
    }
    const results = Array.isArray(res.body.results) ? res.body.results : [];
    for (const r of results) if (isObject(r)) items.push(r);
    if (!results.length) break;
    const pagination = isObject(res.body.pagination) ? res.body.pagination : undefined;
    const nextPage = pagination ? Number(pagination.next ?? 0) : NaN;
    if (pagination) {
      if (!Number.isFinite(nextPage) || nextPage <= page) break;
    } else if (!res.body.next) {
      break;
    }
  }
  return { items };
}

interface JsonResult {
  ok: boolean;
  body?: unknown;
  error?: string;
}

/**
 * One GET, with a timeout and no way to throw.
 *
 * Error text carries the status and the endpoint origin only. The token must never
 * reach a summary, a note or a log line, so nothing here interpolates the headers.
 */
async function getJson(
  doFetch: FetchLike,
  url: string,
  headers: Record<string, string> | undefined,
  cfg: LabViewConfig,
): Promise<JsonResult> {
  try {
    const res = await doFetch(url, {
      headers: headers ?? { Accept: "application/json" },
      signal: AbortSignal.timeout(cfg.authentik.timeoutMs),
    });
    if (!res.ok) {
      const hint =
        res.status === 401 || res.status === 403
          ? " (token rejected — check it is valid and its service account may view applications, providers and outposts)"
          : "";
      return { ok: false, error: `HTTP ${res.status}${hint}` };
    }
    return { ok: true, body: await res.json() };
  } catch (err) {
    const e = err as Error;
    const reason = e.name === "TimeoutError" || e.name === "AbortError" ? "timed out" : e.message;
    return { ok: false, error: reason };
  }
}

/**
 * Assemble applications with their providers and the outposts serving them.
 *
 * LDAP and SCIM providers are attached to an application as *backchannel*
 * providers, so reading only the primary `provider` would miss every LDAP-protected
 * app. Both lists are walked, and `backchannel` records which was which.
 */
function buildApplications(
  apps: Record<string, unknown>[],
  proxies: Record<string, unknown>[],
  oauth2: Record<string, unknown>[],
  outposts: Record<string, unknown>[],
): AuthentikApplication[] {
  const proxyByPk = byPk(proxies);
  const oauthByPk = byPk(oauth2);

  // provider pk -> names of the outposts serving it. An empty list is the point:
  // a proxy or LDAP provider no outpost serves cannot enforce anything.
  const outpostsByProvider = new Map<string, string[]>();
  for (const o of outposts) {
    const name = str(o.name) ?? str(o.pk) ?? "outpost";
    for (const pk of Array.isArray(o.providers) ? o.providers : []) {
      const key = String(pk);
      const list = outpostsByProvider.get(key);
      if (list) list.push(name);
      else outpostsByProvider.set(key, [name]);
    }
  }

  const out: AuthentikApplication[] = [];
  for (const app of apps) {
    const slug = str(app.slug);
    if (!slug) continue;
    const providers: AuthentikProvider[] = [];

    const primary = isObject(app.provider_obj) ? app.provider_obj : undefined;
    if (primary) {
      providers.push(toProvider(primary, false, proxyByPk, oauthByPk, outpostsByProvider));
    }
    for (const bc of Array.isArray(app.backchannel_providers_obj) ? app.backchannel_providers_obj : []) {
      if (isObject(bc)) {
        providers.push(toProvider(bc, true, proxyByPk, oauthByPk, outpostsByProvider));
      }
    }

    out.push({
      name: str(app.name) ?? slug,
      slug,
      group: str(app.group) || undefined,
      launchUrl: concreteUrl(str(app.launch_url)) ?? concreteUrl(str(app.meta_launch_url)),
      providers,
    });
  }
  return out;
}

function toProvider(
  raw: Record<string, unknown>,
  backchannel: boolean,
  proxyByPk: Map<string, Record<string, unknown>>,
  oauthByPk: Map<string, Record<string, unknown>>,
  outpostsByProvider: Map<string, string[]>,
): AuthentikProvider {
  const pk = str(raw.pk) ?? "";
  // The type is read from whichever of the three descriptive fields is present, so
  // a rename in any one of them does not silently reclassify a provider.
  const rawKind = [str(raw.component), str(raw.meta_model_name), str(raw.verbose_name)]
    .filter(Boolean)
    .join(" ");
  const kind = providerKind(rawKind);
  const detail = kind === "proxy" ? proxyByPk.get(pk) : kind === "oauth2" ? oauthByPk.get(pk) : undefined;

  return {
    name: str(raw.name) ?? pk,
    kind,
    rawKind: str(raw.verbose_name) ?? str(raw.component) ?? rawKind,
    mode: detail ? str(detail.mode) : undefined,
    internalHost: detail ? str(detail.internal_host) : undefined,
    externalHost: detail ? str(detail.external_host) : undefined,
    redirectUris: detail ? redirectUris(detail.redirect_uris) : undefined,
    backchannel,
    outposts: outpostsByProvider.get(pk) ?? [],
  };
}

/** Normalize the API's provider descriptors onto the kinds this version models. */
function providerKind(descriptor: string): AuthentikProviderKind {
  const d = descriptor.toLowerCase();
  if (d.includes("proxy")) return "proxy";
  if (d.includes("ldap")) return "ldap";
  if (d.includes("saml")) return "saml";
  if (d.includes("scim")) return "scim";
  if (d.includes("radius")) return "radius";
  if (d.includes("oauth") || d.includes("oidc")) return "oauth2";
  return "other";
}

/**
 * OAuth2 redirect URIs, which have been both a newline-delimited string and a list
 * of `{matching_mode, url}` objects across Authentik versions. Both are read.
 */
function redirectUris(value: unknown): string[] | undefined {
  const out: string[] = [];
  if (typeof value === "string") {
    out.push(...value.split(/\s+/).filter(Boolean));
  } else if (Array.isArray(value)) {
    for (const entry of value) {
      if (typeof entry === "string") out.push(entry);
      else if (isObject(entry)) {
        const url = str(entry.url);
        if (url) out.push(url);
      }
    }
  }
  return out.length ? out : undefined;
}

/**
 * A URL usable for matching.
 *
 * `launch_url` is computed per requesting user and may be null, and
 * `meta_launch_url` may be a template containing placeholders like `%(username)s`.
 * A template names no single host, so it is dropped rather than matched on.
 */
function concreteUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  if (value.includes("%(") || value.includes("{{")) return undefined;
  return value;
}

function byPk(list: Record<string, unknown>[]): Map<string, Record<string, unknown>> {
  const out = new Map<string, Record<string, unknown>>();
  for (const item of list) {
    const pk = str(item.pk);
    if (pk) out.set(pk, item);
  }
  return out;
}

/** Scheme + host + port of a base URL, with any embedded credentials dropped. */
function safeOrigin(base: string): string {
  try {
    return new URL(base).origin;
  } catch {
    return base.replace(/\/\/[^@/]*@/, "//");
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  if (typeof v === "string") return v;
  if (typeof v === "number") return String(v);
  return undefined;
}
