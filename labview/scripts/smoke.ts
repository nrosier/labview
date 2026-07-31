/**
 * Smoke test: run the full pipeline (docker disabled) against four fixture roots
 * and assert the analyzer produced the expected classifications. Exits non-zero
 * on any failure so it can gate CI / a pre-commit check.
 *
 *   ./fixtures/apps      — a representative happy-path fleet.
 *   ./fixtures/edge      — regression cases for previously-fixed defects.
 *   ./fixtures/authentik — the identity-provider API integration, driven through an
 *                          injected HTTP layer so no network and no Authentik is
 *                          needed. Canned responses: ./fixtures/authentik-api.json.
 *   ./fixtures/traefik   — the reverse-proxy API integration, driven the same way.
 *                          Canned responses: ./fixtures/traefik-api.json, which also
 *                          carries the Authentik payload for those runs, since the
 *                          cross-check reads all three sources at once.
 *
 *   npx tsx scripts/smoke.ts
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { DockerState, Overview, Service, TraefikLiveRouter } from "../src/model/types.js";
import type { BuildDeps } from "../src/analyze/index.js";
import type { DockerLike } from "../src/enrich/docker.js";
import type { FetchLike, HttpResponse } from "../src/enrich/authentik.js";

const here = dirname(fileURLToPath(import.meta.url));
const appsRoot = resolve(here, "..", "fixtures", "apps");
const edgeRoot = resolve(here, "..", "fixtures", "edge");
const authentikRoot = resolve(here, "..", "fixtures", "authentik");
const traefikRoot = resolve(here, "..", "fixtures", "traefik");

// Configure via env BEFORE importing config.
process.env.LABVIEW_DOCKER_ENABLED = "false";
process.env.LABVIEW_CONFIG = "___none___"; // force defaults
// The Authentik integration is driven explicitly per run below. Clearing these
// first means an operator's own credentials in the environment can neither make
// this test reach the network nor change what it asserts.
delete process.env.LABVIEW_AUTHENTIK_URL;
delete process.env.LABVIEW_AUTHENTIK_TOKEN;
delete process.env.LABVIEW_AUTHENTIK_TOKEN_FILE;
delete process.env.LABVIEW_AUTHENTIK_ENABLED;
// The proxy integration needs one extra precaution the Authentik one does not. It is
// enabled by default and needs no credential to do work, so a fixture fleet that
// looks like it contains a proxy — `fixtures/apps` does, via its resolved tunnel hop
// — would have the runs below issue real requests to a guessed container address
// through the global `fetch`. Off by default here, enabled per run.
process.env.LABVIEW_TRAEFIK_ENABLED = "false";
delete process.env.LABVIEW_TRAEFIK_URL;
delete process.env.LABVIEW_TRAEFIK_USERNAME;
delete process.env.LABVIEW_TRAEFIK_PASSWORD;
delete process.env.LABVIEW_TRAEFIK_PASSWORD_FILE;

const { loadConfig } = await import("../src/config.js");
const { buildOverview } = await import("../src/analyze/index.js");
// Used directly by the container-IP assertions: the trap is not reachable through the
// pipeline, because a container IP only exists in live docker state and smoke runs
// without a docker socket.
const { buildFleetIndex, lookupAddress, lookupContainerAddress } = await import(
  "../src/analyze/origins.js"
);
const { matchTraefik } = await import("../src/analyze/traefik.js");

/** Build an overview for one fixture root. loadConfig() re-reads env each call. */
async function overviewFor(root: string, deps: BuildDeps = {}): Promise<Overview> {
  process.env.LABVIEW_APPS_ROOT = root;
  return buildOverview(loadConfig(), new Date("2024-01-01T00:00:00Z"), deps);
}

let failures = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) {
    console.log(`  ✓ ${name}`);
  } else {
    console.error(`  ✗ ${name} ${detail}`);
    failures++;
  }
}

/** Service lookup bound to one overview. */
function lookup(ov: Overview): (stackId: string, serviceName: string) => Service {
  return (stackId, serviceName) => {
    const s = ov.stacks.find((x) => x.id === stackId)?.services.find((x) => x.name === serviceName);
    if (!s) throw new Error(`service ${stackId}/${serviceName} not found`);
    return s;
  };
}

function envValue(s: Service, key: string): string | null | undefined {
  return s.env.find((e) => e.key === key)?.value;
}

/* -------------------------------------------------------------------------- */
/* Authentik API stub                                                         */
/* -------------------------------------------------------------------------- */

/** The one origin in the fixture fleet that actually serves the Authentik API. */
const AK_ORIGIN = "http://authentik-server:9000";
/** Not a credential: an arbitrary string the stub demands verbatim. */
const AK_TOKEN = "smoke-fixture-token-0000000000";
const AK_FIXTURE = JSON.parse(
  readFileSync(resolve(here, "..", "fixtures", "authentik-api.json"), "utf8"),
) as Record<string, unknown>;

interface Recorded {
  url: string;
  /** Whether an Authorization header was sent — the leak check, not an auth check. */
  sentToken: boolean;
  /** Cookies echoed back, for the one exchange that depends on them. */
  cookie?: string;
}

/**
 * One canned HTTP response. `setCookie` is served through the same optional
 * `headers.get` shape the real `fetch` Response has, since that is what the client
 * reads it from.
 */
function reply(status: number, body: unknown, setCookie?: string): HttpResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    headers: { get: (name) => (/^set-cookie$/i.test(name) ? (setCookie ?? null) : null) },
  };
}

/**
 * Answer one Authentik API request from a fixture payload, or return undefined when
 * the request is not for this origin.
 *
 * Shared by both stubs below: the Traefik runs need the same Authentik payload served
 * for the three-way cross-check, and duplicating the pagination envelopes would mean
 * two places for the assumed shape to drift apart.
 *
 * It behaves like the real thing in the three ways that matter to the client:
 * `/api/v3/root/config/` answers without credentials (it is `AllowAny` upstream),
 * every other endpoint demands the exact bearer token, and any other origin — the
 * outpost, the worker, a bare service name — is simply not an API.
 */
function authentikResponse(
  fixture: Record<string, unknown>,
  origin: string,
  token: string,
  url: URL,
  header: string | undefined,
): HttpResponse | undefined {
  if (url.origin !== origin) return undefined;

  const endpoint = url.pathname.replace(/^\/api\/v3\//, "").replace(/\/$/, "");
  if (endpoint === "root/config") return reply(200, fixture["root/config"]);
  if (header !== `Bearer ${token}`) {
    return reply(403, { detail: "Authentication credentials were not provided." });
  }

  const list = fixture[endpoint];
  if (!Array.isArray(list)) return reply(404, { detail: "Not found." });
  // A fixture states one page as a flat array and several as an array of arrays.
  const pages: unknown[][] = Array.isArray(list[0]) ? (list as unknown[][]) : [list];
  const page = Number(url.searchParams.get("page") ?? "1");
  const results: unknown[] = pages[page - 1] ?? [];
  const count = pages.reduce((n, p) => n + p.length, 0);

  // Outposts answer in the DRF envelope, everything else in Authentik's own, so
  // both branches of the pagination reader are exercised by one fixture.
  if (endpoint === "outposts/instances") {
    return reply(200, { count, next: null, previous: null, results });
  }
  return reply(200, {
    pagination: {
      next: page < pages.length ? page + 1 : 0,
      previous: page > 1 ? page - 1 : 0,
      count,
      current: page,
      total_pages: pages.length,
    },
    results,
  });
}

/**
 * Stand in for the fixture fleet's Authentik instance.
 *
 * Every request is recorded, which is what lets the test assert the *absence* of a
 * request: the token must never be sent to a candidate that failed the probe.
 */
function authentikStub(): { fetchImpl: FetchLike; calls: Recorded[] } {
  const calls: Recorded[] = [];

  const fetchImpl: FetchLike = async (url, init) => {
    const header = init?.headers?.Authorization;
    calls.push({ url, sentToken: Boolean(header) });
    return (
      authentikResponse(AK_FIXTURE, AK_ORIGIN, AK_TOKEN, new URL(url), header) ??
      reply(404, { detail: "Not found." })
    );
  };

  return { fetchImpl, calls };
}

/** Point the config loader at the stub instance — or at nothing — for the next run. */
function authentikEnv(opts: { url?: string; token?: string }): void {
  if (opts.url) process.env.LABVIEW_AUTHENTIK_URL = opts.url;
  else delete process.env.LABVIEW_AUTHENTIK_URL;
  if (opts.token) process.env.LABVIEW_AUTHENTIK_TOKEN = opts.token;
  else delete process.env.LABVIEW_AUTHENTIK_TOKEN;
}

/* -------------------------------------------------------------------------- */
/* Traefik API stub                                                           */
/* -------------------------------------------------------------------------- */

/** The container address endpoint discovery tries first, and the only one listening. */
const TF_ORIGIN_INTERNAL = "http://edge-proxy:8080";
/** The public hostname the proxy's own `api@internal` router serves. */
const TF_ORIGIN_GATED = "https://edge.example.com";
/** Where the Authentik API answers in this fleet — the outpost service. */
const TF_AK_ORIGIN = "http://authentik-outpost:9000";
/** Not credentials: arbitrary strings the stub demands verbatim. */
const TF_USER = "labview";
const TF_PASSWORD = "smoke-fixture-app-password-0000";
const TF_BASIC = `Basic ${Buffer.from(`${TF_USER}:${TF_PASSWORD}`).toString("base64")}`;
const TF_SESSION = "authentik_proxy_session=smoke-fixture-session";
const TF_FIXTURE = JSON.parse(
  readFileSync(resolve(here, "..", "fixtures", "traefik-api.json"), "utf8"),
) as Record<string, unknown>;
const TF_AK_FIXTURE = TF_FIXTURE.authentik as Record<string, unknown>;

interface TraefikStubOptions {
  /** Serve the API on the gated public hostname instead of the container address. */
  gated?: boolean;
  /** Fail `/api/entrypoints`, leaving the read partial. */
  entrypointsFail?: boolean;
}

/**
 * Stand in for the fixture fleet's proxy — and, on its own origin, for the Authentik
 * instance, because the cross-check is only meaningful when all three sources answer
 * in one run.
 *
 * Two behaviours are the point of it. Exactly one address serves the API, so every
 * other candidate discovery generated 404s as a container port with nothing on it. And
 * in `gated` mode the API sits behind the outpost: no credential, no answer, and the
 * session cookie it sets on the way in must come back on the follow-up requests, which
 * is what authentik's documentation says to expect.
 *
 * Every request is recorded with whether it carried a credential, which is what lets
 * the test assert the *absence* of one — the rule that a guessed address is probed and
 * never authenticated to cannot be checked any other way.
 */
function traefikStub(opts: TraefikStubOptions = {}): { fetchImpl: FetchLike; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const origin = opts.gated ? TF_ORIGIN_GATED : TF_ORIGIN_INTERNAL;

  const fetchImpl: FetchLike = async (url, init) => {
    const auth = init?.headers?.Authorization;
    const cookie = init?.headers?.Cookie;
    calls.push({ url, sentToken: Boolean(auth), cookie });

    const parsed = new URL(url);
    const ak = authentikResponse(TF_AK_FIXTURE, TF_AK_ORIGIN, AK_TOKEN, parsed, auth);
    if (ak) return ak;
    if (parsed.origin !== origin) return reply(404, { detail: "no such host" });

    const probing = parsed.pathname === "/api/version";
    if (opts.gated) {
      if (auth !== TF_BASIC) return reply(401, { detail: "authentication required" });
      if (!probing && cookie !== TF_SESSION) return reply(401, { detail: "session not echoed" });
    }

    if (probing) return reply(200, TF_FIXTURE.version, opts.gated ? TF_SESSION : undefined);
    if (parsed.pathname === "/api/rawdata") return reply(200, TF_FIXTURE.rawdata);
    if (parsed.pathname === "/api/entrypoints") {
      return opts.entrypointsFail
        ? reply(500, { error: "internal server error" })
        : reply(200, TF_FIXTURE.entrypoints);
    }
    return reply(404, { detail: "not found" });
  };

  return { fetchImpl, calls };
}

/** Point the config loader at the stub proxy — or at nothing — for the next run. */
function traefikEnv(opts: { enabled?: boolean; url?: string; credential?: boolean }): void {
  if (opts.enabled === false) process.env.LABVIEW_TRAEFIK_ENABLED = "false";
  else delete process.env.LABVIEW_TRAEFIK_ENABLED;
  if (opts.url) process.env.LABVIEW_TRAEFIK_URL = opts.url;
  else delete process.env.LABVIEW_TRAEFIK_URL;
  if (opts.credential) {
    process.env.LABVIEW_TRAEFIK_USERNAME = TF_USER;
    process.env.LABVIEW_TRAEFIK_PASSWORD = TF_PASSWORD;
  } else {
    delete process.env.LABVIEW_TRAEFIK_USERNAME;
    delete process.env.LABVIEW_TRAEFIK_PASSWORD;
  }
}

console.log("LabView smoke test\n");

/* ========================================================================== */
/* fixtures/apps — representative fleet                                       */
/* ========================================================================== */

const ov = await overviewFor(appsRoot);
const svc = lookup(ov);

console.log("discovery");
check("found 6 stacks", ov.stats.stacks === 6, `got ${ov.stats.stacks}`);
check("docker reported unavailable", ov.meta.dockerAvailable === false);

console.log("\ncompose parsing");
const jf = svc("jellyfin", "jellyfin");
check("jellyfin image parsed", jf.image === "jellyfin/jellyfin:10.9.11", jf.image ?? "");
check("jellyfin has published port 8096", jf.ports.some((p) => p.published === "8096" && p.target === "8096"));
check("jellyfin media bind is read-only", jf.mounts.some((m) => m.target === "/media" && m.readOnly));

console.log("\ningress classification");
check("jellyfin is public+local", jf.ingress === "public+local", jf.ingress);
check("jellyfin cloudflare hostname", jf.cloudflare[0]?.hostname === "jellyfin.example.com");
check("jellyfin traefik host", jf.traefik[0]?.hosts.includes("jellyfin.example.com") ?? false);
const emby = svc("emby", "emby");
// Tunnel origin straight at the container, plus a published host port: public
// via Cloudflare and directly answerable on the LAN, with no proxy either way.
check("emby is public+host-port (dockflare only, port published)", emby.ingress === "public+host-port", emby.ingress);
check("emby has no traefik route", emby.traefik.length === 0);

console.log("\nauth posture");
check(
  "jellyfin -> authentik forward-auth (cross-stack middleware registry)",
  jf.auth.method === "authentik-forward-auth",
  jf.auth.method,
);
check("emby exposed without auth", emby.auth.exposedWithoutAuth === true, String(emby.auth.exposedWithoutAuth));
const nc = svc("nextcloud", "nextcloud");
check("nextcloud -> authentik LDAP", nc.auth.method === "authentik-ldap", nc.auth.method);
const outline = svc("outline", "outline");
check(
  "outline -> authentik OAuth (host auto-discovered)",
  outline.auth.method === "authentik-oauth",
  outline.auth.method,
);
const akServer = svc("authentik", "server");
check("authentik server not misflagged (headers mw ignored)", akServer.auth.method !== "basic-auth", akServer.auth.method);

console.log("\nsecret masking + interpolation");
const pgPass = akServer.env.find((e) => e.key === "AUTHENTIK_POSTGRESQL__PASSWORD");
check("secret value is masked", pgPass?.masked === true && pgPass.value === null);
const ncDbPass = svc("nextcloud", "db").env.find((e) => e.key === "POSTGRES_PASSWORD");
check("db password masked", ncDbPass?.masked === true);
const ldapHost = nc.env.find((e) => e.key === "LDAP_HOST");
check("non-secret LDAP_HOST kept visible", ldapHost?.masked === false && ldapHost.value === "ldap://authentik-server:389");

console.log("\ntunnel origin resolution");
const HOP = "svc:proxy/gateway";
const outlineOrigin = outline.cloudflare[0]?.origin;
check(
  "an origin naming another service's published host port resolves to that service",
  outlineOrigin?.kind === "fleet-service" && outlineOrigin.hopKey === "proxy/gateway",
  `${outlineOrigin?.kind} ${outlineOrigin?.hopKey ?? ""}`,
);
check(
  "...on the strength of the port and the shared network, both quoted",
  (outlineOrigin?.evidence.includes("host port 443") && outlineOrigin.evidence.includes("proxy")) ?? false,
  outlineOrigin?.evidence ?? "",
);
check(
  "an origin naming this service's own host port stays direct",
  emby.cloudflare[0]?.origin?.kind === "self-host-port",
  `${emby.cloudflare[0]?.origin?.kind} — ${emby.cloudflare[0]?.origin?.evidence}`,
);
check(
  "an origin naming this service's own container stays direct",
  jf.cloudflare[0]?.origin?.kind === "self-network",
  `${jf.cloudflare[0]?.origin?.kind} — ${jf.cloudflare[0]?.origin?.evidence}`,
);
// The same host port declared over TCP and UDP is one candidate, not two rivals.
// If they were counted separately the origin above would be reported ambiguous.
check(
  "a port declared twice by one service is not a tie with itself",
  svc("proxy", "gateway").ports.filter((p) => p.published === "443").length === 2,
  String(svc("proxy", "gateway").ports.length),
);

console.log("\ngraph draws the path, not a shortcut");
const cfEdges = ov.graph.edges.filter((e) => e.kind === "ingress" && e.source === "ext:cloudflare");
check("tunnel -> proxy edge exists", cfEdges.some((e) => e.target === HOP), cfEdges.map((e) => e.target).join(","));
check(
  "proxy -> service edge exists",
  ov.graph.edges.some((e) => e.kind === "ingress" && e.source === HOP && e.target === "svc:outline/outline"),
);
// The revert-proof assertion: back the chain out and this is what fails.
check(
  "and NO direct tunnel -> service edge remains",
  !cfEdges.some((e) => e.target === "svc:outline/outline"),
  cfEdges.filter((e) => e.target === "svc:outline/outline").map((e) => e.id).join(","),
);
check(
  "the resolved hop is marked as a proxy",
  ov.graph.nodes.find((n) => n.id === HOP)?.role === "proxy",
  String(ov.graph.nodes.find((n) => n.id === HOP)?.role),
);
check(
  "the hop stays an ordinary, clickable service node",
  ov.graph.nodes.find((n) => n.id === HOP)?.kind === "service",
);
check(
  "a service whose origin resolved to itself keeps the direct edge",
  cfEdges.some((e) => e.target === "svc:emby/emby"),
);
// Outline's tunnel hostname and its proxy router describe one link between the
// same two nodes; the graph states it once.
check(
  "one hop -> service edge, not one per route",
  ov.graph.edges.filter((e) => e.source === HOP && e.target === "svc:outline/outline").length === 1,
  String(ov.graph.edges.filter((e) => e.source === HOP && e.target === "svc:outline/outline").length),
);
check(
  "the generic proxy hub is still used where no hop was resolved",
  ov.graph.edges.some((e) => e.source === "ext:traefik" && e.target === "svc:jellyfin/jellyfin"),
);

console.log("\ngraph + interconnection");
const proxyNode = ov.graph.nodes.find((n) => n.kind === "network" && n.label === "proxy");
check("shared external 'proxy' network node exists", Boolean(proxyNode));
const sharedMedia = ov.graph.nodes.find((n) => n.id === "bind:/mnt/media");
check("shared /mnt/media bind detected across jellyfin+emby", Boolean(sharedMedia));
check("cloudflare hub node exists", ov.graph.nodes.some((n) => n.id === "ext:cloudflare"));
check("authentik hub node exists", ov.graph.nodes.some((n) => n.id === "ext:authentik"));
const dependsEdges = ov.graph.edges.filter((e) => e.kind === "depends_on");
check("authentik depends_on edges present", dependsEdges.length >= 2, String(dependsEdges.length));

/* ========================================================================== */
/* fixtures/edge — regression cases                                           */
/* ========================================================================== */

const edge = await overviewFor(edgeRoot);
const eSvc = lookup(edge);

console.log("\n--- regression fixtures (fixtures/edge) ---");

console.log("\nedge discovery");
check("found 8 edge stacks", edge.stats.stacks === 8, `got ${edge.stats.stacks}`);

console.log("\ncredentials embedded in URL values");
const api = eSvc("dbstack", "api");
check(
  "DATABASE_URL password redacted, host kept",
  envValue(api, "DATABASE_URL") === "postgresql://appuser:***@db:5432/app",
  String(envValue(api, "DATABASE_URL")),
);
check("DATABASE_URL flagged as masked", api.env.find((e) => e.key === "DATABASE_URL")?.masked === true);
check(
  "REDIS_URL password redacted with empty user",
  envValue(api, "REDIS_URL") === "redis://:***@cache:6379/0",
  String(envValue(api, "REDIS_URL")),
);
check(
  "credential-free URL left untouched",
  envValue(api, "PUBLIC_ENDPOINT") === "https://api.example.com/health" &&
    api.env.find((e) => e.key === "PUBLIC_ENDPOINT")?.masked === false,
  String(envValue(api, "PUBLIC_ENDPOINT")),
);
check(
  "userinfo without a password left untouched",
  envValue(api, "SMTP_URL") === "smtp://notify@mail.example.com:587" &&
    api.env.find((e) => e.key === "SMTP_URL")?.masked === false,
  String(envValue(api, "SMTP_URL")),
);

console.log("\nenv_file containment");
check("env_file inside the stack dir is loaded", envValue(api, "LOCAL_ENV_FILE_LOADED") === "yes");
check(
  "env_file escaping the apps root is refused",
  !api.env.some((e) => e.key === "LEAKED_FROM_OUTSIDE_ROOT"),
  api.env.map((e) => e.key).join(","),
);
check(
  "refusal is surfaced as a service note",
  api.notes.some((n) => n.includes("outside the apps root")),
  api.notes.join(" | "),
);

console.log("\ndockflare enable flag");
const staged = eSvc("cfdisabled", "app");
check("dockflare.enable=false yields no route", staged.cloudflare.length === 0, String(staged.cloudflare.length));
check("...so the service is internal", staged.ingress === "internal", staged.ingress);
check("...and is not flagged exposed-without-auth", staged.auth.exposedWithoutAuth === false);
const live = eSvc("cfdisabled", "live");
check('dockflare.enable="TRUE" still enables the route', live.ingress === "public", live.ingress);

console.log("\nLDAP attribution");
const wiki = eSvc("ldapapp", "wiki");
check(
  "LDAP against a non-Authentik directory -> generic ldap",
  wiki.auth.method === "ldap",
  `${wiki.auth.method} (${wiki.auth.detail})`,
);
const bindPw = wiki.env.find((e) => e.key === "LDAP_BIND_PASSWORD");
check("LDAP bind password masked", bindPw?.masked === true && bindPw.value === null);

console.log("\nnested interpolation");
const web = eSvc("interp", "web");
check("nested default resolves the inner set var", web.image === "nginx:1.27.2", web.image ?? "");
check(
  "nested defaults fall through to the innermost literal",
  envValue(web, "DEEP_LITERAL") === "deep-literal",
  String(envValue(web, "DEEP_LITERAL")),
);
check(
  "nested default reads an inner variable",
  envValue(web, "RESOLVED_HOST") === "fallback.example.com",
  String(envValue(web, "RESOLVED_HOST")),
);
check(
  "a set outer value wins over the nested default",
  envValue(web, "PRESENT_WINS") === "1.27.2",
  String(envValue(web, "PRESENT_WINS")),
);
check(
  "$$ resolves to a literal dollar",
  envValue(web, "LITERAL_DOLLAR") === "cost is $5 per unit",
  String(envValue(web, "LITERAL_DOLLAR")),
);

console.log("\npublished host ports are reachability");
const media = eSvc("hostport", "media");
check(
  "tunnel origin at the container + published port -> public+host-port",
  media.ingress === "public+host-port",
  media.ingress,
);
check("...and is flagged exposed without auth", media.auth.exposedWithoutAuth === true);

const socketproxy = eSvc("hostport", "socketproxy");
check(
  "published port with nothing in front -> host-port, not internal",
  socketproxy.ingress === "host-port",
  socketproxy.ingress,
);
check(
  "...and is flagged exposed without auth",
  socketproxy.auth.exposedWithoutAuth === true,
  `exposedWithoutAuth=${socketproxy.auth.exposedWithoutAuth}`,
);
// socketproxy, plus the two rival proxies in `tunnelorigin` — each publishes a
// port with nothing in front of it.
check("host-port services are counted", edge.stats.hostPortServices === 3, `got ${edge.stats.hostPortServices}`);

const hpApp = eSvc("hostport", "app");
check("proxied service keeps its local kind", hpApp.ingress === "local", hpApp.ingress);
check(
  "cross-stack authentik@docker still resolves",
  hpApp.auth.method === "authentik-forward-auth",
  hpApp.auth.method,
);
check(
  "...but the host-port bypass of that SSO is noted",
  hpApp.notes.some((n) => n.includes("9999") && n.includes("bypassing")),
  hpApp.notes.join(" | "),
);

const hpWorker = eSvc("hostport", "worker");
check("expose: does not publish -> stays internal", hpWorker.ingress === "internal", hpWorker.ingress);
check(
  "...and an internal service gets no bypass note",
  hpWorker.notes.every((n) => !n.includes("bypassing")),
  hpWorker.notes.join(" | "),
);

console.log("\nan unprovable tunnel origin stays unproven");
const offsite = eSvc("tunnelorigin", "offsite");
const offsiteOrigin = offsite.cloudflare[0]?.origin;
check(
  "an origin port nothing in the scan publishes -> unresolved",
  offsiteOrigin?.kind === "unresolved" && offsiteOrigin.hopKey === undefined,
  `${offsiteOrigin?.kind} — ${offsiteOrigin?.evidence}`,
);
check(
  "...said out loud on the service",
  offsite.notes.some((n) => n.includes("Tunnel origin could not be resolved")),
  offsite.notes.join(" | "),
);
check(
  "...and the direct edge is kept rather than dropped",
  edge.graph.edges.some((e) => e.source === "ext:cloudflare" && e.target === "svc:tunnelorigin/offsite"),
);

const ambiguous = eSvc("tunnelorigin", "ambiguous");
const ambOrigin = ambiguous.cloudflare[0]?.origin;
check(
  "two reachable services claiming one host port -> unresolved, not an arbitrary winner",
  ambOrigin?.kind === "unresolved" && ambOrigin.hopKey === undefined,
  `${ambOrigin?.kind} ${ambOrigin?.hopKey ?? ""}`,
);
check(
  "...with the ambiguity itself as the stated reason",
  ambOrigin?.evidence.includes("ambiguous") ?? false,
  ambOrigin?.evidence ?? "",
);
check(
  "no hop is drawn anywhere in a fleet where none could be proven",
  !edge.graph.nodes.some((n) => n.role === "proxy"),
  edge.graph.nodes.filter((n) => n.role === "proxy").map((n) => n.id).join(","),
);
check(
  "a tunnel origin at the service's own published port is still direct",
  media.cloudflare[0]?.origin?.kind === "self-host-port",
  `${media.cloudflare[0]?.origin?.kind} — ${media.cloudflare[0]?.origin?.evidence}`,
);
check(
  "an origin naming a container by name resolves to it without a port match",
  live.cloudflare[0]?.origin?.kind === "self-network",
  `${live.cloudflare[0]?.origin?.kind} — ${live.cloudflare[0]?.origin?.evidence}`,
);

console.log("\nprovider attribution needs proof, not a name");
const opApp = eSvc("otherprovider", "app");
check(
  "third-party OIDC issuer is not attributed to Authentik",
  opApp.auth.method !== "authentik-oauth" && opApp.auth.method !== "authentik-forward-auth",
  `${opApp.auth.method} (${opApp.auth.detail})`,
);
check(
  "a resolved forwardauth address naming an unknown provider -> generic forward-auth",
  opApp.auth.method === "forward-auth",
  opApp.auth.method,
);
check(
  "...backed by the address that was actually read",
  opApp.auth.evidence.some((e) => e.includes("forwardauth -> http://gatekeeper:4180/oauth2/auth")),
  opApp.auth.evidence.join(" | "),
);
check(
  "...and an oauth2-proxy address is not read as Authentik's outpost",
  !/authentik/i.test(opApp.auth.detail),
  opApp.auth.detail,
);
check(
  "...and marked as observed, not inferred",
  opApp.auth.confidence === "observed",
  opApp.auth.confidence,
);
check(
  "...with the unidentified provider stated in the evidence",
  opApp.auth.evidence.some((e) => e.includes("provider not identified")),
  opApp.auth.evidence.join(" | "),
);
check(
  "the OIDC detection is still reported, just not as Authentik",
  opApp.auth.detail.includes("OAuth/OIDC") && opApp.auth.evidence.includes("env OIDC_ISSUER"),
  opApp.auth.detail,
);

// The pinning case: OIDC is the only signal, so no middleware detection can
// outrank a misattribution and hide it in the secondary detail. If hint matching
// goes back to bare substrings, or a `auth.`-style host convention returns to the
// defaults, `oauth.bigcorp.example.com` matches and these two fail.
const opOidc = eSvc("otherprovider", "oidconly");
check(
  "an `oauth.` issuer host is not read as Authentik",
  opOidc.auth.method === "other-oauth",
  `${opOidc.auth.method} (${opOidc.auth.detail})`,
);
check(
  "...and the report claims no provider it could not establish",
  !/authentik/i.test(opOidc.auth.detail) && opOidc.auth.evidence.some((e) => e.includes("provider not identified")),
  `${opOidc.auth.detail} | ${opOidc.auth.evidence.join(" | ")}`,
);

const opUnres = eSvc("otherprovider", "unresolved");
check(
  "an undefined auth-looking middleware is inferred, not asserted",
  opUnres.auth.method === "forward-auth" && opUnres.auth.confidence === "inferred",
  `${opUnres.auth.method}/${opUnres.auth.confidence}`,
);
check(
  "...and the unresolved definition is said out loud",
  opUnres.auth.evidence.some((e) => e.includes("definition not found")),
  opUnres.auth.evidence.join(" | "),
);
check(
  "...and surfaced as a service note",
  opUnres.notes.some((n) => n.includes("inferred from a middleware name")),
  opUnres.notes.join(" | "),
);

const opHdr = eSvc("otherprovider", "headersonly");
check(
  "an undefined header middleware is not read as an auth gate",
  opHdr.auth.method === "none",
  `${opHdr.auth.method} (${opHdr.auth.detail})`,
);
check("...so it counts as exposed without auth", opHdr.auth.exposedWithoutAuth === true);
check(
  "the identified-provider path still works alongside all of this",
  eSvc("hostport", "app").auth.method === "authentik-forward-auth",
  eSvc("hostport", "app").auth.method,
);

/* ========================================================================== */
/* fixtures/authentik — the identity provider's own records                   */
/* ========================================================================== */

console.log("\n--- identity provider API (fixtures/authentik) ---");

const discovered = authentikStub();
authentikEnv({ token: AK_TOKEN });
const ak = await overviewFor(authentikRoot, { fetchImpl: discovered.fetchImpl });
const aSvc = lookup(ak);
const akMeta = ak.meta.authentik!;

console.log("\nendpoint discovery");
check("found 9 stacks", ak.stats.stacks === 9, `got ${ak.stats.stacks}`);
check(
  "the endpoint is discovered from the fleet, not configured",
  akMeta.endpointSource === "discovered" && akMeta.endpoint === AK_ORIGIN,
  `${akMeta.endpointSource} ${akMeta.endpoint ?? ""}`,
);
// The published side of the mapping is 9443 and the public hostname is
// sso.example.com; only the container name and the *target* port give AK_ORIGIN.
check(
  "...from the container name and the target port, not the host port",
  discovered.calls.some((c) => c.url.startsWith(`${AK_ORIGIN}/api/v3/root/config/`)),
  discovered.calls.map((c) => c.url).join(" "),
);
check("the API answered and the token was accepted", akMeta.reachable === true, akMeta.error ?? "");
check("no partial-read error was reported", akMeta.error === undefined, akMeta.error ?? "");

console.log("\nthe token goes nowhere it has not been earned");
const rejected = discovered.calls.filter((c) => !c.url.startsWith(AK_ORIGIN));
check(
  "a non-API Authentik candidate was probed first",
  rejected.some((c) => c.url.startsWith("http://authentik-outpost:9000")),
  rejected.map((c) => c.url).join(" "),
);
// The revert-proof assertion for the probe-before-auth rule: send the token first
// and every one of these carries it.
check(
  "...and no candidate that failed the probe was ever sent the token",
  rejected.every((c) => !c.sentToken),
  rejected.filter((c) => c.sentToken).map((c) => c.url).join(" "),
);
check(
  "...nor asked for anything beyond the unauthenticated probe",
  rejected.every((c) => c.url.includes("/api/v3/root/config/")),
  rejected.map((c) => c.url).join(" "),
);

console.log("\nwhat was read");
check(
  "8 applications across 2 pages, 8 providers, 2 outposts",
  akMeta.applications === 8 && akMeta.providers === 8 && akMeta.outposts === 2,
  `${akMeta.applications}/${akMeta.providers}/${akMeta.outposts}`,
);
check(
  "the second page of applications was requested",
  discovered.calls.some((c) => c.url.includes("core/applications") && c.url.includes("page=2")),
  discovered.calls.filter((c) => c.url.includes("core/applications")).map((c) => c.url).join(" "),
);
check("6 of 8 applications matched a service", akMeta.matchedServices === 6, String(akMeta.matchedServices));

console.log("\nmatch 1: the provider names the service (internal host)");
const akWiki = aSvc("wiki", "wiki");
check(
  "a proxy provider's internal host resolves to the service it forwards to",
  akWiki.authentik?.applications[0]?.slug === "wiki-internal",
  akWiki.authentik?.applications.map((a) => a.slug).join(",") ?? "no match",
);
// Revert-proof for rule 1 specifically: this application's slug matches nothing and
// its launch URL is a per-user template, so no other rule can reach this service.
check(
  "...on that address, quoted as the reason",
  akWiki.authentik?.evidence[0]?.includes("forwards authenticated traffic to http://wiki:3000") ??
    false,
  akWiki.authentik?.evidence.join(" | ") ?? "",
);
check(
  "a per-user launch URL template is not matched on",
  akWiki.authentik?.applications[0]?.launchUrl === undefined,
  String(akWiki.authentik?.applications[0]?.launchUrl),
);
check(
  "the API's account of the gate is the one reported",
  akWiki.auth.method === "authentik-forward-auth" && akWiki.auth.confidence === "confirmed",
  `${akWiki.auth.method}/${akWiki.auth.confidence}`,
);
check(
  "...naming the provider, which no label could have supplied",
  akWiki.auth.detail.includes("Team wiki proxy") && akWiki.auth.detail.includes("forward_single"),
  akWiki.auth.detail,
);
check(
  "...and the middleware's weaker account is kept as evidence",
  akWiki.auth.evidence.some((e) => e.includes("middleware authentik@docker")),
  akWiki.auth.evidence.join(" | "),
);
// Only visible by holding the API's records and the compose labels side by side.
check(
  "a tunnel origin that skips the enforcing outpost is called out",
  akWiki.notes.some((n) => n.includes("never passes the outpost")),
  akWiki.notes.join(" | "),
);

console.log("\nmatch 2: a hostname both sides name");
const docs = aSvc("docs", "docs");
check(
  "an application's launch URL matches a hostname the service serves",
  docs.authentik?.applications[0]?.slug === "documentation",
  docs.authentik?.applications.map((a) => a.slug).join(",") ?? "no match",
);
// The hostname is declared for both the tunnel and the proxy. Count those as two
// rival candidates and this match is discarded as ambiguous.
check(
  "...even though it is declared for both the tunnel and the proxy",
  docs.authentik?.evidence[0]?.includes("its launch URL names docs.example.com") ?? false,
  docs.authentik?.evidence.join(" | ") ?? "",
);
check(
  "an OAuth2 provider is confirmed without any outpost",
  docs.auth.method === "authentik-oauth" && docs.auth.confidence === "confirmed",
  `${docs.auth.method}/${docs.auth.confidence}`,
);
check(
  "...served by the Authentik server itself, and said so",
  docs.auth.evidence.some((e) => e.includes("served by the Authentik server")),
  docs.auth.evidence.join(" | "),
);
check(
  "redirect URIs in the object-list form are read",
  docs.authentik?.applications[0]?.providers[0]?.redirectUris?.includes(
    "https://docs.example.com/auth/oidc/callback",
  ) ?? false,
  JSON.stringify(docs.authentik?.applications[0]?.providers[0]?.redirectUris),
);
check(
  "a backchannel SCIM provider is reported as a provider",
  docs.authentik?.applications[0]?.providers.some((p) => p.kind === "scim" && p.backchannel) ?? false,
  docs.authentik?.applications[0]?.providers.map((p) => p.kind).join(",") ?? "",
);
// SCIM provisions outbound and gates nothing, so "no outpost serves it" would be a
// finding about a provider that never wanted one.
check(
  "...but not as a gate missing its outpost",
  docs.notes.every((n) => !n.includes("no outpost serving it")),
  docs.notes.join(" | "),
);

const metrics = aSvc("metrics", "metrics");
check(
  "an application with no launch URL matches on a redirect URI",
  metrics.authentik?.applications[0]?.slug === "metrics-dash",
  metrics.authentik?.applications.map((a) => a.slug).join(",") ?? "no match",
);
check(
  "...read from the newline-delimited string form",
  metrics.authentik?.evidence[0]?.includes("a redirect URI") ?? false,
  metrics.authentik?.evidence.join(" | ") ?? "",
);

console.log("\nmatch 3: the slug, when it points at exactly one service");
const vault = aSvc("vault", "vault");
check(
  "a slug equal to the stack/service name matches",
  vault.authentik?.applications[0]?.slug === "vault" &&
    (vault.authentik?.evidence[0]?.includes('slug "vault"') ?? false),
  vault.authentik?.evidence.join(" | ") ?? "no match",
);
// Read only the primary `provider` field and this service has no gate at all.
check(
  "a backchannel LDAP provider is found and its outpost with it",
  vault.authentik?.applications[0]?.providers[0]?.kind === "ldap" &&
    (vault.authentik?.applications[0]?.providers[0]?.outposts.includes("LDAP outpost") ?? false),
  JSON.stringify(vault.authentik?.applications[0]?.providers),
);
check(
  "...and it is the reported posture",
  vault.auth.method === "authentik-ldap" && vault.auth.confidence === "confirmed",
  `${vault.auth.method}/${vault.auth.confidence}`,
);

console.log("\nan ambiguous slug is discarded, not arbitrated");
check(
  "a slug naming a two-service stack matches neither",
  aSvc("pair", "blue").authentik === undefined && aSvc("pair", "green").authentik === undefined,
  JSON.stringify([aSvc("pair", "blue").authentik, aSvc("pair", "green").authentik]),
);
check(
  "...and is reported as an application LabView could not place",
  akMeta.unmatchedApplications.includes("pair"),
  akMeta.unmatchedApplications.join(","),
);

console.log("\na shared authentication domain identifies no single service");
// In forward_domain mode `external_host` is the domain every application in it
// authenticates against — here the identity provider's own hostname, which exactly
// one service serves. Match on it and this application is pinned to the Authentik
// server, and with it a gate that has nothing to do with that service.
check(
  "a forward_domain external host is not read as an application hostname",
  aSvc("idp", "server").authentik === undefined,
  JSON.stringify(aSvc("idp", "server").authentik),
);
check(
  "...leaving the application unplaced rather than misplaced",
  akMeta.unmatchedApplications.includes("broad-app") &&
    akMeta.unmatchedApplications.length === 2,
  akMeta.unmatchedApplications.join(","),
);

console.log("\na provider no outpost serves enforces nothing");
const orphan = aSvc("orphan", "orphan");
check(
  "the application still matches — the provider names the service",
  orphan.authentik?.applications[0]?.slug === "orphan-ui",
  orphan.authentik?.applications.map((a) => a.slug).join(",") ?? "no match",
);
// The whole point of reading the API: Authentik's own UI lists an application with
// a proxy provider here, and a reader would call this service protected.
check(
  "...but an unserved proxy provider is not reported as protection",
  orphan.auth.method === "none" && orphan.auth.exposedWithoutAuth === true,
  `${orphan.auth.method} exposed=${orphan.auth.exposedWithoutAuth}`,
);
check(
  "...with the reason stated on the service",
  orphan.notes.some((n) => n.includes("no outpost serving it")),
  orphan.notes.join(" | "),
);
check(
  "...and no bypass claimed for a gate that was never standing anywhere",
  orphan.notes.every((n) => !n.includes("never passes the outpost")),
  orphan.notes.join(" | "),
);
check(
  "the provider is still shown, marked as serving nothing",
  orphan.auth.evidence.some((e) => e.includes("no outpost serves it, so it enforces nothing")),
  orphan.auth.evidence.join(" | "),
);

console.log("\na confirmed gate with no method to report it as");
const reports = aSvc("reports", "reports");
check(
  "a SAML application matches its service",
  reports.authentik?.applications[0]?.providers[0]?.kind === "saml",
  JSON.stringify(reports.authentik?.applications[0]?.providers),
);
// SAML has no AuthMethod (and no colour left in the palette), so the method stays
// `none` — but calling the service unprotected would be a plain falsehood.
check(
  "...and is not counted as reachable without authentication",
  reports.auth.method === "none" && reports.auth.exposedWithoutAuth === false,
  `${reports.auth.method} exposed=${reports.auth.exposedWithoutAuth}`,
);
check(
  "...with the provider stated verbatim instead",
  reports.auth.evidence.some((e) => e.includes('SAML Provider "Reports SAML"')),
  reports.auth.evidence.join(" | "),
);

console.log("\nendpoint from configuration");
const configured = authentikStub();
authentikEnv({ url: AK_ORIGIN, token: AK_TOKEN });
const akCfg = await overviewFor(authentikRoot, { fetchImpl: configured.fetchImpl });
check(
  "a configured URL is used as given",
  akCfg.meta.authentik?.endpointSource === "config" && akCfg.meta.authentik?.endpoint === AK_ORIGIN,
  `${akCfg.meta.authentik?.endpointSource} ${akCfg.meta.authentik?.endpoint ?? ""}`,
);
check(
  "...and nothing else in the fleet is probed",
  configured.calls.every((c) => c.url.startsWith(AK_ORIGIN)),
  configured.calls.filter((c) => !c.url.startsWith(AK_ORIGIN)).map((c) => c.url).join(" "),
);
check(
  "...reaching the same conclusions",
  akCfg.meta.authentik?.matchedServices === 6,
  String(akCfg.meta.authentik?.matchedServices),
);

console.log("\nwithout a token the integration is inert");
const untouched = authentikStub();
authentikEnv({});
const akOff = await overviewFor(authentikRoot, { fetchImpl: untouched.fetchImpl });
const offSvc = lookup(akOff);
check("no token means no request at all", untouched.calls.length === 0, String(untouched.calls.length));
check(
  "...and no error either — unconfigured is not broken",
  akOff.meta.authentik?.configured === false && akOff.meta.authentik?.error === undefined,
  akOff.meta.authentik?.error ?? "",
);
check(
  "...so no service carries provider records",
  akOff.stacks.every((s) => s.services.every((x) => x.authentik === undefined)),
);

// The pair of numbers that shows what the API actually changed. Both must move: the
// first because two gates only the API can see stop counting as absent, the second
// because a label-only read cannot see them at all.
console.log("\nwhat the provider's records are worth");
check(
  "with the API read, 4 services are reachable without auth",
  ak.stats.exposedWithoutAuth === 4,
  String(ak.stats.exposedWithoutAuth),
);
check(
  "...and 6 without it",
  akOff.stats.exposedWithoutAuth === 6,
  String(akOff.stats.exposedWithoutAuth),
);
check(
  "a label-derived gate is still found on its own, just as `observed`",
  offSvc("wiki", "wiki").auth.method === "authentik-forward-auth" &&
    offSvc("wiki", "wiki").auth.confidence === "observed",
  `${offSvc("wiki", "wiki").auth.method}/${offSvc("wiki", "wiki").auth.confidence}`,
);

console.log("\nan unreachable provider never blocks a scan");
const failing: FetchLike = async () => {
  throw new Error("ECONNREFUSED");
};
authentikEnv({ url: AK_ORIGIN, token: AK_TOKEN });
const akDown = await overviewFor(authentikRoot, { fetchImpl: failing });
check(
  "the failure is reported rather than thrown",
  akDown.meta.authentik?.configured === true && akDown.meta.authentik?.reachable === false,
  JSON.stringify(akDown.meta.authentik),
);
check(
  "...with the reason kept and no credential in it",
  (akDown.meta.authentik?.error?.includes("no Authentik API endpoint answered") ?? false) &&
    !akDown.meta.authentik!.error!.includes(AK_TOKEN),
  akDown.meta.authentik?.error ?? "",
);
check(
  "...and the whole fleet is still analyzed from its labels",
  akDown.stats.stacks === 9 && akDown.stats.services === 13,
  `${akDown.stats.stacks}/${akDown.stats.services}`,
);
authentikEnv({});

/* ========================================================================== */
/* fixtures/traefik — the reverse proxy's own runtime configuration           */
/* ========================================================================== */

console.log("\n--- reverse proxy API (fixtures/traefik) ---");

/** Requests that went to the proxy rather than to Authentik, which shares the stub. */
const proxyCalls = (calls: Recorded[]) => calls.filter((c) => !c.url.includes("/api/v3/"));

const internal = traefikStub();
traefikEnv({});
authentikEnv({ token: AK_TOKEN });
const tf = await overviewFor(traefikRoot, { fetchImpl: internal.fetchImpl });
const tSvc = lookup(tf);
const tfMeta = tf.meta.traefik!;

console.log("\nendpoint discovery");
check("found 12 stacks, 12 services", tf.stats.stacks === 12 && tf.stats.services === 12, `${tf.stats.stacks}/${tf.stats.services}`);
check(
  "the endpoint is discovered from the fleet, not configured",
  tfMeta.endpointSource === "discovered" && tfMeta.endpoint === TF_ORIGIN_INTERNAL,
  `${tfMeta.endpointSource} ${tfMeta.endpoint ?? ""}`,
);
// Nothing in the fixture publishes 8080 and no label mentions it: the candidate exists
// because a router on this container targets `api@internal`, and 8080 is the port the
// dedicated `traefik` entrypoint serves the API on.
check(
  "...the container address on the API's own port is tried first",
  proxyCalls(internal.calls)[0]?.url === `${TF_ORIGIN_INTERNAL}/api/version`,
  proxyCalls(internal.calls)[0]?.url ?? "no request",
);
check(
  "...and the public hostname is never reached, since an internal one answered",
  proxyCalls(internal.calls).every((c) => !c.url.startsWith(TF_ORIGIN_GATED)),
  proxyCalls(internal.calls).filter((c) => c.url.startsWith(TF_ORIGIN_GATED)).map((c) => c.url).join(" "),
);
check("the API answered", tfMeta.reachable === true, tfMeta.error ?? "");
// PascalCase in the payload: read case-insensitively or this is undefined.
check("...reporting its version", tfMeta.version === "3.1.2", String(tfMeta.version));
check(
  "...with no credential, which is the answer to whether the API is open",
  tfMeta.credential === "none",
  tfMeta.credential,
);
check("...and both reads completed", tfMeta.entrypointsRead === true && tfMeta.error === undefined, tfMeta.error ?? "");

console.log("\nwhat was read");
check(
  "10 routers, 5 middlewares, 10 services",
  tfMeta.routers === 10 && tfMeta.middlewares === 5 && tfMeta.services === 10,
  `${tfMeta.routers}/${tfMeta.middlewares}/${tfMeta.services}`,
);
check("8 services matched a live router", tfMeta.matchedServices === 8, String(tfMeta.matchedServices));
// The mirror of `unmatchedApplications`: ingress configured outside the scanned stacks.
// `standalone@file` belongs to nothing scanned; `twin-blue@file` matches two services,
// which is a match not made rather than a match to arbitrate.
check(
  "the two routers no single service could be identified for are listed",
  JSON.stringify(tfMeta.unmatchedRouters) === JSON.stringify(["standalone@file", "twin-blue@file"]),
  JSON.stringify(tfMeta.unmatchedRouters),
);
check(
  "...and neither twin was credited with the hostname both claim",
  tSvc("twin-a", "blue").traefikLive === undefined && tSvc("twin-b", "green").traefikLive === undefined,
  `${tSvc("twin-a", "blue").traefikLive?.length ?? 0}/${tSvc("twin-b", "green").traefikLive?.length ?? 0}`,
);

console.log("\na file-provider middleware the scan cannot see");
const tfDocs = tSvc("docs", "docs");
// The gap this feature closes. `secured@file` is defined in a Traefik file provider,
// so a label-only read has nothing but its name — which does not even look like auth.
check(
  "a chain wrapping a forward-auth is a confirmed Authentik gate",
  tfDocs.auth.method === "authentik-forward-auth" && tfDocs.auth.confidence === "confirmed",
  `${tfDocs.auth.method}/${tfDocs.auth.confidence}`,
);
check(
  "...reached through the chain, which is stated as how it was found",
  tfDocs.auth.evidence.some((e) => e.includes("`sso@file`") && e.includes("via chain `secured@file`")),
  tfDocs.auth.evidence.join(" | "),
);
// Backend health is the proxy's own last observation, obtainable from nothing else.
check(
  "a backend the proxy cannot reach is reported DOWN",
  tfDocs.notes.some((n) => n.includes("DOWN for router(s)") && n.includes("http://docs-site:8080")),
  tfDocs.notes.join(" | "),
);

console.log("\nthe downgrade, and the guard on it");
const tfDash = tSvc("dashboards", "dashboards");
// The one finding that moves a service *towards* exposed. The label declares a gate;
// the proxy built no chain for that router at all.
check(
  "a declared gate the proxy never attached stops counting as protection",
  tfDash.auth.method === "none" && tfDash.auth.exposedWithoutAuth === true,
  `${tfDash.auth.method} exposed=${tfDash.auth.exposedWithoutAuth}`,
);
check(
  "...with both accounts named and the live one said to be the one that enforces",
  tfDash.notes.some(
    (n) =>
      n.includes("declares auth middleware `authentik@file`") &&
      n.includes("the chain Traefik built for it is empty") &&
      n.includes("follows it and not the label"),
  ),
  tfDash.notes.join(" | "),
);
const tfMetrics = tSvc("metrics", "metrics");
// Same label, same empty router chain — but its entrypoint carries the gate, which
// appears in no router's middleware list. Drop the entrypoint merge and this service
// is reported wide open while it is in fact protected.
check(
  "a gate attached to the entrypoint is not mistaken for an absent one",
  tfMetrics.auth.method === "authentik-forward-auth" && tfMetrics.auth.confidence === "confirmed",
  `${tfMetrics.auth.method}/${tfMetrics.auth.confidence}`,
);
check(
  "...and is credited to the entrypoint it is attached to",
  tfMetrics.auth.evidence.some((e) => e.includes("on entrypoint secure")),
  tfMetrics.auth.evidence.join(" | "),
);
check(
  "...with no discrepancy claimed",
  !tfMetrics.notes.some((n) => n.includes("declares auth middleware")),
  tfMetrics.notes.join(" | "),
);

console.log("\nrouters the labels and the proxy disagree about the existence of");
const tfBlog = tSvc("blog", "blog");
check(
  "a label router the proxy serves no counterpart for is reported absent",
  tfBlog.notes.some((n) => n.includes("`blog`") && n.includes("the proxy is serving no router by that name")),
  tfBlog.notes.join(" | "),
);
// The absent check runs against every router in the snapshot, not just the matched
// ones: `twin-blue` demonstrably exists, LabView merely could not attribute it.
check(
  "...while a router that exists but could not be attributed is not",
  !tSvc("twin-a", "blue").notes.some((n) => n.includes("serving no router by that name")),
  tSvc("twin-a", "blue").notes.join(" | "),
);
check(
  "...and one that really is missing still is",
  tSvc("twin-b", "green").notes.some((n) => n.includes("serving no router by that name")),
  tSvc("twin-b", "green").notes.join(" | "),
);
const tfLegacy = tSvc("legacy", "legacy");
// A router Traefik is holding but not serving. Its chain names an auth middleware, and
// counting that as protection would be a gate on a road nobody drives.
check(
  "a disabled, errored router is quoted verbatim and protects nothing",
  tfLegacy.notes.some((n) => n.includes("Traefik is not serving router `legacy@docker`")) &&
    tfLegacy.notes.some((n) => n.includes('middleware "authentik@file" does not exist')) &&
    tfLegacy.auth.method === "none",
  `${tfLegacy.auth.method} | ${tfLegacy.notes.join(" | ")}`,
);

console.log("\nthree accounts of one gate");
const tfWiki = tSvc("wiki", "wiki");
check(
  "labels, proxy and identity provider agreeing is stated as such",
  tfWiki.notes.some(
    (n) => n.includes("The labels, the proxy and Authentik agree") && n.includes('application "Wiki"'),
  ),
  tfWiki.notes.join(" | "),
);
// The forward-auth address is resolved back to a scanned service, so the note can say
// *which* service authenticates rather than quoting a URL at the reader.
check(
  "...naming the service the proxy delegates the decision to",
  tfWiki.notes.some((n) => n.includes("(which is sso/outpost)")),
  tfWiki.notes.join(" | "),
);
const tfCrm = tSvc("crm", "crm");
// Neither source reveals this alone: Authentik reports a healthy outpost either way,
// and the proxy has no idea a provider was meant to be in the chain.
check(
  "a forward-auth provider with no forward-auth in the live chain is the finding",
  tfCrm.notes.some((n) => n.includes("never reaches the outpost") && n.includes("`forward_single`")),
  tfCrm.notes.join(" | "),
);
const tfShop = tSvc("shop", "shop");
check(
  "...but a `proxy`-mode provider is exempt: the outpost is the backend, not a callee",
  !tfShop.notes.some((n) => n.includes("never reaches the outpost")) &&
    tfShop.auth.method === "authentik-forward-auth",
  `${tfShop.auth.method} | ${tfShop.notes.join(" | ")}`,
);
check(
  "3 Authentik applications matched a service in this fleet",
  tf.meta.authentik?.matchedServices === 3,
  String(tf.meta.authentik?.matchedServices),
);

console.log("\nthe proxy itself");
const tfEdge = tSvc("edge", "traefik");
check(
  "its own dashboard's basicAuth is confirmed from the live chain",
  tfEdge.auth.method === "basic-auth" && tfEdge.auth.confidence === "confirmed",
  `${tfEdge.auth.method}/${tfEdge.auth.confidence}`,
);
// The direct answer to "I don't know whether `api.insecure` is on" — reported because
// the read succeeded without a credential, not because anything was configured.
check(
  "an API that answered unauthenticated is reported on the service that serves it",
  tfEdge.notes.some((n) => n.includes(`answered at ${TF_ORIGIN_INTERNAL} with no credential`)),
  tfEdge.notes.join(" | "),
);
check(
  "a router the proxy confirmed is drawn from the proxy, not from the generic hub",
  tf.graph.edges.find((e) => e.id === "live->svc:docs/docs:docs@docker")?.source === "svc:edge/traefik",
  JSON.stringify(tf.graph.edges.find((e) => e.id === "live->svc:docs/docs:docs@docker")),
);
check(
  "...and that service is marked as the proxy",
  tf.graph.nodes.find((n) => n.id === "svc:edge/traefik")?.role === "proxy",
);

// A container IP and a published host port are addresses of entirely different kinds,
// and reading one through the other's table gives a confident wrong answer. Asserted
// directly: a container IP only exists in live docker state, which smoke runs without.
console.log("\nthe container-IP trap");
const trapState: DockerState = {
  id: "0000000000000000000000000000000000000000000000000000000000000000",
  name: "docs-site",
  image: "ghcr.io/example/docs:1",
  state: "running",
  status: "Up 1 hour",
  running: true,
  networks: ["proxy"],
  ipAddresses: { proxy: "172.31.0.7" },
  publishedPorts: [],
};
tSvc("docs", "docs").docker = trapState;
const trapIndex = buildFleetIndex(tf.stacks);
const backend = "http://172.31.0.7:3000";
check(
  "a backend on a container IP resolves through the container-IP table",
  lookupContainerAddress(backend, trapIndex).map((r) => `${r.stackId}/${r.serviceName}`).join(",") ===
    "docs/docs",
  lookupContainerAddress(backend, trapIndex).map((r) => `${r.stackId}/${r.serviceName}`).join(","),
);
// The reason it needs its own table: the published-port table answers, and is wrong.
check(
  "...where the published-port table would have named the wrong service entirely",
  lookupAddress(backend, trapIndex).map((r) => `${r.stackId}/${r.serviceName}`).join(",") === "wiki/wiki",
  lookupAddress(backend, trapIndex).map((r) => `${r.stackId}/${r.serviceName}`).join(","),
);
// And that the matcher reads the right one. Asserted on the matcher rather than on the
// lookup, because the two checks above pass whichever table the call site uses; only
// this one fails if it is swapped. The router is deliberately unmatchable by any other
// rule: a `file` provider excludes the router-name rule, and no rule means no hostname.
const trapRouter: TraefikLiveRouter = {
  router: "ip-form-backend",
  provider: "file",
  errors: [],
  hosts: [],
  entryPoints: ["websecure"],
  middlewares: [],
  servers: [{ url: backend }],
  tls: true,
  evidence: [],
};
// Cleared first, because the pipeline run above already attached the routers it matched
// and this asserts what *this* call does, not what is left over from that one.
tSvc("docs", "docs").traefikLive = undefined;
tSvc("wiki", "wiki").traefikLive = undefined;
matchTraefik(tf.stacks, [trapRouter], trapIndex);
const trapAttached = (stack: string, svc: string): string =>
  (tSvc(stack, svc).traefikLive ?? []).map((r) => r.router).join(",");
check(
  "...and the matcher attributes such a backend to the container, not to the port's owner",
  trapAttached("docs", "docs") === "ip-form-backend" && trapAttached("wiki", "wiki") === "",
  `docs=[${trapAttached("docs", "docs")}] wiki=[${trapAttached("wiki", "wiki")}]`,
);

console.log("\na credential goes nowhere ownership was not established");
const withCred = traefikStub();
traefikEnv({ credential: true });
authentikEnv({ token: AK_TOKEN });
const tfCred = await overviewFor(traefikRoot, { fetchImpl: withCred.fetchImpl });
check(
  "an internal endpoint that answers is used with no credential at all",
  tfCred.meta.traefik?.credential === "none" && tfCred.meta.traefik?.endpoint === TF_ORIGIN_INTERNAL,
  `${tfCred.meta.traefik?.credential} ${tfCred.meta.traefik?.endpoint ?? ""}`,
);
// The revert-proof assertion for the probe-before-credential rule: authenticate the
// probe and every one of these carries Basic.
check(
  "...so nothing sent to the proxy carried one",
  proxyCalls(withCred.calls).every((c) => !c.sentToken),
  proxyCalls(withCred.calls).filter((c) => c.sentToken).map((c) => c.url).join(" "),
);
check(
  "...and the public hostname was never contacted",
  withCred.calls.every((c) => !c.url.startsWith(TF_ORIGIN_GATED)),
  withCred.calls.filter((c) => c.url.startsWith(TF_ORIGIN_GATED)).map((c) => c.url).join(" "),
);

console.log("\na gated API, reached with the credential it demands");
const gated = traefikStub({ gated: true });
traefikEnv({ credential: true });
authentikEnv({ token: AK_TOKEN });
const tfGated = await overviewFor(traefikRoot, { fetchImpl: gated.fetchImpl });
const gatedMeta = tfGated.meta.traefik!;
check(
  "the one hostname the API's own router serves is used, with Basic",
  gatedMeta.endpoint === TF_ORIGIN_GATED && gatedMeta.credential === "basic" && gatedMeta.reachable === true,
  `${gatedMeta.endpoint ?? ""} ${gatedMeta.credential} ${gatedMeta.error ?? ""}`,
);
const gatedProbes = gated.calls.filter((c) => c.url === `${TF_ORIGIN_GATED}/api/version`);
check(
  "...probed unauthenticated first, then retried once with the credential",
  gatedProbes.length === 2 && gatedProbes[0]?.sentToken === false && gatedProbes[1]?.sentToken === true,
  gatedProbes.map((c) => `${c.sentToken}`).join(","),
);
// The outpost sets a session cookie and expects it echoed; without replaying it the
// follow-up reads are rejected even though the credential is right.
check(
  "...with the session cookie the outpost set replayed on the reads that follow",
  gated.calls
    .filter((c) => c.url.startsWith(TF_ORIGIN_GATED) && !c.url.endsWith("/api/version"))
    .every((c) => c.cookie === TF_SESSION),
  gated.calls.filter((c) => c.url.startsWith(TF_ORIGIN_GATED)).map((c) => `${c.url} ${c.cookie ?? "-"}`).join(" | "),
);
check(
  "...and the guessed container addresses were probed but never authenticated to",
  proxyCalls(gated.calls)
    .filter((c) => !c.url.startsWith(TF_ORIGIN_GATED))
    .every((c) => !c.sentToken && c.url.endsWith("/api/version")),
  proxyCalls(gated.calls).filter((c) => !c.url.startsWith(TF_ORIGIN_GATED)).map((c) => `${c.url} ${c.sentToken}`).join(" | "),
);
check(
  "...reaching the same conclusions as the internal endpoint",
  gatedMeta.matchedServices === 8 && tfGated.stats.exposedWithoutAuth === tf.stats.exposedWithoutAuth,
  `${gatedMeta.matchedServices} ${tfGated.stats.exposedWithoutAuth}`,
);
// The unauthenticated-API note is evidence, not decoration: it must not appear when
// the API in fact demanded a credential.
check(
  "...and the open-API note is absent, because the API was not open",
  !lookup(tfGated)("edge", "traefik").notes.some((n) => n.includes("with no credential")),
  lookup(tfGated)("edge", "traefik").notes.join(" | "),
);

console.log("\nendpoint from configuration");
const cfgEndpoint = traefikStub();
traefikEnv({ url: TF_ORIGIN_INTERNAL });
authentikEnv({ token: AK_TOKEN });
const tfCfg = await overviewFor(traefikRoot, { fetchImpl: cfgEndpoint.fetchImpl });
check(
  "a configured URL is used as given",
  tfCfg.meta.traefik?.endpointSource === "config" && tfCfg.meta.traefik?.endpoint === TF_ORIGIN_INTERNAL,
  `${tfCfg.meta.traefik?.endpointSource} ${tfCfg.meta.traefik?.endpoint ?? ""}`,
);
check(
  "...and nothing else in the fleet is probed",
  proxyCalls(cfgEndpoint.calls).every((c) => c.url.startsWith(TF_ORIGIN_INTERNAL)),
  proxyCalls(cfgEndpoint.calls).filter((c) => !c.url.startsWith(TF_ORIGIN_INTERNAL)).map((c) => c.url).join(" "),
);
check("...reaching the same conclusions", tfCfg.meta.traefik?.matchedServices === 8, String(tfCfg.meta.traefik?.matchedServices));
// A hand-written URL carries no service key, so the proxy has to be identified from
// the address itself for its own notes and for the graph to draw live routes from it.
check(
  "...and the proxy is still identified from the address it names",
  lookup(tfCfg)("edge", "traefik").notes.some((n) => n.includes("with no credential")),
  lookup(tfCfg)("edge", "traefik").notes.join(" | "),
);

console.log("\na partial read concludes nothing about a missing gate");
const partial = traefikStub({ entrypointsFail: true });
traefikEnv({});
authentikEnv({ token: AK_TOKEN });
const tfPartial = await overviewFor(traefikRoot, { fetchImpl: partial.fetchImpl });
const pSvc = lookup(tfPartial);
check(
  "the runtime config is still read, and the gap is reported",
  tfPartial.meta.traefik?.reachable === true &&
    tfPartial.meta.traefik?.entrypointsRead === false &&
    (tfPartial.meta.traefik?.error?.includes("/api/entrypoints could not be read") ?? false),
  tfPartial.meta.traefik?.error ?? "",
);
// Without the entrypoints an attached gate is invisible, so calling the label wrong
// would invert the finding. The discrepancy is printed; the posture does not move.
check(
  "the declared gate is still counted, and the discrepancy reported rather than acted on",
  pSvc("dashboards", "dashboards").auth.method === "authentik-forward-auth" &&
    pSvc("dashboards", "dashboards").auth.exposedWithoutAuth === false &&
    pSvc("dashboards", "dashboards").notes.some((n) => n.includes("reported rather than acted on")),
  `${pSvc("dashboards", "dashboards").auth.method} | ${pSvc("dashboards", "dashboards").notes.join(" | ")}`,
);
check(
  "...and a gate only the entrypoints could have confirmed falls back to the label",
  pSvc("metrics", "metrics").auth.confidence === "inferred",
  pSvc("metrics", "metrics").auth.confidence,
);
check(
  "...and the Authentik cross-check makes no claim either",
  !pSvc("crm", "crm").notes.some((n) => n.includes("never reaches the outpost")),
  pSvc("crm", "crm").notes.join(" | "),
);

console.log("\nan unreachable proxy never blocks a scan");
const throwing: FetchLike = async () => {
  throw new Error("ECONNREFUSED");
};
traefikEnv({ url: TF_ORIGIN_INTERNAL, credential: true });
authentikEnv({});
const tfDown = await overviewFor(traefikRoot, { fetchImpl: throwing });
check(
  "the failure is reported rather than thrown",
  tfDown.meta.traefik?.configured === true && tfDown.meta.traefik?.reachable === false,
  JSON.stringify(tfDown.meta.traefik),
);
check(
  "...with the reason kept and no credential in it",
  (tfDown.meta.traefik?.error?.includes("no Traefik API endpoint answered") ?? false) &&
    !tfDown.meta.traefik!.error!.includes(TF_PASSWORD) &&
    !tfDown.meta.traefik!.error!.includes(TF_BASIC),
  tfDown.meta.traefik?.error ?? "",
);
check(
  "...and the whole fleet is still analyzed from its labels",
  tfDown.stats.stacks === 12 &&
    tfDown.stats.services === 12 &&
    lookup(tfDown)("dashboards", "dashboards").auth.method === "authentik-forward-auth",
  `${tfDown.stats.stacks}/${tfDown.stats.services}`,
);

// Both reasons below say what to *fix*, which is the whole value of a soft failure.
// `fetch` reports a name that does not resolve and a service that is not listening with
// the same opaque message, and those call for opposite fixes.
const opaque: FetchLike = async () => {
  throw Object.assign(new Error("fetch failed"), { cause: { code: "ENOTFOUND" } });
};
traefikEnv({ url: TF_ORIGIN_INTERNAL, credential: true });
const tfDns = await overviewFor(traefikRoot, { fetchImpl: opaque });
check(
  "a transport failure keeps the reason `fetch` hid in `cause`",
  tfDns.meta.traefik?.error?.includes("ENOTFOUND") === true,
  tfDns.meta.traefik?.error ?? "",
);
// The likeliest real outcome of pointing this at a gated hostname: the login page is
// served with a 200, so only the body gives it away.
const loginPage: FetchLike = async () => ({
  ok: true,
  status: 200,
  json: async () => {
    throw new SyntaxError("Unexpected token '<', \"<!DOCTYPE \"... is not valid JSON");
  },
});
const tfHtml = await overviewFor(traefikRoot, { fetchImpl: loginPage });
check(
  "an HTML answer is reported as one, not as a JSON parser error",
  tfHtml.meta.traefik?.error?.includes("the body was not JSON") === true &&
    !tfHtml.meta.traefik!.error!.includes("Unexpected token"),
  tfHtml.meta.traefik?.error ?? "",
);
check(
  "...and it is not mistaken for a Traefik API, so no credential follows it",
  tfHtml.meta.traefik?.reachable === false && tfHtml.meta.traefik?.credential === "none",
  `${tfHtml.meta.traefik?.reachable} ${tfHtml.meta.traefik?.credential}`,
);

console.log("\nwithout the API the integration is inert");
const idle = traefikStub();
traefikEnv({ enabled: false });
authentikEnv({});
const tfOff = await overviewFor(traefikRoot, { fetchImpl: idle.fetchImpl });
const oSvc = lookup(tfOff);
check("disabled means no request at all", idle.calls.length === 0, String(idle.calls.length));
check(
  "...and no service carries live routers",
  tfOff.stacks.every((s) => s.services.every((x) => x.traefikLive === undefined)),
);
check(
  "...so a label router is drawn from the generic hub instead of a proxy",
  tfOff.graph.edges.find((e) => e.id === "tr->svc:docs/docs:docs")?.source === "ext:traefik",
  JSON.stringify(tfOff.graph.edges.find((e) => e.id === "tr->svc:docs/docs:docs")),
);

// The pair of numbers that shows what reading the proxy is worth, and that it moves in
// both directions: gates only the proxy can see stop counting as absent, and gates the
// labels claim that it never attached stop counting as present.
console.log("\nwhat the proxy's runtime configuration is worth");
check(
  "with the API read, 4 services are reachable without auth and 7 are protected",
  tf.stats.exposedWithoutAuth === 4 && tf.stats.authProtected === 7,
  `${tf.stats.exposedWithoutAuth}/${tf.stats.authProtected}`,
);
check(
  "...and from the labels alone, 6 and 5",
  tfOff.stats.exposedWithoutAuth === 6 && tfOff.stats.authProtected === 5,
  `${tfOff.stats.exposedWithoutAuth}/${tfOff.stats.authProtected}`,
);
check(
  "a file-provider middleware is unclassifiable from its name alone",
  oSvc("docs", "docs").auth.method === "none" && oSvc("docs", "docs").auth.exposedWithoutAuth === true,
  `${oSvc("docs", "docs").auth.method} exposed=${oSvc("docs", "docs").auth.exposedWithoutAuth}`,
);
check(
  "...and a label-named one is only ever `inferred`",
  oSvc("metrics", "metrics").auth.method === "authentik-forward-auth" &&
    oSvc("metrics", "metrics").auth.confidence === "inferred",
  `${oSvc("metrics", "metrics").auth.method}/${oSvc("metrics", "metrics").auth.confidence}`,
);
traefikEnv({ enabled: false });
authentikEnv({});

/* ========================================================================== */
/* connection diagnostics — why a read failed, for every target               */
/* ========================================================================== */

/*
 * "unreachable" is one word for a dozen different fixes, so each of them is pinned
 * here. Every assertion below is written to fail if its distinction is removed: merging
 * 401 into 403, or an inaccessible socket into a refused connection, produces a report
 * that is still plausible and sends the operator to the wrong place — which is exactly
 * the failure mode a test has to catch, because nothing else will.
 *
 * No daemon, no network and no Authentik: the HTTP paths go through the injectable
 * `fetchImpl`, the socket paths through real files under `os.tmpdir()`, and the one TCP
 * assertion dials a closed port on loopback.
 */
const { phaseForCode, phaseForStatus, getJson } = await import("../src/enrich/http.js");
const { probeSocketPath, phaseForSocket, classifyDockerError, snapshotDocker } = await import(
  "../src/enrich/docker.js"
);
const {
  changedConnections,
  rememberConnections,
  dominantPhase,
  formatConnection,
  hintFor,
  shouldBanner,
} = await import("../src/model/connections.js");
const { createServer } = await import("node:net");
// The unreadable-socket case is driven through `phaseForSocket` on a literal probe
// rather than by chmod-ing a real one: a test running as root can open any socket
// regardless of its mode, so the filesystem would refuse to reproduce the situation.
const { mkdtempSync, writeFileSync } = await import("node:fs");
const { tmpdir } = await import("node:os");

console.log("\na transport failure names the stage, not just `fetch failed`");
for (const [code, phase] of [
  ["ENOTFOUND", "resolve"],
  ["EAI_AGAIN", "resolve"],
  ["ECONNREFUSED", "connect"],
  ["EHOSTUNREACH", "connect"],
  ["DEPTH_ZERO_SELF_SIGNED_CERT", "tls"],
  ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "tls"],
  ["CERT_HAS_EXPIRED", "tls"],
  ["ERR_TLS_CERT_ALTNAME_INVALID", "tls"],
  ["ETIMEDOUT", "timeout"],
  ["UND_ERR_HEADERS_TIMEOUT", "timeout"],
] as const) {
  check(`${code} → ${phase}`, phaseForCode(code) === phase, phaseForCode(code));
}
// The generalisation is deliberate and has to stay one: an unknown code means the
// connection did not come up, which is true and carries the code alongside it.
check("an unknown code falls through to connect", phaseForCode("EWEIRD") === "connect", phaseForCode("EWEIRD"));
check("...and so does no code at all", phaseForCode(undefined) === "connect", phaseForCode(undefined));

console.log("\nan error status names the stage too");
// The pair this whole taxonomy exists for. 401 means bring a credential; 403 means the
// credential is not allowed here — and on a socket proxy the second is the single most
// likely misconfiguration. Collapsing them yields the wrong hint every time.
check(
  "401 is authenticate and 403 is authorize, not one phase for both",
  phaseForStatus(401) === "authenticate" && phaseForStatus(403) === "authorize",
  `${phaseForStatus(401)}/${phaseForStatus(403)}`,
);
check("407 joins 401", phaseForStatus(407) === "authenticate", phaseForStatus(407));
check("404 and 405 are path", phaseForStatus(404) === "path" && phaseForStatus(405) === "path");
check("502 is a plain status", phaseForStatus(502) === "status", phaseForStatus(502));
check("...and so is 500", phaseForStatus(500) === "status", phaseForStatus(500));

console.log("\nthe shared HTTP client carries the phase to its caller");
const statusStub = (status: number): FetchLike => async () => reply(status, { detail: "x" });
for (const [status, phase] of [
  [401, "authenticate"],
  [403, "authorize"],
  [404, "path"],
  [502, "status"],
] as const) {
  const r = await getJson(statusStub(status), "http://stub.invalid/api", { timeoutMs: 100 });
  check(
    `HTTP ${status} arrives as ${phase}`,
    r.phase === phase && r.code === String(status),
    `${r.phase} ${r.code ?? ""}`,
  );
}
const htmlResult = await getJson(loginPage, "http://stub.invalid/api", { timeoutMs: 100 });
check(
  "a 200 with an HTML body is protocol — something answered, and it was not this API",
  htmlResult.phase === "protocol",
  htmlResult.phase,
);
// Worth its own assertion: `path` would say "wrong URL" about an address that is
// right and gated, which is the likeliest way this integration is misconfigured.
check("...and explicitly not path", htmlResult.phase !== "path");
const dnsResult = await getJson(opaque, "http://stub.invalid/api", { timeoutMs: 100 });
check(
  "a code hidden in `cause` reaches the phase and the report",
  dnsResult.phase === "resolve" && dnsResult.code === "ENOTFOUND",
  `${dnsResult.phase} ${dnsResult.code ?? ""}`,
);
const timedOut = await getJson(
  async () => {
    throw Object.assign(new Error("The operation was aborted"), { name: "TimeoutError" });
  },
  "http://stub.invalid/api",
  { timeoutMs: 100 },
);
check("an aborted request is a timeout, not a connect failure", timedOut.phase === "timeout", timedOut.phase);
const okResult = await getJson(async () => reply(200, { ok: true }), "http://stub.invalid/api", {
  timeoutMs: 100,
});
check("and a success says so", okResult.phase === "connected" && okResult.ok, okResult.phase);

console.log("\nthe docker socket file is diagnosed before dockerode sees it");
const socketDir = mkdtempSync(resolve(tmpdir(), "labview-smoke-"));
const missingSocket = resolve(socketDir, "missing.sock");
const plainFile = resolve(socketDir, "not-a-socket");
writeFileSync(plainFile, "");
const liveSocket = resolve(socketDir, "live.sock");
const socketServer = createServer();
await new Promise<void>((ready) => socketServer.listen(liveSocket, () => ready()));

check(
  "a path that does not exist probes as absent",
  JSON.stringify(probeSocketPath(missingSocket)) ===
    JSON.stringify({ exists: false, isSocket: false, readable: false }),
  JSON.stringify(probeSocketPath(missingSocket)),
);
// The empty-bind-mount case: docker creates a *directory* for a host path that is not
// there, so "exists" is true and the socket is still not a socket.
check(
  "a regular file probes as present but not a socket",
  JSON.stringify(probeSocketPath(plainFile)) ===
    JSON.stringify({ exists: true, isSocket: false, readable: true }),
  JSON.stringify(probeSocketPath(plainFile)),
);
check(
  "a listening socket probes as usable",
  JSON.stringify(probeSocketPath(liveSocket)) ===
    JSON.stringify({ exists: true, isSocket: true, readable: true }),
  JSON.stringify(probeSocketPath(liveSocket)),
);

const absent = phaseForSocket({ exists: false, isSocket: false, readable: false }, "/s.sock");
check(
  "an absent socket is a connect failure that names the mount",
  absent?.phase === "connect" && absent.detail.includes("does not exist") && absent.hint.includes("/s.sock:/s.sock"),
  JSON.stringify(absent),
);
const notSocket = phaseForSocket({ exists: true, isSocket: false, readable: true }, "/s.sock");
check(
  "...a non-socket says so rather than repeating the same message",
  notSocket?.phase === "connect" && notSocket.detail.includes("is not a socket"),
  JSON.stringify(notSocket),
);
// The distinction that matters most of the four: dockerode's own words for a socket the
// process may not open are `connect EACCES`, which reads as a network problem. It is a
// group-membership problem, and only `authorize` sends the operator to the right fix.
const noAccess = phaseForSocket({ exists: true, isSocket: true, readable: false }, "/s.sock");
check(
  "...and an inaccessible socket is authorize, not connect",
  noAccess?.phase === "authorize" && noAccess.detail.includes("not accessible"),
  JSON.stringify(noAccess),
);
check(
  "a usable socket produces no complaint at all",
  phaseForSocket({ exists: true, isSocket: true, readable: true }, "/s.sock") === undefined,
);

console.log("\ndockerode's own failures map to the same phases");
// A socket proxy with the containers endpoint switched off answers exactly this, and it
// is indistinguishable from a network problem in dockerode's message alone.
const refused403 = classifyDockerError({ statusCode: 403, reason: "Forbidden", message: "(HTTP code 403)" });
check(
  "a proxy's 403 is authorize with the status kept",
  refused403.phase === "authorize" && refused403.code === "403",
  JSON.stringify(refused403),
);
check(
  "...and its hint names the proxy switch rather than the network",
  (hintFor("docker", "authorize") ?? "").includes("CONTAINERS=1"),
  hintFor("docker", "authorize") ?? "",
);
const noEntry = classifyDockerError(Object.assign(new Error("connect ENOENT /v.sock"), { code: "ENOENT" }));
check("a libuv code on the error itself is read", noEntry.phase === "connect" && noEntry.code === "ENOENT", JSON.stringify(noEntry));
// dockerode implements its `timeout` option by destroying the socket, so a black-holed
// endpoint arrives as an ordinary reset: the deadline is nowhere in the error, and only
// the clock separates it from a peer that hung up. Reporting `connect` here would print
// "nothing accepted the connection" about an endpoint that demonstrably did.
const blackHole = classifyDockerError(
  Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }),
  { elapsedMs: 5001, timeoutMs: 5000 },
);
check(
  "a reset at its own deadline is a timeout, not a connect failure",
  blackHole.phase === "timeout" && blackHole.detail.includes("5000ms"),
  JSON.stringify(blackHole),
);
const earlyReset = classifyDockerError(
  Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }),
  { elapsedMs: 12, timeoutMs: 5000 },
);
check(
  "...and the same reset well inside it is still a connect failure",
  earlyReset.phase === "connect",
  JSON.stringify(earlyReset),
);
const slow403 = classifyDockerError({ statusCode: 403, message: "(HTTP code 403)" }, { elapsedMs: 9000, timeoutMs: 5000 });
check(
  "...while a slow answer that did arrive keeps its status",
  slow403.phase === "authorize",
  JSON.stringify(slow403),
);

console.log("\nboth docker transports are named the way an operator writes them");
const dockerBase = loadConfig();
const dockerCfg = (over: Partial<typeof dockerBase.docker>) => ({
  ...dockerBase,
  docker: { ...dockerBase.docker, enabled: true, ...over },
});
const unixFail = await snapshotDocker(dockerCfg({ socketPath: missingSocket }));
check(
  "a socket endpoint is `unix://…` and its failure names the stage",
  unixFail.connection.endpoint === `unix://${missingSocket}` &&
    unixFail.connection.phase === "connect" &&
    unixFail.connection.target === "docker",
  JSON.stringify(unixFail.connection),
);
check(
  "...and a socket path nobody configured would report as the default",
  dockerCfg({}).docker.socketPath === "/var/run/docker.sock" &&
    (await snapshotDocker(dockerCfg({ socketPath: plainFile }))).connection.source === "config",
);
// A closed port on loopback: no network, and refused in single-digit milliseconds.
const tcpFail = await snapshotDocker(dockerCfg({ host: "127.0.0.1", port: 1 }));
check(
  "a TCP endpoint is `tcp://host:port`, so the log says which transport was used",
  tcpFail.connection.endpoint === "tcp://127.0.0.1:1" && tcpFail.connection.phase === "connect",
  JSON.stringify(tcpFail.connection),
);
check(
  "a disabled endpoint is `disabled` — not a fault, and not banner-worthy",
  (await snapshotDocker(dockerBase)).connection.phase === "disabled" &&
    !shouldBanner((await snapshotDocker(dockerBase)).connection),
);
socketServer.close();

console.log("\na container the Engine would not describe is a gap, and says so");
// The Engine is injected for these two, because the situation cannot be asked of a real
// daemon on demand: a socket proxy that allows the container *list* and refuses each
// container's *detail* is an ordinary misconfiguration, and today it is the one failure
// that leaves the scan quietly weaker than it looks — every port, network and health
// value for the refused containers is simply missing from every conclusion drawn after.
const fakeEngine = (count: number, refuse: (index: number) => boolean): DockerLike => {
  const ids = Array.from({ length: count }, (_, i) => `feedface${String(i).padStart(4, "0")}`);
  return {
    ping: async () => ({}),
    listContainers: async () => ids.map((Id) => ({ Id, Status: "Up 2 hours" })) as never,
    getContainer: (id: string) => ({
      inspect: async () => {
        const index = ids.indexOf(id);
        if (refuse(index)) throw Object.assign(new Error("(HTTP code 403) Forbidden"), { statusCode: 403 });
        return {
          Id: id,
          Name: `/example-${index}`,
          Created: "2024-01-01T00:00:00Z",
          RestartCount: 0,
          Image: "sha256:0000000000000000",
          Config: { Image: "example.com/app:1", Labels: {} },
          State: { Status: "running", Running: true, StartedAt: "2024-01-01T00:00:00Z" },
          NetworkSettings: { Networks: {}, Ports: {} },
        } as never;
      },
    }),
  };
};
const engineCfg = dockerCfg({ host: "127.0.0.1", port: 2375 });
const allInspected = await snapshotDocker(engineCfg, { createDocker: () => fakeEngine(3, () => false) });
check(
  "every container described is a plain `connected`, with the count read",
  allInspected.connection.phase === "connected" && allInspected.connection.read === "3 containers",
  JSON.stringify(allInspected.connection),
);
const someRefused = await snapshotDocker(engineCfg, { createDocker: () => fakeEngine(3, (i) => i === 1) });
check(
  "one refused inspect is `partial` — connected, and not everything was read",
  someRefused.available &&
    someRefused.connection.ok &&
    someRefused.connection.phase === "partial" &&
    someRefused.connection.read === "3 containers, 1 could not be inspected",
  JSON.stringify(someRefused.connection),
);
check(
  "...it banners, unlike the other two `ok` phases",
  shouldBanner(someRefused.connection) && !shouldBanner(allInspected.connection),
);
check(
  "...its hint names the proxy endpoint to widen",
  (someRefused.connection.hint ?? "").includes("CONTAINERS=1"),
  someRefused.connection.hint ?? "",
);
// The count is the whole report: which container failed is a fleet identifier (I2), and
// the number is what tells the operator this happened at all.
check(
  "...and it counts them without naming one",
  formatConnection(someRefused.connection).every((l) => !l.includes("example-") && !l.includes("feedface")),
  formatConnection(someRefused.connection).join(" / "),
);
check(
  "the two containers that did answer are still in the snapshot",
  someRefused.byKey.get("example-0") !== undefined &&
    someRefused.byKey.get("example-2") !== undefined &&
    someRefused.byKey.get("example-1") === undefined,
  [...someRefused.byKey.keys()].join(","),
);

console.log("\nevery target reports, in the order LabView reads them");
traefikEnv({});
authentikEnv({ token: AK_TOKEN });
const diag = traefikStub();
const ovConn = await overviewFor(traefikRoot, { fetchImpl: diag.fetchImpl });
check(
  "three reports, docker then authentik then traefik",
  ovConn.meta.connections.map((c) => c.target).join(",") === "docker,authentik,traefik",
  ovConn.meta.connections.map((c) => c.target).join(","),
);
const tfConn = ovConn.meta.connections.find((c) => c.target === "traefik")!;
check(
  "a working proxy read says what it read",
  tfConn.ok &&
    tfConn.phase === "connected" &&
    tfConn.read?.includes("Traefik ") === true &&
    tfConn.read?.includes(" routers") === true &&
    tfConn.read?.includes(" middlewares") === true,
  JSON.stringify(tfConn),
);
// The first candidate discovery generates is the proxy's own container address, and here
// it answers — so nothing was rejected, and the report says so rather than inventing a
// list. The case where candidates *were* rejected is asserted below.
check(
  "...and reaching it on the first candidate leaves no rejected ones",
  tfConn.attempts.length === 0,
  JSON.stringify(tfConn.attempts),
);
// Success is not a place to list candidates: they lost a race, and printing them reads
// as a list of problems on a connection that is working.
check(
  "...but a successful line does not recite them",
  !formatConnection(tfConn).some((l) => l.startsWith("  · ")),
  formatConnection(tfConn).join("\n"),
);
check(
  "the working line reads like the scanning line beside it",
  formatConnection(tfConn)[0]?.startsWith("LabView connected to traefik at ") === true,
  formatConnection(tfConn)[0] ?? "",
);

// A discovery run that had to walk past dead candidates to find the API. The report is
// `ok` and still names every one it rejected, with the stage each failed at — the same
// list that is printed when none of them answers, which is what makes that case
// diagnosable at all.
const gatedApi = traefikStub({ gated: true });
const unresolvableInternally: FetchLike = async (url, init) => {
  if (url.startsWith(TF_ORIGIN_GATED) || url.startsWith(TF_AK_ORIGIN)) return gatedApi.fetchImpl(url, init);
  throw Object.assign(new Error("fetch failed"), { cause: { code: "ENOTFOUND" } });
};
traefikEnv({ credential: true });
authentikEnv({ token: AK_TOKEN });
const tfWalked = await overviewFor(traefikRoot, { fetchImpl: unresolvableInternally });
const walkedConn = tfWalked.meta.connections.find((c) => c.target === "traefik")!;
check(
  "a candidate rejected on the way to a working endpoint is kept, with its stage",
  walkedConn.ok &&
    walkedConn.endpoint === TF_ORIGIN_GATED &&
    walkedConn.attempts.length > 0 &&
    walkedConn.attempts.every((a) => a.phase === "resolve" && a.code === "ENOTFOUND" && Boolean(a.why)),
  JSON.stringify({ ok: walkedConn.ok, endpoint: walkedConn.endpoint, attempts: walkedConn.attempts }),
);

console.log("\nthe phase reported is the furthest any candidate got");
// Several candidates, one failure each, one phase to report. A host that answered 401
// exists, is listening and speaks the right protocol — so `authenticate` is the
// operator's actual problem even though other candidates never resolved. Reporting
// `resolve` would send them to DNS over a working endpoint with a wrong credential.
const gatedNoCred = traefikStub({ gated: true });
traefikEnv({});
const tfGatedDiag = await overviewFor(traefikRoot, { fetchImpl: gatedNoCred.fetchImpl });
const gatedConn = tfGatedDiag.meta.connections.find((c) => c.target === "traefik")!;
check(
  "a 401 among 404s reports authenticate",
  gatedConn.phase === "authenticate" && !gatedConn.ok,
  `${gatedConn.phase} ${JSON.stringify(gatedConn.attempts.map((a) => a.phase))}`,
);
check(
  "...and its hint names the credential the gate wants",
  (gatedConn.hint ?? "").includes("app password"),
  gatedConn.hint ?? "",
);
check(
  "the ranking is what produces that, on the attempts alone",
  dominantPhase([
    { endpoint: "http://a", why: "a", phase: "resolve", detail: "x" },
    { endpoint: "http://b", why: "b", phase: "authenticate", detail: "y" },
    { endpoint: "http://c", why: "c", phase: "connect", detail: "z" },
  ]) === "authenticate",
);
check("...and it survives the order being reversed", dominantPhase([
  { endpoint: "http://b", why: "b", phase: "authenticate", detail: "y" },
  { endpoint: "http://a", why: "a", phase: "resolve", detail: "x" },
]) === "authenticate");

console.log("\nan integration nobody switched on says so quietly");
traefikEnv({ enabled: false });
authentikEnv({});
const inert = await overviewFor(traefikRoot, { fetchImpl: traefikStub().fetchImpl });
const akInert = inert.meta.connections.find((c) => c.target === "authentik")!;
check(
  "no token is `not-configured`, and no banner",
  akInert.phase === "not-configured" && !shouldBanner(akInert),
  JSON.stringify(akInert),
);
check(
  "...and its line says LabView is not reading it, not that it failed",
  formatConnection(akInert)[0]?.startsWith("LabView is not reading authentik") === true,
  formatConnection(akInert)[0] ?? "",
);
// The half-configured case, which is the one worth shouting about: a token with nowhere
// to send it will never work, and it is invisible if it shares `not-configured`.
authentikEnv({ token: AK_TOKEN });
const akOrphan = await overviewFor(appsRoot, { fetchImpl: async () => reply(404, {}) });
const orphanConn = akOrphan.meta.connections.find((c) => c.target === "authentik")!;
check(
  "a token with no endpoint is its own phase and does banner",
  orphanConn.phase !== "not-configured" && shouldBanner(orphanConn),
  JSON.stringify({ phase: orphanConn.phase, banner: shouldBanner(orphanConn) }),
);
authentikEnv({});

console.log("\nrepeat scans do not repeat themselves");
const seen = new Map<string, string>();
const base: Parameters<typeof changedConnections>[1] = [
  { target: "docker", ok: true, phase: "connected", endpoint: "unix:///var/run/docker.sock", read: "86 containers", attempts: [] },
  { target: "authentik", ok: false, phase: "resolve", endpoint: "https://sso.invalid", attempts: [] },
];
check("the first scan reports everything", changedConnections(seen, base).length === 2);
rememberConnections(seen, base);
check("an unchanged scan reports nothing", changedConnections(seen, base).length === 0);
// The reason `read` is excluded from the signature: a container count moves on nearly
// every scan, and including it turns "log on change" back into "log every scan".
const counted = base.map((r) => (r.target === "docker" ? { ...r, read: "87 containers" } : r));
check("a changed count alone is not a change", changedConnections(seen, counted).length === 0, JSON.stringify(changedConnections(seen, counted)));
const moved = base.map((r) => (r.target === "authentik" ? { ...r, phase: "authenticate" as const } : r));
check(
  "a moved phase is, and only that one report is repeated",
  changedConnections(seen, moved).length === 1 && changedConnections(seen, moved)[0]?.target === "authentik",
  JSON.stringify(changedConnections(seen, moved).map((r) => r.target)),
);
const relocated = base.map((r) => (r.target === "authentik" ? { ...r, endpoint: "https://other.invalid" } : r));
check("...and so is a different endpoint at the same phase", changedConnections(seen, relocated).length === 1);

console.log("\nno diagnostic carries a credential");
// Same discipline as the existing error-string checks: these lines go to a log the
// operator may paste somewhere, and a report is built from a request that had a
// credential in scope.
traefikEnv({ url: TF_ORIGIN_GATED, credential: true });
const leaky = await overviewFor(traefikRoot, { fetchImpl: traefikStub({ gated: true }).fetchImpl });
const everyLine = leaky.meta.connections.flatMap(formatConnection).join("\n");
check(
  "not the password, not the basic header, not a cookie",
  !everyLine.includes(TF_PASSWORD) && !everyLine.includes(TF_BASIC) && !everyLine.includes(TF_SESSION),
  everyLine,
);
check(
  "...and not the API token either",
  !leaky.meta.connections.flatMap(formatConnection).join("\n").includes(AK_TOKEN),
);
traefikEnv({ enabled: false });
authentikEnv({});

console.log(`\n${failures === 0 ? "PASS" : "FAIL"} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
