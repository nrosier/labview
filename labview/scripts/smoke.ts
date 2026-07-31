/**
 * Smoke test: run the full pipeline (docker disabled) against three fixture roots
 * and assert the analyzer produced the expected classifications. Exits non-zero
 * on any failure so it can gate CI / a pre-commit check.
 *
 *   ./fixtures/apps      — a representative happy-path fleet.
 *   ./fixtures/edge      — regression cases for previously-fixed defects.
 *   ./fixtures/authentik — the identity-provider API integration, driven through an
 *                          injected HTTP layer so no network and no Authentik is
 *                          needed. Canned responses: ./fixtures/authentik-api.json.
 *
 *   npx tsx scripts/smoke.ts
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { Overview, Service } from "../src/model/types.js";
import type { BuildDeps } from "../src/analyze/index.js";
import type { FetchLike, HttpResponse } from "../src/enrich/authentik.js";

const here = dirname(fileURLToPath(import.meta.url));
const appsRoot = resolve(here, "..", "fixtures", "apps");
const edgeRoot = resolve(here, "..", "fixtures", "edge");
const authentikRoot = resolve(here, "..", "fixtures", "authentik");

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

const { loadConfig } = await import("../src/config.js");
const { buildOverview } = await import("../src/analyze/index.js");

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
}

/**
 * Stand in for the fixture fleet's Authentik instance.
 *
 * It behaves like the real thing in the three ways that matter to the client:
 * `/api/v3/root/config/` answers without credentials (it is `AllowAny` upstream),
 * every other endpoint demands the exact bearer token, and any other origin — the
 * outpost, the worker, a bare service name — is simply not an API and 404s.
 *
 * Every request is recorded, which is what lets the test assert the *absence* of a
 * request: the token must never be sent to a candidate that failed the probe.
 */
function authentikStub(): { fetchImpl: FetchLike; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const reply = (status: number, body: unknown): HttpResponse => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });

  const fetchImpl: FetchLike = async (url, init) => {
    const header = init?.headers?.Authorization;
    calls.push({ url, sentToken: Boolean(header) });

    const parsed = new URL(url);
    if (parsed.origin !== AK_ORIGIN) return reply(404, { detail: "Not found." });

    const endpoint = parsed.pathname.replace(/^\/api\/v3\//, "").replace(/\/$/, "");
    if (endpoint === "root/config") return reply(200, AK_FIXTURE["root/config"]);
    if (header !== `Bearer ${AK_TOKEN}`) {
      return reply(403, { detail: "Authentication credentials were not provided." });
    }

    const pages = AK_FIXTURE[endpoint];
    if (!Array.isArray(pages)) return reply(404, { detail: "Not found." });
    const page = Number(parsed.searchParams.get("page") ?? "1");
    const results: unknown[] = Array.isArray(pages[page - 1]) ? pages[page - 1] : [];
    const count = pages.reduce((n: number, p: unknown) => n + (Array.isArray(p) ? p.length : 0), 0);

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

console.log(`\n${failures === 0 ? "PASS" : "FAIL"} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
