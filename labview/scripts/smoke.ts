/**
 * Smoke test: run the full pipeline (docker disabled) against two fixture roots
 * and assert the analyzer produced the expected classifications. Exits non-zero
 * on any failure so it can gate CI / a pre-commit check.
 *
 *   ./fixtures/apps — a representative happy-path fleet.
 *   ./fixtures/edge — regression cases for previously-fixed defects.
 *
 *   npx tsx scripts/smoke.ts
 */
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { Overview, Service } from "../src/model/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const appsRoot = resolve(here, "..", "fixtures", "apps");
const edgeRoot = resolve(here, "..", "fixtures", "edge");

// Configure via env BEFORE importing config.
process.env.LABVIEW_DOCKER_ENABLED = "false";
process.env.LABVIEW_CONFIG = "___none___"; // force defaults

const { loadConfig } = await import("../src/config.js");
const { buildOverview } = await import("../src/analyze/index.js");

/** Build an overview for one fixture root. loadConfig() re-reads env each call. */
async function overviewFor(root: string): Promise<Overview> {
  process.env.LABVIEW_APPS_ROOT = root;
  return buildOverview(loadConfig(), new Date("2024-01-01T00:00:00Z"));
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

console.log(`\n${failures === 0 ? "PASS" : "FAIL"} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
