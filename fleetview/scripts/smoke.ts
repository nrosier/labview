/**
 * Smoke test: run the full pipeline against ./fixtures/apps (docker disabled) and
 * assert the analyzer produced the expected classifications. Exits non-zero on
 * any failure so it can gate CI / a pre-commit check.
 *
 *   npx tsx scripts/smoke.ts
 */
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesRoot = resolve(here, "..", "fixtures", "apps");

// Configure via env BEFORE importing config.
process.env.FLEETVIEW_APPS_ROOT = fixturesRoot;
process.env.FLEETVIEW_DOCKER_ENABLED = "false";
process.env.FLEETVIEW_CONFIG = "___none___"; // force defaults

const { loadConfig } = await import("../src/config.js");
const { buildOverview } = await import("../src/analyze/index.js");

const cfg = loadConfig();
const ov = await buildOverview(cfg, new Date("2024-01-01T00:00:00Z"));

let failures = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) {
    console.log(`  ✓ ${name}`);
  } else {
    console.error(`  ✗ ${name} ${detail}`);
    failures++;
  }
}

function svc(stackId: string, serviceName: string) {
  const s = ov.stacks.find((s) => s.id === stackId)?.services.find((x) => x.name === serviceName);
  if (!s) throw new Error(`service ${stackId}/${serviceName} not found`);
  return s;
}

console.log("FleetView smoke test\n");

console.log("discovery");
check("found 5 stacks", ov.stats.stacks === 5, `got ${ov.stats.stacks}`);
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
check("emby is public (dockflare only)", emby.ingress === "public", emby.ingress);
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

console.log("\ngraph + interconnection");
const proxyNode = ov.graph.nodes.find((n) => n.kind === "network" && n.label === "proxy");
check("shared external 'proxy' network node exists", Boolean(proxyNode));
const sharedMedia = ov.graph.nodes.find((n) => n.id === "bind:/mnt/media");
check("shared /mnt/media bind detected across jellyfin+emby", Boolean(sharedMedia));
check("cloudflare hub node exists", ov.graph.nodes.some((n) => n.id === "ext:cloudflare"));
check("authentik hub node exists", ov.graph.nodes.some((n) => n.id === "ext:authentik"));
const dependsEdges = ov.graph.edges.filter((e) => e.kind === "depends_on");
check("authentik depends_on edges present", dependsEdges.length >= 2, String(dependsEdges.length));

console.log(`\n${failures === 0 ? "PASS" : "FAIL"} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
