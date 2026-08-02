/**
 * Smoke test: run the full pipeline (docker disabled) against four fixture roots
 * and assert the analyzer produced the expected classifications. Exits non-zero
 * on any failure so it can gate CI / a pre-commit check.
 *
 *   ./fixtures/apps      — a representative happy-path fleet.
 *   ./fixtures/edge      — regression cases for previously-fixed defects.
 *   ./fixtures/nets      — what connects two services, and what merely lets them reach each
 *                          other: one `external:` network across four stacks, sidecars
 *                          declaring the dependencies compose cannot express, a co-member
 *                          that declares nothing, every way a reference can fail to resolve,
 *                          a dependency with no network to travel over, and the two kinds of
 *                          single-service network.
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
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type {
  AppStack,
  AuthMethod,
  DeclaredAuthMechanism,
  DockerState,
  IngressKind,
  Overview,
  Service,
  SessionInfo,
  TraefikLiveRouter,
} from "../src/model/types.js";
import type { TagFilter } from "../src/model/filter.js";
import type { BuildDeps } from "../src/analyze/index.js";
import type { DockerLike } from "../src/enrich/docker.js";
import type { FetchLike, HttpResponse } from "../src/enrich/authentik.js";
// Type-only, so importing it here does not load the module before the environment below
// is set — the same reason every value import in this file is a dynamic one.
import type { SessionCheck } from "../src/auth/session.js";

const here = dirname(fileURLToPath(import.meta.url));
const appsRoot = resolve(here, "..", "fixtures", "apps");
const edgeRoot = resolve(here, "..", "fixtures", "edge");
const netsRoot = resolve(here, "..", "fixtures", "nets");
const authentikRoot = resolve(here, "..", "fixtures", "authentik");
const traefikRoot = resolve(here, "..", "fixtures", "traefik");
// Not a fleet: three passwd files for LabView's own login. They are files rather than
// stack directories because that is what the feature reads — see the section at the end.
const authRoot = resolve(here, "..", "fixtures", "auth");

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
// LabView's own access control, cleared for both reasons at once. An operator with a
// real `LABVIEW_SESSION_SECRET` or OIDC client secret exported would otherwise have this
// test assert against their credentials, and a real `LABVIEW_AUTH_PASSWD_FILE` would
// make the enforcement assertions depend on a file that is not in this repository.
delete process.env.LABVIEW_AUTH_PASSWD_ENABLED;
delete process.env.LABVIEW_AUTH_PASSWD_FILE;
delete process.env.LABVIEW_AUTH_MAX_FAILED_ATTEMPTS;
delete process.env.LABVIEW_AUTH_LOCKOUT_SECONDS;
delete process.env.LABVIEW_AUTH_COOKIE_SECURE;
delete process.env.LABVIEW_OIDC_ENABLED;
delete process.env.LABVIEW_OIDC_ISSUER;
delete process.env.LABVIEW_OIDC_CLIENT_ID;
delete process.env.LABVIEW_OIDC_CLIENT_SECRET;
delete process.env.LABVIEW_OIDC_CLIENT_SECRET_FILE;
delete process.env.LABVIEW_OIDC_REDIRECT_URI;
delete process.env.LABVIEW_OIDC_SCOPES;
delete process.env.LABVIEW_OIDC_USERNAME_CLAIM;
delete process.env.LABVIEW_OIDC_LABEL;
delete process.env.LABVIEW_OIDC_TIMEOUT;
delete process.env.LABVIEW_SESSION_SECRET;
delete process.env.LABVIEW_SESSION_SECRET_FILE;
delete process.env.LABVIEW_SESSION_TTL_MINUTES;
delete process.env.LABVIEW_SESSION_COOKIE_NAME;

const { loadConfig, retiredSettings } = await import("../src/config.js");
const { buildOverview } = await import("../src/analyze/index.js");
// Used directly by the container-IP assertions: the trap is not reachable through the
// pipeline, because a container IP only exists in live docker state and smoke runs
// without a docker socket.
const { buildFleetIndex, lookupAddress, lookupContainerAddress } = await import(
  "../src/analyze/origins.js"
);
const { matchTraefik } = await import("../src/analyze/traefik.js");
// Likewise for the sidecar validator: the caps and the malformed-input rules would
// otherwise need a committed 64 KiB file and a thousand-entry list to reach.
const { MAX_AUTH_ENTRIES, MAX_LIST_ENTRIES, MAX_SIDECAR_BYTES, MAX_TEXT_CHARS, parseSidecar, readSidecar } =
  await import("../src/scan/sidecar.js");
// The declared-vs-detected comparison lives in `src/` for the same reason the filter
// below does: it is a truth table over two vocabularies, and the only honest way to
// assert the layer rule is to enumerate the pairs rather than click through a browser.
const {
  DECLARED_AUTH_MECHANISMS,
  compareDeclaredAuth,
  declaredAuthFamily,
  declaredAuthLabel,
  detectedAuthFamily,
  formatExposureCount,
  showsDeclaredAuth,
} = await import("../src/model/declarations.js");
const { INGRESS_KINDS, ingressMatchesExpectation, isExternallyReachable, normalizeIngress, rollUpIngress } =
  await import("../src/model/ingress.js");
// How connected services are drawn. In `src/` so the two caps and the visibility rule are
// assertable at all: they decide what a reader is shown about which services can reach
// each other, and a rule that only exists inside a `.tsx` cannot be caught getting it
// wrong. The caps are exercised against synthetic elements below — a rule that only fires
// past twelve spokes should not need a twelve-service fixture to prove.
const {
  MAX_DRAWER_PEERS,
  MAX_GRAPH_SPOKES,
  MAX_LIST_PEERS,
  graphServiceId,
  hiddenNetworksNote,
  networkGroups,
  networkLinks,
  networkMembershipText,
  networkNodeLabel,
  serviceConnections,
  showsDirectDependency,
  showsNetworkNode,
  visibleSpokes,
} = await import("../src/model/networks.js");
// When the absence of an authentication mechanism may be reported at all. In `src/` for
// the same reason as the two above, and asserted here because the alternative is a
// dashboard that says "No proxy auth" about every internal database and gets believed.
const { NO_AUTH_REASONS, noAuthReason, noAuthText, showsAuthMethod } = await import("../src/model/auth.js");
const { hasEnforcedAuthentikGate } = await import("../src/labels/auth.js");
// The tri-state filter lives in `src/` rather than in the web bundle precisely so it
// can be asserted here: smoke never mounts a DOM, and AND/OR/NOT is a truth table
// that deserves better than being exercised by hand in a browser.
const { EMPTY_TAG_FILTER, cycleTag, describeTagFilter, matchesTagFilter, tagFilterActive } = await import(
  "../src/model/filter.js"
);

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

/**
 * A service's ingress as one comparable string, in canonical order.
 *
 * Compared as a joined string rather than element by element so a failing assertion
 * prints both sets — `got "public, lan, internal"` against an expectation of
 * `"public, traefik, lan, internal"` says which kind went missing, which is the whole
 * question when a classification rule regresses.
 */
function ing(s: Service): string {
  return s.ingress.join(", ");
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
 * It behaves like the real thing in the four ways that matter to the client:
 * `/api/v3/root/config/` answers without credentials (it is `AllowAny` upstream),
 * every other endpoint demands the exact bearer token, any other origin — the
 * outpost, the worker, a bare service name — is simply not an API, and
 * `/core/applications/` withholds part of its own list unless `superuser_full_list`
 * is both sent and honoured, while still reporting the full `count`.
 */
function authentikResponse(
  fixture: Record<string, unknown>,
  origin: string,
  token: string,
  url: URL,
  header: string | undefined,
  opts: { superuser?: boolean; hides?: string[] } = {},
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

  // The applications endpoint paginates and *then* policy-filters the page as the
  // token's own user, so the applications it withholds are missing from `results`
  // while still counted in `pagination.count`. `count` is therefore the full total in
  // every mode below, because upstream computes it before the filter runs — and it is
  // the field the shortfall reporting rests on.
  //
  // What the filter removes is the `:withheld` key: all of it by default, or just the
  // slugs in `hides`, which is how a run where recovery closes the *whole* gap is
  // reachable. `superuser_full_list=true` skips the filter entirely, and only for a
  // token this stub treats as a superuser — the two conditions the real early-return
  // requires, so sending the parameter alone proves nothing.
  const extra = fixture[`${endpoint}:withheld`];
  const all: unknown[][] = Array.isArray(extra) ? [...pages, extra] : pages;
  const count = all.reduce((n, p) => n + p.length, 0);
  const honoured = opts.superuser && url.searchParams.get("superuser_full_list") === "true";
  const filter = new Set(
    opts.hides ??
      (Array.isArray(extra) ? extra.map((r) => String((r as { slug?: unknown }).slug)) : []),
  );
  const served = honoured
    ? all
    : all
        .map((p) => p.filter((r) => !filter.has(String((r as { slug?: unknown }).slug))))
        .filter((p) => p.length > 0);

  const results: unknown[] = served[page - 1] ?? [];

  // Outposts answer in the DRF envelope, everything else in Authentik's own, so
  // both branches of the pagination reader are exercised by one fixture.
  if (endpoint === "outposts/instances") {
    return reply(200, { count, next: null, previous: null, results });
  }
  return reply(200, {
    pagination: {
      next: page < served.length ? page + 1 : 0,
      previous: page > 1 ? page - 1 : 0,
      count,
      current: page,
      total_pages: served.length,
    },
    results,
  });
}

/**
 * Stand in for the fixture fleet's Authentik instance.
 *
 * Every request is recorded, which is what lets the test assert the *absence* of a
 * request: the token must never be sent to a candidate that failed the probe.
 *
 * `superuser` decides whether the instance honours `superuser_full_list` — the default
 * is the least-privilege token most fleets will use, and the one the reporting has to
 * be honest under. `hides` narrows which applications the policy filter removes.
 */
function authentikStub(opts: { superuser?: boolean; hides?: string[] } = {}): {
  fetchImpl: FetchLike;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];

  const fetchImpl: FetchLike = async (url, init) => {
    const header = init?.headers?.Authorization;
    calls.push({ url, sentToken: Boolean(header) });
    return (
      authentikResponse(AK_FIXTURE, AK_ORIGIN, AK_TOKEN, new URL(url), header, opts) ??
      reply(404, { detail: "Not found." })
    );
  };

  return { fetchImpl, calls };
}

/**
 * Point the config loader at the stub instance — or at nothing — for the next run.
 *
 * `token: ""` is a third state, and the tests below need it to be reachable: a variable
 * that is set and carries nothing is not the same as one that was never set, and since
 * §6 made the environment the only place a credential comes from it is the one way one
 * still goes missing by accident. So this checks for `undefined` rather than truthiness.
 */
function authentikEnv(opts: { url?: string; token?: string }): void {
  if (opts.url) process.env.LABVIEW_AUTHENTIK_URL = opts.url;
  else delete process.env.LABVIEW_AUTHENTIK_URL;
  if (opts.token !== undefined) process.env.LABVIEW_AUTHENTIK_TOKEN = opts.token;
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
  /**
   * Serve the runtime config without this route — its router and its like-named service.
   *
   * Both together because that is how a route leaves: the docker provider derives a router
   * and a service from the same container, and deleting the container removes both. The one
   * thing a stub option can produce that no fixture edit can — two *successful* reads of the
   * same files that differ in what the proxy returned.
   */
  dropRoute?: string;
}

/** The runtime config as the stub serves it, minus a dropped route. */
function traefikRawdata(opts: TraefikStubOptions): unknown {
  const raw = TF_FIXTURE.rawdata as Record<string, unknown>;
  const name = opts.dropRoute;
  if (!name) return raw;
  const without = (section: unknown): Record<string, unknown> =>
    Object.fromEntries(Object.entries(section as Record<string, unknown>).filter(([k]) => k.split("@")[0] !== name));
  return { ...raw, routers: without(raw.routers), services: without(raw.services) };
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
    if (parsed.pathname === "/api/rawdata") return reply(200, traefikRawdata(opts));
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
// Three tags at once, which is the whole reason the field is a set: a tunnel route, a
// proxy route and a published host port are three independent facts about one service,
// and no single value could carry them. A shared container network is a fourth fact and
// this service has that too — `internal` is absent from the set because the three above
// already answer "who can reach it", not because the evidence for it is missing.
check("jellyfin carries every external reachability tag", ing(jf) === "public, traefik, lan", ing(jf));
check("jellyfin cloudflare hostname", jf.cloudflare[0]?.hostname === "jellyfin.example.com");
check("jellyfin traefik host", jf.traefik[0]?.hosts.includes("jellyfin.example.com") ?? false);
const emby = svc("emby", "emby");
// Tunnel origin straight at the container, plus a published host port: public
// via Cloudflare and directly answerable on the LAN, with no proxy either way —
// so `traefik` is the one external kind that is absent.
check("emby is public+lan with no proxy tag", ing(emby) === "public, lan", ing(emby));
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
// ...and every one of them is expressed *through* the network the pair shares, not as a
// line beside it. This used to assert only that the edges existed; the stronger statement
// about the same fixture is that each names the network it travels over, that the network
// therefore does not need a direct arrow drawn, and that both membership legs carry the
// arrowhead which makes the path dependent -> network -> dependency readable.
check(
  "every depends_on in this fleet names the network it travels over",
  dependsEdges.every((e) => (e.via?.length ?? 0) > 0),
  dependsEdges.filter((e) => !e.via?.length).map((e) => e.id).join(","),
);
check(
  "...so none of them is drawn as a direct service-to-service line",
  dependsEdges.every((e) => !showsDirectDependency(e)),
);
check(
  "...and both legs either side of the network carry the dependency",
  dependsEdges.every((e) =>
    (e.via ?? []).every(
      (net) =>
        ov.graph.edges.some(
          (m) =>
            m.kind === "network" &&
            m.source === e.source &&
            m.target === `net:${net}` &&
            (m.flow === "to-network" || m.flow === "both"),
        ) &&
        ov.graph.edges.some(
          (m) =>
            m.kind === "network" &&
            m.source === e.target &&
            m.target === `net:${net}` &&
            (m.flow === "to-service" || m.flow === "both"),
        ),
    ),
  ),
);

/* ========================================================================== */
/* fixtures/edge — regression cases                                           */
/* ========================================================================== */

const edge = await overviewFor(edgeRoot);
const eSvc = lookup(edge);

console.log("\n--- regression fixtures (fixtures/edge) ---");

console.log("\nedge discovery");
check("found 18 edge stacks", edge.stats.stacks === 18, `got ${edge.stats.stacks}`);

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
// It keeps `internal` — the sibling service shares the stack's implicit network —
// but no external tag, which is the part the staged route must not grant.
check("...so nothing external reaches it", ing(staged) === "internal", ing(staged));
check("...and is not flagged exposed-without-auth", staged.auth.exposedWithoutAuth === false);
// The sibling on the same implicit network, and the sharpest pair for the withholding
// rule: identical `internal` evidence, and the tag survives on exactly the one of them
// that has nothing else. The switched-on route is the whole difference.
const live = eSvc("cfdisabled", "live");
check('dockflare.enable="TRUE" still enables the route', ing(live) === "public", ing(live));

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

console.log("\npublished host ports are LAN reachability");
const media = eSvc("hostport", "media");
check(
  "tunnel origin at the container + published port -> public and lan",
  ing(media) === "public, lan",
  ing(media),
);
check("...and is flagged exposed without auth", media.auth.exposedWithoutAuth === true);

const socketproxy = eSvc("hostport", "socketproxy");
check(
  "published port with nothing in front -> lan",
  ing(socketproxy) === "lan",
  ing(socketproxy),
);
check(
  "...and is flagged exposed without auth",
  socketproxy.auth.exposedWithoutAuth === true,
  `exposedWithoutAuth=${socketproxy.auth.exposedWithoutAuth}`,
);
// Every service with a published port, proxied or not — the counter no longer folds
// the proxied ones away, which is what made "LAN 2" misleading in a fleet where a
// dozen proxied services also answer on the host.
check("every published port is counted as lan", edge.stats.lanServices === 8, `got ${edge.stats.lanServices}`);

// The overlap, now carried rather than collapsed: a proxied service that also
// publishes a port holds `traefik` *and* `lan`, and the LAN path is still raised as a
// note — the note explains the bypass, the tag makes it filterable.
const hpApp = eSvc("hostport", "app");
check("a proxied service that publishes a port holds both tags", ing(hpApp) === "traefik, lan", ing(hpApp));
check(
  "cross-stack authentik@docker still resolves",
  hpApp.auth.method === "authentik-forward-auth",
  hpApp.auth.method,
);
check(
  "...but the bypass of that SSO is noted",
  hpApp.notes.some((n) => n.includes("9999") && n.includes("bypassing")),
  hpApp.notes.join(" | "),
);
check(
  "...and the note says that bypass is on the LAN, the word the kind uses",
  hpApp.notes.some((n) => n.includes("bypassing") && n.includes("LAN")),
  hpApp.notes.join(" | "),
);
// The bypass guard keys on the `traefik` tag being *present*, not on it being the
// whole classification. A tunnelled and proxied service that also publishes a port
// must get the same note, or the guard would only fire for the proxy-only case.
check(
  "a tunnelled+proxied service that publishes a port gets the same bypass note",
  jf.ingress.includes("traefik") && jf.notes.some((n) => n.includes("8096") && n.includes("bypassing")),
  `${ing(jf)}: ${jf.notes.join(" | ")}`,
);

const hpWorker = eSvc("hostport", "worker");
check("expose: does not publish -> no lan tag", ing(hpWorker) === "internal", ing(hpWorker));
check(
  "...and a service with no external tag gets no bypass note",
  hpWorker.notes.every((n) => !n.includes("bypassing")),
  hpWorker.notes.join(" | "),
);

// `internal` is positive evidence, and there are exactly two ways to earn it. Each
// fixture isolates one, so dropping either arm of the rule fails a named assertion
// here rather than quietly reclassifying a third of the fleet as unreachable.
const shBroker = eSvc("sharednet", "broker");
const shWorker = eSvc("sharednet", "worker");
check(
  "two services in one file share the implicit default network -> internal",
  ing(shBroker) === "internal" && ing(shWorker) === "internal",
  `${ing(shBroker)} / ${ing(shWorker)}`,
);
check("expose: on its own is internal", ing(eSvc("exposeonly", "cache")) === "internal", ing(eSvc("exposeonly", "cache")));
// The contrast that makes the two above mean something: same empty shape, but one
// service, so the implied network carries nobody and there is nothing to reach.
check("a lone service with nothing declared is no-ingress", ing(eSvc("interp", "web")) === "none", ing(eSvc("interp", "web")));
check("...and so is the other one", ing(eSvc("ldapapp", "wiki")) === "none", ing(eSvc("ldapapp", "wiki")));
check("no-ingress services are counted", edge.stats.noIngressServices === 2, `got ${edge.stats.noIngressServices}`);
// A published port is not a reason to assume a neighbour: this service publishes on
// the LAN and is alone in its stack, so `lan` stands on its own.
//
// Worth being honest about what this can and cannot catch now. Since `internal` is
// withheld beside any external kind, a service with `lan` would read `lan` whether or
// not it had a neighbour, so this line no longer distinguishes the two. What still pins
// "`internal` is positive evidence, never a fallback" is the pair just above —
// `interp/web` and `ldapapp/wiki` classify as `none`, and a fallback would say `internal`.
check(
  "a published port alone does not imply internal reachability",
  ing(eSvc("accepted", "status")) === "lan",
  ing(eSvc("accepted", "status")),
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

console.log("\noperator declarations (.labview)");
// The line the whole declaration layer is drawn along: a statement in a sidecar is a
// second source, not evidence. It may change a *verdict* — "does a reader need to act
// on this" — and it may never touch a *measurement*. So `exposedWithoutAuth` considers
// it and `method`, `confidence`, `byAuthMethod` and `authProtected` are computed as if
// the file were not there.
const decl = eSvc("declared", "media");
check("a declared mechanism leaves the detected method alone", decl.auth.method === "none", decl.auth.method);
check(
  "...and the detected-method distribution is unmoved",
  edge.stats.byAuthMethod.none === 25 &&
    !DECLARED_AUTH_MECHANISMS.some((m) => m in edge.stats.byAuthMethod),
  JSON.stringify(edge.stats.byAuthMethod),
);
// The verdict is the one thing it does move. This service publishes a host port with
// nothing in front of it, so the scan found an exposure and the operator's statement
// that the app authenticates itself is the only reason it is not counted.
check(
  "a declared mechanism takes a service out of the exposed count",
  decl.auth.exposedWithoutAuth === false && decl.declared?.authAgreement === "supplies",
  `exposedWithoutAuth=${decl.auth.exposedWithoutAuth} agreement=${decl.declared?.authAgreement}`,
);
check(
  "...counted in its own statistic, apart from the ones the scan proved",
  edge.stats.declaredAuthProtected === 1 && edge.stats.authProtected === 10,
  `${edge.stats.declaredAuthProtected} declared-protected, ${edge.stats.authProtected} detected`,
);
// The failure this rule invites is a public service quietly becoming unremarkable, so
// the note that replaces the exposure finding has to say all three things: that it is
// reachable, that nothing was detected in front of it, and that the verdict rests on
// something unverifiable.
check(
  "...and says so in place of the finding: reachable, nothing detected, unverified",
  decl.notes.some(
    (n) =>
      n.includes("Reachable (lan)") &&
      n.includes("no detected proxy/SSO authentication") &&
      n.includes("declares the service authenticates itself") &&
      n.includes("this scan cannot verify"),
  ),
  decl.notes.join(" | "),
);
check(
  "the declaration is attached beside the facts, tagged with the file it came from",
  decl.declared?.file === ".labview" &&
    decl.declared.auth.map((a) => a.mechanism).join(",") === "app-local-accounts,app-ldap",
  JSON.stringify(decl.declared?.auth),
);
check(
  "...counted only in its own statistic",
  edge.stats.declaredAuth === 7,
  `got ${edge.stats.declaredAuth}`,
);
check(
  "...worded through the shared mechanism labels, so a note and a badge cannot disagree",
  decl.notes.some((n) => n.includes(declaredAuthLabel("app-local-accounts")) && n.includes(declaredAuthLabel("app-ldap"))),
  decl.notes.join(" | "),
);
const declStack = edge.stacks.find((s) => s.id === "declared")?.declared;
check(
  "stack-level fields are read for the directory, not for a service",
  declStack?.owner === "platform-team" && declStack.criticality === "high" && declStack.description !== undefined,
  JSON.stringify(declStack),
);
check(
  "a link with no label falls back to its url rather than rendering blank",
  declStack?.links[1]?.label === "https://example.com/docs",
  JSON.stringify(declStack?.links),
);
check(
  "a bare-string dependency is the same shape as the long form",
  declStack?.dependencies[0]?.name === "Share mounted by the host" &&
    declStack.dependencies[0].detail === undefined,
  JSON.stringify(declStack?.dependencies),
);

const acc = eSvc("accepted", "status");
check(
  "an accepted exposure is still an exposure",
  acc.auth.exposedWithoutAuth === true,
  `exposedWithoutAuth=${acc.auth.exposedWithoutAuth}`,
);
check(
  "...with the acceptance recorded separately",
  acc.declared?.unauthenticatedAccepted?.reason === "Read-only status page, trusted VLAN only.",
  JSON.stringify(acc.declared?.unauthenticatedAccepted),
);
check(
  "...and the reason carried on the exposure note itself, where the finding is read",
  acc.notes.some(
    (n) => n.includes("no detected proxy/SSO authentication") && n.includes("accepted in .labview: Read-only status page"),
  ),
  acc.notes.join(" | "),
);
check(
  "the accepted count is beside the exposure count, never subtracted from it",
  edge.stats.exposureAccepted === 1 && edge.stats.exposedWithoutAuth === 10,
  `${edge.stats.exposureAccepted} accepted of ${edge.stats.exposedWithoutAuth} exposed`,
);
// `23/28` — needing attention over found. The numerator is what nobody has looked at;
// the denominator never drops, which is the difference between "reviewed" and "gone".
check(
  "...and printed as unaccepted over total, from one shared formatter",
  formatExposureCount(edge.stats.exposedWithoutAuth, edge.stats.exposureAccepted) === "9/10",
  formatExposureCount(edge.stats.exposedWithoutAuth, edge.stats.exposureAccepted),
);
check(
  "...a plain total when nothing was accepted, so no reader looks for a missing half",
  formatExposureCount(28, 0) === "28" && formatExposureCount(28, 5) === "23/28" && formatExposureCount(0, 0) === "0",
  `${formatExposureCount(28, 0)} / ${formatExposureCount(28, 5)} / ${formatExposureCount(0, 0)}`,
);

// A sidecar's real failure mode is not a typo, it is going quietly out of date.
const stale = eSvc("staledecl", "worker");
check("a stale declaration does not move the posture", ing(stale) === "internal" && stale.auth.exposedWithoutAuth === false, `${ing(stale)}/${stale.auth.exposedWithoutAuth}`);
check(
  "an acceptance the scan can see no longer applies is reported as drift",
  stale.declared?.drift.some((d) => d.includes("no longer applies")) === true,
  JSON.stringify(stale.declared?.drift),
);
check(
  "a declared expectation that disagrees with the scan is reported as drift, naming both",
  stale.declared?.drift.some((d) => d.includes('expects ingress "lan"') && d.includes('"internal"')) === true,
  JSON.stringify(stale.declared?.drift),
);
// Two sets are not something an operator should have to diff by eye, so the drift
// says which way each difference runs: `lan` was expected and is absent, `internal`
// was found and was not expected.
check(
  "...and spells out which kinds are missing and which are unexpected",
  stale.declared?.drift.some((d) => d.includes("missing: lan") && d.includes("unexpected: internal")) === true,
  JSON.stringify(stale.declared?.drift),
);
check(
  "...one entry per disagreement, so fixing one does not hide the other",
  stale.declared?.drift.length === 2,
  String(stale.declared?.drift.length),
);
// The other half of the drift pair. `staledecl` disagrees about the primary kind as
// well, so on its own it cannot tell a set comparison from a single-value one: this
// service is `public, traefik` against an expected `public, lan`, so the first kind
// matches and everything after it does not.
//
// Both differences are external kinds on purpose. `internal` would be withheld from a
// service with a route, so a disagreement phrased with it would collapse to a
// one-directional one and this assertion would pass while covering half of what it says.
const pdApi = eSvc("partialdrift", "api");
check(
  "an expectation that agrees about the primary kind and nothing else still drifts",
  ing(pdApi) === "public, traefik" &&
    pdApi.declared?.drift.some((d) => d.includes("missing: lan") && d.includes("unexpected: traefik")) === true,
  `${ing(pdApi)}: ${JSON.stringify(pdApi.declared?.drift)}`,
);
check("drift has its own counter too", edge.stats.declarationDrift === 3, `got ${edge.stats.declarationDrift}`);

/* -------------------------------------------------------------------------- */
/* Declared against detected: which declarations are reported, and which warn  */
/* -------------------------------------------------------------------------- */

// Four services in `declcompare/`, three of them configured identically, so the only
// thing that can explain a different outcome is the sidecar.
const dcConflict = eSvc("declcompare", "conflict");
const dcRedundant = eSvc("declcompare", "redundant");
const dcLayered = eSvc("declcompare", "layered");
const dcDefence = eSvc("declcompare", "defence");
check(
  "three identically configured services are detected identically",
  [dcConflict, dcRedundant, dcLayered].every((s) => s.auth.method === "ldap" && ing(s) === "internal"),
  [dcConflict, dcRedundant, dcLayered].map((s) => `${s.name}=${s.auth.method}/${ing(s)}`).join(" "),
);
check(
  "...so an outcome that differs between them came from the declaration alone",
  dcConflict.declared?.authAgreement === "conflicts" &&
    dcRedundant.declared?.authAgreement === "redundant" &&
    dcLayered.declared?.authAgreement === "supplements",
  [dcConflict, dcRedundant, dcLayered].map((s) => `${s.name}=${s.declared?.authAgreement}`).join(" "),
);
// Declared OIDC against a detected LDAP bind: both are the app logging a user in, so
// they cannot both be current.
check(
  "a declaration that contradicts the scan at the same tier is drift, naming both sides",
  dcConflict.declared?.drift.some(
    (d) => d.includes(declaredAuthLabel("app-oidc")) && d.includes("scan detected ldap") && d.includes("out of date"),
  ) === true,
  JSON.stringify(dcConflict.declared?.drift),
);
// The rule that keeps every layered setup out of the warning path: the same declared
// mechanism as `conflict` above, and no warning, because the gate the scan found sits
// at a different tier of the request path.
check(
  "the same declaration behind a detected proxy gate is not a disagreement",
  dcDefence.auth.method === "authentik-forward-auth" &&
    dcDefence.declared?.auth[0]?.mechanism === dcConflict.declared?.auth[0]?.mechanism &&
    dcDefence.declared?.authAgreement === "supplements" &&
    dcDefence.declared.drift.length === 0,
  `${dcDefence.auth.method}: ${dcDefence.declared?.authAgreement}, drift=${JSON.stringify(dcDefence.declared?.drift)}`,
);
// The agreement half of the ingress comparison, which neither drift fixture can cover
// because both of them disagree. Several kinds at once, written in the sidecar in the
// opposite order to the classification: the expectation is normalized on the way in and
// compared as a set on the way out, so this has to be silence rather than drift.
check(
  "a multi-kind expectation that agrees with the scan is not a disagreement",
  ing(dcDefence) === "traefik, lan" &&
    dcDefence.declared?.expectedIngress?.join(",") === "traefik,lan" &&
    dcDefence.declared.drift.every((d) => !d.includes("expects ingress")),
  `${ing(dcDefence)} vs ${JSON.stringify(dcDefence.declared?.expectedIngress)}: ${JSON.stringify(dcDefence.declared?.drift)}`,
);
// A declaration the scan already made is worth nothing to a reader and costs them a
// second source to check, so it is reported nowhere at all.
check(
  "a declaration the scan already detected is reported nowhere",
  dcRedundant.notes.length === 0 && dcRedundant.declared?.drift.length === 0,
  `notes=${JSON.stringify(dcRedundant.notes)} drift=${JSON.stringify(dcRedundant.declared?.drift)}`,
);
check(
  "...while one the scan could not see is reported, and only that one claims 'not detected'",
  dcLayered.notes.some(
    (n) => n.includes(declaredAuthLabel("app-local-accounts")) && n.includes("not detected by this scan"),
  ) && !dcConflict.notes.some((n) => n.includes("not detected by this scan")),
  `${JSON.stringify(dcLayered.notes)} | ${JSON.stringify(dcConflict.notes)}`,
);
// The same silence in the UI. Both render rules live in the model rather than in the
// components precisely so this pass can call them: a decision inside a `.tsx` file is
// unassertable, and "agreement is not shown" is the kind of rule that regresses without
// anything failing. `conflicts` renders on purpose — it is the disagreement itself.
check(
  "the render rule agrees: a redundant declaration is shown nowhere, every other outcome is",
  showsDeclaredAuth("redundant") === false &&
    (["supplies", "conflicts", "supplements"] as const).every((a) => showsDeclaredAuth(a)) &&
    showsDeclaredAuth(dcRedundant.declared?.authAgreement) === false &&
    showsDeclaredAuth(dcLayered.declared?.authAgreement),
  `redundant=${showsDeclaredAuth("redundant")} layered=${showsDeclaredAuth(dcLayered.declared?.authAgreement)}`,
);
// The expected-ingress row is gated on this, so an expectation that holds renders no row
// at all. Order-independent on both sides, which is what makes `public+lan+traefik` in a
// sidecar the same statement however it was typed.
check(
  "...and an expectation that holds is a match in any order, so its row never renders",
  ingressMatchesExpectation(["lan", "traefik"], dcDefence.ingress) &&
    ingressMatchesExpectation(dcDefence.declared?.expectedIngress ?? [], dcDefence.ingress) &&
    !ingressMatchesExpectation(["lan", "public", "traefik"], ["traefik", "public"]) &&
    ingressMatchesExpectation(["lan", "public", "traefik"], ["traefik", "lan", "public"]),
  `${JSON.stringify(dcDefence.declared?.expectedIngress)} vs ${JSON.stringify(dcDefence.ingress)}`,
);

// The comparison itself, as a table. Reading `compareDeclaredAuth` and believing the
// layer rule is not the same as enumerating the pairs it has to get right.
const cmp = (mechanism: DeclaredAuthMechanism, detected: AuthMethod, wouldBeExposed = false) =>
  compareDeclaredAuth([{ mechanism }], detected, wouldBeExposed);
const CMP_TABLE: [DeclaredAuthMechanism, AuthMethod, string][] = [
  // Same family, either provider: the scan already says it.
  ["app-oidc", "authentik-oauth", "redundant"],
  ["app-oidc", "other-oauth", "redundant"],
  ["app-ldap", "authentik-ldap", "redundant"],
  ["app-ldap", "ldap", "redundant"],
  ["external-proxy", "authentik-forward-auth", "redundant"],
  ["external-proxy", "forward-auth", "redundant"],
  // Same tier, different mechanism: one of the two is stale.
  ["app-oidc", "ldap", "conflicts"],
  ["app-oidc", "authentik-ldap", "conflicts"],
  ["app-ldap", "other-oauth", "conflicts"],
  ["app-ldap", "authentik-oauth", "conflicts"],
  // Different tiers. The app logging users in and a gate in front of it are both true
  // at once, and this is the half of the table a "declared != detected" rule gets wrong.
  ["app-oidc", "authentik-forward-auth", "supplements"],
  ["app-oidc", "forward-auth", "supplements"],
  ["app-ldap", "forward-auth", "supplements"],
  ["external-proxy", "authentik-oauth", "supplements"],
  ["external-proxy", "ldap", "supplements"],
  // A detected mechanism with no counterpart in the declared vocabulary.
  ["app-oidc", "basic-auth", "supplements"],
  ["app-ldap", "basic-auth", "supplements"],
];
check(
  "the declared/detected table holds in every direction",
  CMP_TABLE.every(([m, d, want]) => cmp(m, d) === want),
  CMP_TABLE.filter(([m, d, want]) => cmp(m, d) !== want)
    .map(([m, d, want]) => `${m}+${d}: want ${want}, got ${cmp(m, d)}`)
    .join("; ") || "all pairs",
);
// Enumerated from the map rather than from a list written beside it, so a mechanism
// that gains a family later cannot keep being asserted as if it had none.
const incomparable = DECLARED_AUTH_MECHANISMS.filter((m) => declaredAuthFamily(m) === undefined);
const everyDetected: AuthMethod[] = [
  "authentik-forward-auth",
  "authentik-oauth",
  "authentik-ldap",
  "forward-auth",
  "other-oauth",
  "ldap",
  "basic-auth",
  "none",
];
check(
  "a mechanism this scan can never observe never contradicts it",
  incomparable.length === 6 &&
    incomparable.every((m) => everyDetected.every((d) => cmp(m, d) !== "conflicts" && cmp(m, d) !== "redundant")),
  `${incomparable.join(", ")} against ${everyDetected.length} detected methods`,
);
check(
  "...and every detected method is either comparable or explicitly not",
  everyDetected.every((d) => (d === "basic-auth" || d === "none") === (detectedAuthFamily(d) === undefined)),
  everyDetected.map((d) => `${d}=${detectedAuthFamily(d) ?? "-"}`).join(" "),
);
// The bound on the whole feature. `supplies` is the only outcome that changes a verdict,
// and what earns it is the exposure the scan found — not anything about the mechanism
// named. So the same declaration against the same detected method is load-bearing on a
// reachable service and merely additional on an unreachable one...
check(
  "what makes a declaration load-bearing is the exposure, not the mechanism",
  cmp("app-oidc", "none", true) === "supplies" && cmp("app-oidc", "none", false) === "supplements",
  `${cmp("app-oidc", "none", true)} / ${cmp("app-oidc", "none", false)}`,
);
// ...and no comparison of two *named* mechanisms can produce it, so a family table that
// grew a wrong entry could at worst warn wrongly — never quietly un-flag a service.
check(
  "...so comparing two named mechanisms can never change one",
  everyDetected.filter((d) => detectedAuthFamily(d) !== undefined).every((d) => cmp("app-oidc", d) !== "supplies"),
  everyDetected.map((d) => `${d}=${cmp("app-oidc", d)}`).join(" "),
);
check(
  "nothing declared is not an outcome, it is the absence of one",
  compareDeclaredAuth([], "none", true) === undefined,
  String(compareDeclaredAuth([], "none", true)),
);
// A declaration is only redundant when *all* of it is: the part the scan cannot see
// still has to be reported.
check(
  "a declaration that is partly redundant is still shown",
  compareDeclaredAuth([{ mechanism: "app-ldap" }, { mechanism: "app-local-accounts" }], "ldap", false) ===
    "supplements",
  String(compareDeclaredAuth([{ mechanism: "app-ldap" }, { mechanism: "app-local-accounts" }], "ldap", false)),
);
// Agreement about the tier settles the tier: something else declared alongside it is
// additional, not contradictory.
check(
  "...and one that agrees about the tier does not conflict over what else it names",
  compareDeclaredAuth([{ mechanism: "app-ldap" }, { mechanism: "app-oidc" }], "ldap", false) === "supplements",
  String(compareDeclaredAuth([{ mechanism: "app-ldap" }, { mechanism: "app-oidc" }], "ldap", false)),
);

// Over every fixture at once, because the number on the dashboard and the badge on the
// service are read by the same person and a divergence between them is invisible from
// either side alone.
const eAll = edge.stacks.flatMap((s) => s.services);
const supplied = eAll.filter((s) => s.declared?.authAgreement === "supplies");
check(
  "the declared-protected counter is exactly the services wearing that badge",
  supplied.length === edge.stats.declaredAuthProtected,
  `${supplied.length} services, counter says ${edge.stats.declaredAuthProtected}`,
);
check(
  "...none of which is also counted as exposed, or the same service would be both",
  supplied.every((s) => !s.auth.exposedWithoutAuth && s.auth.method === "none"),
  supplied.map((s) => `${s.name}=${s.auth.method}/${s.auth.exposedWithoutAuth}`).join(" "),
);
// The other direction, and the one that matters: every service reachable from outside
// with nothing detected in front of it is either counted as exposed or accounted for by a
// declaration. A third state would be a service that has quietly dropped out of the
// report altogether — which is precisely the risk in letting a declaration clear a
// finding. Recomputed from the evidence rather than read off `exposedWithoutAuth`, so it
// is a partition check and not a restatement of the flag.
const unprotected = (s: Service) =>
  isExternallyReachable(s.ingress) &&
  s.auth.method === "none" &&
  !hasEnforcedAuthentikGate(s) &&
  !s.cloudflare.some((r) => r.access && (r.access.policy || r.access.group || r.access.emails?.length));
check(
  "every reachable service with no detected auth is either exposed or declared-protected",
  eAll.filter(unprotected).every((s) => s.auth.exposedWithoutAuth || s.declared?.authAgreement === "supplies"),
  eAll
    .filter((s) => unprotected(s) && !s.auth.exposedWithoutAuth && s.declared?.authAgreement !== "supplies")
    .map((s) => s.name)
    .join(" ") || "none unaccounted for",
);

// Everything wrong with a sidecar is a warning; nothing about it fails a scan (I4).
const badStack = edge.stacks.find((s) => s.id === "badsidecar")!;
const badWarn = badStack.warnings.join(" | ");
check("a sidecar full of mistakes reports every one of them", badStack.warnings.length === 4, badWarn);
check("...a mistyped key is named rather than silently dropped", badWarn.includes('unknown key(s) "descripton"'), badWarn);
check(
  "...a mechanism named after a product is refused, with the vocabulary quoted back",
  badWarn.includes('"authentik-proxy" is not a known mechanism') && badWarn.includes("app-local-accounts"),
  badWarn,
);
check(
  "...an acceptance with no reason is refused, because it cannot be told from a mistake",
  badWarn.includes('needs a "reason"'),
  badWarn,
);
check(
  "...and a declaration for a service the compose file does not define is named",
  badWarn.includes('declares service "ghost"'),
  badWarn,
);
const bad = eSvc("badsidecar", "app");
check(
  "the refused acceptance leaves nothing behind",
  bad.declared?.unauthenticatedAccepted === undefined,
  JSON.stringify(bad.declared?.unauthenticatedAccepted),
);
check(
  "the valid declarations in the same file are still read",
  bad.declared?.auth.length === 1 &&
    bad.declared.auth[0]?.mechanism === "app-token" &&
    badStack.declared?.description?.startsWith("The valid half") === true,
  JSON.stringify({ auth: bad.declared?.auth, stack: badStack.declared?.description }),
);
check("...and the scan itself completed", bad.image === "example/app:1.0.0", String(bad.image));

const yml = eSvc("sidecaryml", "app");
check(
  "the .labview.yml spelling is probed too, and says which file it came from",
  yml.declared?.file === ".labview.yml",
  String(yml.declared?.file),
);
check(
  "a bare mechanism name is accepted as shorthand for {mechanism}",
  yml.declared?.auth[0]?.mechanism === "app-token" && yml.declared.auth[0].detail === undefined,
  JSON.stringify(yml.declared?.auth),
);

// LabView builds the sidecar path itself, so a symlink is the only way out of the
// tree — and a quiet one, since the contents would come back as a `description`.
const escStack = edge.stacks.find((s) => s.id === "escapedecl")!;
check(
  "a sidecar symlinked outside the apps root is refused",
  escStack.warnings.length === 1 && escStack.warnings[0]?.includes("outside the apps root") === true,
  JSON.stringify(escStack.warnings),
);
check(
  "...and nothing it declared is attached",
  escStack.declared === undefined && eSvc("escapedecl", "app").declared === undefined,
  JSON.stringify(escStack.declared),
);
// Both escape fixtures use the same marker, so this one comparison covers the
// sidecar and the `env_file` path at once, anywhere in the served payload.
check(
  "...nor reachable anywhere in the overview",
  !JSON.stringify(edge).includes("LEAKED_FROM_OUTSIDE_ROOT"),
);

console.log("\nsidecar validation, asserted directly");
// The rules that would need a committed 64 KiB file or a thousand-entry list to
// reach through the pipeline. `parseSidecar` is pure, so they are asserted on it.
const names = ["app"];
const yamlBad = parseSidecar("services:\n  app:\n   description: [unclosed\n", names, ".labview");
check(
  "malformed YAML is one warning and no declarations, not a failed scan",
  yamlBad.warnings.length === 1 &&
    yamlBad.warnings[0]?.includes("YAML parse error") === true &&
    yamlBad.services.size === 0 &&
    yamlBad.stack === undefined,
  JSON.stringify(yamlBad.warnings),
);
const notMapping = parseSidecar("- a list where a mapping belongs\n", names, ".labview");
check(
  "a top level that is not a mapping is reported",
  notMapping.warnings.length === 1 && notMapping.warnings[0]?.includes("expected a mapping at the top level") === true,
  JSON.stringify(notMapping.warnings),
);
for (const [what, text] of [
  ["an empty file", ""],
  ["a file of comments only", "# nothing declared yet\n"],
] as const) {
  const empty = parseSidecar(text, names, ".labview");
  check(
    `${what} declares nothing and complains about nothing`,
    empty.warnings.length === 0 && empty.services.size === 0 && empty.stack === undefined,
    JSON.stringify(empty.warnings),
  );
}
const long = parseSidecar(`description: ${"x".repeat(MAX_TEXT_CHARS + 500)}\n`, names, ".labview");
check(
  "an over-long string is truncated, marked, and reported",
  long.stack?.description?.length === MAX_TEXT_CHARS + 1 &&
    long.stack.description.endsWith("…") &&
    long.warnings.some((w) => w.includes(`truncated to ${MAX_TEXT_CHARS}`)),
  `${long.stack?.description?.length} chars | ${long.warnings.join(" | ")}`,
);
const listItems = (n: number, item: (i: number) => string): string =>
  Array.from({ length: n }, (_, i) => item(i)).join("");
const capped = parseSidecar(
  `links:\n${listItems(MAX_LIST_ENTRIES + 3, (i) => `  - url: https://example.com/${i}\n`)}` +
    `dependencies:\n${listItems(MAX_LIST_ENTRIES + 3, (i) => `  - dep-${i}\n`)}`,
  names,
  ".labview",
);
check(
  "links and dependencies are capped, each reported separately",
  capped.stack?.links.length === MAX_LIST_ENTRIES &&
    capped.stack.dependencies.length === MAX_LIST_ENTRIES &&
    capped.warnings.filter((w) => w.includes(`more than ${MAX_LIST_ENTRIES} entries`)).length === 2,
  JSON.stringify(capped.warnings),
);
const manyAuth = parseSidecar(
  `services:\n  app:\n    auth:\n${listItems(MAX_AUTH_ENTRIES + 2, () => "      - app-token\n")}`,
  names,
  ".labview",
);
check(
  "declared mechanisms are capped too",
  manyAuth.services.get("app")?.auth.length === MAX_AUTH_ENTRIES &&
    manyAuth.warnings.some((w) => w.includes(`more than ${MAX_AUTH_ENTRIES} entries`)),
  JSON.stringify({ n: manyAuth.services.get("app")?.auth.length, warnings: manyAuth.warnings }),
);
const other = parseSidecar(
  "services:\n  app:\n    auth:\n      - other\n      - mechanism: other\n        detail: A hardware key at the door.\n",
  names,
  ".labview",
);
check(
  '"other" says nothing on its own, so it is refused without a detail and kept with one',
  other.services.get("app")?.auth.length === 1 &&
    other.services.get("app")?.auth[0]?.detail === "A hardware key at the door." &&
    other.warnings.some((w) => w.includes('mechanism "other" needs a "detail"')),
  JSON.stringify({ auth: other.services.get("app")?.auth, warnings: other.warnings }),
);
const badIngress = parseSidecar("services:\n  app:\n    expected:\n      ingress: everywhere\n", names, ".labview");
check(
  "an unknown expected ingress is refused with the five kinds listed",
  badIngress.services.size === 0 &&
    badIngress.warnings.some((w) => w.includes('"everywhere" is not one of') && w.includes("internal, none")),
  JSON.stringify(badIngress.warnings),
);
// A service can be reachable several ways, so an expectation has to be able to say
// so. The scalar form stays valid — most services need exactly one kind, and a
// sidecar that had to be rewritten as a list to keep working would be a needless
// break.
const listIngress = parseSidecar(
  "services:\n  app:\n    expected:\n      ingress: [public, lan]\n",
  names,
  ".labview",
);
check(
  "an expected ingress can be a list of kinds",
  listIngress.services.get("app")?.expectedIngress?.join(", ") === "public, lan",
  JSON.stringify(listIngress.services.get("app")?.expectedIngress),
);
const scalarIngress = parseSidecar("services:\n  app:\n    expected:\n      ingress: lan\n", names, ".labview");
check(
  "...and a bare scalar still parses, as one kind",
  scalarIngress.services.get("app")?.expectedIngress?.join(", ") === "lan",
  JSON.stringify(scalarIngress.services.get("app")?.expectedIngress),
);
// Per-entry validation, so one typo costs one kind rather than the whole
// expectation — and the warning says which entry, since a list has no other handle.
const mixedIngress = parseSidecar(
  "services:\n  app:\n    expected:\n      ingress: [traefik, sideways]\n",
  names,
  ".labview",
);
check(
  "...and one bad entry in a list keeps the good ones and names its index",
  mixedIngress.services.get("app")?.expectedIngress?.join(", ") === "traefik" &&
    mixedIngress.warnings.some((w) => w.includes("ingress[1]") && w.includes('"sideways"')),
  JSON.stringify({ kinds: mixedIngress.services.get("app")?.expectedIngress, warnings: mixedIngress.warnings }),
);
// Written out of order and doubled, read back in the canonical most-to-least-exposed
// order, so a drift message and a badge row can never disagree about sequence.
const dupIngress = parseSidecar(
  "services:\n  app:\n    expected:\n      ingress: [lan, public, lan]\n",
  names,
  ".labview",
);
check(
  "...and the kinds are deduped and canonically ordered on the way in",
  dupIngress.services.get("app")?.expectedIngress?.join(", ") === "public, lan",
  JSON.stringify(dupIngress.services.get("app")?.expectedIngress),
);
// The sidecar side of the withholding rule, and the reason the rule lives in
// `normalizeIngress` rather than in the classifier. An operator writing down everything
// that is true of a service — including the container network, which is true of nearly
// all of them — must not be told they are wrong about a scan that will never report it.
// So the declared `internal` is dropped here, quietly, leaving an expectation the scan
// can actually match. The internal-only expectation below is the other half: there it is
// the whole statement, and it survives untouched.
const impliedInternal = parseSidecar(
  "services:\n  app:\n    expected:\n      ingress: [public, lan, internal]\n",
  names,
  ".labview",
);
check(
  "a declared `internal` beside an external kind is dropped, not drifted against",
  impliedInternal.services.get("app")?.expectedIngress?.join(", ") === "public, lan" &&
    impliedInternal.warnings.length === 0,
  `${JSON.stringify(impliedInternal.services.get("app")?.expectedIngress)} ${JSON.stringify(impliedInternal.warnings)}`,
);
const onlyInternal = parseSidecar(
  "services:\n  app:\n    expected:\n      ingress: internal\n",
  names,
  ".labview",
);
check(
  "...and on its own it is an expectation like any other",
  onlyInternal.services.get("app")?.expectedIngress?.join(", ") === "internal",
  JSON.stringify(onlyInternal.services.get("app")?.expectedIngress),
);
const linkCred = parseSidecar("links:\n  - url: https://admin:hunter2@example.com/panel\n", names, ".labview");
check(
  "a password embedded in a declared url is redacted, since no mask reaches prose",
  linkCred.stack?.links[0]?.url === "https://admin:***@example.com/panel" &&
    !JSON.stringify(linkCred).includes("hunter2"),
  JSON.stringify(linkCred.stack?.links),
);
// A mechanism with no label would render as `undefined` in a badge; the record is
// exhaustive by type, so this catches a member added without wording.
check(
  "every declarable mechanism has wording a reader can use",
  DECLARED_AUTH_MECHANISMS.every((m) => declaredAuthLabel(m).length > 2) &&
    new Set(DECLARED_AUTH_MECHANISMS.map(declaredAuthLabel)).size === DECLARED_AUTH_MECHANISMS.length,
  DECLARED_AUTH_MECHANISMS.map(declaredAuthLabel).join(" | "),
);
// The skeleton is the documentation. If it drifts from the validator, the first
// thing an operator copies produces warnings — so it is parsed here as input.
const skeleton = parseSidecar(
  readFileSync(resolve(here, "..", ".labview.example"), "utf8"),
  ["emby"],
  ".labview.example",
);
check(
  "the shipped skeleton parses with no warnings at all",
  skeleton.warnings.length === 0,
  JSON.stringify(skeleton.warnings),
);
check(
  "...and every documented field actually lands somewhere",
  skeleton.stack?.description !== undefined &&
    skeleton.stack.owner !== undefined &&
    skeleton.stack.criticality !== undefined &&
    skeleton.stack.notes !== undefined &&
    skeleton.stack.data !== undefined &&
    skeleton.stack.links.length > 0 &&
    skeleton.stack.dependencies.length > 0 &&
    skeleton.services.get("emby")?.auth.length === 2 &&
    skeleton.services.get("emby")?.unauthenticatedAccepted !== undefined &&
    skeleton.services.get("emby")?.expectedIngress !== undefined,
  JSON.stringify({ stack: skeleton.stack, emby: skeleton.services.get("emby") }),
);
// The skeleton is the only documentation most operators will read, so it has to
// demonstrate the multi-kind form rather than describe it — and if the parser ever
// stops accepting a list, the file shipped as an example is the first thing to break.
// Two kinds, both external: the example is also the one place the `internal` rule would
// be most tempting to write out, so it must not hand an operator a list that the reader
// silently shortens.
check(
  "...including the skeleton's own multi-kind expectation, parsed as two kinds",
  skeleton.services.get("emby")?.expectedIngress?.join(", ") === "public, lan",
  JSON.stringify(skeleton.services.get("emby")?.expectedIngress),
);
// The size cap is I/O, so it is the one rule that needs a file — written to a temp
// dir rather than committed, since the point is that it is larger than a sidecar
// has any business being.
const bigDir = mkdtempSync(resolve(tmpdir(), "labview-sidecar-"));
writeFileSync(resolve(bigDir, ".labview"), `description: ${"y".repeat(MAX_SIDECAR_BYTES + 10)}\n`);
const tooBig = readSidecar(
  { id: "big", dir: bigDir, composeFile: resolve(bigDir, "compose.yml"), sidecarFile: resolve(bigDir, ".labview") },
  bigDir,
  ["app"],
);
check(
  "a sidecar larger than the cap is refused unread, with its size said out loud",
  tooBig.stack === undefined &&
    tooBig.warnings.length === 1 &&
    tooBig.warnings[0]?.includes(`exceeds the ${MAX_SIDECAR_BYTES}-byte limit`) === true,
  JSON.stringify(tooBig.warnings),
);
rmSync(bigDir, { recursive: true, force: true });

// `depends_on`, read but never resolved: the parser sees one stack, and the service a
// reference names is usually in another. So the reference is kept exactly as written and
// only checked for a shape that could name a service at all — which is also what makes
// every one of these rules assertable with no fixture fleet behind it.
console.log("\nthe sidecar's reading of a service reference");
const deps1 = parseSidecar(
  "services:\n  app:\n    depends_on:\n      - other/backup\n      - service: two/agent\n        detail: nightly dump\n",
  names,
  ".labview",
);
check(
  "both forms are read, and the reference is stored as written",
  deps1.services.get("app")?.dependsOn.map((d) => d.ref).join(", ") === "other/backup, two/agent" &&
    deps1.warnings.length === 0,
  `${JSON.stringify(deps1.services.get("app")?.dependsOn)} ${JSON.stringify(deps1.warnings)}`,
);
check(
  "...with the operator's note where they wrote one",
  deps1.services.get("app")?.dependsOn[1]?.detail === "nightly dump",
);
// A service whose sidecar entry says nothing else at all. Declarations with no content are
// dropped, and a dependency is content — losing it here would lose the whole feature for
// the operator who only wanted to state one thing.
check(
  "a service declaring nothing but a dependency is still kept",
  parseSidecar("services:\n  app:\n    depends_on: [other/agent]\n", names, ".labview").services.get("app")
    ?.dependsOn.length === 1,
);
const depsBad = parseSidecar(
  "services:\n  app:\n    depends_on:\n      - a/b/c\n      - has space\n      - detail: no service key\n      - true\n",
  names,
  ".labview",
);
check(
  "a reference that could not name a service is refused, one warning each",
  !depsBad.services.has("app") && depsBad.warnings.length === 4,
  `${JSON.stringify(depsBad.services.get("app"))} ${JSON.stringify(depsBad.warnings)}`,
);
check(
  "...naming the shape it should have had rather than just rejecting it",
  depsBad.warnings.filter((w) => w.includes('write "stack/service"')).length === 2 &&
    depsBad.warnings.some((w) => w.includes('needs a "service"')) &&
    depsBad.warnings.some((w) => w.includes('expected "stack/service" or {service, detail}')),
  JSON.stringify(depsBad.warnings),
);
check(
  "...and the list is capped like every other",
  parseSidecar(
    `services:\n  app:\n    depends_on:\n${Array.from({ length: MAX_LIST_ENTRIES + 5 }, (_, i) => `      - s/n${i}\n`).join("")}`,
    names,
    ".labview",
  ).services.get("app")?.dependsOn.length === MAX_LIST_ENTRIES,
);
// At stack level the key cannot say *which* of the stack's services depends on the target,
// which is a different mistake from a typo — and told apart from one, because the generic
// unknown-key warning would send an operator looking for a spelling error.
const depsStack = parseSidecar("depends_on:\n  - other/agent\n", names, ".labview");
check(
  "at stack level it is refused with the reason it cannot work there",
  depsStack.warnings.length === 1 &&
    depsStack.warnings[0]?.includes("is a service-level key") === true &&
    depsStack.warnings[0]?.includes("which service depends on the target") === true,
  JSON.stringify(depsStack.warnings),
);
check(
  "...and not reported as an unknown key, which would be the wrong thing to go looking for",
  !depsStack.warnings.some((w) => w.includes("unknown")),
  JSON.stringify(depsStack.warnings),
);

/* ========================================================================== */
/* fixtures/nets — services connected through shared networks                 */
/* ========================================================================== */

const nets = await overviewFor(netsRoot);
const nSvc = lookup(nets);
const netNode = (name: string) => nets.graph.nodes.find((n) => n.kind === "network" && n.label === name);
const membership = (svc: string, net: string) =>
  nets.graph.edges.find((e) => e.kind === "network" && e.source === svc && e.target === `net:${net}`);

console.log("\n--- network connections (fixtures/nets) ---");

/** The dependency edge between two services, from either source. */
const dependency = (from: string, to: string) =>
  nets.graph.edges.find(
    (e) => e.kind === "depends_on" && e.source === `svc:${from}` && e.target === `svc:${to}`,
  );
/** One service's drift entries joined, so a substring assertion never depends on order. */
const nDrift = (stack: string, svc: string) => (nSvc(stack, svc).declared?.drift ?? []).join(" | ");

console.log("\none external network across four stacks");
const backup = netNode("backup");
check("the shared network is one node, not one per stack", Boolean(backup));
check("...named by its real docker name, so every stack means the same network", backup?.id === "net:backup");
check("...scoped external, since several projects name it and it belongs to none", backup?.scope === "external");
check("...counting every scanned service on it", backup?.memberCount === 4, String(backup?.memberCount));
check("...and the stacks they come from", backup?.stackCount === 4, String(backup?.stackCount));

// The case the whole feature exists for. Two databases in two stacks are backed up by an
// agent in a third; compose cannot say so, because `depends_on` reaches no further than its
// own project. The sidecars say it, each on its own database — and the agent, which has no
// sidecar at all, has to show both of them as services that need it.
console.log("\nthe dependency compose cannot express");
check(
  "the reference is kept exactly as the sidecar wrote it, qualified",
  nSvc("shared-a", "db-a").declared?.dependsOn[0]?.ref === "shared-c/backup-agent",
  JSON.stringify(nSvc("shared-a", "db-a").declared?.dependsOn),
);
check(
  "...and it resolves to an edge over the network the two share",
  dependency("shared-a/db-a", "shared-c/backup-agent")?.via?.join(",") === "backup",
  JSON.stringify(dependency("shared-a/db-a", "shared-c/backup-agent")),
);
check(
  "...marked as the operator's statement, naming the file that made it",
  dependency("shared-a/db-a", "shared-c/backup-agent")?.declaredBy?.file === ".labview" &&
    dependency("shared-a/db-a", "shared-c/backup-agent")?.declaredBy?.detail?.startsWith("Nightly dump") === true,
  JSON.stringify(dependency("shared-a/db-a", "shared-c/backup-agent")?.declaredBy),
);
check(
  "an unqualified name resolves across the fleet to the same target",
  dependency("shared-b/db-b", "shared-c/backup-agent")?.via?.join(",") === "backup",
  JSON.stringify(dependency("shared-b/db-b", "shared-c/backup-agent")),
);
// The asymmetry the design rests on: one entry on each dependent, nothing on the target,
// and the target still reports both. A `required_by` key would have to be edited for every
// database anyone adds — which is the maintenance this avoids.
const agent = serviceConnections(nets.graph, graphServiceId("shared-c", "backup-agent"));
check("the consumer's connections are found through the network", agent.links.length === 1);
check(
  "the target has no sidecar of its own at all",
  nSvc("shared-c", "backup-agent").declared === undefined,
  JSON.stringify(nSvc("shared-c", "backup-agent").declared),
);
check(
  "...and still reports both databases as services that require it",
  agent.links[0]?.dependencies.map((p) => `${p.stack}/${p.service}:${p.relation}`).join(", ") ===
    "shared-a/db-a:required-by, shared-b/db-b:required-by",
  JSON.stringify(agent.links[0]?.dependencies),
);
check(
  "...each naming the file it was declared in, which belongs to the other stack",
  agent.links[0]?.dependencies.every((p) => p.declared === true && p.file === ".labview") === true,
  JSON.stringify(agent.links[0]?.dependencies),
);
check(
  "...and neither is also drawn straight across, since the network carries them",
  agent.direct.every((d) => d.service !== "db-a" && d.service !== "db-b"),
  JSON.stringify(agent.direct),
);
// Two of the four resolved dependencies are the pair above; the fleet counter is what the
// CLI prints, and it counts resolved edges rather than references written.
check(
  "the fleet counts what a sidecar stated and the scan could resolve",
  nets.stats.declaredDependencies === 5,
  String(nets.stats.declaredDependencies),
);

// Read from the other end, the same network reports the same membership. A per-service
// view that disagreed with the fleet view about who is on a network would be worse than
// either alone.
const groups = networkGroups(nets.graph);
const backupGroup = groups.find((g) => g.name === "backup");
check(
  "the fleet list reports the same four members",
  backupGroup?.members.map((m) => `${m.stack}/${m.service}`).join(", ") ===
    "shared-a/db-a, shared-b/db-b, shared-c/backup-agent, shared-d/monitor",
  JSON.stringify(backupGroup?.members),
);
check(
  "...and names the two dependencies it carries as declared, not observed",
  backupGroup?.pairs.map((p) => `${p.from.service}->${p.to.service}:${p.declared === true}`).join(", ") ===
    "db-a->backup-agent:true, db-b->backup-agent:true",
  JSON.stringify(backupGroup?.pairs),
);
check(
  "...and the most-connecting network is listed first",
  groups[0]?.name === "backup",
  groups.map((g) => g.name).join(","),
);

// The other half of the rule, and the reason the feature exists in this shape: a fourth
// service is on that same network and nothing anywhere says it depends on, or is depended on
// by, any of the others. It is a member. It is not a connection.
console.log("\nsharing a network is not a dependency");
check(
  "the co-member is on the network",
  Boolean(membership("svc:shared-d/monitor", "backup")),
);
check(
  "...and its leg carries no arrowhead, because nothing crosses it",
  membership("svc:shared-d/monitor", "backup")?.flow === undefined,
  String(membership("svc:shared-d/monitor", "backup")?.flow),
);
check(
  "...it is listed as reachable rather than as a dependency",
  agent.links[0]?.alsoOn.map((p) => `${p.stack}/${p.service}`).join(", ") === "shared-d/monitor" &&
    agent.links[0]?.dependencies.every((p) => p.service !== "monitor") === true,
  JSON.stringify({ alsoOn: agent.links[0]?.alsoOn, deps: agent.links[0]?.dependencies }),
);
const monitor = serviceConnections(nets.graph, graphServiceId("shared-d", "monitor"));
check(
  "...and from its own side the network connects it to nothing",
  monitor.links[0]?.dependencies.length === 0 && monitor.direct.length === 0,
  JSON.stringify(monitor),
);
check(
  "...while still naming all three services it could reach",
  monitor.links[0]?.alsoOn.map((p) => `${p.stack}/${p.service}`).join(", ") ===
    "shared-a/db-a, shared-b/db-b, shared-c/backup-agent",
  JSON.stringify(monitor.links[0]?.alsoOn),
);
check(
  "...and the fleet list keeps it out of the pairs while keeping it in the members",
  backupGroup?.members.some((m) => m.service === "monitor") === true &&
    backupGroup?.pairs.every((p) => p.from.service !== "monitor" && p.to.service !== "monitor") === true,
);

console.log("\na dependency drawn through the network that carries it");
const inner = netNode("layered_inner");
check("the stack's own network is scoped stack-local", inner?.scope === "stack-local");
check("...and its name is the compose project's, not the key's", inner?.id === "net:layered_inner");
const webDep = nets.graph.edges.find(
  (e) => e.kind === "depends_on" && e.source === "svc:layered/web" && e.target === "svc:layered/api",
);
check("the dependency records the network it travels over", webDep?.via?.join(",") === "layered_inner");
check("...so it is not drawn as a line straight between the two services", !showsDirectDependency(webDep!));
check(
  "the dependent's leg points at the network",
  membership("svc:layered/web", "layered_inner")?.flow === "to-network",
  String(membership("svc:layered/web", "layered_inner")?.flow),
);
check(
  "...and the dependency's leg points back out at the service",
  membership("svc:layered/cache", "layered_inner")?.flow === "to-service",
  String(membership("svc:layered/cache", "layered_inner")?.flow),
);
// Which is what makes the middle of a chain readable: api is needed by web and needs
// cache, both over the same network, so its one leg carries an arrowhead at each end.
check(
  "a service at both ends of a chain carries both arrowheads on one leg",
  membership("svc:layered/api", "layered_inner")?.flow === "both",
  String(membership("svc:layered/api", "layered_inner")?.flow),
);
check(
  "a service with no dependency either way carries no arrowhead",
  membership("svc:layered/probe", "layered_inner")?.flow === undefined,
  String(membership("svc:layered/probe", "layered_inner")?.flow),
);
// Provenance travels with the arrowhead, because the arrowhead alone cannot say whether
// anyone measured what it claims. `extra` needs the cache by declaration only; the cache is
// needed by `api` as well, which compose does state, so its leg carries both provenances and
// must read as observed — something crossing it was read from a compose file.
check(
  "an arrowhead put there by compose is marked observed",
  membership("svc:layered/web", "layered_inner")?.flowSource === "observed",
  String(membership("svc:layered/web", "layered_inner")?.flowSource),
);
check(
  "...one put there by a sidecar alone is marked declared",
  membership("svc:layered/extra", "layered_inner")?.flowSource === "declared" &&
    membership("svc:layered/extra", "layered_inner")?.flow === "to-network",
  JSON.stringify(membership("svc:layered/extra", "layered_inner")),
);
check(
  "...and a leg carrying one of each says so, rather than picking a side",
  membership("svc:layered/cache", "layered_inner")?.flowSource === "both",
  String(membership("svc:layered/cache", "layered_inner")?.flowSource),
);
check(
  "a leg with no arrowhead has no provenance to report",
  membership("svc:layered/probe", "layered_inner")?.flowSource === undefined,
  String(membership("svc:layered/probe", "layered_inner")?.flowSource),
);
// The declaration does not need to cross a stack boundary to be worth making: compose's own
// key would order the containers, which is a different claim from "reads the cache".
check(
  "a sidecar can state a dependency inside one stack too",
  dependency("layered/extra", "layered/cache")?.declaredBy?.file === ".labview" &&
    dependency("layered/extra", "layered/cache")?.via?.join(",") === "layered_inner",
  JSON.stringify(dependency("layered/extra", "layered/cache")),
);
check(
  "...and the one compose stated carries no declaration",
  dependency("layered/api", "layered/cache")?.declaredBy === undefined,
  JSON.stringify(dependency("layered/api", "layered/cache")?.declaredBy),
);
// The pairing the arrowheads cannot express once several dependencies cross one network, said
// in words instead — this is why the graph is not the only view of it.
check(
  "the network's row names every pair it carries, dependent first",
  groups
    .find((g) => g.name === "layered_inner")
    ?.pairs.map((p) => `${p.from.service}->${p.to.service}:${p.declared === true}`)
    .join(", ") === "web->api:false, api->cache:false, extra->cache:true",
  JSON.stringify(groups.find((g) => g.name === "layered_inner")?.pairs),
);
// The drawer reads the same relations from one service's point of view, and has to tell
// the two directions apart: api needs cache, and web needs api.
const apiConn = serviceConnections(nets.graph, graphServiceId("layered", "api"));
check(
  "the drawer tells 'depends on' from 'required by' on the same network",
  apiConn.links[0]?.dependencies.map((p) => `${p.service}:${p.relation}`).join(", ") ===
    "cache:depends-on, web:required-by",
  JSON.stringify(apiConn.links[0]?.dependencies),
);
check(
  "...and keeps the rest of the network off that list, in the reachable one",
  apiConn.links[0]?.alsoOn.map((p) => p.service).join(", ") === "extra, probe",
  JSON.stringify(apiConn.links[0]?.alsoOn),
);
check(
  "...naming no stack, since one stack owns every service on it",
  apiConn.links[0]?.dependencies.every((p) => p.stack === "layered") === true,
);

console.log("\na dependency with no network to travel over");
const disjoint = nets.graph.edges.find(
  (e) => e.kind === "depends_on" && e.source === "svc:disjoint/front" && e.target === "svc:disjoint/back",
);
check("the pair shares no network", disjoint?.via?.length === 0, JSON.stringify(disjoint?.via));
check("...so the direct arrow is the one drawing left, and it is kept", showsDirectDependency(disjoint!));
check(
  "...and the service says what that means, since a picture alone would not",
  nSvc("disjoint", "front").notes.some(
    (n) => n.includes("share no docker network") && n.includes("neither container can reach the other"),
  ),
  JSON.stringify(nSvc("disjoint", "front").notes),
);
check(
  "the same dependency is reported by the drawer as direct rather than through a network",
  serviceConnections(nets.graph, graphServiceId("disjoint", "front")).direct.map((d) => d.service).join(",") ===
    "back",
);
// The same geometry, reached by declaration instead of by compose — and it needs a different
// sentence, because the compose one ("startup is ordered") is simply false here. Nothing
// orders these two containers; a sidecar cannot.
const declaredApart = dependency("disjoint/back", "shared-c/backup-agent");
check("a declared dependency can be just as unreachable", declaredApart?.via?.length === 0);
check("...and the arrow between the two is the drawing that survives", showsDirectDependency(declaredApart!));
check(
  "...said as a statement the scan cannot confirm, not as an ordering it never established",
  nSvc("disjoint", "back").notes.some(
    (n) =>
      n.includes("is declared as a dependency in .labview") &&
      n.includes("share no docker network") &&
      n.includes("a published port, the host, or a proxy"),
  ),
  JSON.stringify(nSvc("disjoint", "back").notes),
);
check(
  "...and the note is not the compose one, which would claim an ordering",
  !nSvc("disjoint", "back").notes.some((n) => n.includes("startup is ordered")),
  JSON.stringify(nSvc("disjoint", "back").notes),
);
// Both of this service's dependencies are unreachable, one declared and one from compose,
// and the drawer draws both straight across — the declared one marked as declared, so the
// two are never confused for having the same standing.
const backConn = serviceConnections(nets.graph, graphServiceId("disjoint", "back"));
check(
  "the drawer draws it straight across, marked as declared and named with its stack",
  backConn.direct.map((d) => `${d.stack}/${d.service}:${d.relation}:${d.declared === true}`).join(", ") ===
    "shared-c/backup-agent:depends-on:true, disjoint/front:required-by:false",
  JSON.stringify(backConn.direct),
);

// Four things a reference can turn out to be, three of which draw nothing. Each is reported
// against the sidecar that made the claim rather than swallowed, because a reference that
// silently resolves to nothing is the failure mode of the whole key.
console.log("\nwhat a reference can turn out to name");
check(
  "a name matching no scanned service is reported as such",
  nDrift("badref", "caller").includes('depends_on "nope/missing", which names no scanned service'),
  nDrift("badref", "caller"),
);
check(
  "...a name matching the declaring service itself, likewise",
  nDrift("badref", "caller").includes('depends_on "caller", which is this service itself'),
  nDrift("badref", "caller"),
);
check(
  "...and an unqualified name matching two services names both and asks for a stack",
  nDrift("disjoint", "front").includes(
    'depends_on "probe", which names 2 services (layered/probe, shared-d/probe) — qualify it as "stack/service"',
  ),
  nDrift("disjoint", "front"),
);
check(
  "...with no edge drawn for any of the three",
  !dependency("badref/caller", "badref/caller") &&
    !dependency("disjoint/front", "layered/probe") &&
    !dependency("disjoint/front", "shared-d/probe"),
);
check(
  "an unqualified name prefers the declaring stack's own service, as compose's key would",
  dependency("badref/caller", "badref/cache")?.declaredBy?.file === ".labview",
  JSON.stringify(dependency("badref/caller", "badref/cache")),
);
check(
  "...and naming the same target twice draws one edge and says nothing about it",
  nets.graph.edges.filter((e) => e.kind === "depends_on" && e.source === "svc:badref/caller").length === 1 &&
    !nDrift("badref", "caller").includes("cache"),
  nDrift("badref", "caller"),
);
// Resolution reads the declaration; it must never write back into it. The sidecar object is
// what a rescan compares to report an edited file (§3.11), so a target resolved out of the
// fleet has no business inside it — a rename in another stack would read as this file
// changing. All four references are still here, exactly as written, duplicate included.
check(
  "the declaration survives resolution unedited, failures and duplicate included",
  nSvc("badref", "caller").declared?.dependsOn.map((d) => d.ref).join(", ") ===
    "nope/missing, caller, cache, badref/cache",
  JSON.stringify(nSvc("badref", "caller").declared?.dependsOn),
);
check(
  "...and every failure is reported as drift, which a rescan comparison excludes",
  nSvc("badref", "caller").declared?.drift?.length === 2 && nets.stats.declarationDrift === 2,
  JSON.stringify({ drift: nSvc("badref", "caller").declared?.drift, fleet: nets.stats.declarationDrift }),
);

console.log("\nnetworks that connect nothing");
check("a stack-local network with one service on it is not drawn", !showsNetworkNode(netNode("lonely_island")!));
// The other arm of the same rule, and the reason it is two arms: an external network with
// one scanned service on it says something a stack-local one cannot — a container this
// scan never saw may be on the other end.
check("an external network with one service on it is drawn", showsNetworkNode(netNode("outside")!));
check(
  "...and says what it can and cannot see, rather than reporting it as empty",
  networkMembershipText(networkLinks(nets.graph, graphServiceId("lonely", "edge-facing"))[0]!).includes(
    "containers this scan cannot see may be",
  ),
);
check(
  "a stack-local network with nothing else on it says the opposite",
  networkMembershipText({
    id: "net:x",
    name: "x",
    scope: "stack-local",
    memberCount: 1,
    stackCount: 1,
    dependencies: [],
    dependenciesOmitted: 0,
    alsoOn: [],
    alsoOnOmitted: 0,
  }).includes("only this stack's own services could be"),
);
// The third case, and the one the request turns on: services are on it, and being on it is
// all that is true of them. Said in words, because the diagram deliberately draws nothing.
check(
  "a network with members but no dependency says reachable, not dependent",
  networkMembershipText(networkLinks(nets.graph, graphServiceId("shared-d", "monitor"))[0]!) ===
    "3 other services are on it. Sharing a network makes them reachable, not dependent — " +
      "nothing declares a dependency across it.",
  networkMembershipText(networkLinks(nets.graph, graphServiceId("shared-d", "monitor"))[0]!),
);
check(
  "...and says nothing at all where a dependency does cross it, leaving the chips to speak",
  networkMembershipText(agent.links[0]!) === "",
  networkMembershipText(agent.links[0]!),
);
check(
  "the counters split the fleet's networks into drawn and left out",
  nets.stats.networks === 9 &&
    nets.stats.connectingNetworks === 3 &&
    nets.stats.crossStackNetworks === 1 &&
    nets.stats.soloLocalNetworks === 5,
  JSON.stringify({
    networks: nets.stats.networks,
    connecting: nets.stats.connectingNetworks,
    crossStack: nets.stats.crossStackNetworks,
    soloLocal: nets.stats.soloLocalNetworks,
  }),
);
// The arithmetic that makes the omission checkable rather than a matter of trust: what the
// graph draws plus what it leaves out is every network in the fleet.
check(
  "...so drawn networks plus omitted ones account for all of them",
  nets.graph.nodes.filter((n) => n.kind === "network" && showsNetworkNode(n)).length +
    nets.stats.soloLocalNetworks ===
    nets.stats.networks,
);
check(
  "...and the reader is told how many were left out",
  hiddenNetworksNote(nets.stats.soloLocalNetworks) ===
    "5 stack-local networks with a single service on them are not drawn.",
  hiddenNetworksNote(nets.stats.soloLocalNetworks),
);
check("nothing is said when none was left out", hiddenNetworksNote(0) === "");

console.log("\nthe caps on a network too large to draw");
// Synthetic, on purpose: the rule fires past twelve spokes and past eight peers, and
// proving it with fixtures would mean committing a twenty-service fleet whose only job is
// to be big. The functions are pure, so this asserts the rule itself.
const bigNet = { id: "net:big", label: "big", kind: "network" as const, scope: "external" as const, memberCount: 20, stackCount: 4 };
const bigSpokes = Array.from({ length: 20 }, (_, i) => ({
  id: `svc:s/n${i}->net:big`,
  source: `svc:s/n${i}`,
  target: "net:big",
  kind: "network" as const,
  // Two spokes carry a dependency, and they are the last two in scan order — so keeping
  // them proves the sort rather than the slice.
  ...(i >= 18 ? { flow: "to-network" as const } : {}),
}));
const cappedSpokes = visibleSpokes(bigSpokes);
check("a network with more spokes than the cap draws exactly the cap", cappedSpokes.kept.length === MAX_GRAPH_SPOKES);
check("...and reports the rest rather than dropping them silently", cappedSpokes.omitted === 20 - MAX_GRAPH_SPOKES);
check(
  "...keeping the spokes that carry a dependency, which are the ones that say anything",
  cappedSpokes.kept.filter((e) => e.flow).length === 2,
  String(cappedSpokes.kept.filter((e) => e.flow).length),
);
check("a network within the cap is drawn whole", visibleSpokes(bigSpokes.slice(0, 5)).omitted === 0);
check(
  "the node's own label carries the counts and the omission",
  networkNodeLabel(bigNet, MAX_GRAPH_SPOKES) === "big\n20 services · 4 stacks · +8 not drawn",
  networkNodeLabel(bigNet, MAX_GRAPH_SPOKES),
);
check(
  "...and says nothing about an omission where there is none",
  networkNodeLabel({ ...bigNet, memberCount: 2, stackCount: 1 }, 2) === "big\n2 services",
  networkNodeLabel({ ...bigNet, memberCount: 2, stackCount: 1 }, 2),
);
// The drawer's two caps are separate, because the two lists cost different things: a
// dependency becomes a leg in a diagram, a co-member becomes a word in a sentence. One
// shared cap would let twelve services that are merely reachable crowd out a dependency —
// which is the failure this whole change is about, arriving by a different route.
const CROWD = 26;
const crowded = {
  nodes: [
    { id: "net:big", label: "big", kind: "network" as const, scope: "external" as const, memberCount: CROWD, stackCount: 1 },
    ...Array.from({ length: CROWD }, (_, i) => ({
      id: `svc:s/n${i}`,
      label: `n${i}`,
      kind: "service" as const,
      stack: "s",
    })),
  ],
  edges: [
    ...Array.from({ length: CROWD }, (_, i) => ({
      id: `svc:s/n${i}->net:big`,
      source: `svc:s/n${i}`,
      target: "net:big",
      kind: "network" as const,
    })),
    // n0 depends on the *last* ten members in scan order, so a cap that simply took the
    // first eight members of the network would keep none of them.
    ...Array.from({ length: 10 }, (_, i) => ({
      id: `d${i}`,
      source: "svc:s/n0",
      target: `svc:s/n${CROWD - 10 + i}`,
      kind: "depends_on" as const,
      via: ["big"],
    })),
  ],
};
const crowdedLink = networkLinks(crowded, "svc:s/n0")[0]!;
check("the drawer caps the dependencies it names", crowdedLink.dependencies.length === MAX_DRAWER_PEERS);
check("...and reports how many it left out", crowdedLink.dependenciesOmitted === 10 - MAX_DRAWER_PEERS);
check(
  "...keeping dependencies whatever their scan position, since a co-member cannot displace one",
  crowdedLink.dependencies[0]?.service === "n16" &&
    crowdedLink.dependencies.every((p) => p.relation === "depends-on"),
  JSON.stringify(crowdedLink.dependencies[0]),
);
check(
  "the co-members are capped on their own, larger allowance",
  crowdedLink.alsoOn.length === MAX_LIST_PEERS,
  String(crowdedLink.alsoOn.length),
);
check(
  "...and report their own omission separately",
  crowdedLink.alsoOnOmitted === CROWD - 1 - 10 - MAX_LIST_PEERS,
  String(crowdedLink.alsoOnOmitted),
);
check(
  "...and no service is in both lists",
  crowdedLink.alsoOn.every((a) => !crowdedLink.dependencies.some((d) => d.id === a.id)),
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

/** The unmatched entry for one application slug, with its reason and trace. */
function akUnplaced(slug: string) {
  return akMeta.unmatchedApplications.find((u) => u.application.slug === slug);
}
/** Slugs LabView could not place, sorted — the shape most assertions below want. */
function akUnplacedSlugs(): string {
  return akMeta.unmatchedApplications
    .map((u) => u.application.slug)
    .sort()
    .join(",");
}
/** Everything one unmatched entry says, for a substring assertion over the whole trace. */
function akTrace(slug: string): string {
  const u = akUnplaced(slug);
  return u ? [u.reason, u.detail, ...u.considered].join(" | ") : `no unmatched entry for ${slug}`;
}
/**
 * Slugs of every application this run rebuilt from a provider, matched or not, sorted.
 *
 * Both halves matter: an application missing from here was silently upgraded to a
 * list-sourced record, and one wrongly present claims less evidence than it has.
 */
function akRebuiltSlugs(): string {
  const matched = ak.stacks
    .flatMap((s) => s.services)
    .flatMap((s) => s.authentik?.applications ?? []);
  return [...matched, ...akMeta.unmatchedApplications.map((u) => u.application)]
    .filter((a) => a.discoveredVia === "provider")
    .map((a) => a.slug)
    .sort()
    .join(",");
}

console.log("\nendpoint discovery");
check("found 14 stacks", ak.stats.stacks === 14, `got ${ak.stats.stacks}`);
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
// The one gap this run reports is the policy filter, asserted in full below. Any other
// clause here would mean an endpoint failed, which would invalidate the counts.
check(
  "every endpoint was read",
  !(akMeta.error ?? "").includes("could not be read"),
  akMeta.error ?? "",
);

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
  "15 applications known, 16 providers, 2 outposts",
  akMeta.applications === 15 && akMeta.providers === 16 && akMeta.outposts === 2,
  `${akMeta.applications}/${akMeta.providers}/${akMeta.outposts}`,
);
check(
  "the second page of applications was requested",
  discovered.calls.some((c) => c.url.includes("core/applications") && c.url.includes("page=2")),
  discovered.calls.filter((c) => c.url.includes("core/applications")).map((c) => c.url).join(" "),
);
check("10 of 15 applications were placed, on 10 distinct services", akMeta.matchedServices === 10, String(akMeta.matchedServices));

// `/core/applications/` policy-filters the page it has already counted, so a
// least-privilege token is served a subset and told the total. Reporting the subset as
// the total is what made a service protected by a withheld application read as open.
console.log("\nthe applications endpoint withholds part of its own list");
check(
  "the full list is asked for, so a superuser token is not silently under-read",
  discovered.calls.some(
    (c) => c.url.includes("core/applications") && c.url.includes("superuser_full_list=true"),
  ),
  discovered.calls.filter((c) => c.url.includes("core/applications")).map((c) => c.url).join(" "),
);
// The count survives the filter because pagination runs before it. Reverting the capture
// leaves `applicationsConfigured` undefined and every number below collapses to the
// filtered one, which is the bug.
check(
  "the total Authentik reports is kept, not the number it returned",
  akMeta.applicationsConfigured === 16 && akMeta.applicationsWithheld === 3,
  `configured=${akMeta.applicationsConfigured} withheld=${akMeta.applicationsWithheld}`,
);
check(
  "...and the withheld ones are rebuilt from the providers assigned to them",
  akMeta.applicationsRecovered === 2 && akMeta.applications === 15,
  `recovered=${akMeta.applicationsRecovered} applications=${akMeta.applications}`,
);
// Recovery closing part of the gap must not be mistaken for closing all of it: the SAML
// provider's application is named by nothing LabView reads, so it stays unaccounted for.
check(
  "...and the one it cannot reach is reported rather than rounded away",
  akMeta.error?.includes("Authentik reports 16 applications and returned 13") === true &&
    akMeta.error?.includes("2 of the rest were rebuilt") === true &&
    akMeta.error?.includes("1 could not be") === true,
  akMeta.error ?? "no error",
);
const akWithheldConn = ak.meta.connections.find((c) => c.target === "authentik");
// `partial` on a connection that succeeded is the phase `shouldBanner` shows anyway
// (asserted separately below), so reporting the gap here is what puts it in the banner.
check(
  "...as a partial connection that still succeeded, so the banner and the hint carry it",
  akWithheldConn?.phase === "partial" &&
    akWithheldConn.ok === true &&
    (akWithheldConn.hint?.includes("superuser") ?? false),
  `${akWithheldConn?.phase}/${akWithheldConn?.ok} ${akWithheldConn?.hint ?? ""}`,
);
check(
  "...and the read line states the shortfall instead of the subset",
  akWithheldConn?.read ===
    "13 of 16 applications (2 recovered from providers), 16 providers, 2 outposts",
  akWithheldConn?.read ?? "",
);

// The user-visible half of the bug: a service whose only gate is a withheld application.
// Nothing in this stack's labels or env names a gate, so before recovery it read as
// published with no authentication at all.
const archive = aSvc("archive", "archive");
check(
  "a service gated only by a withheld application is no longer reported as open",
  archive.authentik?.applications[0]?.slug === "rec-01" &&
    archive.auth.method === "authentik-oauth" &&
    archive.auth.exposedWithoutAuth === false,
  `${archive.authentik?.applications.map((a) => a.slug).join(",") ?? "no match"} ${
    archive.auth.method
  } exposed=${archive.auth.exposedWithoutAuth}`,
);
check(
  "...matched on the provider's own address, so the tie is confirmed",
  archive.auth.confidence === "confirmed" &&
    (archive.authentik?.evidence[0]?.includes("points at archive") ?? false),
  `${archive.auth.confidence} ${archive.authentik?.evidence.join(" | ") ?? ""}`,
);
// A rebuilt record is thinner than a returned one — no launch URL, no group, only the
// providers this token may read. Presenting it as equivalent would overstate the evidence.
check(
  "...and is marked as rebuilt, on exactly the applications that were",
  akRebuiltSlugs() === "rec-01,wh-02",
  akRebuiltSlugs(),
);
check(
  "...and carries neither a launch URL nor a group, because neither was readable",
  archive.authentik?.applications[0]?.launchUrl === undefined &&
    archive.authentik?.applications[0]?.group === undefined,
  JSON.stringify(archive.authentik?.applications[0]),
);
// The second recovered application matches nothing, which is where the narrower basis
// has to be stated: an operator seeing it unplaced needs to know the record itself was
// withheld, or the missing launch URL reads as an Authentik misconfiguration.
check(
  "a rebuilt application that matches nothing says what it was rebuilt from",
  akUnplaced("wh-02")?.reason === "no-candidate" &&
    akTrace("wh-02").includes("rebuilt from the provider that names it"),
  akTrace("wh-02"),
);
check(
  "...and its detail blames the withholding, not the application's own contents",
  akUnplaced("wh-02")?.detail.includes("withheld by the applications endpoint") === true,
  akUnplaced("wh-02")?.detail ?? "",
);

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

console.log("\nmatch 2: an address inside a URL the provider hands out");
const notebook = aSvc("notebook", "notebook");
check(
  "a redirect URI naming a container matches the container it names",
  notebook.authentik?.applications[0]?.slug === "nb-app",
  notebook.authentik?.applications.map((a) => a.slug).join(",") ?? "no match",
);
check(
  "...on the address, not on a resemblance between two names",
  notebook.authentik?.evidence[0]?.includes("points at notebook") ?? false,
  notebook.authentik?.evidence.join(" | ") ?? "",
);
// The whole case for reading the API. This service declares no hostname for either the
// tunnel or the proxy, references no middleware and carries no OIDC env key — the gate
// exists only in the identity provider's records, and the container answers on a host
// port, so without them it reads as reachable by anyone.
check(
  "an OIDC gate no file mentions is what stops a published port reading as exposed",
  notebook.ingress.includes("lan") &&
    notebook.auth.method === "authentik-oauth" &&
    notebook.auth.exposedWithoutAuth === false,
  `${ing(notebook)}/${notebook.auth.method} exposed=${notebook.auth.exposedWithoutAuth}`,
);
check(
  "...and an addressed tie is reported as confirmed",
  notebook.auth.confidence === "confirmed",
  notebook.auth.confidence,
);
// An IP literal in a redirect URI addresses the *host*, so resolving it through the
// published-port table pins the application to whatever publishes that port — here the
// identity provider itself, on 9443. Declining the form is the only safe reading.
check(
  "a redirect URI on an IP literal is not resolved through the published-port table",
  akUnplaced("ext-01") !== undefined && aSvc("idp", "server").authentik === undefined,
  `${akUnplacedSlugs()} ${JSON.stringify(aSvc("idp", "server").authentik)}`,
);
// Declining the form is only half the job: an operator looking at an application the
// integration did not place needs to be told it was declined, or a deliberate refusal
// reads as a defect. The reason is machine-readable so the UI can group on it and this
// assertion can hold it without matching prose.
check(
  "...and says so, naming the address literal it refused to resolve",
  akUnplaced("ext-01")?.reason === "no-candidate" &&
    /address literal/.test(akUnplaced("ext-01")?.detail ?? "") &&
    akTrace("ext-01").includes("198.51.100.10"),
  akTrace("ext-01"),
);

console.log("\nmatch 3: a hostname both sides name");
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

console.log("\nmatch 4: a name, when it points at exactly one service");
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
  "...and it is the reported posture, one step down for resting on a name",
  vault.auth.method === "authentik-ldap" && vault.auth.confidence === "observed",
  `${vault.auth.method}/${vault.auth.confidence}`,
);

// Separators are the difference between the two names an operator would give the same
// product: "Home Assistant" in the identity provider, `home-assistant` on disk. The
// service and container are named something else again, so the stack directory is the
// only thing this can reach, and the application's own name is the only candidate that
// reaches it — the slug is `ha-portal` and the provider is "Household OIDC".
const hass = aSvc("home-assistant", "hass");
check(
  "an application's name matches a stack whose separators differ",
  hass.authentik?.applications[0]?.slug === "ha-portal" &&
    (hass.authentik?.evidence[0]?.includes('its name "Home Assistant"') ?? false),
  hass.authentik?.evidence.join(" | ") ?? "no match",
);

// Authentik's own wizard names providers after the mechanism, so the words that survive
// that pattern are the only part naming a service.
const ledger = aSvc("ledger", "ledger");
check(
  "a provider's name matches once the words naming the mechanism are dropped",
  ledger.authentik?.applications[0]?.slug === "fin-01" &&
    (ledger.authentik?.evidence[0]?.includes('the name of its oauth2 provider "Provider for ledger"') ??
      false),
  ledger.authentik?.evidence.join(" | ") ?? "no match",
);
// Why the strength is carried at all: this posture rests on two people having chosen the
// same word, and it says so instead of reading like a resolved address.
check(
  "a gate found only by name is reported one step down and labelled as such",
  ledger.auth.method === "authentik-oauth" &&
    ledger.auth.confidence === "observed" &&
    ledger.auth.detail.includes("by name alone"),
  `${ledger.auth.method}/${ledger.auth.confidence} — ${ledger.auth.detail}`,
);
check(
  "...while still counting as a gate, so its published port does not read as exposed",
  ledger.ingress.includes("lan") && ledger.auth.exposedWithoutAuth === false,
  `${ing(ledger)} exposed=${ledger.auth.exposedWithoutAuth}`,
);

console.log("\na name too generic to identify anything matches nothing");
// Two-character names are everywhere in a fleet and identify nobody. "DB Provider"
// reduces to `db`; allow a residue that short and this database is reported as gated by
// an OIDC provider belonging to an unrelated application.
const shortName = aSvc("db", "db");
check(
  "a two-character residue does not claim the service it happens to equal",
  shortName.authentik === undefined && shortName.auth.method === "none",
  JSON.stringify(shortName.authentik),
);
check(
  "...and a name that is nothing but mechanism words leaves the application unplaced",
  akUnplaced("s01") !== undefined,
  akUnplacedSlugs(),
);
check(
  "...reported as the short residue it was, not as a bare miss",
  akUnplaced("s01")?.reason === "no-candidate" &&
    /under 3 characters/.test(akUnplaced("s01")?.detail ?? "") &&
    akTrace("s01").includes('"db"'),
  akTrace("s01"),
);

console.log("\nan ambiguous name is discarded, not arbitrated");
check(
  "a slug naming a two-service stack matches neither",
  aSvc("pair", "blue").authentik === undefined && aSvc("pair", "green").authentik === undefined,
  JSON.stringify([aSvc("pair", "blue").authentik, aSvc("pair", "green").authentik]),
);
check(
  "...and is reported as an application LabView could not place",
  akUnplaced("pair") !== undefined,
  akUnplacedSlugs(),
);
// The one unmatched reason an operator can act on, so it must not read like the rest:
// the contest is named as a contest, and both contestants are named. Grouping every
// failure under one word is what made this invisible.
check(
  "...as contested rather than absent, naming both services it could not choose between",
  akUnplaced("pair")?.reason === "ambiguous" &&
    akTrace("pair").includes("pair/blue") &&
    akTrace("pair").includes("pair/green"),
  akTrace("pair"),
);
// Its provider reduces to the same contested name, and it is an OIDC one — so a match
// arbitrated between the two services would visibly hand the winner a gate.
check(
  "...nor does its provider's name arbitrate between them",
  aSvc("pair", "blue").auth.method === "none" && aSvc("pair", "green").auth.method === "none",
  `${aSvc("pair", "blue").auth.method}/${aSvc("pair", "green").auth.method}`,
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
  akUnplaced("broad-app") !== undefined,
  akUnplacedSlugs(),
);
check(
  "...and the exclusion is reported as a decision, naming the mode that caused it",
  akUnplaced("broad-app")?.reason === "no-candidate" &&
    /forward_domain/.test(akUnplaced("broad-app")?.detail ?? ""),
  akTrace("broad-app"),
);
// The five that must stay unplaced, and no sixth: every other application in the stub
// is reachable by exactly one rule, so a rule that started matching too freely would
// show up here as a shorter list.
check(
  "five applications in all, each for a stated reason",
  akUnplacedSlugs() === "broad-app,ext-01,pair,s01,wh-02",
  akUnplacedSlugs(),
);
// Five unmatched applications and five distinguishable answers. A rule that stopped
// recording what it looked at would leave a hole here rather than a wrong statement,
// which is exactly the kind of gap a trace is supposed to make impossible.
check(
  "...and every one carries the application itself and a non-empty trace",
  akMeta.unmatchedApplications.every(
    (u) =>
      u.application.name.length > 0 &&
      u.application.providers.length > 0 &&
      u.detail.length > 0 &&
      u.considered.length > 0,
  ),
  JSON.stringify(
    akMeta.unmatchedApplications.map((u) => [u.application.slug, u.considered.length]),
  ),
);
check(
  "...only one of the five is the operator's to fix",
  akMeta.unmatchedApplications.filter((u) => u.reason === "ambiguous").length === 1,
  akMeta.unmatchedApplications.map((u) => `${u.application.slug}=${u.reason}`).join(","),
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
  akCfg.meta.authentik?.matchedServices === 10,
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

// A token variable that is *set and carries nothing* is the one way this credential still
// goes missing by accident, now that the environment is the only place it comes from
// (§6): `LABVIEW_AUTHENTIK_TOKEN: ${AK_TOKEN}` with `AK_TOKEN` absent from the `.env`
// beside compose.yml expands to an empty value and compose passes it on without a word.
// Absent is quiet; this is not, because the operator did ask for the integration.
console.log("\na token variable that arrived empty is said out loud");
const blankTok = authentikStub();
authentikEnv({ url: AK_ORIGIN, token: "" });
const akBlank = await overviewFor(authentikRoot, { fetchImpl: blankTok.fetchImpl });
const blankConn = akBlank.meta.connections.find((c) => c.target === "authentik")!;
check(
  "it is the `credential` phase, not `not-configured` — half-finished reads differently from off",
  blankConn.phase === "credential" && blankConn.ok === false,
  JSON.stringify({ phase: blankConn.phase, ok: blankConn.ok }),
);
check(
  "...and the detail names the variable to look at",
  blankConn.detail?.includes("LABVIEW_AUTHENTIK_TOKEN is set but carries nothing") === true,
  blankConn.detail ?? "",
);
check(
  "...and its hint says where an empty value comes from, so the fix is one line away",
  blankConn.hint?.includes(".env") === true && blankConn.hint?.includes("${") === true,
  blankConn.hint ?? "",
);
check(
  "...and nothing was requested: an empty bearer would only earn a 403 and a log line",
  blankTok.calls.length === 0,
  String(blankTok.calls.length),
);
check(
  "...with the summary reporting it as an error rather than as an unconfigured integration",
  akBlank.meta.authentik?.reachable === false && akBlank.meta.authentik?.error?.includes("LABVIEW_AUTHENTIK_TOKEN") === true,
  akBlank.meta.authentik?.error ?? "",
);
authentikEnv({});

// The pair of numbers that shows what the API actually changed. Both must move: the
// first because five gates only the API can see stop counting as absent, the second
// because a label-only read cannot see them at all. Three of those five are OIDC gates
// that appear in no label and no env key — and one of those three is an application the
// API withheld and LabView rebuilt — so the gap is the whole of what reading the
// provider buys.
console.log("\nwhat the provider's records are worth");
check(
  "with the API read, 4 services are reachable without auth",
  ak.stats.exposedWithoutAuth === 4,
  String(ak.stats.exposedWithoutAuth),
);
check(
  "...and 9 without it",
  akOff.stats.exposedWithoutAuth === 9,
  String(akOff.stats.exposedWithoutAuth),
);
check(
  "a label-derived gate is still found on its own, just as `observed`",
  offSvc("wiki", "wiki").auth.method === "authentik-forward-auth" &&
    offSvc("wiki", "wiki").auth.confidence === "observed",
  `${offSvc("wiki", "wiki").auth.method}/${offSvc("wiki", "wiki").auth.confidence}`,
);

// The same instance read with a token whose user is a superuser, which is the one case
// where `superuser_full_list` is honoured and the endpoint hands over its whole list.
// Nothing about the fleet changes, so this run says whether the rebuilt records were
// faithful to the ones they stood in for.
console.log("\na superuser token is served the list itself");
const full = authentikStub({ superuser: true });
authentikEnv({ url: AK_ORIGIN, token: AK_TOKEN });
const akFull = await overviewFor(authentikRoot, { fetchImpl: full.fetchImpl });
const akFullMeta = akFull.meta.authentik!;
/** Every application slug an overview knows, matched or not, sorted. */
function akSlugs(ov: Overview): string[] {
  const meta = ov.meta.authentik;
  const matched = ov.stacks
    .flatMap((s) => s.services)
    .flatMap((s) => s.authentik?.applications ?? []);
  return [...matched, ...(meta?.unmatchedApplications ?? []).map((u) => u.application)]
    .map((a) => a.slug)
    .sort();
}
check(
  "the full list leaves nothing withheld and nothing to rebuild",
  akFullMeta.applicationsConfigured === 16 &&
    akFullMeta.applicationsWithheld === 0 &&
    akFullMeta.applicationsRecovered === 0 &&
    akFullMeta.applications === 16,
  `configured=${akFullMeta.applicationsConfigured} withheld=${akFullMeta.applicationsWithheld} recovered=${akFullMeta.applicationsRecovered} applications=${akFullMeta.applications}`,
);
// The counterpart to the partial above: with nothing missing there is nothing to warn
// about, so a closed gap must not leave a banner behind.
check(
  "...so the connection is plainly connected, with no gap to state",
  akFull.meta.connections.find((c) => c.target === "authentik")?.phase === "connected" &&
    akFullMeta.error === undefined,
  `${akFull.meta.connections.find((c) => c.target === "authentik")?.phase} ${akFullMeta.error ?? ""}`,
);
check(
  "...and every application is list-sourced, because every one was returned",
  akSlugs(akFull).length === 16 &&
    akFull.stacks
      .flatMap((s) => s.services)
      .flatMap((s) => s.authentik?.applications ?? [])
      .every((a) => a.discoveredVia === "list"),
  akSlugs(akFull).join(","),
);
// Recovery is faithful, not inventive: the rebuilt run knows a subset of what the full
// run knows, and the difference is exactly the application no readable provider named.
check(
  "what the rebuilt run knew is a subset of what the full one returned",
  akSlugs(ak).every((s) => akSlugs(akFull).includes(s)),
  `${akSlugs(ak).join(",")} vs ${akSlugs(akFull).join(",")}`,
);
check(
  "...short by exactly the application only a SAML provider names",
  akSlugs(akFull).filter((s) => !akSlugs(ak).includes(s)).join(",") === "hidden-01",
  akSlugs(akFull).filter((s) => !akSlugs(ak).includes(s)).join(","),
);
// The measure that matters to an operator: the rebuilt record produced the same posture
// on the same service as the record it stood in for.
const fullArchive = lookup(akFull)("archive", "archive");
check(
  "...and the service the rebuilt application gated reads identically either way",
  fullArchive.auth.method === archive.auth.method &&
    fullArchive.auth.confidence === archive.auth.confidence &&
    akFullMeta.matchedServices === akMeta.matchedServices,
  `${fullArchive.auth.method}/${fullArchive.auth.confidence} ${akFullMeta.matchedServices}`,
);

// The third possibility, and the one that decides whether the warning is trustworthy:
// applications were withheld and every one of them was rebuilt. Nothing is missing, so
// nothing may be reported as missing — a banner an operator cannot clear stops being
// read, and then the case above stops working too.
console.log("\na gap recovery closes completely is not reported as a gap");
const closable = authentikStub({ hides: ["rec-01", "wh-02"] });
authentikEnv({ url: AK_ORIGIN, token: AK_TOKEN });
const akClosed = await overviewFor(authentikRoot, { fetchImpl: closable.fetchImpl });
const akClosedMeta = akClosed.meta.authentik!;
check(
  "the withheld applications are counted and rebuilt",
  akClosedMeta.applicationsConfigured === 16 &&
    akClosedMeta.applicationsWithheld === 2 &&
    akClosedMeta.applicationsRecovered === 2 &&
    akClosedMeta.applications === 16,
  `configured=${akClosedMeta.applicationsConfigured} withheld=${akClosedMeta.applicationsWithheld} recovered=${akClosedMeta.applicationsRecovered} applications=${akClosedMeta.applications}`,
);
check(
  "...and with nothing left unaccounted for, no gap is stated and no banner is raised",
  akClosedMeta.error === undefined &&
    akClosed.meta.connections.find((c) => c.target === "authentik")?.phase === "connected",
  `${akClosedMeta.error ?? "no error"} ${akClosed.meta.connections.find((c) => c.target === "authentik")?.phase}`,
);
// The count is still not the subset, so the read line has to say both numbers even
// though there is nothing to warn about.
check(
  "...while the read line still distinguishes what was returned from what exists",
  akClosed.meta.connections.find((c) => c.target === "authentik")?.read ===
    "14 of 16 applications (2 recovered from providers), 17 providers, 2 outposts",
  akClosed.meta.connections.find((c) => c.target === "authentik")?.read ?? "",
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
  akDown.stats.stacks === 14 && akDown.stats.services === 18,
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
const tfUnplaced = (name: string) =>
  tfMeta.unmatchedRouters.find((u) => `${u.router.router}@${u.router.provider}` === name);
const tfTrace = (name: string) => {
  const u = tfUnplaced(name);
  return u ? [u.reason, u.detail, ...u.considered].join(" | ") : `no unmatched entry for ${name}`;
};
check(
  "the two routers no single service could be identified for are listed",
  JSON.stringify(
    tfMeta.unmatchedRouters.map((u) => `${u.router.router}@${u.router.provider}`),
  ) === JSON.stringify(["standalone@file", "twin-blue@file"]),
  JSON.stringify(tfMeta.unmatchedRouters.map((u) => u.router.router)),
);
// The same distinction as on the Authentik side, and the same reason for it: one of
// these two is a contest the operator can settle, the other is ingress that simply
// belongs to nothing scanned. A single "unmatched" label hides the difference.
check(
  "...told apart: one contested between two services, one belonging to nothing scanned",
  tfUnplaced("twin-blue@file")?.reason === "ambiguous" &&
    tfTrace("twin-blue@file").includes("twin-a/blue") &&
    tfTrace("twin-blue@file").includes("twin-b/green") &&
    tfUnplaced("standalone@file")?.reason === "no-candidate",
  `${tfTrace("twin-blue@file")} /// ${tfTrace("standalone@file")}`,
);
// `detail` is the headline, and every assertion above reads the whole trace — so a
// `detail` reduced to a constant would pass all of them on the strength of `considered`
// still carrying the contested line. Asserted on its own for that reason: the one-liner
// a reader sees first has to be the actionable rule, not a restatement of "unmatched".
check(
  "...and the headline is the contested rule itself, not a generic one",
  /twin-a\/blue|twin-b\/green/.test(tfUnplaced("twin-blue@file")?.detail ?? "") &&
    tfUnplaced("standalone@file")?.detail !== tfUnplaced("twin-blue@file")?.detail,
  `${tfUnplaced("twin-blue@file")?.detail} /// ${tfUnplaced("standalone@file")?.detail}`,
);
// A bare `name@provider` threw all of this away, which is why an unmatched router used
// to be unreviewable: the rule is the only thing that says what the route actually is.
check(
  "...each carrying the router itself — rule, entrypoints and chain — and a trace",
  tfMeta.unmatchedRouters.every(
    (u) =>
      u.router.rule !== undefined &&
      u.router.entryPoints.length > 0 &&
      u.detail.length > 0 &&
      u.considered.length > 0,
  ),
  JSON.stringify(tfMeta.unmatchedRouters.map((u) => [u.router.rule, u.considered.length])),
);
// The name rule is skipped for a non-docker provider, and skipping is not the same as
// looking and finding nothing. Say which, or the trace reads as if the name was checked.
check(
  "...and the trace says the router name was not matched on, not that it did not match",
  tfTrace("standalone@file").includes("`file` provider takes the name from"),
  tfTrace("standalone@file"),
);
// The traces are new prose built from scanned configuration and served to the browser,
// so they are held to the same rule as every other string in the payload (I6). They may
// name what the payload already holds — slugs, service keys, hostnames — and nothing else.
// The gap-reporting strings are held to it too: they are assembled from a count and a
// hint rather than from a payload field, so the only way one carries a credential or a
// fleet identifier is a mistake — and it would be a mistake shown in the banner.
const everyTraceLine = [
  ...akMeta.unmatchedApplications.flatMap((u) => [u.detail, ...u.considered]),
  ...tfMeta.unmatchedRouters.flatMap((u) => [u.detail, ...u.considered]),
  ...[ak, akFull].flatMap((ov) => [
    ov.meta.authentik?.error ?? "",
    ...ov.meta.connections
      .filter((c) => c.target === "authentik")
      .flatMap((c) => [c.read ?? "", c.detail ?? "", c.hint ?? ""]),
  ]),
].join("\n");
check(
  "no unmatched trace carries a value out of the configuration",
  !/super-secret-value|another-secret|ldap-bind-secret|oidc-client-secret-value|xxxxxxxx/.test(
    everyTraceLine,
  ) && !everyTraceLine.includes(AK_TOKEN),
  everyTraceLine,
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

// The Traefik half of the blank-variable rule, and the other way this credential can be
// half-configured. Both are reported rather than absorbed, because either one produces a
// request that cannot succeed — and neither answer carries the value (**I6**).
console.log("\nhalf a credential is reported, never completed by guesswork");
const blankPw = traefikStub();
traefikEnv({ url: TF_ORIGIN_INTERNAL });
process.env.LABVIEW_TRAEFIK_USERNAME = TF_USER;
process.env.LABVIEW_TRAEFIK_PASSWORD = "";
authentikEnv({ token: AK_TOKEN });
const tfBlankPw = await overviewFor(traefikRoot, { fetchImpl: blankPw.fetchImpl });
check(
  "a password variable that arrived empty is said out loud, on a read that succeeded without it",
  tfBlankPw.meta.traefik?.reachable === true &&
    tfBlankPw.meta.traefik?.error?.includes("LABVIEW_TRAEFIK_PASSWORD is set but carries nothing") === true,
  tfBlankPw.meta.traefik?.error ?? "",
);
check(
  "...and no Basic header was built out of a username and nothing",
  tfBlankPw.meta.traefik?.credential === "none" && proxyCalls(blankPw.calls).every((c) => !c.sentToken),
  `${tfBlankPw.meta.traefik?.credential} ${proxyCalls(blankPw.calls).filter((c) => c.sentToken).length}`,
);
check(
  "...and the report names the variable, not the account it belongs to",
  !JSON.stringify(tfBlankPw.meta.traefik).includes(TF_USER),
);

const noUser = traefikStub();
process.env.LABVIEW_TRAEFIK_USERNAME = "";
process.env.LABVIEW_TRAEFIK_PASSWORD = TF_PASSWORD;
const tfNoUser = await overviewFor(traefikRoot, { fetchImpl: noUser.fetchImpl });
check(
  "a password with no username is reported too — inventing one would mean picking a vendor's reserved account",
  tfNoUser.meta.traefik?.error?.includes("no username") === true,
  tfNoUser.meta.traefik?.error ?? "",
);
check(
  "...with nothing sent, and the password nowhere in the report",
  tfNoUser.meta.traefik?.credential === "none" &&
    proxyCalls(noUser.calls).every((c) => !c.sentToken) &&
    !JSON.stringify(tfNoUser.meta.traefik).includes(TF_PASSWORD),
  tfNoUser.meta.traefik?.credential ?? "",
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

/* -------------------------------------------------------------------------- */
/* Rescan: force semantics, and what a rescan found                           */
/* -------------------------------------------------------------------------- */

/**
 * The two halves of a trustworthy rescan.
 *
 * First, that a forced request is never answered by a scan that began before it: a build
 * reads the compose files once at its start, so an older build cannot contain an edit made
 * after it started, and handing it to the operator who just pressed Rescan is
 * indistinguishable from never re-reading the files at all. Driven through an injected
 * clock and a build nobody can finish except this test, because the ordering is the
 * behaviour and a live server cannot be asked for one ordering on demand.
 *
 * Second, that the diff reports configuration and only configuration. A container that
 * restarted between two scans is not an edit, and a diff that says otherwise would report
 * everything on every rescan — the same trap `read` is kept out of the connection
 * signature for.
 *
 * Third, that the half the first two exclude is nevertheless reported. A rescan re-runs
 * both API exchanges every time, and between the configuration diff excluding live answers
 * and the connection signature excluding `read`, an application count going 18 → 40 used to
 * produce no line anywhere.
 */
const { createScanCache } = await import("../src/server/cache.js");
const {
  diffStacks,
  scanDiffText,
  scanDiffDetails,
  formatScanDiff,
  formatScanTotals,
  diffIntegrations,
  integrationDiffText,
  integrationDiffDetails,
  formatRescan,
} = await import("../src/model/changes.js");
const { cpSync, mkdirSync } = await import("node:fs");

console.log("\na forced rescan is never answered by a scan that started before it");

const settle = () => new Promise<void>((r) => setTimeout(r, 0));

/** A cache whose clock and whose builds only this test can move. */
function harness() {
  let clock = 1_000;
  let started = 0;
  const waiting: Array<{ ok: (v: string) => void; err: (e: unknown) => void }> = [];
  const built: Array<{ next: string; prev: string | undefined; forced: boolean }> = [];
  const cache = createScanCache<string>({
    ttlMs: 5_000,
    now: () => clock,
    build: () =>
      new Promise<string>((ok, err) => {
        started++;
        waiting.push({ ok, err });
      }),
    onBuilt: (next, prev, info) => built.push({ next, prev, forced: info.forced }),
  });
  return {
    cache,
    built,
    get started() {
      return started;
    },
    advance: (ms: number) => {
      clock += ms;
    },
    finish: (value: string) => {
      const w = waiting.shift();
      if (!w) throw new Error("no build is waiting — the assertion would be vacuous");
      w.ok(value);
      return settle();
    },
    fail: (e: unknown) => {
      const w = waiting.shift();
      if (!w) throw new Error("no build is waiting — the assertion would be vacuous");
      w.err(e);
      return settle();
    },
  };
}

const h = harness();
const firstCaller = h.cache.get(false);
check("the first caller starts a scan", h.started === 1);
const alongside = h.cache.get(false);
check("a second caller waiting on it does not start another", h.started === 1);
await h.finish("scan-1");
check("...and both are answered by the one scan", (await firstCaller) === "scan-1" && (await alongside) === "scan-1");
check(
  "onBuilt fires once per scan, not once per caller, and the first has nothing to compare against",
  h.built.length === 1 && h.built[0]?.prev === undefined && h.built[0]?.next === "scan-1",
  JSON.stringify(h.built),
);
check("inside the TTL nothing is re-read", (await h.cache.get(false)) === "scan-1" && h.started === 1);
h.advance(6_000);
const afterTtl = h.cache.get(false);
check("past the TTL a passive caller rebuilds", h.started === 2);
await h.finish("scan-2");
check(
  "...and onBuilt is handed the scan it replaced, which is what lets a caller diff them",
  (await afterTtl) === "scan-2" && h.built[1]?.prev === "scan-1" && h.built[1]?.forced === false,
  JSON.stringify(h.built[1]),
);

// The defect this rule exists for. A passive scan is already running; the operator edits a
// compose file and presses Rescan. That running scan read the files before the edit, so
// answering the click with it returns the pre-edit fleet — which looks exactly like
// "LabView did not re-read the files", and is invisible when it happens.
h.advance(6_000);
const running = h.cache.get(false);
check("a passive scan is in flight", h.started === 3);
h.advance(1);
const clicked = h.cache.get(true);
check(
  "the click does not join it, and does not sweep the Engine alongside it either",
  h.started === 3,
  `${h.started} scans`,
);
await h.finish("pre-edit-scan");
check("the in-flight scan answers the passive caller", (await running) === "pre-edit-scan");
check("...and the click gets a scan of its own, started after it asked", h.started === 4);
await h.finish("post-edit-scan");
check("...whose result is what the click returns", (await clicked) === "post-edit-scan");
check("two scans in total: the click waited its turn rather than doubling the load", h.started === 4);
check("...and the forced build says so to onBuilt", h.built[3]?.forced === true, JSON.stringify(h.built[3]));

h.advance(1);
const clickA = h.cache.get(true);
const clickB = h.cache.get(true);
check("two clicks at once still coalesce into one scan", h.started === 5);
await h.finish("scan-5");
check("...and both are answered by it", (await clickA) === "scan-5" && (await clickB) === "scan-5");

h.advance(6_000);
const doomed = h.cache.get(false);
let doomedRejected = false;
// The handler goes on before the rejection, not after: a promise left bare for one turn
// of the event loop is an unhandled rejection, and this run would die instead of asserting.
const doomedSettled = doomed.catch(() => {
  doomedRejected = true;
});
await h.fail(new Error("the Engine went away"));
await doomedSettled;
check("a scan that fails rejects its caller", doomedRejected);
check("...and leaves the previous scan readable rather than poisoning the cache", h.cache.peek() === "scan-5");
const retried = h.cache.get(false);
check("...and the next caller tries again", h.started === 7);
await h.finish("scan-7");
check("...successfully", (await retried) === "scan-7");

console.log("\nwhat a rescan found, compared over the parsed configuration");

const baseScan = await overviewFor(appsRoot);
const stacksA = baseScan.stacks;
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

check("a scan compared against itself reports nothing", diffStacks(stacksA, stacksA).unchanged);

const firstStack = stacksA[0]!;
const withoutFirst = stacksA.slice(1);
const addedDiff = diffStacks(withoutFirst, stacksA);
check(
  "a stack that appeared is named, with how many services came with it",
  addedDiff.added.length === 1 &&
    addedDiff.added[0]?.id === firstStack.id &&
    addedDiff.added[0]?.services === firstStack.services.length &&
    addedDiff.removed.length === 0 &&
    !addedDiff.unchanged,
  JSON.stringify(addedDiff.added),
);
const removedDiff = diffStacks(stacksA, withoutFirst);
check(
  "a stack that disappeared likewise, and the totals are of the new scan",
  removedDiff.removed.length === 1 &&
    removedDiff.removed[0]?.id === firstStack.id &&
    removedDiff.added.length === 0 &&
    removedDiff.stacks === withoutFirst.length,
  JSON.stringify({ removed: removedDiff.removed, stacks: removedDiff.stacks }),
);

const grown = clone(stacksA);
const multiService = grown.find((s) => s.services.length > 1)!;
const spare = clone(multiService.services[0]!);
spare.name = "smoke-sidecar";
spare.containerName = "smoke-sidecar";
multiService.services.push(spare);
const svcAdded = diffStacks(stacksA, grown);
check(
  "a service added to an existing stack is that stack, changed, naming the service",
  svcAdded.changed.length === 1 &&
    svcAdded.changed[0]?.id === multiService.id &&
    svcAdded.changed[0]?.servicesAdded.join(",") === "smoke-sidecar" &&
    svcAdded.changed[0]?.stackChanged === false,
  JSON.stringify(svcAdded.changed),
);
check(
  "...and taking it away again is the mirror image",
  diffStacks(grown, stacksA).changed[0]?.servicesRemoved.join(",") === "smoke-sidecar",
);

// Every one of these comes straight out of the compose document, so every one of them is
// an edit an operator made and expects to see reported.
const edits: Array<[string, (s: Service) => void]> = [
  ["image", (s) => void (s.image = "example.com/other:2")],
  ["command", (s) => void (s.command = "sleep infinity")],
  ["restart", (s) => void (s.restart = "no")],
  ["labels", (s) => void (s.labels = { ...s.labels, "smoke.marker": "1" })],
  ["ports", (s) => s.ports.push({ published: "19999", target: "80", protocol: "tcp", raw: "19999:80" })],
  // `expose` is the newest of these and the one most likely to be forgotten: it is
  // read off the compose file, it decides an ingress tag, and it is diffed only
  // because nobody added it to `VOLATILE_SERVICE_FIELDS`.
  ["expose", (s) => s.expose.push("19999")],
  ["networks", (s) => s.networks.push("smoke-net")],
  ["dependsOn", (s) => s.dependsOn.push("smoke-dep")],
  ["mounts", (s) => s.mounts.push({ type: "bind", source: "/tmp/smoke", target: "/smoke", readOnly: true, raw: "/tmp/smoke:/smoke:ro" })],
];
for (const [field, mutate] of edits) {
  const edited = clone(stacksA);
  const svc = edited[0]!.services[0]!;
  mutate(svc);
  const d = diffStacks(stacksA, edited);
  check(
    `an edited ${field} is a changed service`,
    d.changed.length === 1 && d.changed[0]?.servicesChanged.join(",") === svc.name && !d.unchanged,
    JSON.stringify(d.changed),
  );
}

const stackEdited = clone(stacksA);
stackEdited[0]!.declaredNetworks.push({ name: "smoke-net", external: true });
const stackDiff = diffStacks(stacksA, stackEdited);
check(
  "an edit to the stack itself is reported as the stack, not as a service",
  stackDiff.changed.length === 1 &&
    stackDiff.changed[0]?.stackChanged === true &&
    stackDiff.changed[0]?.servicesChanged.length === 0,
  JSON.stringify(stackDiff.changed),
);

// A `.labview` is parsed off disk like the compose file beside it, so editing one is an
// edit the operator made and expects Rescan to report. That comes for free from the
// deny-list — `declared` is simply not in `VOLATILE_SERVICE_FIELDS` — which is exactly
// why it is worth an assertion: adding it there would be a one-line, silent regression.
const declAdded = clone(stacksA);
declAdded[0]!.declared = {
  file: ".labview",
  description: "a sidecar the operator just wrote",
  links: [],
  dependencies: [],
};
check(
  "a sidecar added at stack level is a changed stack",
  diffStacks(stacksA, declAdded).changed[0]?.stackChanged === true,
  JSON.stringify(diffStacks(stacksA, declAdded).changed),
);
const declSvcEdited = clone(stacksA);
const declSvc = declSvcEdited[0]!.services[0]!;
declSvc.declared = {
  file: ".labview",
  links: [],
  dependencies: [],
  dependsOn: [],
  auth: [{ mechanism: "app-ldap" }],
  drift: [],
};
const declSvcDiff = diffStacks(stacksA, declSvcEdited);
check(
  "a declaration added to a service is that service, changed",
  declSvcDiff.changed.length === 1 && declSvcDiff.changed[0]?.servicesChanged.join(",") === declSvc.name,
  JSON.stringify(declSvcDiff.changed),
);

// The other half of the same rule, and the reason `DERIVED_DECLARATION_FIELDS` exists.
// `drift` and `authAgreement` live *on* the declaration but are written by the analyzer,
// so a scan in which the detected posture moved — a Traefik read that worked this time,
// a container that came up on another network — would otherwise be reported as an edit to
// a sidecar nobody touched. The declaration is compared, its conclusions are not.
const driftOnly = clone(declSvcEdited);
const driftSvc = driftOnly[0]!.services[0]!.declared!;
driftSvc.drift = ["the scan reached a different conclusion this pass"];
driftSvc.authAgreement = "conflicts";
check(
  "a conclusion the analyzer wrote onto a declaration is not a file edit",
  diffStacks(declSvcEdited, driftOnly).unchanged,
  JSON.stringify(diffStacks(declSvcEdited, driftOnly).changed),
);
// …while the parsed part of the very same block still is, so the exclusion above is
// narrow rather than "declarations are ignored".
const descEdited = clone(declSvcEdited);
descEdited[0]!.services[0]!.declared!.description = "what the operator now says this is";
const descDiff = diffStacks(declSvcEdited, descEdited);
check(
  "…while an edit to the words in the same block is",
  descDiff.changed.length === 1 && descDiff.changed[0]?.servicesChanged.join(",") === declSvc.name,
  JSON.stringify(descDiff.changed),
);
// A declared dependency sits on the parsed side of that line, and has to: the reference is
// stored as the operator wrote it, so adding one *is* an edit to the file. It is the resolved
// target that is a conclusion, and that is why resolution never writes into the declaration —
// otherwise a rename in another stack would report this sidecar as changed.
const depAdded = clone(declSvcEdited);
depAdded[0]!.services[0]!.declared!.dependsOn = [{ ref: "other/backup-agent" }];
const depDiff = diffStacks(declSvcEdited, depAdded);
check(
  "a dependency declared in a sidecar is an edit to that sidecar",
  depDiff.changed.length === 1 && depDiff.changed[0]?.servicesChanged.join(",") === declSvc.name,
  JSON.stringify(depDiff.changed),
);

// Key order is a property of how the object was built, not of the configuration. Without
// the sorted-key comparison every rescan would report every stack.
const reversedKeys = <T extends object>(o: T): T => Object.fromEntries(Object.entries(o).reverse()) as T;
const reordered = stacksA.map((s) => reversedKeys({ ...s, services: s.services.map(reversedKeys) }));
check("key order is not a change", diffStacks(stacksA, reordered).unchanged);

// The load-bearing exclusion, at unit level: everything a scan learns from a live source
// or derives for itself moves without anyone editing a file.
const liveState: DockerState = {
  id: "feedface0001",
  name: "example",
  image: "example.com/app:1",
  state: "exited",
  status: "Exited (137) 2 minutes ago",
  health: "unhealthy",
  running: false,
  restartCount: 12,
  networks: ["proxy"],
  ipAddresses: { proxy: "172.30.9.9" },
  publishedPorts: [],
};
const liveOnly = clone(stacksA);
for (const s of liveOnly) {
  for (const svc of s.services) {
    svc.docker = liveState;
    svc.traefikLive = [];
    svc.notes = [...svc.notes, "a note this pass happened to add"];
    svc.ingress = svc.ingress.includes("internal") ? ["traefik"] : ["internal"];
  }
}
check(
  "live state and derived conclusions are not configuration changes",
  diffStacks(stacksA, liveOnly).unchanged,
  JSON.stringify(diffStacks(stacksA, liveOnly).changed.slice(0, 2)),
);

console.log("\nthe same, through the whole pipeline, with an Engine that answers differently each time");
// The assertion the `BuildDeps.createDocker` passthrough exists for. Two builds over one
// unedited root, an Engine reporting a different state, a different address and a
// different restart count each time — the rescan must still say nothing changed. The
// container names are the fixture fleet's, so the live state actually merges onto services
// instead of landing nowhere and making this vacuous.
const fixtureContainers = ["authentik-server", "authentik-postgres", "authentik-redis", "jellyfin", "emby", "nextcloud", "nextcloud-db", "outline", "gateway"];
const shiftingEngine = (pass: number): DockerLike => ({
  ping: async () => ({}),
  listContainers: async () =>
    fixtureContainers.map((name, i) => ({
      Id: `feedface${String(i).padStart(4, "0")}`,
      Status: pass === 1 ? "Up 3 hours (healthy)" : "Up 12 seconds",
    })) as never,
  getContainer: (id: string) => ({
    inspect: async () => {
      const index = Number(id.replace("feedface", ""));
      const name = fixtureContainers[index] ?? "unknown";
      return {
        Id: id,
        Name: `/${name}`,
        Created: "2024-01-01T00:00:00Z",
        RestartCount: pass === 1 ? 0 : 7,
        Image: "sha256:0000000000000000",
        Config: { Image: "example.com/app:1", Labels: {} },
        State: {
          Status: pass === 1 ? "running" : "restarting",
          Running: pass === 1,
          StartedAt: pass === 1 ? "2024-01-01T00:00:00Z" : "2024-06-01T00:00:00Z",
          Health: { Status: pass === 1 ? "healthy" : "starting" },
        },
        NetworkSettings: {
          Networks: { proxy: { IPAddress: pass === 1 ? `172.30.0.${index + 2}` : `172.31.0.${index + 2}` } },
          Ports: {},
        },
      } as never;
    },
  }),
});
process.env.LABVIEW_DOCKER_ENABLED = "true";
process.env.LABVIEW_DOCKER_HOST = "tcp://127.0.0.1:2375";
const livePass1 = await overviewFor(appsRoot, { createDocker: () => shiftingEngine(1) });
const livePass2 = await overviewFor(appsRoot, { createDocker: () => shiftingEngine(2) });
process.env.LABVIEW_DOCKER_ENABLED = "false";
delete process.env.LABVIEW_DOCKER_HOST;
const liveA = livePass1.stacks.flatMap((s) => s.services).filter((s) => s.docker);
const liveB = livePass2.stacks.flatMap((s) => s.services).filter((s) => s.docker);
check(
  "the Engine really did reach the services, and really did report something else",
  liveA.length > 0 &&
    liveA.length === liveB.length &&
    liveA[0]?.docker?.state !== liveB[0]?.docker?.state &&
    liveA[0]?.docker?.ipAddresses.proxy !== liveB[0]?.docker?.ipAddresses.proxy,
  JSON.stringify({ merged: liveA.length, a: liveA[0]?.docker?.state, b: liveB[0]?.docker?.state }),
);
const liveDiff = diffStacks(livePass1.stacks, livePass2.stacks);
check(
  "and the rescan still reports no configuration change",
  liveDiff.unchanged,
  JSON.stringify(liveDiff.changed.slice(0, 2)),
);

console.log("\na rescan of a root that really changed on disk");
// Through the scanner rather than by editing parsed objects, because the question the
// operator is asking is about files: a `.env` value that reaches a service's environment,
// a whole new directory under the root.
const tmpRoot = mkdtempSync(resolve(tmpdir(), "labview-rescan-"));
cpSync(appsRoot, tmpRoot, { recursive: true });
const envFile = resolve(tmpRoot, "authentik", ".env");
const diskBefore = await overviewFor(tmpRoot);
writeFileSync(envFile, readFileSync(envFile, "utf8").replace("PG_USER=authentik", "PG_USER=rescan-probe-user"));
const diskAfterEnv = await overviewFor(tmpRoot);
const envDiff = diffStacks(diskBefore.stacks, diskAfterEnv.stacks);
check(
  "an .env edit is caught wherever it was interpolated, because interpolation happens at parse time",
  envDiff.changed.length === 1 &&
    envDiff.changed[0]?.id === "authentik" &&
    envDiff.changed[0]?.servicesChanged.length === 2,
  JSON.stringify(envDiff.changed),
);
// The documented consequence of masking before the payload exists (I6): the diff compares
// what LabView holds, and it does not hold rotated secrets.
writeFileSync(envFile, readFileSync(envFile, "utf8").replace("PG_PASS=super-secret-value", "PG_PASS=rotated"));
const diskAfterSecret = await overviewFor(tmpRoot);
check(
  "a rotated secret is invisible to the diff — it never reaches the payload (I6)",
  diffStacks(diskAfterEnv.stacks, diskAfterSecret.stacks).unchanged,
);
mkdirSync(resolve(tmpRoot, "zz-smoke-stack"));
writeFileSync(
  resolve(tmpRoot, "zz-smoke-stack", "compose.yml"),
  "services:\n  probe:\n    image: example.com/probe:1\n    ports:\n      - 19998:80\n",
);
const diskGrown = await overviewFor(tmpRoot);
const grownDiff = diffStacks(diskAfterSecret.stacks, diskGrown.stacks);
check(
  "a directory that appeared under the root is a new stack, with its services counted",
  grownDiff.added.length === 1 &&
    grownDiff.added[0]?.id === "zz-smoke-stack" &&
    grownDiff.added[0]?.services === 1,
  JSON.stringify(grownDiff.added),
);
// The same again for a sidecar written next to a compose file that did not change: the
// stack is reported, and it is reported as the *stack* having changed rather than any
// of its services, because that is where a top-level declaration lives.
writeFileSync(
  resolve(tmpRoot, "zz-smoke-stack", ".labview"),
  "description: a sidecar written after the first scan\nservices:\n  probe:\n    criticality: low\n",
);
const diskSidecar = await overviewFor(tmpRoot);
const sidecarDiff = diffStacks(diskGrown.stacks, diskSidecar.stacks);
check(
  "a .labview written after a scan is reported by the next one",
  sidecarDiff.changed.length === 1 &&
    sidecarDiff.changed[0]?.id === "zz-smoke-stack" &&
    sidecarDiff.changed[0]?.stackChanged === true &&
    sidecarDiff.changed[0]?.servicesChanged.join(",") === "probe",
  JSON.stringify(sidecarDiff.changed),
);
check(
  "...and its declarations are what the scan now carries",
  diskSidecar.stacks.find((s) => s.id === "zz-smoke-stack")?.declared?.description ===
    "a sidecar written after the first scan",
  JSON.stringify(diskSidecar.stacks.find((s) => s.id === "zz-smoke-stack")?.declared),
);

// Comparing the parsed configuration rather than the file has one visible consequence,
// and this is it: a rescan after a comment-only edit reports nothing, because nothing
// LabView documents moved. That is the intended answer, not a miss.
const composeFile = resolve(tmpRoot, "zz-smoke-stack", "compose.yml");
writeFileSync(composeFile, `# a comment nobody parses\n${readFileSync(composeFile, "utf8")}`);
const diskCommented = await overviewFor(tmpRoot);
check(
  "a comment-only edit reports nothing — the parsed configuration is what is compared",
  diffStacks(diskSidecar.stacks, diskCommented.stacks).unchanged,
);

console.log("\nthe rescan line says what moved, and says so when nothing did");
check(
  "nothing moved has its own wording, so the button is never silent",
  scanDiffText(diffStacks(stacksA, stacksA)) === "no config changes",
  scanDiffText(diffStacks(stacksA, stacksA)),
);
check("one stack is singular", scanDiffText(addedDiff) === "+1 stack", scanDiffText(addedDiff));
check(
  "two are plural",
  scanDiffText(diffStacks(stacksA.slice(2), stacksA)) === "+2 stacks",
  scanDiffText(diffStacks(stacksA.slice(2), stacksA)),
);
check(
  "a service is counted separately from the stack it is in",
  scanDiffText(svcAdded) === "1 stack changed, +1 service",
  scanDiffText(svcAdded),
);
check(
  "a removal is signed, so it cannot be mistaken for an addition",
  scanDiffText(removedDiff) === "-1 stack",
  scanDiffText(removedDiff),
);
check(
  "the detail line names the stack and the service that moved",
  scanDiffDetails(svcAdded).join("|") === `· changed: ${multiService.id} — services added: smoke-sidecar`,
  scanDiffDetails(svcAdded).join("|"),
);
check(
  "an added stack's detail line carries its service count",
  scanDiffDetails(addedDiff).join("|") === `· added: ${firstStack.id} (${firstStack.services.length} services)`,
  scanDiffDetails(addedDiff).join("|"),
);
const logLines = formatScanDiff("/data/apps", svcAdded);
check(
  "the log line names the root, leads with the same summary, and carries the totals",
  logLines[0] === `LabView rescanned /data/apps — 1 stack changed, +1 service (${svcAdded.stacks} stacks, ${svcAdded.services} services)` &&
    logLines[1] === `  ${scanDiffDetails(svcAdded)[0]}`,
  JSON.stringify(logLines),
);
check(
  "the first scan states the baseline instead, since it has nothing to compare against",
  formatScanTotals("/data/apps", stacksA) ===
    `LabView read ${stacksA.length} stacks, ${stacksA.flatMap((s) => s.services).length} services from /data/apps`,
  formatScanTotals("/data/apps", stacksA),
);
// A long list is truncated, but never silently: a rescan that reports 12 of 30 changed
// stacks as though that were all of them is worse than one that reports nothing.
const manyChanged: AppStack[] = Array.from({ length: 20 }, (_, i) => ({
  ...clone(firstStack),
  id: `stack-${String(i).padStart(2, "0")}`,
}));
const manyDetails = scanDiffDetails(diffStacks([], manyChanged));
check(
  "a long list of changes says how many it left out",
  manyDetails.length === 13 && manyDetails[12] === "· … and 8 more stacks",
  JSON.stringify(manyDetails.slice(-2)),
);

console.log("\na rescan also says what the integration reads came back with");
// The same root, the same stub, twice. The configuration diff is silent about live API
// answers on purpose, and `read` is kept out of the connection signature so a moving count
// does not log every scan — between them, nothing said the reads had happened at all.
const sameTwice = diffIntegrations(ak, ak);
check(
  "the same answer twice is stated as read and unchanged, not left silent",
  sameTwice.unchanged &&
    sameTwice.changes.length === 1 &&
    sameTwice.changes[0]?.state === "unchanged" &&
    integrationDiffText(sameTwice) === "authentik unchanged",
  `${integrationDiffText(sameTwice)} | ${JSON.stringify(sameTwice.changes.map((c) => c.state))}`,
);
check(
  "...and adds no detail line, because the summary already said it",
  integrationDiffDetails(sameTwice).length === 0,
  integrationDiffDetails(sameTwice).join("|"),
);

// Same files, a different answer from the API. The two diffs must disagree, and that is
// the point: one reports what was edited, the other what was read.
const apiMoved = diffIntegrations(ak, akFull);
check(
  "a different API answer over identical files moves one diff and not the other",
  diffStacks(ak.stacks, akFull.stacks).unchanged && !apiMoved.unchanged,
  `config unchanged=${diffStacks(ak.stacks, akFull.stacks).unchanged} integrations unchanged=${apiMoved.unchanged}`,
);
check(
  "...with every count that moved signed, and the modifiers read as modifiers",
  apiMoved.changes[0]?.counts.join(", ") === "+1 application, -3 withheld, -2 recovered, +1 provider, +1 unmatched",
  apiMoved.changes[0]?.counts.join(", ") ?? "",
);
check(
  "...and the application that appeared named, from the same payload the drawer shows",
  apiMoved.changes[0]?.appeared.join(",") === "hidden-01" && apiMoved.changes[0]?.disappeared.length === 0,
  `appeared=${apiMoved.changes[0]?.appeared.join(",")} disappeared=${apiMoved.changes[0]?.disappeared.join(",")}`,
);

// The rule the whole line's trustworthiness rests on. A failed read reports zeros, so
// comparing counts across it would announce `-15 applications`: a claim about Authentik's
// contents from a scan that never reached Authentik.
const stopped = diffIntegrations(ak, akDown);
check(
  "a read that failed reports the failure and no delta at all",
  stopped.changes[0]?.state === "stopped" && stopped.changes[0]?.counts.length === 0,
  JSON.stringify(stopped.changes[0]),
);
check(
  "...stating no loss anywhere, because nothing was lost — a read failed",
  integrationDiffText(stopped) === "authentik not read" &&
    !integrationDiffText(stopped).includes("-") &&
    !integrationDiffDetails(stopped).join("|").includes("-"),
  `${integrationDiffText(stopped)} | ${integrationDiffDetails(stopped).join("|")}`,
);
const started = diffIntegrations(akDown, ak);
check(
  "a read that recovered says so, and is equally silent about numbers",
  started.changes[0]?.state === "started" &&
    started.changes[0]?.counts.length === 0 &&
    integrationDiffText(started) === "authentik now readable",
  `${integrationDiffText(started)} | ${JSON.stringify(started.changes[0]?.counts)}`,
);

// An integration nobody switched on is not a status, and a failure that persists is not
// news on every rescan — the banner and the connection line already carry it.
check(
  "an integration nobody configured contributes nothing to say",
  diffIntegrations(akOff, akOff).changes.length === 0 && integrationDiffText(diffIntegrations(akOff, akOff)) === "",
  `${diffIntegrations(akOff, akOff).changes.length} "${integrationDiffText(diffIntegrations(akOff, akOff))}"`,
);
check(
  "...and neither does a failure that was already failing last scan",
  diffIntegrations(akDown, akDown).changes.length === 0,
  JSON.stringify(diffIntegrations(akDown, akDown).changes),
);

// The other target, over the other root: two successful reads of the same files where the
// proxy stopped serving a route. Authentik and Traefik report different nouns off different
// summaries, so a table covering one and not the other would look fine up to here.
//
// Both runs are made here rather than reusing the module-scope `tf`: an assertion above
// attaches a synthetic router to that payload to test the matcher directly, so it is no
// longer a faithful record of the scan that produced it.
console.log("\nthe same holds for the proxy, in its own vocabulary");
traefikEnv({});
authentikEnv({ token: AK_TOKEN });
const tfWhole = await overviewFor(traefikRoot, { fetchImpl: traefikStub().fetchImpl });
const tfPruned = await overviewFor(traefikRoot, { fetchImpl: traefikStub({ dropRoute: "docs" }).fetchImpl });
const proxyMoved = diffIntegrations(tfWhole, tfPruned);
const proxyChange = proxyMoved.changes.find((c) => c.target === "traefik");
check(
  "a route the proxy stopped serving is counted and named",
  proxyChange?.state === "moved" &&
    proxyChange.disappeared.join(",") === "docs" &&
    proxyChange.appeared.length === 0,
  JSON.stringify(proxyChange),
);
check(
  "...in the proxy's own nouns, where a live service is not a fleet service",
  proxyChange?.counts.join(", ") === "-1 router, -1 live service, -1 matched",
  proxyChange?.counts.join(", ") ?? "",
);
check(
  "...and the two targets are reported side by side, each labelled",
  integrationDiffText(proxyMoved) === "authentik unchanged; traefik -1 router, -1 live service, -1 matched" &&
    integrationDiffDetails(proxyMoved).some((l) => l === "· traefik disappeared: docs"),
  `${integrationDiffText(proxyMoved)} | ${integrationDiffDetails(proxyMoved).join(" | ")}`,
);

console.log("\nwhen a rescan speaks, and when it stays quiet");
const quiet = diffStacks(stacksA, stacksA);
check(
  "a timer rebuild that found nothing on either side stays silent",
  formatRescan("/data/apps", quiet, sameTwice, false).length === 0,
  JSON.stringify(formatRescan("/data/apps", quiet, sameTwice, false)),
);
check(
  "...but a rescan somebody pressed answers on both halves anyway",
  formatRescan("/data/apps", quiet, sameTwice, true)[0] ===
    `LabView rescanned /data/apps — no config changes; authentik unchanged (${quiet.stacks} stacks, ${quiet.services} services)`,
  formatRescan("/data/apps", quiet, sameTwice, true)[0] ?? "",
);
check(
  "...and an API that moved speaks even though no file was edited",
  formatRescan("/data/apps", quiet, apiMoved, false)[1] === "  · authentik: +1 application, -3 withheld, -2 recovered, +1 provider, +1 unmatched" &&
    formatRescan("/data/apps", quiet, apiMoved, false)[2] === "  · authentik appeared: hidden-01",
  JSON.stringify(formatRescan("/data/apps", quiet, apiMoved, false)),
);
check(
  "the configuration-only line is untouched by any of this",
  formatScanDiff("/data/apps", svcAdded).join("|") === logLines.join("|"),
  formatScanDiff("/data/apps", svcAdded).join("|"),
);

// A fleet with forty applications must not put forty names in one log line, and what it
// left out is stated — the same rule as the stack list, applied per line because three
// lines per target could never reach a line ceiling.
const manyNames = {
  changes: [
    {
      target: "authentik" as const,
      state: "moved" as const,
      counts: [] as string[],
      appeared: Array.from({ length: 20 }, (_, i) => `app-${String(i).padStart(2, "0")}`),
      disappeared: [] as string[],
    },
  ],
  unchanged: false,
};
const manyNameLine = integrationDiffDetails(manyNames)[0] ?? "";
check(
  "a long list of names says how many it left out",
  manyNameLine.endsWith("… and 8 more") && manyNameLine.includes("app-11") && !manyNameLine.includes("app-12"),
  manyNameLine,
);
check(
  "...and the summary says what happened, even when every count came back equal",
  integrationDiffText(manyNames) === "authentik 20 applications replaced",
  integrationDiffText(manyNames),
);

console.log("\nno rescan line carries a value out of the configuration");
// Same discipline as the connection lines: these go to a log and to a tooltip, and the
// diff is computed from a payload that has env values in it. It reports *that* a service
// changed and never *to what*.
const everyDiffLine = [
  ...formatScanDiff(tmpRoot, envDiff),
  ...formatScanDiff(tmpRoot, grownDiff),
  ...scanDiffDetails(envDiff),
  // The integration half too: it is built from a payload that holds an API token and the
  // fixture's env values, and it reports records by name.
  ...formatRescan(tmpRoot, envDiff, apiMoved, true),
  ...formatRescan(tmpRoot, quiet, stopped, true),
  ...integrationDiffDetails(apiMoved),
  integrationDiffText(apiMoved),
].join("\n");
check(
  "not the new value, and not the old one either",
  !everyDiffLine.includes("rescan-probe-user") && !everyDiffLine.includes("PG_USER"),
  everyDiffLine,
);
check(
  "and no fixture secret, from any of the three .env files",
  !everyDiffLine.includes("super-secret-value") &&
    !everyDiffLine.includes("another-secret") &&
    !everyDiffLine.includes("ldap-bind-secret") &&
    !everyDiffLine.includes("oidc-client-secret-value"),
  everyDiffLine,
);
check(
  "and no API token either, on a line that reports what that token was used to read",
  !everyDiffLine.includes(AK_TOKEN),
  everyDiffLine,
);

console.log("\nthe ingress vocabulary normalizes on the way in");
// `normalizeIngress` is the only constructor, so these rules hold everywhere a tag set
// exists — the classifier, the sidecar and any future source.
const kinds = (...k: IngressKind[]): string => normalizeIngress(k).join(", ");
check("duplicates collapse", kinds("lan", "lan", "public", "lan") === "public, lan", kinds("lan", "lan", "public", "lan"));
check(
  "order is canonical, most exposed first, whatever order they arrived in",
  kinds("lan", "traefik", "public") === "public, traefik, lan",
  kinds("lan", "traefik", "public"),
);
// The invariant the whole model rests on: a service always carries at least one tag,
// so no view has to render an empty cell and no filter has to special-case nothing.
check("an empty set becomes no-ingress rather than staying empty", kinds() === "none", kinds());
// The withholding rule, enumerated from the vocabulary rather than from a hand-written
// list of three: a kind added to `INGRESS_KINDS` and forgotten here would otherwise
// leave `internal` sitting beside it, which is the whole thing this prevents.
const externals = INGRESS_KINDS.filter((k) => k !== "internal" && k !== "none");
check(
  "`internal` is withheld beside every external kind there is",
  externals.length === 3 && externals.every((k) => kinds("internal", k) === k),
  externals.map((k) => `${k}: ${kinds("internal", k)}`).join(" | "),
);
check(
  "...and beside all of them at once",
  kinds("internal", ...externals) === "public, traefik, lan",
  kinds("internal", ...externals),
);
// The other half, and the reason this is a withholding rather than a deletion: with
// nothing external beside it, `internal` is the answer and is kept.
check("...but stands alone when it is the only way in", kinds("internal") === "internal", kinds("internal"));
check(
  "...and `none` is not an external kind, so it cannot displace it either",
  kinds("internal", "none") === "internal",
  kinds("internal", "none"),
);
// The same rule as a property of every service both fixture roots produce, rather than of
// the handful with a line of their own further up. A stack added later, a fourth external
// kind, or a second classifier is covered by this without anyone remembering to extend a
// list — and it is the assertion a revert of the withholding cannot get past.
const everyService = [ov, edge].flatMap((o) => o.stacks.flatMap((s) => s.services));
const bothAtOnce = everyService.filter((s) => s.ingress.includes("internal") && isExternallyReachable(s.ingress));
check(
  "no service anywhere carries `internal` beside a way in from outside",
  bothAtOnce.length === 0 && everyService.length > 0,
  `${bothAtOnce.length} of ${everyService.length}: ${bothAtOnce.map((s) => `${s.name}=${ing(s)}`).join(" | ")}`,
);
// And the counter is that partition, read off the tags rather than re-derived from
// reachability — which would quietly fold in the services nothing reaches at all.
const internalOnly = edge.stacks.flatMap((s) => s.services).filter((s) => ing(s) === "internal");
check(
  "...and `internalServices` counts exactly the services it is the only way in to",
  edge.stats.internalServices === internalOnly.length && internalOnly.length > 0,
  `${edge.stats.internalServices} counted, ${internalOnly.length} internal-only, ${edge.stats.noIngressServices} unreachable`,
);
// The stack row is the one place the withholding must NOT apply, and now the only place a
// stack-level `internal` appears at all: a public frontend beside a database only its
// neighbour can reach is a stack that is both, and rolling the union through the service
// rule would let the frontend's exposure erase the database from the collapsed view. Every
// mixed stack in the fixtures is checked, not one named example.
const mixed = edge.stacks.filter(
  (s) => s.services.some((v) => isExternallyReachable(v.ingress)) && s.services.some((v) => ing(v) === "internal"),
);
const rolledUp = mixed.map((s) => rollUpIngress(s.services.map((v) => v.ingress)));
check(
  "a stack keeps `internal` in its roll-up even when a sibling is reachable from outside",
  mixed.length > 0 && rolledUp.every((r) => r.includes("internal") && isExternallyReachable(r)),
  `${mixed.length} mixed stack(s): ${rolledUp.map((r) => r.join("+")).join(" | ")}`,
);
// ...while the services underneath it still carry the rule, so the badge on the row and the
// badges on the rows below say different things on purpose.
check(
  "...and none of its externally reachable services carries the tag itself",
  mixed.flatMap((s) => s.services).filter((v) => isExternallyReachable(v.ingress) && v.ingress.includes("internal"))
    .length === 0,
  mixed
    .flatMap((s) => s.services)
    .filter((v) => isExternallyReachable(v.ingress))
    .map((v) => ing(v))
    .join(" | "),
);
// A stack of one internal-only service rolls up to exactly that, so the union is not
// smuggling the tag in from somewhere.
const soloInternal = edge.stacks.filter((s) => s.services.every((v) => ing(v) === "internal"));
check(
  "...and a stack whose every service is internal-only rolls up to just `internal`",
  soloInternal.length > 0 &&
    soloInternal.every((s) => rollUpIngress(s.services.map((v) => v.ingress)).join(", ") === "internal"),
  `${soloInternal.length} stack(s)`,
);

console.log("\nthe tag filter: OR, AND and NOT");
// A truth table, because the UI is never rendered here and clicking three chips in a
// browser is not a regression test.
const F = (include: string[], exclude: string[] = [], mode: "any" | "all" = "any"): TagFilter => ({
  include,
  exclude,
  mode,
});
check("no chips selected shows everything", matchesTagFilter(["internal"], EMPTY_TAG_FILTER));
check("...and reports itself inactive, which is what dims nothing", !tagFilterActive(EMPTY_TAG_FILTER));
check("one include is a plain membership test", matchesTagFilter(["public", "lan"], F(["lan"])));
check("...and rejects a service without the tag", !matchesTagFilter(["internal"], F(["lan"])));
check("`any` is OR: either tag will do", matchesTagFilter(["internal"], F(["lan", "internal"])));
check(
  "`all` is AND: both tags must be present",
  matchesTagFilter(["public", "lan"], F(["public", "lan"], [], "all")) &&
    !matchesTagFilter(["public"], F(["public", "lan"], [], "all")),
);
check("...and the same pair under `any` accepts the one-tag service", matchesTagFilter(["public"], F(["public", "lan"])));
// Tag sets the classifier can actually produce, here and throughout: `internal` never
// arrives beside an external kind, so a truth table built on `["public", "internal"]`
// would read as an example of something the model forbids.
check("an exclude is AND-NOT", !matchesTagFilter(["traefik", "lan"], F([], ["lan"])));
check("...and passes a service that lacks it", matchesTagFilter(["public"], F([], ["internal"])));
// The one genuinely ambiguous case, decided in `matchesTagFilter` and pinned here:
// a contradictory filter rejects rather than quietly dropping half of itself.
check(
  "exclusion beats an include of the same tag",
  !matchesTagFilter(["lan"], F(["lan"], ["lan"])),
);
check(
  "an exclude alone counts as filtering, so the untouched chips still dim",
  tagFilterActive(F([], ["internal"])),
);
// Three clicks on one chip return to where they started; without that the only way
// to clear one tag would be to clear the whole filter.
const c1 = cycleTag(EMPTY_TAG_FILTER, "lan");
const c2 = cycleTag(c1, "lan");
const c3 = cycleTag(c2, "lan");
check(
  "a chip cycles include -> exclude -> off",
  c1.include.join() === "lan" && c2.exclude.join() === "lan" && c2.include.length === 0 && !tagFilterActive(c3),
  JSON.stringify([c1, c2, c3]),
);
// The readout exists because a mode and an exclusion cannot be read off which chips
// look bright. If its wording drifts from the semantics above, the reader is misled
// about what they are looking at, which is worse than a wrong colour.
const up = (t: string): string => t.toUpperCase();
check(
  "the readout names the mode when more than one tag is included",
  describeTagFilter(F(["public", "lan"], ["internal"], "all"), up) === "all of PUBLIC, LAN; not INTERNAL",
  describeTagFilter(F(["public", "lan"], ["internal"], "all"), up),
);
check(
  "...says `any of` for the other mode",
  describeTagFilter(F(["public", "lan"]), up) === "any of PUBLIC, LAN",
  describeTagFilter(F(["public", "lan"]), up),
);
check(
  "...drops the mode for a single tag, where both modes mean the same thing",
  describeTagFilter(F(["lan"]), up) === "LAN",
  describeTagFilter(F(["lan"]), up),
);
check("...and says nothing at all when nothing is filtered", describeTagFilter(EMPTY_TAG_FILTER, up) === "");

console.log("\nthe ingress palette and the stylesheet name the same variables");
// Both halves of the colour lookup are strings the compiler never sees together:
// `ingressVar` falls back to `--muted` for a kind it has no entry for, and
// `resolveVar` falls back to #888888 for a property the stylesheet never defines. So
// a variable renamed in one file only, or a kind added to the union and nowhere else,
// degrades to grey swatches and a grey graph with no error anywhere. These two
// assertions are what stands between that and a silent regression.
const paletteSrc = readFileSync(resolve(here, "..", "web", "lib", "palette.ts"), "utf8");
const stylesSrc = readFileSync(resolve(here, "..", "web", "styles.css"), "utf8");
const ingressBlock = paletteSrc.slice(paletteSrc.indexOf("INGRESS_META"), paletteSrc.indexOf("AUTH_META"));
const paletteVars = [...ingressBlock.matchAll(/cssVar:\s*"(--[a-z0-9-]+)"/g)].map((m) => m[1]!);
const definedVars = new Set([...stylesSrc.matchAll(/^\s*(--[a-z0-9-]+)\s*:/gm)].map((m) => m[1]!));
const missingVars = paletteVars.filter((v) => !definedVars.has(v));
check(
  // The count guard matters as much as the emptiness one: a regex that stopped
  // matching would otherwise pass this by finding nothing to check.
  "every ingress colour the palette names is defined in styles.css",
  paletteVars.length === 5 && missingVars.length === 0,
  `${paletteVars.length} named, undefined: ${missingVars.join(", ") || "none"}`,
);
// The union is the source of truth, and `INGRESS_KINDS` is the union written down —
// so this walks every kind there will ever be without a second list to keep in step.
const unstyled = INGRESS_KINDS.filter((k) => !ingressBlock.includes(`key: "${k}"`));
check(
  "and every ingress kind has a palette entry, so none falls back to grey",
  unstyled.length === 0,
  `no entry for: ${unstyled.join(", ") || "none"}`,
);

console.log("\na missing gate is only reported where a gate was expected");
// The rule this group exists for: authentication is expected in front of what someone
// outside the container network can reach, and nowhere else. Say "no proxy auth" about
// every internal database and the fleet acquires twenty warnings that are all correct
// topology, after which nobody reads the one that is a finding. So the four reasons a
// service has no mechanism are told apart, and exactly one of them is reportable.
const bare = eSvc("cfdisabled", "live");
check(
  "reachable, nothing in front of it, nothing declared — the one reportable case",
  noAuthReason(bare) === "gap" && bare.auth.exposedWithoutAuth === true,
  `${noAuthReason(bare)}, exposedWithoutAuth=${bare.auth.exposedWithoutAuth}`,
);
// `acc` is the same finding with a reason attached. It stays `gap`, because an
// acceptance says the exposure was read, not that it is gone.
check(
  "...still that case when the exposure has been accepted, which changes only who has read it",
  noAuthReason(acc) === "gap",
  String(noAuthReason(acc)),
);
// Both arms of "outside can reach it": a container-network neighbour, and nothing at all.
check(
  "nothing outside can reach it, so nothing is expected in front of it",
  noAuthReason(eSvc("exposeonly", "cache")) === "not-reachable" &&
    noAuthReason(eSvc("interp", "web")) === "not-reachable",
  `${noAuthReason(eSvc("exposeonly", "cache"))} / ${noAuthReason(eSvc("interp", "web"))}`,
);
// The operator's statement is taken at face value here. It does not become evidence —
// `decl.auth.method` is still `none` two hundred lines above — but a reader is not told
// a gate is missing on a service someone has said authenticates itself.
check(
  "a declared mechanism is assumed to be working, not answered with a missing gate",
  noAuthReason(decl) === "declared",
  String(noAuthReason(decl)),
);
// The SAML application from the identity-provider section: protected, with no
// `AuthMethod` to be reported as. Calling that a missing gate is the falsehood the
// fixture beside it was written to prevent.
check(
  "a confirmed gate this model cannot name is protected, not bare",
  noAuthReason(reports) === "unnamed-gate",
  String(noAuthReason(reports)),
);
// The first branch, over a whole fleet: there is something to explain exactly when
// there is no mechanism, so the drawer's `Method` row never renders two answers or none.
check(
  "...and there is a reason to give precisely when no mechanism was detected",
  edge.stacks
    .flatMap((s) => s.services)
    .every((s) => (noAuthReason(s) === undefined) === (s.auth.method !== "none")),
  edge.stacks
    .flatMap((s) => s.services)
    .filter((s) => (noAuthReason(s) === undefined) !== (s.auth.method !== "none"))
    .map((s) => s.name)
    .join(", "),
);
// Every branch has a fixture behind it, so none of the four can be quietly deleted.
const reasonsSeen = new Set(
  [...edge.stacks, ...ak.stacks].flatMap((s) => s.services).map(noAuthReason).filter(Boolean),
);
check(
  "every reason is reached by a fixture",
  NO_AUTH_REASONS.every((r) => reasonsSeen.has(r)) && reasonsSeen.size === NO_AUTH_REASONS.length,
  [...reasonsSeen].join(", "),
);
// The wording, in one place, and the phrase that started this: it belongs to the finding
// and to nothing else. The other three reasons describe an absence that is correct, and
// a reader who sees the same six words on all four learns to skip all four.
const claiming = NO_AUTH_REASONS.filter((r) =>
  /no proxy auth/i.test(`${noAuthText(r).label} ${noAuthText(r).title}`),
);
check(
  'the words "no proxy auth" are used for exactly one of the four',
  claiming.length === 1 && claiming[0] === "gap",
  claiming.join(", ") || "none",
);
check(
  "...and each of the others still answers the question rather than leaving it blank",
  NO_AUTH_REASONS.every((r) => noAuthText(r).label.length > 0 && noAuthText(r).title.length > 0),
  NO_AUTH_REASONS.map((r) => `${r}=${noAuthText(r).label}`).join(" | "),
);
// A badge row lists mechanisms, and `none` is the absence of one. Read off the palette
// text rather than a second list, for the reason the ingress check above gives.
const authBlock = paletteSrc.slice(paletteSrc.indexOf("AUTH_META"));
const authKeys = [...authBlock.matchAll(/key: "([a-z-]+)"/g)].map((m) => m[1] as AuthMethod);
check(
  "`none` is the only method with no badge of its own, because it is not one",
  authKeys.length === 8 && authKeys.filter((k) => !showsAuthMethod(k)).join(",") === "none",
  // "(nothing)" rather than "none": the suppressed member *is* called `none`, so the
  // obvious fallback word makes a failure that suppresses nothing read exactly like a
  // pass.
  `${authKeys.length} methods, suppressed: ${authKeys.filter((k) => !showsAuthMethod(k)).join(",") || "(nothing)"}`,
);
// The bucket in the distribution bar keeps counting every service with no mechanism —
// it is a measurement, and `byAuthMethod.none` is asserted above. What it may not do is
// carry the finding's wording, which is how the phrase reached every internal service in
// the fleet in the first place.
check(
  "...and the distribution bar labels that bucket as a count, not as a finding",
  !/no proxy auth/i.test(authBlock),
  authBlock.split("\n").find((l) => l.includes('key: "none"')) ?? "no entry",
);

// ---------------------------------------------------------------------------------
// Access control (fixtures/auth)
//
// LabView's own login, which is a different subject from every section above: nothing
// here reads a compose file or a fleet. It is asserted in this file anyway, and at this
// length, because it is the only part of LabView where a silent regression is a security
// hole rather than a wrong label — an allowlist that admits one path too many, a nonce
// nobody checks, a hash id nobody refuses. Each group below pins one such rule, and the
// revert contract applies: undo the rule in `src/` and a check here must go red.
//
// Imported locally, at the end, for the reason `node:net` is below: the modules under
// test read files and mint keys, and the sections above must not pay for that.
// ---------------------------------------------------------------------------------
console.log("\n--- access control (fixtures/auth) ---");

const { chmodSync } = await import("node:fs");
const { createHmac, generateKeyPairSync, sign: signWithKey } = await import("node:crypto");
const {
  DEFAULT_COST,
  SUPPORTED_HASH_IDS,
  decoyHash,
  hashAlgorithmId,
  hashAlgorithmName,
  hashCost,
  hashPassword,
  isSupportedHash,
  passwordTruncates,
  verifyPassword,
} = await import("../src/auth/hash.js");
const { MAX_PASSWD_ENTRIES, clearPasswdCache, parsePasswd, readPasswd, verifyLogin } = await import(
  "../src/auth/passwd.js"
);
const {
  CLOCK_SKEW_SECONDS,
  OidcClient,
  buildAuthorizeUrl,
  createVerifier,
  isSecureUrl,
  parseDiscovery,
  pkceChallenge,
  redirectUriFor,
  scopeString,
  usernameFromClaims,
  verifyIdToken,
} = await import("../src/auth/oidc.js");
const {
  SessionRevocations,
  effectiveHost,
  effectiveProtocol,
  issueSession,
  originAllowed,
  readCookie,
  safeEqual,
  serializeCookie,
  shouldSecureCookie,
  signPayload,
  verifySession,
} = await import("../src/auth/session.js");
const { LoginThrottle } = await import("../src/auth/throttle.js");
const { isPublicPath, readAccess, requiresSession, resolveAccessMode, resolveOidc, resolveSessionSecret } =
  await import("../src/auth/index.js");
const { accessModeSummary, isValidUsername, loginFailureText, oidcButtonLabel, sanitizeUsername } = await import(
  "../src/model/access.js"
);

const passwdOk = resolve(authRoot, "passwd.ok");
const passwdMessy = resolve(authRoot, "passwd.messy");
const passwdEmpty = resolve(authRoot, "passwd.empty");

console.log("\nthe algorithm is whatever the hash says it is");
{
  const okFile = readPasswd(passwdOk);
  // Read out of the fixture rather than repeated here: a hash literal in this file would
  // be a second copy to keep in step, and one more string a future reader has to satisfy
  // themselves is not a credential.
  const alice = okFile.entries.get("alice")?.hash ?? "";
  const bob = okFile.entries.get("bob")?.hash ?? "";
  const carol = okFile.entries.get("carol")?.hash ?? "";

  check("a bcrypt hash's id is read off its prefix", hashAlgorithmId(alice) === "2b", hashAlgorithmId(alice));
  check(
    "the two older bcrypt prefixes are the same function, and are accepted",
    hashAlgorithmId(bob) === "2a" && hashAlgorithmId(carol) === "2y" && SUPPORTED_HASH_IDS.length === 3,
  );
  check("a value with no $ has no algorithm — in a passwd file that means plaintext", hashAlgorithmId("hunter2") === undefined);
  check("a foreign id is named, so a refusal can say what it refused", hashAlgorithmName("6") === "sha512-crypt");
  check("...an unknown one is quoted back as itself rather than guessed at", hashAlgorithmName("zz9") === "$zz9$");
  check("...and every supported id is called bcrypt", SUPPORTED_HASH_IDS.every((id) => hashAlgorithmName(id) === "bcrypt"));

  check("a well-formed hash is verifiable", isSupportedHash(alice) && isSupportedHash(bob) && isSupportedHash(carol));
  check(
    "a truncated one is not, which is what turns a copy-paste into a warning instead of a user who can never sign in",
    !isSupportedHash(alice.slice(0, 40)),
  );
  check("...nor is a hash of an algorithm LabView cannot compute", !isSupportedHash("$6$rounds=5000$abc$def"));
  check("the cost comes out of the hash itself", hashCost(alice) === 4 && hashCost("nonsense") === undefined);

  // The three passwords are in the fixture's comments. They are strings only these
  // assertions ever use, hashed at cost 4 so this stays fast.
  check("each of the three prefixes verifies its own password", (await Promise.all([
    verifyPassword("alice-secret", alice),
    verifyPassword("bob-secret", bob),
    verifyPassword("carol-secret", carol),
  ])).every(Boolean));
  check("a wrong password does not", (await verifyPassword("alice-secretx", alice)) === false);
  check(
    "an unusable hash is a wrong password, not an error — a caller that could tell them apart could probe the file",
    (await verifyPassword("hunter2", "hunter2")) === false && (await verifyPassword("x", alice.slice(0, 40))) === false,
  );

  const minted = await hashPassword("round-trip", 4);
  check(
    "a freshly hashed password round-trips, at $2b$ and the cost it was asked for",
    hashAlgorithmId(minted) === "2b" && hashCost(minted) === 4 && (await verifyPassword("round-trip", minted)),
  );
  check("the default cost is what `hashpw` will use, not what the fixtures use", DEFAULT_COST === 12);
  check("a cost below bcrypt's own floor is clamped rather than rejected", hashCost(await hashPassword("x", 1)) === 4);
  check(
    "bcrypt's 72-byte limit is reported where it can still be acted on",
    !passwordTruncates("a".repeat(72)) && passwordTruncates("a".repeat(73)) && passwordTruncates(`${"€".repeat(24)}x`),
  );

  const decoy = await decoyHash(4);
  check(
    "the unknown-user decoy is a real bcrypt hash at the file's own cost, so the unknown path costs what the known one does",
    isSupportedHash(decoy) && hashCost(decoy) === 4,
  );
  check("...and is minted once per cost, not per attempt", (await decoyHash(4)) === decoy);
  check("...and differs per cost, because that is the point of it", (await decoyHash(5)) !== decoy);
}

console.log("\na passwd file names its own mistakes");
{
  const ok = parsePasswd(readFileSync(passwdOk, "utf8"));
  check("comments and blank lines are not entries", ok.entries.size === 3 && ok.warnings.length === 0);
  check(
    "the entries keep the file's order, which is the order a duplicate is judged in",
    [...ok.entries.keys()].join(",") === "alice,bob,carol",
  );

  const messy = parsePasswd(readFileSync(passwdMessy, "utf8"));
  const w = (i: number): string => messy.warnings[i] ?? "";
  check(
    "one warning per bad line, and one usable entry left over",
    messy.warnings.length === 7 && messy.entries.size === 1 && messy.entries.has("frank"),
    `${messy.warnings.length} warnings, ${messy.entries.size} entries`,
  );
  // The line numbers are asserted, not just the wording: a warning that points at the
  // wrong line is worse than none, and off-by-one is exactly what a refactor breaks.
  check("a line with no separator is named by number, and not echoed", w(0) === 'passwd line 10: no "user:hash" separator — entries look like alice:$2b$12$…', w(0));
  check(
    "a username over 64 characters is refused, without echoing it",
    w(1) === "passwd line 13: username is not usable — letters, digits and . _ @ - only, up to 64 characters",
    w(1),
  );
  check("a separator with nothing after it names the user", w(2) === 'passwd line 16: user "bob" has no hash', w(2));
  check(
    "a plaintext password is refused, and the operator is told how to make a hash",
    w(3) ===
      'passwd line 19: user "carol" has a plaintext password, not a hash — LabView never accepts one; run `npm run hashpw`',
    w(3),
  );
  check(
    "a foreign algorithm is named rather than called unsupported",
    w(4) ===
      'passwd line 23: user "dave" uses sha256-crypt, which LabView cannot verify — rehash with bcrypt (`npm run hashpw` or `htpasswd -nbB`)',
    w(4),
  );
  check(
    "a truncated bcrypt hash says what a complete one looks like",
    w(5) === 'passwd line 26: user "erin" has a malformed bcrypt hash — a complete one is 60 characters',
    w(5),
  );
  check(
    "a repeated username is warned about, and the first entry is the one that stands",
    w(6) === 'passwd line 33: user "frank" is already defined above — the first entry wins',
    w(6),
  );
  check(
    "no warning ever carries a hash, however malformed the line was",
    messy.warnings.every((line) => !line.includes("$04$")),
  );

  // First-wins, proven by behaviour and not only by the warning: the duplicate line
  // hashes a *different* password, so the second entry taking effect would show up here.
  const messyFile = readPasswd(passwdMessy);
  check("the first entry is the one that verifies", await verifyLogin(messyFile, "frank", "other-secret"));
  check("...and the shadowed duplicate's password is not accepted", (await verifyLogin(messyFile, "frank", "long-secret")) === false);

  const empty = parsePasswd(readFileSync(passwdEmpty, "utf8"));
  check("a file of nothing but comments yields no users and no complaints", empty.entries.size === 0 && empty.warnings.length === 0);

  const okFile = readPasswd(passwdOk);
  check("an unknown username is refused", (await verifyLogin(okFile, "nobody", "alice-secret")) === false);
  check("...as is a username the format would not allow at all", (await verifyLogin(okFile, "al ice", "alice-secret")) === false);
  check("...and an absurd password is refused without being hashed", (await verifyLogin(okFile, "alice", "x".repeat(2000))) === false);
  check("a known username with its own password is accepted", await verifyLogin(okFile, "alice", "alice-secret"));
  check("...with surrounding whitespace forgiven on the name, never on the password", await verifyLogin(okFile, "  alice  ", "alice-secret"));

  const aliceHash = ok.entries.get("alice")?.hash ?? "";
  const spaced = parsePasswd(`  alice  :  ${aliceHash}  \n`);
  check("whitespace around either half of an entry is trimmed", spaced.entries.size === 1 && spaced.entries.has("alice"));
  check(
    "only the first colon separates, so a third field is part of the hash and refused rather than quietly dropped",
    parsePasswd(`alice:${aliceHash}:extra`).entries.size === 0,
  );
  check(
    "the username character set is the same one every log line is sanitised against",
    isValidUsername("a.b_c@d-e") && !isValidUsername("a b") && !isValidUsername("a\nb") && !isValidUsername(""),
  );
  check("...and an unusable name collapses to a single harmless token", sanitizeUsername("a\nb") === "?" && sanitizeUsername("alice") === "alice");

  // The cap needs a thousand entries to reach, which is why it is built here rather than
  // committed as a fixture.
  const many = parsePasswd(Array.from({ length: MAX_PASSWD_ENTRIES + 5 }, (_, i) => `u${i}:${aliceHash}`).join("\n"));
  check(
    "the entry count is capped, and says so once rather than per ignored line",
    many.entries.size === MAX_PASSWD_ENTRIES &&
      many.warnings.length === 1 &&
      many.warnings[0] === `passwd: stopped at ${MAX_PASSWD_ENTRIES} users; later lines were ignored`,
    `${many.entries.size} entries, ${many.warnings.length} warnings`,
  );
}

console.log("\nreading the file, including the ways it goes wrong");
{
  const dir = mkdtempSync(resolve(tmpdir(), "labview-passwd-"));
  const file = resolve(dir, "passwd");
  const hash = readPasswd(passwdOk).entries.get("alice")?.hash ?? "";
  clearPasswdCache();

  writeFileSync(file, `alice:${hash}\n`);
  const first = readPasswd(file);
  check("a readable file parses", first.state === "ok" && first.entries.size === 1);
  check("an unchanged file is not parsed twice", readPasswd(file) === first);
  writeFileSync(file, `alice:${hash}\nbob:${hash}\n`);
  const second = readPasswd(file);
  check(
    "a changed file is re-read, so adding a user needs no restart",
    second !== first && second.entries.size === 2,
    `${second.entries.size} entries`,
  );

  const missing = readPasswd(resolve(dir, "not-there"));
  check(
    "a file that is not there is the unconfigured default, not a fault: no state, no warning",
    missing.state === "missing" && missing.entries.size === 0 && missing.warnings.length === 0,
  );

  const asDir = readPasswd(dir);
  check(
    "a directory at the path names the Docker bind-mount cause, which is how this actually goes wrong",
    asDir.state === "unreadable" &&
      (asDir.warnings[0] ?? "").includes("is a directory, not a file — Docker creates one at a bind-mount path"),
    asDir.warnings[0],
  );

  const big = resolve(dir, "huge");
  writeFileSync(big, "#\n".repeat(40_000));
  const oversize = readPasswd(big);
  check(
    "something other than a passwd file mounted at the path is refused by size, and the limit is stated",
    oversize.state === "unreadable" && (oversize.warnings[0] ?? "").includes("over the 65536-byte limit for a passwd file"),
    oversize.warnings[0],
  );

  // Root can read a mode-000 file, so this cannot be produced there. Skipped out loud
  // rather than passed quietly: a ✓ for something that was not tested is a lie.
  if (typeof process.getuid === "function" && process.getuid() !== 0) {
    chmodSync(file, 0o000);
    clearPasswdCache();
    const denied = readPasswd(file);
    chmodSync(file, 0o600);
    check(
      "a file the container's user cannot read says so, and says why that is expected",
      denied.state === "unreadable" && (denied.warnings[0] ?? "").includes("LabView runs unprivileged"),
      denied.warnings[0],
    );
  } else {
    console.log("  – skipped: an unreadable file cannot be produced as root");
  }

  rmSync(dir, { recursive: true, force: true });
  clearPasswdCache();
}

// A fixed clock for everything below, so a session's lifetime and a lockout's window are
// arithmetic rather than a race against the test's own runtime.
const T0 = new Date("2024-06-01T12:00:00Z");
const at = (seconds: number): Date => new Date(T0.getTime() + seconds * 1000);
const epoch = (d: Date): number => Math.floor(d.getTime() / 1000);
/** Not a credential: an HMAC key this file mints for itself. */
const SESSION_KEY = "smoke-session-key-not-a-secret";
/**
 * Why a token was refused, or `""` when it was not.
 *
 * `SessionCheck` is a discriminated union, so `.reason` exists only on the failing arm.
 * Asserting the reason rather than the boolean is the point — "refused" is satisfied by a
 * verifier that refuses everything — and this is what lets a check read
 * `why(...) === "expired"` without narrowing at each call site.
 */
const why = (check: SessionCheck): string => (check.ok ? "" : check.reason);

console.log("\na session token is signed, dated and revocable");
{
  const issued = issueSession("alice", "passwd", SESSION_KEY, 720, T0);
  const good = verifySession(issued.token, SESSION_KEY, T0);
  check(
    "a fresh token verifies, carrying the user and the method that signed them in",
    good.ok && good.payload.u === "alice" && good.payload.via === "passwd",
  );
  check("...and lasts exactly the configured ttl", issued.payload.exp - issued.payload.iat === 720 * 60);
  check("...and two tokens for the same user are distinguishable, so one can be revoked", issueSession("alice", "passwd", SESSION_KEY, 720, T0).payload.jti !== issued.payload.jti);
  check("a token one second past its expiry is refused", why(verifySession(issued.token, SESSION_KEY, at(720 * 60 + 1))) === "expired");
  check("a token issued by another key is refused", why(verifySession(issued.token, `${SESSION_KEY}x`, T0)) === "signature");

  const parts = issued.token.split(".");
  const body = parts[1] ?? "";
  const mac = parts[2] ?? "";
  check(
    "rewriting the payload invalidates the signature, which is the whole point of signing it",
    why(
      verifySession(
        `v1.${Buffer.from(JSON.stringify({ ...issued.payload, u: "root" }), "utf8").toString("base64url")}.${mac}`,
        SESSION_KEY,
        T0,
      ),
    ) === "signature",
  );
  // The *first* character, and to a value it demonstrably is not. Appending a chosen
  // letter in place of the last one is the obvious way to write this and is wrong twice
  // over: one run in sixteen the MAC already ends in that letter and the "tampered" token
  // is the original, and the final base64url character of a 32-byte digest carries only
  // two significant bits, so a change there can decode to the same bytes.
  const flipped = `${mac.startsWith("A") ? "B" : "A"}${mac.slice(1)}`;
  check("flipping the signature is refused", flipped !== mac && why(verifySession(`v1.${body}.${flipped}`, SESSION_KEY, T0)) === "signature");
  check("a token claiming another version is refused", verifySession(`v2.${body}.${mac}`, SESSION_KEY, T0).ok === false);
  check("a token of the wrong shape is refused before anything is parsed", why(verifySession(`${body}.${mac}`, SESSION_KEY, T0)) === "malformed");
  check("...as is an empty cookie value", why(verifySession("", SESSION_KEY, T0)) === "malformed");
  // Signed by the right key and still refused: the payload has to be a session, so a
  // future field with a wider type cannot smuggle in a method that no longer exists.
  check(
    "a correctly signed token whose method is not one LabView has is refused, not trusted",
    why(verifySession(signPayload({ u: "alice", via: "basic", iat: epoch(T0), exp: epoch(T0) + 60, jti: "x" }, SESSION_KEY), SESSION_KEY, T0)) ===
      "malformed",
  );
  check(
    "...and one whose username could forge a log line is refused",
    why(
      verifySession(
        signPayload({ u: "alice\nWARN: fake", via: "passwd", iat: epoch(T0), exp: epoch(T0) + 60, jti: "x" }, SESSION_KEY),
        SESSION_KEY,
        T0,
      ),
    ) === "malformed",
  );

  const revocations = new SessionRevocations();
  check("a live token is not revoked", verifySession(issued.token, SESSION_KEY, T0, revocations).ok);
  revocations.revoke(issued.payload.jti, issued.payload.exp, T0);
  check("signing out refuses the token it was holding", why(verifySession(issued.token, SESSION_KEY, T0, revocations)) === "revoked");
  check("...and only that token", verifySession(issueSession("alice", "passwd", SESSION_KEY, 720, T0).token, SESSION_KEY, T0, revocations).ok);

  const bounded = new SessionRevocations(2);
  bounded.revoke("a", epoch(at(10)), T0);
  bounded.revoke("b", epoch(at(20)), T0);
  bounded.revoke("c", epoch(at(30)), T0);
  check(
    "the revocation set is bounded, dropping the entry closest to expiring anyway",
    bounded.size === 2 && !bounded.has("a") && bounded.has("c"),
  );
  bounded.prune(at(25));
  check("...and forgets a revocation once the token could no longer be used", bounded.size === 1 && bounded.has("c"));

  check("comparing two equal strings is true", safeEqual("abc", "abc"));
  check("...two different ones false, and a length mismatch does not throw", !safeEqual("abc", "abd") && !safeEqual("abc", "abcd"));
}

console.log("\nthe cookie that carries it");
{
  const set = serializeCookie({ name: "labview_session", value: "tok", maxAgeSeconds: 43_200, secure: false, path: "/" });
  check(
    "a session cookie is HttpOnly and SameSite=Lax, with the configured lifetime",
    set === "labview_session=tok; Path=/; Max-Age=43200; HttpOnly; SameSite=Lax",
    set,
  );
  check(
    "Secure is added only when the browser's request was https, or it would be dropped on a LAN address",
    serializeCookie({ name: "s", value: "t", maxAgeSeconds: 60, secure: true, path: "/" }).endsWith("; Secure"),
  );
  check(
    "signing out sends the same cookie with no value and no lifetime",
    serializeCookie({ name: "labview_session", value: "", maxAgeSeconds: 0, secure: false, path: "/" }).startsWith(
      "labview_session=; Path=/; Max-Age=0",
    ),
  );
  check("a negative lifetime cannot produce a cookie that outlives its intent", serializeCookie({ name: "s", value: "", maxAgeSeconds: -5, secure: false, path: "/" }).includes("Max-Age=0"));

  check("one cookie is read out of several", readCookie("theme=dark; labview_session=tok; tz=CET", "labview_session") === "tok");
  check("a cookie that is not there is undefined rather than empty", readCookie("theme=dark", "labview_session") === undefined);
  check("no Cookie header at all is the same answer", readCookie(undefined, "labview_session") === undefined);
  check("a repeated cookie takes the first, as a browser sends it", readCookie("s=first; s=second", "s") === "first");
  // The transient OIDC cookie's name is the session cookie's name plus a suffix, so a
  // prefix match here would hand the session verifier the wrong value entirely.
  check("a name that is a prefix of another is not mistaken for it", readCookie("labview_session_oidc=t; labview_session=real", "labview_session") === "real");

  check("the browser's scheme comes from the proxy's header when it set one", effectiveProtocol("https", "http") === "https");
  check("...from the first hop of a chained one", effectiveProtocol("https, http", "http") === "https");
  check("...and from the socket when nothing set it", effectiveProtocol(undefined, "HTTP") === "http");
  check(
    "the host is read the same way, since the redirect URI is built from it",
    effectiveHost("LabView.Example.com", "internal:8080") === "labview.example.com" && effectiveHost(undefined, "Internal:8080") === "internal:8080",
  );
  check(
    "a cookie is Secure on https, never on http, and the operator can override both ways",
    shouldSecureCookie("auto", "https") && !shouldSecureCookie("auto", "http") && shouldSecureCookie("true", "http") && !shouldSecureCookie("false", "https"),
  );

  check("a POST with no Origin is allowed, so curl and a health checker still work", originAllowed(undefined, "labview.example.com"));
  check(
    "an Origin naming this host is allowed whatever its scheme, because a TLS-terminating proxy makes them differ",
    originAllowed("https://labview.example.com", "labview.example.com") && originAllowed("http://labview.example.com", "labview.example.com"),
  );
  check("a foreign Origin is refused", !originAllowed("https://evil.example", "labview.example.com"));
  check("...and `Origin: null` is refused rather than read as absent", !originAllowed("null", "labview.example.com"));
}

console.log("\nfailed sign-ins are counted per username, not per address");
{
  const th = new LoginThrottle(2, 60);
  const key = LoginThrottle.key(sanitizeUsername("Alice"));
  check("the bucket is case-insensitive, so capitalisation alone does not multiply the allowance", key === "alice");
  check("asking does not consume an attempt", th.check(key, T0).allowed && th.size === 0);
  th.fail(key, T0);
  check("one failure short of the limit still allows an attempt", th.check(key, at(1)).allowed);
  const locked = th.fail(key, at(50));
  check("the limit locks, with a wait the route can put in Retry-After", !locked.allowed && locked.retryAfterSeconds === 60, JSON.stringify(locked));
  // Anchored to the latest failure: anchoring to the first would let an attacker pace
  // their guesses to the window boundary and never be locked out at all.
  check("the window runs from the most recent failure", th.check(key, at(100)).retryAfterSeconds === 10);
  check("...and opens again after that much quiet, dropping the bucket with it", th.check(key, at(111)).allowed && th.size === 0);

  th.fail(key, at(200));
  th.fail(key, at(201));
  const beforeSuccess = th.check(key, at(202)).allowed;
  th.succeed(key);
  check("a correct password clears the count, ending the lockout", !beforeSuccess && th.check(key, at(202)).allowed);

  const pruned = new LoginThrottle(1, 30);
  pruned.fail("stale", T0);
  pruned.fail("recent", at(20));
  pruned.prune(at(31));
  check("pruning drops only the buckets whose window has closed", pruned.size === 1 && pruned.check("stale", at(31)).allowed && !pruned.check("recent", at(31)).allowed);

  // A script posting a million distinct usernames must be a lockout, not a memory leak.
  const capped = new LoginThrottle(1, 600, 2);
  capped.fail("first", T0);
  capped.fail("second", at(1));
  capped.fail("third", at(2));
  check(
    "at the cap the least recently failed bucket is evicted — a spray of usernames costs a lockout, never memory",
    capped.size === 2 && capped.check("first", at(3)).allowed && !capped.check("second", at(3)).allowed && !capped.check("third", at(3)).allowed,
  );
  check("every junk username shares one bucket, because a script spraying names is one attacker", LoginThrottle.key(sanitizeUsername("a\nb")) === LoginThrottle.key(sanitizeUsername("c d")));
}

console.log("\nopen unless configured");
{
  const off = { passwdEnabled: true, passwdUsers: 0, oidcEnabled: true, oidcIssuer: "", oidcClientId: "" };
  check(
    "nothing configured enforces nothing, which is what makes a new image safe to pull",
    resolveAccessMode(off).enforced === false && resolveAccessMode(off).methods.length === 0,
  );
  check("...and says nothing, because there is no login card to explain", resolveAccessMode(off).notes.length === 0);
  const withUsers = resolveAccessMode({ ...off, passwdUsers: 3 });
  check("one usable entry turns the gate on", withUsers.enforced && withUsers.methods.join(",") === "passwd");
  const disabled = resolveAccessMode({ ...off, passwdEnabled: false, passwdUsers: 3 });
  check(
    "...unless password sign-in was switched off, which is the off switch an external-provider setup wants",
    !disabled.enforced && disabled.methods.length === 0,
  );
  const oidcOnly = resolveAccessMode({ ...off, oidcIssuer: "https://idp.example.com/application/o/labview/", oidcClientId: "cid" });
  check("an issuer and a client id turn it on with no passwd file at all", oidcOnly.enforced && oidcOnly.methods.join(",") === "oidc");
  check(
    "half-configured OIDC never enforces on its own",
    !resolveAccessMode({ ...off, oidcIssuer: "https://idp.example.com" }).enforced && !resolveAccessMode({ ...off, oidcClientId: "cid" }).enforced,
  );
  const both = resolveAccessMode({ ...off, passwdUsers: 2, oidcIssuer: "https://idp.example.com", oidcClientId: "cid" });
  check("with both live, password comes first — the local account is what works when the provider is broken", both.methods.join(",") === "passwd,oidc");
  const halfWhileEnforcing = resolveAccessMode({ ...off, passwdUsers: 2, oidcIssuer: "https://idp.example.com" });
  check(
    "a method that is on but unusable is a note while enforcing, never a failure",
    halfWhileEnforcing.enforced && halfWhileEnforcing.notes.join("|") === "Single sign-on is configured but not available.",
    halfWhileEnforcing.notes.join("|"),
  );
  check(
    "...and the same is said of a passwd file that lost its users",
    resolveAccessMode({ ...off, oidcIssuer: "https://idp.example.com", oidcClientId: "cid" }).notes.join("|") ===
      "Password sign-in is configured but not available.",
  );

  check(
    "the open posture says so in one line, and names what is holding the door",
    accessModeSummary(resolveAccessMode(off), { users: 0, oidcHost: "" }) ===
      "LabView access control: none — the HTTP surface is open to anyone who can reach it, relying on your edge",
  );
  check(
    "the enforcing line counts users and pluralises",
    accessModeSummary(withUsers, { users: 1, oidcHost: "" }) === "LabView access control: password login (1 user) — /api requires a session" &&
      accessModeSummary(withUsers, { users: 3, oidcHost: "" }) === "LabView access control: password login (3 users) — /api requires a session",
  );
  check(
    "...and names the provider's host, since that is what an operator recognises",
    accessModeSummary(both, { users: 2, oidcHost: "idp.example.com" }) ===
      "LabView access control: password login (2 users) + OIDC (idp.example.com) — /api requires a session",
  );
  check(
    "a log line is a count, never a list of accounts to try",
    !accessModeSummary(both, { users: 2, oidcHost: "idp.example.com" }).includes("alice"),
  );
  check("an unparseable issuer degrades the label rather than the line", oidcButtonLabel("", "not a url") === "Sign in with your provider" && oidcButtonLabel(" SSO ", "https://idp.example.com") === "SSO");
  check("every failure code has wording a visitor can act on", loginFailureText("credentials") === "Invalid username or password." && loginFailureText("oidc-state").length > 0);
}

console.log("\nthe posture comes from the file, read as configured");
{
  const cfgFor = (env: Record<string, string | undefined>): ReturnType<typeof loadConfig> => {
    for (const [k, v] of Object.entries(env)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    return loadConfig();
  };

  clearPasswdCache();
  const okSnap = readAccess(cfgFor({ LABVIEW_AUTH_PASSWD_FILE: passwdOk }));
  check(
    "a good file enforces, with a user count and nothing to fix",
    okSnap.mode.enforced && okSnap.users === 3 && okSnap.warnings.length === 0 && okSnap.hints.length === 0,
  );
  const emptySnap = readAccess(cfgFor({ LABVIEW_AUTH_PASSWD_FILE: passwdEmpty }));
  check("a file of comments leaves the surface open, and does not complain about it", !emptySnap.mode.enforced && emptySnap.users === 0 && emptySnap.warnings.length === 0);
  const messySnap = readAccess(cfgFor({ LABVIEW_AUTH_PASSWD_FILE: passwdMessy }));
  check("a messy file enforces on what it can use and reports the rest", messySnap.mode.enforced && messySnap.users === 1 && messySnap.warnings.length === 7);
  const missingSnap = readAccess(cfgFor({ LABVIEW_AUTH_PASSWD_FILE: resolve(authRoot, "passwd.absent") }));
  check(
    "a missing file is a hint naming where LabView looked, not a warning",
    !missingSnap.mode.enforced && missingSnap.warnings.length === 0 && missingSnap.hints.some((h) => h.includes("passwd.absent")),
    missingSnap.hints.join("|"),
  );
  const disabledSnap = readAccess(cfgFor({ LABVIEW_AUTH_PASSWD_FILE: passwdOk, LABVIEW_AUTH_PASSWD_ENABLED: "false" }));
  check(
    "switching password sign-in off does not read the file at all",
    !disabledSnap.mode.enforced && disabledSnap.users === 0 && disabledSnap.passwd.state === "missing",
  );
  const halfSnap = readAccess(
    cfgFor({ LABVIEW_AUTH_PASSWD_ENABLED: undefined, LABVIEW_OIDC_ISSUER: "https://idp.example.com/application/o/labview/" }),
  );
  check(
    "an issuer with no client id is a warning that names the setting to fix",
    halfSnap.warnings.some((warning) => warning.includes("auth.oidc.clientId is empty")),
    halfSnap.warnings.join("|"),
  );
  const bothOff = readAccess(cfgFor({ LABVIEW_OIDC_ISSUER: undefined, LABVIEW_AUTH_PASSWD_ENABLED: "false", LABVIEW_OIDC_ENABLED: "false" }));
  check(
    "with both methods switched off, the hint says LabView will never ask — so an open surface is never a surprise",
    bothOff.hints.some((hint) => hint.includes("LabView will not ask for a sign-in")),
    bothOff.hints.join("|"),
  );

  const generated = resolveSessionSecret(cfgFor({ LABVIEW_AUTH_PASSWD_ENABLED: undefined, LABVIEW_OIDC_ENABLED: undefined }), () => "minted");
  check(
    "no configured secret mints one and says restarts will sign everyone out — degrade, never refuse to start",
    generated.generated && generated.secret === "minted" && generated.notes.some((n) => n.includes("restart signs everyone out")),
  );
  const configured = resolveSessionSecret(cfgFor({ LABVIEW_SESSION_SECRET: SESSION_KEY }), () => "minted");
  check("a configured secret is used as-is", !configured.generated && configured.secret === SESSION_KEY && configured.notes.length === 0);

  // A credential comes from one variable and nowhere else, so the one way one still goes
  // missing by accident is a variable that is *set and carries nothing* —
  // `${LABVIEW_SESSION_SECRET}` in a compose file with no matching `.env` entry, which
  // compose expands to an empty value and passes on without a word. Each reader says so in
  // its own vocabulary; for LabView's own login that is a startup note.
  const blankSession = resolveSessionSecret(cfgFor({ LABVIEW_SESSION_SECRET: "" }), () => "minted");
  check(
    "a session secret that is set and carries nothing mints a key and says both things",
    blankSession.generated &&
      blankSession.secret === "minted" &&
      blankSession.notes.some((n) => n.includes("LABVIEW_SESSION_SECRET is set but carries nothing")) &&
      blankSession.notes.some((n) => n.includes("restart signs everyone out")),
    blankSession.notes.join("|"),
  );
  const spacedSession = resolveSessionSecret(cfgFor({ LABVIEW_SESSION_SECRET: "   " }), () => "minted");
  check(
    "...and one holding only whitespace is the same mistake, not a key made of spaces",
    spacedSession.generated && spacedSession.notes.some((n) => n.includes("carries nothing")),
    spacedSession.notes.join("|"),
  );

  const noOidc = resolveOidc(cfgFor({ LABVIEW_SESSION_SECRET: undefined }));
  check("no issuer means no OIDC client is built", noOidc.settings === undefined && noOidc.notes.length === 0);
  const oidcCfg = resolveOidc(
    cfgFor({
      LABVIEW_OIDC_ISSUER: " https://idp.example.com/application/o/labview/ ",
      LABVIEW_OIDC_CLIENT_ID: " labview ",
      LABVIEW_OIDC_CLIENT_SECRET: "  inline-client-secret  ",
    }),
  );
  check(
    "the issuer, the client id and the secret beside it are all trimmed of what an operator pasted",
    oidcCfg.settings?.issuer === "https://idp.example.com/application/o/labview/" &&
      oidcCfg.settings?.clientId === "labview" &&
      oidcCfg.settings?.clientSecret === "inline-client-secret" &&
      oidcCfg.notes.length === 0,
    JSON.stringify({ issuer: oidcCfg.settings?.issuer, clientId: oidcCfg.settings?.clientId }),
  );
  const blankClientSecret = resolveOidc(cfgFor({ LABVIEW_OIDC_CLIENT_SECRET: "" }));
  check(
    "a client secret that arrived empty is a note and a working public client, never a refusal to start (I4)",
    blankClientSecret.settings?.clientSecret === "" &&
      blankClientSecret.notes.some((n) => n.includes("LABVIEW_OIDC_CLIENT_SECRET is set but carries nothing")),
    blankClientSecret.notes.join("|"),
  );
  const publicClient = resolveOidc(cfgFor({ LABVIEW_OIDC_CLIENT_SECRET: undefined }));
  check(
    "no secret at all is a public client authenticating by PKCE, and not worth a word",
    publicClient.settings !== undefined && publicClient.settings.clientSecret === "" && publicClient.notes.length === 0,
  );

  // Two empty variables beside two real credentials: what is reported is the *names* of
  // the empty ones, and no note goes anywhere near the values of the others. This is the
  // one place a credential could reach a log, since masking runs on the API payload.
  const mixed = cfgFor({
    LABVIEW_OIDC_CLIENT_SECRET: "",
    LABVIEW_SESSION_SECRET: "",
    LABVIEW_AUTHENTIK_TOKEN: "smoke-authentik-token",
    LABVIEW_TRAEFIK_PASSWORD: "smoke-app-password",
  });
  check(
    "blankCredentialVars names exactly the variables that arrived empty, in the order they are read",
    mixed.blankCredentialVars.join(",") === "LABVIEW_OIDC_CLIENT_SECRET,LABVIEW_SESSION_SECRET",
    mixed.blankCredentialVars.join(","),
  );
  check(
    "...and holds no value: the two credentials that did arrive are not in it",
    mixed.blankCredentialVars.every((v) => !v.includes("smoke-")),
    mixed.blankCredentialVars.join(","),
  );
  const mixedNotes = [...resolveOidc(mixed).notes, ...resolveSessionSecret(mixed, () => "minted").notes];
  check(
    "...and no note carries a credential either, only the name of a variable",
    mixedNotes.length === 3 && mixedNotes.every((n) => !n.includes("smoke-authentik-token") && !n.includes("smoke-app-password")),
    mixedNotes.join("|"),
  );

  cfgFor({
    LABVIEW_OIDC_ISSUER: undefined,
    LABVIEW_OIDC_CLIENT_ID: undefined,
    LABVIEW_OIDC_CLIENT_SECRET: undefined,
    LABVIEW_SESSION_SECRET: undefined,
    LABVIEW_AUTHENTIK_TOKEN: undefined,
    LABVIEW_TRAEFIK_PASSWORD: undefined,
    LABVIEW_AUTH_PASSWD_FILE: undefined,
  });
  clearPasswdCache();
}

console.log("\nsettings LabView no longer reads");
{
  // The four `*_FILE` variables and their config-file keys are recognised for one purpose:
  // to say they are gone. Ignoring one would be a lock-out dressed up as a simplification
  // (I4) — a client secret that was a mounted file becomes a public client on the next
  // pull, and the provider refuses every sign-in with nothing in any log to explain it.
  const cfg = loadConfig();
  check("with none of them set, nothing is said", retiredSettings(cfg, {}).length === 0, retiredSettings(cfg, {}).join("|"));

  const retired = [
    ["LABVIEW_AUTHENTIK_TOKEN_FILE", "LABVIEW_AUTHENTIK_TOKEN"],
    ["LABVIEW_TRAEFIK_PASSWORD_FILE", "LABVIEW_TRAEFIK_PASSWORD"],
    ["LABVIEW_OIDC_CLIENT_SECRET_FILE", "LABVIEW_OIDC_CLIENT_SECRET"],
    ["LABVIEW_SESSION_SECRET_FILE", "LABVIEW_SESSION_SECRET"],
  ] as const;
  for (const [was, now] of retired) {
    const lines = retiredSettings(cfg, { [was]: "/run/secrets/somewhere" });
    // `slice(was.length)` rather than a bare `includes`: every replacement name is a
    // prefix of the variable that replaced it, so "names the replacement" has to be
    // asserted *past* the mention of the retired one or it holds for free.
    check(
      `${was} is reported, and names ${now} as where the value goes`,
      lines.length === 1 && lines[0]!.startsWith(was) && lines[0]!.slice(was.length).includes(now),
      lines.join("|"),
    );
    check(`...without echoing the path ${was} pointed at`, lines.every((l) => !l.includes("/run/secrets/somewhere")));
  }
  check(
    "one set to nothing at all is still reported — the operator still has a value to move",
    retiredSettings(cfg, { LABVIEW_SESSION_SECRET_FILE: "" }).length === 1,
  );
  check(
    "all four at once produce four lines, so a deployment hears about every one of them",
    retiredSettings(cfg, Object.fromEntries(retired.map(([was]) => [was, "/x"]))).length === 4,
  );
  check(
    "the variable that replaced them is not itself a complaint",
    retiredSettings(cfg, { LABVIEW_AUTHENTIK_TOKEN: "still-fine", LABVIEW_SESSION_SECRET: "also-fine" }).length === 0,
  );

  // The config-file half. `merge` keeps keys it does not recognise, which is what makes a
  // `config.yml` written against the previous `config.example.yml` still parse — and still
  // need telling.
  const legacyDir = mkdtempSync(resolve(tmpdir(), "labview-legacy-"));
  const legacyPath = resolve(legacyDir, "config.yml");
  writeFileSync(legacyPath, "authentik:\n  tokenFile: /config/authentik-token\nauth:\n  session:\n    secretFile: /config/session-key\n");
  process.env.LABVIEW_CONFIG = legacyPath;
  const legacy = loadConfig();
  process.env.LABVIEW_CONFIG = "___none___"; // back to the sentinel the run started with
  const legacyLines = retiredSettings(legacy, {});
  check(
    "a config.yml written against the old example is caught too, at both nesting depths",
    legacyLines.length === 2 &&
      legacyLines.some((l) => l.includes("authentik.tokenFile") && l.includes("LABVIEW_AUTHENTIK_TOKEN")) &&
      legacyLines.some((l) => l.includes("auth.session.secretFile") && l.includes("LABVIEW_SESSION_SECRET")),
    legacyLines.join("|"),
  );
  check("...and neither line echoes the path that was in the file", legacyLines.every((l) => !l.includes("/config/")));
  rmSync(legacyDir, { recursive: true, force: true });
}

console.log("\nwhat may be read without a session");
{
  for (const path of ["/api/healthz", "/api/session", "/api/login", "/api/logout"]) {
    check(`${path} is reachable without one, since a login flow could not start otherwise`, isPublicPath(path) && !requiresSession(path));
  }
  check("the fleet itself is not", requiresSession("/api/overview") && !isPublicPath("/api/overview"));
  check("...nor is a rescan", requiresSession("/api/rescan"));
  check("...nor an /api path that does not exist, so the gate answers before routing does", requiresSession("/api/nope") && requiresSession("/api"));
  // The three ways the prefix version of this allowlist would leak, spelled out.
  check("a dot-segment cannot walk out of a public path", requiresSession("/api/healthz/../overview"));
  check("a name that merely starts with a public one is not public", requiresSession("/api/sessionx") && requiresSession("/api/loginx"));
  check("a doubled slash does not evade the gate", requiresSession("//api/overview") && requiresSession("/api//overview"));
  check("nor does case", requiresSession("/API/OVERVIEW"));
  check("a query string or fragment does not make a public path private", isPublicPath("/api/session?x=1") && isPublicPath("/api/healthz#frag"));
  check("...and does not make a private one public", requiresSession("/api/overview?x=/api/session"));
  check(
    "the SPA shell, its bundle and its stylesheet stay public — nothing in them is fleet-specific",
    !requiresSession("/") && !requiresSession("/app.js") && !requiresSession("/styles.css") && !requiresSession("/graph"),
  );
  check("the OIDC round trip is never gated, because it is how a session is obtained", !requiresSession("/auth/oidc/start") && !requiresSession("/auth/oidc/callback"));
}

console.log("\nsingle sign-on: the parts that are pure arithmetic");
{
  // The RFC 7636 appendix B vector, so the derivation is pinned against the spec rather
  // than against itself — a `pkceChallenge` that hashed the wrong thing consistently
  // would satisfy any round-trip test written from it.
  check(
    "the S256 challenge matches the RFC's own test vector",
    pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") === "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
  );
  const verifier = createVerifier();
  check("a verifier is 43 base64url characters, which is what the RFC allows", verifier.length === 43 && /^[A-Za-z0-9_-]+$/.test(verifier));
  check("...and two are not the same", createVerifier() !== verifier);

  check("openid is sent whether or not it was configured", scopeString(["profile", "email"]) === "openid profile email" && scopeString([]) === "openid");
  check("...and never twice, however it was written down", scopeString([" openid ", "profile", "profile"]) === "openid profile");
  check("a configured redirect URI is used verbatim, because the provider matches it exactly", redirectUriFor(" https://labview.example.com/auth/oidc/callback ", "http", "10.0.0.5:8080") === "https://labview.example.com/auth/oidc/callback");
  check("...and one is derived from the request when it was not configured, so a first attempt on a LAN address works", redirectUriFor("", "http", "10.0.0.5:8080") === "http://10.0.0.5:8080/auth/oidc/callback");
  check("https is required of a provider endpoint", isSecureUrl("https://idp.example.com/x") && !isSecureUrl("http://idp.example.com/x") && !isSecureUrl("nonsense"));
  check("...with loopback excepted, which is what makes a local stub issuer testable", isSecureUrl("http://localhost:9000/x") && isSecureUrl("http://127.0.0.1:9000/x"));
}

console.log("\nsingle sign-on: the provider's documents");
{
  const ISSUER = "https://idp.example.com/application/o/labview/";
  const doc = {
    issuer: ISSUER,
    authorization_endpoint: "https://idp.example.com/application/o/authorize/",
    token_endpoint: "https://idp.example.com/application/o/token/",
    jwks_uri: "https://idp.example.com/application/o/labview/jwks/",
  };

  const parsed = parseDiscovery(doc, ISSUER);
  check("a complete discovery document parses", parsed.ok && parsed.doc.tokenEndpoint === doc.token_endpoint);
  check(
    "a trailing slash either side is forgiven, because that is what an operator's copy-paste does to an issuer",
    parseDiscovery(doc, ISSUER.replace(/\/$/, "")).ok && parseDiscovery({ ...doc, issuer: ISSUER.replace(/\/$/, "") }, ISSUER).ok,
  );
  const mixUp = parseDiscovery({ ...doc, issuer: "https://evil.example/" }, ISSUER);
  check(
    "a document naming another issuer is refused — the mix-up defence, and it names the setting to check",
    !mixUp.ok && mixUp.detail.includes("does not match the configured issuer — check auth.oidc.issuer"),
    mixUp.ok ? "accepted" : mixUp.detail,
  );
  const noToken = parseDiscovery({ ...doc, token_endpoint: "" }, ISSUER);
  check("a document missing an endpoint says which one", !noToken.ok && noToken.detail === "the discovery document has no token_endpoint", noToken.ok ? "accepted" : noToken.detail);
  const downgraded = parseDiscovery({ ...doc, token_endpoint: "http://idp.example.com/token/" }, ISSUER);
  check(
    "a plain-http endpoint is refused, so a downgraded document cannot turn the exchange into a cleartext one",
    !downgraded.ok && downgraded.detail.includes("token_endpoint is not an https URL"),
    downgraded.ok ? "accepted" : downgraded.detail,
  );
  check("something that is not a document at all is refused without throwing", !parseDiscovery("<html>", ISSUER).ok && !parseDiscovery(null, ISSUER).ok);

  const settings = {
    issuer: ISSUER,
    clientId: "labview",
    clientSecret: "",
    redirectUri: "https://labview.example.com/auth/oidc/callback",
    scopes: ["openid", "profile", "email"],
    usernameClaim: "preferred_username",
    timeoutMs: 500,
  };
  const authorize = new URL(
    buildAuthorizeUrl(
      { issuer: ISSUER, authorizationEndpoint: doc.authorization_endpoint, tokenEndpoint: doc.token_endpoint, jwksUri: doc.jwks_uri },
      settings,
      settings.redirectUri,
      { state: "the-state", nonce: "the-nonce", verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" },
    ),
  );
  const param = (name: string): string => authorize.searchParams.get(name) ?? "";
  check("the authorize URL asks for a code, as this client id, back at this redirect URI", param("response_type") === "code" && param("client_id") === "labview" && param("redirect_uri") === settings.redirectUri);
  check("...with the scopes, the state and the nonce this attempt generated", param("scope") === "openid profile email" && param("state") === "the-state" && param("nonce") === "the-nonce");
  check(
    "...and the PKCE challenge, by S256 — never the verifier itself, which would defeat the exercise",
    param("code_challenge") === "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" &&
      param("code_challenge_method") === "S256" &&
      !authorize.search.includes("dBjftJeZ"),
  );
}

console.log("\nsingle sign-on: an ID token is not believed until it verifies");
{
  const ISSUER = "https://idp.example.com/application/o/labview/";
  const CLIENT = "labview";
  const NONCE = "the-nonce-of-this-attempt";
  // Generated per run rather than committed: a private key in a repository is a private
  // key, whatever the comment beside it says.
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  const jwks = { keys: [{ ...jwk, kid: "smoke-1", use: "sig", alg: "RS256" }] };
  const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const jwt = (header: Record<string, unknown>, claims: unknown, sign: (data: Buffer) => Buffer): string => {
    const signing = `${b64(header)}.${b64(claims)}`;
    return `${signing}.${sign(Buffer.from(signing, "utf8")).toString("base64url")}`;
  };
  const rsa = (data: Buffer): Buffer => signWithKey("sha256", data, privateKey);
  const claims = { iss: ISSUER, aud: CLIENT, sub: "8f14e45f", exp: epoch(at(300)), iat: epoch(T0), nonce: NONCE, preferred_username: "alice" };
  const token = (over: Record<string, unknown> = {}): string => jwt({ alg: "RS256", kid: "smoke-1", typ: "JWT" }, { ...claims, ...over }, rsa);
  const opts = { issuer: ISSUER, clientId: CLIENT, nonce: NONCE, now: T0 };

  const accepted = verifyIdToken(token(), jwks, opts);
  check("a well-formed token from the configured provider verifies", accepted.ok && accepted.claims.preferred_username === "alice" && accepted.kid === "smoke-1", accepted.ok ? "" : accepted.detail);

  const parts = token().split(".");
  const swapped = `${parts[0] ?? ""}.${b64({ ...claims, sub: "root", preferred_username: "root" })}.${parts[2] ?? ""}`;
  const tamper = verifyIdToken(swapped, jwks, opts);
  check("a payload swapped under a real signature is refused", !tamper.ok && tamper.detail === "the ID token's signature did not verify", tamper.ok ? "accepted" : tamper.detail);

  // The order is the rule: reading `exp` off an unverified token and reporting it is how
  // a verifier ends up acting on attacker-supplied JSON.
  const expiredAndForged = `${parts[0] ?? ""}.${b64({ ...claims, exp: epoch(at(-9999)) })}.${parts[2] ?? ""}`;
  const ordered = verifyIdToken(expiredAndForged, jwks, opts);
  check("the signature is checked before any claim is believed", !ordered.ok && ordered.detail.includes("signature"), ordered.ok ? "accepted" : ordered.detail);

  const unsigned = verifyIdToken(jwt({ alg: "none" }, claims, () => Buffer.alloc(0)), jwks, opts);
  check("an unsigned token is refused by algorithm, before a key is even looked for", !unsigned.ok && unsigned.detail === "the ID token is signed with none, which LabView does not accept", unsigned.ok ? "accepted" : unsigned.detail);

  // The classic confusion: sign with the *public* key as an HMAC secret and hope the
  // verifier picks its algorithm from the token instead of from its own policy.
  const pem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const hmac = verifyIdToken(jwt({ alg: "HS256", kid: "smoke-1" }, claims, (data) => createHmac("sha256", pem).update(data).digest()), jwks, opts);
  check("an HMAC-signed token beside an asymmetric JWKS is refused, and the algorithm is named so the provider setting can be fixed", !hmac.ok && hmac.detail === "the ID token is signed with HS256, which LabView does not accept", hmac.ok ? "accepted" : hmac.detail);

  const rotated = verifyIdToken(jwt({ alg: "RS256", kid: "rotated" }, claims, rsa), jwks, opts);
  check("a token naming a key the JWKS does not have reports the kid, which is the one recoverable failure", !rotated.ok && rotated.unknownKid === "rotated", rotated.ok ? "accepted" : rotated.detail);
  const encOnly = verifyIdToken(token(), { keys: [{ ...jwk, kid: "smoke-1", use: "enc" }] }, opts);
  check("a key marked for encryption is not a signing key", !encOnly.ok, encOnly.ok ? "accepted" : encOnly.detail);
  check("a token that is not a three-part JWT is refused", !verifyIdToken("nope", jwks, opts).ok && !verifyIdToken("a.b", jwks, opts).ok);

  const cases: [string, string, string][] = [
    ["another issuer is refused", token({ iss: "https://evil.example/" }), "the ID token's iss is not the configured issuer"],
    ["a token for another client is refused", token({ aud: "someone-else" }), "the ID token's aud does not include this client id"],
    ["...and so is one authorized to another party", token({ aud: [CLIENT, "other"], azp: "other" }), "the ID token's azp is another client"],
    ["an expired token is refused", token({ exp: epoch(at(-CLOCK_SKEW_SECONDS - 1)) }), "the ID token has expired"],
    ["a token from the future is refused, and the clocks are blamed", token({ iat: epoch(at(CLOCK_SKEW_SECONDS + 1)) }), "the ID token was issued in the future — check the clocks"],
    ["a token from another sign-in attempt is refused", token({ nonce: "some-other-attempt" }), "the ID token's nonce does not match this sign-in attempt"],
    ["...as is one with no nonce at all", token({ nonce: undefined }), "the ID token's nonce does not match this sign-in attempt"],
  ];
  for (const [name, value, detail] of cases) {
    const got = verifyIdToken(value, jwks, opts);
    check(name, !got.ok && got.detail === detail, got.ok ? "accepted" : got.detail);
  }
  check("an audience list containing this client is accepted", verifyIdToken(token({ aud: ["other", CLIENT] }), jwks, opts).ok);
  check("...and an azp naming this client is what it should be", verifyIdToken(token({ aud: [CLIENT, "other"], azp: CLIENT }), jwks, opts).ok);
  check(
    "a token just inside the clock skew is accepted, because two machines are never in step",
    verifyIdToken(token({ exp: epoch(at(-CLOCK_SKEW_SECONDS + 1)) }), jwks, opts).ok &&
      verifyIdToken(token({ iat: epoch(at(CLOCK_SKEW_SECONDS - 1)) }), jwks, opts).ok,
  );

  const base = { iss: ISSUER, aud: CLIENT, sub: "8f14e45f", exp: epoch(at(300)), iat: epoch(T0) };
  check("the configured claim is preferred", usernameFromClaims({ ...base, nickname: "nick", preferred_username: "pref" }, "nickname") === "nick");
  check("...then preferred_username", usernameFromClaims({ ...base, preferred_username: "pref", email: "a@b.example" }, "nickname") === "pref");
  check("...then the email address", usernameFromClaims({ ...base, email: "a@b.example" }, "nickname") === "a@b.example");
  check("...and finally sub, the only claim a provider must send", usernameFromClaims(base, "nickname") === "8f14e45f");
  check(
    "a claim a log line could not survive is skipped in favour of the next candidate",
    usernameFromClaims({ ...base, preferred_username: "two words", email: "a@b.example" }, "") === "a@b.example",
  );
  check("...and if none is usable, none is invented", usernameFromClaims({ ...base, sub: "a b" }, "") === undefined);
}

console.log("\nsingle sign-on: the token exchange, against a stubbed provider");
{
  const ISSUER = "https://idp.example.com/application/o/labview/";
  const CLIENT = "labview";
  const NONCE = "the-nonce-of-this-attempt";
  /** Not a credential: a string the stub demands back, so it can be asserted. */
  const CLIENT_SECRET = "smoke-oidc-client-secret";
  const DISCOVERY_URL = "https://idp.example.com/application/o/labview/.well-known/openid-configuration";
  const doc = {
    issuer: ISSUER,
    authorization_endpoint: "https://idp.example.com/application/o/authorize/",
    token_endpoint: "https://idp.example.com/application/o/token/",
    jwks_uri: "https://idp.example.com/application/o/labview/jwks/",
  };
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwks = { keys: [{ ...publicKey.export({ format: "jwk" }), kid: "smoke-1", use: "sig", alg: "RS256" }] };
  const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const idToken = (over: Record<string, unknown> = {}, kid = "smoke-1"): string => {
    const signing = `${b64({ alg: "RS256", kid, typ: "JWT" })}.${b64({
      iss: ISSUER,
      aud: CLIENT,
      sub: "8f14e45f",
      exp: epoch(at(300)),
      iat: epoch(T0),
      nonce: NONCE,
      preferred_username: "alice",
      ...over,
    })}`;
    return `${signing}.${signWithKey("sha256", Buffer.from(signing, "utf8"), privateKey).toString("base64url")}`;
  };

  interface StubOpts {
    discovery?: unknown;
    tokenStatus?: number;
    tokenBody?: unknown;
  }
  /** A provider that answers the three requests a login makes, and records them. */
  function providerStub(opts: StubOpts = {}): { doFetch: FetchLike; calls: string[]; bodies: string[] } {
    const calls: string[] = [];
    const bodies: string[] = [];
    const doFetch: FetchLike = async (url, init) => {
      calls.push(url);
      if (init?.body !== undefined) bodies.push(init.body);
      if (url === DISCOVERY_URL) return reply(200, opts.discovery ?? doc);
      if (url === doc.jwks_uri) return reply(200, jwks);
      if (url === doc.token_endpoint) return reply(opts.tokenStatus ?? 200, opts.tokenBody ?? { id_token: idToken(), token_type: "Bearer" });
      return reply(404, { detail: "no such endpoint" });
    };
    return { doFetch, calls, bodies };
  }
  const settings = {
    issuer: ISSUER,
    clientId: CLIENT,
    clientSecret: CLIENT_SECRET,
    redirectUri: "https://labview.example.com/auth/oidc/callback",
    scopes: ["openid", "profile", "email"],
    usernameClaim: "preferred_username",
    timeoutMs: 500,
  };
  const transient = { state: "the-state", nonce: NONCE, verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", exp: epoch(at(300)) };

  const happy = providerStub();
  const redeemed = await new OidcClient(settings, happy.doFetch).redeem("the-code", settings.redirectUri, transient, T0);
  check("a code is exchanged and the identity in the ID token comes back", redeemed.ok && redeemed.username === "alice", redeemed.ok ? "" : redeemed.failure.detail);
  check(
    "the exchange carries the PKCE verifier and the client secret, as a confidential client",
    (happy.bodies[0] ?? "").includes("grant_type=authorization_code") &&
      (happy.bodies[0] ?? "").includes(`code_verifier=${transient.verifier}`) &&
      (happy.bodies[0] ?? "").includes(`client_secret=${CLIENT_SECRET}`),
    happy.bodies[0]?.replace(CLIENT_SECRET, "…"),
  );
  check("...and it reaches the token endpoint the document named, not a guessed one", happy.calls.includes(doc.token_endpoint) && happy.calls[0] === DISCOVERY_URL);

  const publicClient = providerStub();
  await new OidcClient({ ...settings, clientSecret: "" }, publicClient.doFetch).redeem("the-code", settings.redirectUri, transient, T0);
  check("a public client sends no secret and still sends its verifier", !(publicClient.bodies[0] ?? "").includes("client_secret") && (publicClient.bodies[0] ?? "").includes("code_verifier="));

  const cached = providerStub();
  const client = new OidcClient(settings, cached.doFetch);
  await client.redeem("code-1", settings.redirectUri, transient, T0);
  await client.redeem("code-2", settings.redirectUri, transient, at(60));
  check(
    "a second login inside the TTL re-uses the discovery document and the keys, so signing in is one request",
    cached.calls.filter((u) => u === DISCOVERY_URL).length === 1 && cached.calls.filter((u) => u === doc.jwks_uri).length === 1,
    cached.calls.join(" "),
  );

  const rotated = providerStub({ tokenBody: { id_token: idToken({}, "rotated") } });
  const rotatedResult = await new OidcClient(settings, rotated.doFetch).redeem("the-code", settings.redirectUri, transient, T0);
  check(
    "an unknown key id refetches the JWKS exactly once, so key rotation recovers and a bogus kid cannot be used to hammer the provider",
    !rotatedResult.ok && rotated.calls.filter((u) => u === doc.jwks_uri).length === 2,
    `${rotated.calls.filter((u) => u === doc.jwks_uri).length} jwks fetches`,
  );

  const refused: [string, StubOpts, string, string][] = [
    ["a document naming another issuer stops the login at the provider", { discovery: { ...doc, issuer: "https://evil.example/" } }, "provider", "does not match the configured issuer"],
    ["a refused exchange names the stage and what to check", { tokenStatus: 400 }, "token", "check the client id, secret and the redirect URI"],
    ["a response with no ID token says the openid scope may be missing", { tokenBody: { access_token: "opaque" } }, "token", "the provider may not have the openid scope enabled"],
    ["a token from another attempt is refused at the token stage", { tokenBody: { id_token: idToken({ nonce: "another" }) } }, "token", "nonce does not match this sign-in attempt"],
    ["a token with no usable username fails on identity, naming the claims that were tried", { tokenBody: { id_token: idToken({ preferred_username: undefined, email: undefined, sub: "a b" }) } }, "identity", "add the profile or email scope"],
  ];
  for (const [name, stubOpts, stage, detail] of refused) {
    const stub = providerStub(stubOpts);
    const got = await new OidcClient(settings, stub.doFetch).redeem("the-code", settings.redirectUri, transient, T0);
    check(name, !got.ok && got.failure.stage === stage && got.failure.detail.includes(detail), got.ok ? "accepted" : `${got.failure.stage}: ${got.failure.detail}`);
    check(`...and that failure carries no credential (${stage})`, got.ok || !got.failure.detail.includes(CLIENT_SECRET));
  }
}

console.log("\nthe gate itself, driven through real requests");
{
  // The one part of this feature no unit test can reach. Every rule above is a function
  // of its arguments, and each of them can be right while the server is wrong: a hook
  // that decides correctly and forgets to reply, an allowlist consulted after routing
  // instead of before it, a cookie set on the wrong path, a 401 that arrives with the
  // body still attached. So these go through `app.inject()` — real hooks, real routes,
  // real headers, no socket.
  //
  // Both postures run, because "open unless configured" is a promise about what happens
  // when an operator changes nothing, and an untested promise is a comment.
  const { buildApp } = await import("../src/server/server.js");

  // The open pass lets a real `/api/overview` through, so the fleet behind it has to be
  // a fixture and the integrations have to stay off: an operator's exported Authentik URL
  // would otherwise turn this section into an outbound request to their own lab.
  process.env.LABVIEW_APPS_ROOT = appsRoot;
  process.env.LABVIEW_DOCKER_ENABLED = "false";
  process.env.LABVIEW_TRAEFIK_ENABLED = "false";
  delete process.env.LABVIEW_TRAEFIK_URL;
  delete process.env.LABVIEW_AUTHENTIK_URL;
  delete process.env.LABVIEW_AUTHENTIK_TOKEN;
  // Every refusal below is logged, and a hundred pino lines through the middle of this
  // section would bury the ✓ and ✗ it exists to print. Restored afterwards, so a reader
  // does not have to know that running these checks changes a global.
  const priorLogLevel = process.env.LABVIEW_LOG_LEVEL;
  process.env.LABVIEW_LOG_LEVEL = "silent";

  const HOST = "labview.example.com";
  type App = Awaited<ReturnType<typeof buildApp>>["app"];
  /** GET and POST against one app, always with a host, so `Origin` can be judged. */
  function driver(app: App) {
    return {
      get: (url: string, extra: Record<string, string> = {}) =>
        app.inject({ method: "GET", url, headers: { host: HOST, ...extra } }),
      post: (url: string, payload: Record<string, unknown>, extra: Record<string, string> = {}) =>
        app.inject({ method: "POST", url, payload, headers: { host: HOST, ...extra } }),
    };
  }

  /** `Set-Cookie` as a list, whatever Node made of a repeated header. */
  const cookies = (raw: unknown): string[] =>
    Array.isArray(raw) ? raw.map(String) : raw === undefined ? [] : [String(raw)];
  const cookieNamed = (list: string[], name: string): string => list.find((c) => c.startsWith(`${name}=`)) ?? "";
  const cookieValue = (list: string[], name: string): string => {
    const one = cookieNamed(list, name);
    const eq = one.indexOf("=");
    return eq < 0 ? "" : (one.slice(eq + 1).split(";", 1)[0] ?? "");
  };
  /** The three headers that cost nothing and are therefore never conditional. */
  const hardened = (h: Record<string, unknown>): boolean =>
    h["x-content-type-options"] === "nosniff" &&
    h["referrer-policy"] === "same-origin" &&
    h["x-frame-options"] === "DENY";

  const COOKIE = "labview_session";

  // ---- enforcing: one passwd file with three users --------------------------------
  process.env.LABVIEW_AUTH_PASSWD_FILE = passwdOk;
  clearPasswdCache();
  const strict = await buildApp(loadConfig(), { now: () => T0 });
  const on = driver(strict.app);

  const anon = await on.get("/api/session");
  const anonInfo = anon.json() as SessionInfo;
  check(
    "a visitor with no cookie is told what to do: enforcement is on and a password is the way in",
    anon.statusCode === 200 && anonInfo.enforced && anonInfo.methods.join(",") === "passwd" && anonInfo.user === undefined,
    `${anon.statusCode} ${JSON.stringify(anonInfo)}`,
  );
  check(
    "...and told nothing else — no username, no count, no path to the file",
    !anon.body.includes("alice") && !anon.body.includes("passwd.ok") && !anon.body.includes("3"),
    anon.body,
  );

  const denied = await on.get("/api/overview");
  check(
    "the data is refused without a session, which is the whole point of the feature",
    denied.statusCode === 401 && denied.body === '{"error":"unauthorized"}',
    // Truncated on purpose: when this one goes red the body is a whole overview, and a
    // failing assertion should print what went wrong rather than the thing it leaked.
    `${denied.statusCode} ${denied.body.slice(0, 60)}`,
  );
  check(
    "...and that refusal is not cached by anything between here and the browser",
    denied.headers["cache-control"] === "no-store" && hardened(denied.headers),
    String(denied.headers["cache-control"]),
  );

  const health = await on.get("/api/healthz");
  check(
    "healthz stays open, so a container health check does not need a credential",
    health.statusCode === 200 && health.body === '{"ok":true}',
    `${health.statusCode} ${health.body}`,
  );

  const shell = await on.get("/");
  check(
    "the SPA shell is served without a session — it is what renders the login card",
    shell.statusCode === 200 && String(shell.headers["content-type"]).includes("text/html") && hardened(shell.headers),
    `${shell.statusCode} ${String(shell.headers["content-type"])}`,
  );
  // Whatever caching the static plugin asks for is left alone — asserted as "not
  // no-store" rather than as an exact value, because the shell is served by
  // `@fastify/static` when `web/dist` has been built and by a one-line fallback route
  // when it has not, and those two disagree about `Cache-Control` for good reasons of
  // their own. The rule here is only that the gate does not reach outside `/api`.
  check(
    "...and the gate does not mark it no-store: the shell carries nothing about the fleet, so it is the one thing worth caching",
    !String(shell.headers["cache-control"] ?? "").includes("no-store"),
    String(shell.headers["cache-control"]),
  );
  // Not asserted as a 200: `web/dist` is built by `npm run build:web` and CI runs this
  // suite without it. What matters is that the bundle is never the thing that 401s.
  const bundle = await on.get("/app.js");
  check("the bundle is never gated, however this suite was run", bundle.statusCode !== 401, String(bundle.statusCode));

  const unknownPath = await on.get("/api/nope");
  check(
    "an unrouted API path is refused before routing, so a 404 cannot be used to map the surface",
    unknownPath.statusCode === 401,
    String(unknownPath.statusCode),
  );

  const wrongPassword = await on.post("/api/login", { username: "carol", password: "not-carols" });
  const noSuchUser = await on.post("/api/login", { username: "nobody", password: "not-carols" });
  check(
    "a wrong password and a name that does not exist are the same 401, byte for byte",
    wrongPassword.statusCode === 401 && noSuchUser.statusCode === 401 && wrongPassword.body === noSuchUser.body,
    `${wrongPassword.statusCode} ${wrongPassword.body} / ${noSuchUser.statusCode} ${noSuchUser.body}`,
  );
  check("...and that one body says only which of the two things was wrong: neither", wrongPassword.body === '{"error":"credentials"}', wrongPassword.body);

  const signedIn = await on.post("/api/login", { username: "alice", password: "alice-secret" });
  const issued = cookies(signedIn.headers["set-cookie"]);
  const token = cookieValue(issued, COOKIE);
  check(
    "the right password signs in and says who signed in",
    signedIn.statusCode === 200 && signedIn.body === '{"ok":true,"user":{"name":"alice","via":"passwd"}}',
    `${signedIn.statusCode} ${signedIn.body}`,
  );
  check(
    "...on a cookie script cannot read, that a cross-site form cannot send, scoped to the whole app",
    cookieNamed(issued, COOKIE).includes("HttpOnly") &&
      cookieNamed(issued, COOKIE).includes("SameSite=Lax") &&
      cookieNamed(issued, COOKIE).includes("Path=/") &&
      cookieNamed(issued, COOKIE).includes("Max-Age=43200"),
    cookieNamed(issued, COOKIE),
  );
  check(
    "...and not marked Secure over plain http, because a Secure cookie there is never stored and the symptom is a login that silently loops",
    !cookieNamed(issued, COOKIE).includes("Secure") && token.startsWith("v1."),
    cookieNamed(issued, COOKIE),
  );

  const withCookie = { cookie: `${COOKIE}=${token}` };
  const allowed = await on.get("/api/overview", withCookie);
  check(
    "the same request with that cookie is answered",
    allowed.statusCode === 200 && Array.isArray((allowed.json() as Overview).stacks),
    String(allowed.statusCode),
  );
  const mine = (await on.get("/api/session", withCookie)).json() as SessionInfo;
  check("...and the session names the user and how they got here", mine.user?.name === "alice" && mine.user?.via === "passwd", JSON.stringify(mine));

  const tampered = await on.get("/api/overview", { cookie: `${COOKIE}=${token.split(".").slice(0, 2).join(".")}.${Buffer.from("not-the-mac").toString("base64url")}` });
  check("a cookie with a forged signature is no cookie at all", tampered.statusCode === 401, String(tampered.statusCode));

  const crossSite = await on.post("/api/login", { username: "alice", password: "alice-secret" }, { origin: "https://evil.example" });
  check(
    "a POST from another origin is refused before the credentials are even looked at",
    crossSite.statusCode === 403 && crossSite.body === '{"error":"forbidden"}',
    `${crossSite.statusCode} ${crossSite.body}`,
  );
  check("...and no session comes back from it, correct password or not", cookies(crossSite.headers["set-cookie"]).length === 0);
  const sameSite = await on.post("/api/login", { username: "alice", password: "alice-secret" }, { origin: `http://${HOST}` });
  check("...while this host's own form still works, which is the point of checking the host and not the header's presence", sameSite.statusCode === 200, String(sameSite.statusCode));

  const signedOut = await on.post("/api/logout", {}, withCookie);
  check(
    "signing out clears the cookie",
    signedOut.statusCode === 200 && cookieNamed(cookies(signedOut.headers["set-cookie"]), COOKIE).includes("Max-Age=0"),
    cookieNamed(cookies(signedOut.headers["set-cookie"]), COOKIE),
  );
  const revoked = await on.get("/api/overview", withCookie);
  check(
    "...and revokes it, so a copy taken before the sign-out is dead too — the token is still valid and still refused",
    revoked.statusCode === 401,
    String(revoked.statusCode),
  );

  const attempts: number[] = [];
  for (let i = 0; i < 6; i++) attempts.push((await on.post("/api/login", { username: "bob", password: "not-bobs" })).statusCode);
  check("five wrong passwords for one name are each answered", attempts.slice(0, 5).every((c) => c === 401), attempts.join(" "));
  check("...and the sixth is not answered at all", attempts[5] === 429, attempts.join(" "));
  const locked = await on.post("/api/login", { username: "bob", password: "bob-secret" });
  check(
    "the right password does not end a lockout, which is what stops the count being a way to test passwords",
    locked.statusCode === 429 && locked.body === '{"error":"throttled","retryAfterSeconds":60}',
    `${locked.statusCode} ${locked.body}`,
  );
  check("...and the wait is in a header a client can act on", locked.headers["retry-after"] === "60", String(locked.headers["retry-after"]));
  const capitalised = await on.post("/api/login", { username: "BOB", password: "bob-secret" });
  check("...and capitalising the name does not buy five more attempts", capitalised.statusCode === 429, String(capitalised.statusCode));
  const bystander = await on.post("/api/login", { username: "alice", password: "alice-secret" });
  check(
    "a lockout belongs to the username, not the caller — behind a tunnel and a proxy every request shares one address",
    bystander.statusCode === 200,
    String(bystander.statusCode),
  );

  // OIDC is not configured in this pass, so both halves of the flow must land on the
  // login card with a code it can render — never a stack trace, and never a 500.
  const oidcStart = await on.get("/auth/oidc/start");
  const oidcCallback = await on.get("/auth/oidc/callback?code=x&state=y");
  check(
    "a sign-in through a provider nobody configured redirects to the login card with a reason",
    oidcStart.statusCode === 302 &&
      oidcStart.headers.location === "/?login_error=method-unavailable" &&
      oidcCallback.statusCode === 302 &&
      oidcCallback.headers.location === "/?login_error=method-unavailable",
    `${oidcStart.statusCode} ${String(oidcStart.headers.location)} / ${oidcCallback.statusCode} ${String(oidcCallback.headers.location)}`,
  );

  await strict.app.close();

  // ---- open: a passwd file with nothing usable in it ------------------------------
  //
  // The regression this pass exists to catch is the worst one this feature could ship: an
  // operator who pulls a new image and finds a login screen nobody has a password for.
  process.env.LABVIEW_AUTH_PASSWD_FILE = passwdEmpty;
  clearPasswdCache();
  const open = await buildApp(loadConfig(), { now: () => T0 });
  const off = driver(open.app);

  const openSession = (await off.get("/api/session")).json() as SessionInfo;
  check(
    "a file with no usable entry enforces nothing and offers no method",
    openSession.enforced === false && openSession.methods.length === 0,
    JSON.stringify(openSession),
  );
  const openData = await off.get("/api/overview");
  check(
    "the overview is served to a caller with no cookie, exactly as it was before this feature existed",
    openData.statusCode === 200 && Array.isArray((openData.json() as Overview).stacks),
    String(openData.statusCode),
  );
  check(
    "...uncached only in the sense that it is not marked no-store, while the free headers stay on",
    openData.headers["cache-control"] === undefined && hardened(openData.headers),
    String(openData.headers["cache-control"]),
  );
  const openLogin = await off.post("/api/login", { username: "alice", password: "alice-secret" });
  check(
    "signing in is refused as unavailable rather than accepted against a file with no users",
    openLogin.statusCode === 400 && openLogin.body === '{"error":"method-unavailable"}',
    `${openLogin.statusCode} ${openLogin.body}`,
  );
  const openCrossSite = await off.post("/api/login", { username: "alice", password: "alice-secret" }, { origin: "https://evil.example" });
  check(
    "the CSRF check applies only while there is a session to forge, so an open LabView is not made stricter than it was",
    openCrossSite.statusCode === 400,
    String(openCrossSite.statusCode),
  );
  const openMissing = await off.get("/api/nope");
  check("an unknown API path is a 404 again once nothing is enforced", openMissing.statusCode === 404, String(openMissing.statusCode));

  await open.app.close();

  delete process.env.LABVIEW_AUTH_PASSWD_FILE;
  clearPasswdCache();
  if (priorLogLevel === undefined) delete process.env.LABVIEW_LOG_LEVEL;
  else process.env.LABVIEW_LOG_LEVEL = priorLogLevel;
}

console.log(`\n${failures === 0 ? "PASS" : "FAIL"} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
