import Fastify, { type FastifyBaseLogger, type FastifyInstance } from "fastify";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import { retiredSettings, withProbeEnabled, type LabViewConfig } from "../config.js";
import type { ConnectionReport, Overview, ScanRequest } from "../model/types.js";
import { buildOverview } from "../analyze/index.js";
import {
  changedConnections,
  formatConnection,
  levelFor,
  rememberConnections,
} from "../model/connections.js";
import { diffIntegrations, diffStacks, formatRescan, formatScanTotals } from "../model/changes.js";
import { createScanCache } from "./cache.js";
import { registerAccessControl, type AccessControlOptions } from "./auth.js";

const here = dirname(fileURLToPath(import.meta.url));
// dist/server -> project root -> web/dist
const webRoot = join(here, "..", "..", "web", "dist");

/**
 * The whole application, wired but not listening.
 *
 * Separate from {@link startServer} so the gate can be driven with `app.inject()`: a
 * hook that forgets to reply, or an allowlist that accidentally admits
 * `/api/overview`, is invisible to a unit test and is exactly the kind of thing that
 * regresses quietly. Everything else about the two paths is identical — there is no
 * "test mode" branch anywhere below.
 */
export async function buildApp(cfg: LabViewConfig, access: AccessControlOptions = {}): Promise<BuiltApp> {
  const app = Fastify({ logger: { level: process.env.LABVIEW_LOG_LEVEL ?? "info" } });

  // First of all, because a retired setting is most often a credential something below
  // needs, and "the gate is open" or "authentik is not configured" are both easier to read
  // once you know a value LabView used to pick up is now being ignored.
  for (const line of retiredSettings(cfg)) app.log.warn(`config: ${line}`);

  // Before the API routes, so the hooks it installs apply to them, and before the
  // scanning line, so the startup block opens with who may read this LabView.
  registerAccessControl(app, cfg, access);

  // What each target's last logged outcome was. A long-running server rescans on a
  // timer and on demand, so repeating identical connection lines every time would bury
  // the one that changed — which is the only one worth a reader's attention.
  const lastConnections = new Map<string, string>();

  const cache = createScanCache<Overview, ScanRequest>({
    build: async (req) => {
      const overview = await buildOverview(
        // A clone with `probe.enabled` replaced, never an edit to `cfg`: the next timer
        // rebuild has to see the operator's value again, and a build already in flight is
        // still reading this object.
        req.probe === undefined ? cfg : withProbeEnabled(cfg, req.probe),
        new Date(),
      );
      // `buildOverview` can only report `config` — a rewritten config is indistinguishable
      // from one off disk once it is in there. This closure is the only place that knows a
      // caller asked, so it is the only place that may say so.
      if (req.probe !== undefined) overview.meta.probe.source = "request";
      return overview;
    },
    ttlMs: cfg.cacheTtlSeconds * 1000,
    onBuilt: (next, prev, { forced }) => {
      logConnections(app.log, lastConnections, next.meta.connections);
      logScan(app.log, cfg.appsRoot, next, prev, forced);
    },
  });
  const getOverview = (force: boolean, req: ScanRequest = {}) => cache.get(force, req);

  // A page load never carries a request: reading the dashboard must not be able to change
  // what the next scan does, and a TTL rebuild it happens to trigger is configuration's.
  app.get("/api/overview", async () => getOverview(false));
  app.post("/api/rescan", async (request) => getOverview(true, readScanRequest(request.body)));
  app.get("/api/healthz", async () => ({ ok: true }));

  // Serve the built web UI when present; otherwise a helpful message.
  if (existsSync(webRoot)) {
    await app.register(fastifyStatic, { root: webRoot, prefix: "/" });
    app.setNotFoundHandler((req, reply) => {
      if (req.url.startsWith("/api/")) {
        reply.code(404).send({ error: "not found" });
        return;
      }
      reply.type("text/html").sendFile("index.html");
    });
  } else {
    app.get("/", async (_req, reply) => {
      reply.type("text/html").send(
        "<h1>LabView</h1><p>Web UI not built. Run <code>npm run build:web</code>. API is at <code>/api/overview</code>.</p>",
      );
    });
  }

  return { app, scan: getOverview };
}

/**
 * The application and the handle that starts a scan.
 *
 * `scan` is returned rather than run by `buildApp` because building the app must not
 * touch the filesystem or the Docker socket: a test that injects one request would
 * otherwise start a real scan of whatever `appsRoot` points at.
 */
export interface BuiltApp {
  app: FastifyInstance;
  scan: (force: boolean, req?: ScanRequest) => Promise<Overview>;
}

/**
 * What a `POST /api/rescan` body asked for, ignoring everything it is not.
 *
 * The only place in LabView where a request decides anything, so it is read the way every
 * other untrusted document here is read: one known key, one known type, and no attempt to
 * interpret the rest. A missing body, an array, a string, `{"probe":"yes"}` and
 * `{"probe":1}` all come back empty — which means *use configuration*, the behaviour every
 * client had before the body existed.
 *
 * Ignoring rather than rejecting is the same choice `parseSidecar` makes about a key it
 * does not know: a 400 would break a client for sending a field a future version might
 * add, and there is nothing here worth failing a scan over (**I4**).
 */
function readScanRequest(body: unknown): ScanRequest {
  if (!body || typeof body !== "object" || Array.isArray(body)) return {};
  const probe = (body as Record<string, unknown>).probe;
  return typeof probe === "boolean" ? { probe } : {};
}

export async function startServer(cfg: LabViewConfig): Promise<void> {
  const { app, scan } = await buildApp(cfg);

  // Said before the scan starts rather than after the listener is up, so the connection
  // lines the scan produces read as its result instead of arriving before it is announced.
  app.log.info(`LabView scanning ${cfg.appsRoot}`);

  // Warm the cache in the background so the first page load is instant.
  scan(true).catch((err) => app.log.error(err, "initial scan failed"));

  await app.listen({ host: cfg.server.host, port: cfg.server.port });
}

/**
 * Log every connection whose outcome differs from the last scan.
 *
 * The first scan reports all of them, because nothing has been seen yet — so a startup
 * block says what LabView reached and what it could not, in one place. Afterwards only
 * a change speaks: an endpoint that recovers, or one that starts failing, and at which
 * stage. Levels come from `levelFor`, so an integration nobody switched on stays at
 * `debug` and never looks like a fault.
 */
function logConnections(
  log: FastifyBaseLogger,
  seen: Map<string, string>,
  reports: ConnectionReport[],
): void {
  for (const r of changedConnections(seen, reports)) {
    const level = levelFor(r);
    for (const line of formatConnection(r)) {
      if (level === "warn") log.warn(line);
      else if (level === "debug") log.debug(line);
      else log.info(line);
    }
  }
  rememberConnections(seen, reports);
}

/**
 * Say what this scan read, so a rescan is never silent about its result.
 *
 * The first build states the baseline — how many stacks and services came out of the
 * root — because a startup block that says only "scanning <root>" leaves the operator
 * without the one number that proves the root was the right one.
 *
 * Afterwards two comparisons, side by side: what changed in the parsed configuration, and
 * what the Authentik and Traefik reads came back with. A rescan re-runs both exchanges, so
 * reporting only the first left an application count going 18 → 40 with no line anywhere.
 *
 * The cadence rule itself lives in {@link formatRescan}, where it can be asserted: a change
 * on either side always speaks, a rescan somebody asked for answers even when the answer is
 * "nothing moved", and only a timer rebuild that found nothing at all stays quiet — that
 * one is LabView talking to itself.
 */
function logScan(
  log: FastifyBaseLogger,
  appsRoot: string,
  next: Overview,
  prev: Overview | undefined,
  forced: boolean,
): void {
  if (!prev) {
    log.info(formatScanTotals(appsRoot, next.stacks));
    return;
  }
  const config = diffStacks(prev.stacks, next.stacks);
  const integrations = diffIntegrations(prev, next);
  for (const line of formatRescan(appsRoot, config, integrations, forced)) log.info(line);
}
