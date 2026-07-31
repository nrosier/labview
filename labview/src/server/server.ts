import Fastify, { type FastifyBaseLogger } from "fastify";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import type { LabViewConfig } from "../config.js";
import type { ConnectionReport, Overview } from "../model/types.js";
import { buildOverview } from "../analyze/index.js";
import {
  changedConnections,
  formatConnection,
  levelFor,
  rememberConnections,
} from "../model/connections.js";
import { diffStacks, formatScanDiff, formatScanTotals } from "../model/changes.js";
import { createScanCache } from "./cache.js";

const here = dirname(fileURLToPath(import.meta.url));
// dist/server -> project root -> web/dist
const webRoot = join(here, "..", "..", "web", "dist");

export async function startServer(cfg: LabViewConfig): Promise<void> {
  const app = Fastify({ logger: { level: process.env.LABVIEW_LOG_LEVEL ?? "info" } });
  // What each target's last logged outcome was. A long-running server rescans on a
  // timer and on demand, so repeating identical connection lines every time would bury
  // the one that changed — which is the only one worth a reader's attention.
  const lastConnections = new Map<string, string>();

  const cache = createScanCache<Overview>({
    build: () => buildOverview(cfg, new Date()),
    ttlMs: cfg.cacheTtlSeconds * 1000,
    onBuilt: (next, prev, { forced }) => {
      logConnections(app.log, lastConnections, next.meta.connections);
      logScan(app.log, cfg.appsRoot, next, prev, forced);
    },
  });
  const getOverview = (force: boolean) => cache.get(force);

  app.get("/api/overview", async () => getOverview(false));
  app.post("/api/rescan", async () => getOverview(true));
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

  // Said before the scan starts rather than after the listener is up, so the connection
  // lines the scan produces read as its result instead of arriving before it is announced.
  app.log.info(`LabView scanning ${cfg.appsRoot}`);

  // Warm the cache in the background so the first page load is instant.
  getOverview(true).catch((err) => app.log.error(err, "initial scan failed"));

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
 * Afterwards the same cadence rule as the connection lines: a change always speaks, and
 * a rescan somebody asked for answers even when the answer is "nothing moved". Only a
 * timer rebuild that found nothing stays quiet — that one is LabView talking to itself.
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
  const diff = diffStacks(prev.stacks, next.stacks);
  if (diff.unchanged && !forced) return;
  for (const line of formatScanDiff(appsRoot, diff)) log.info(line);
}
