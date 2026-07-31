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

const here = dirname(fileURLToPath(import.meta.url));
// dist/server -> project root -> web/dist
const webRoot = join(here, "..", "..", "web", "dist");

interface Cache {
  overview: Overview | null;
  builtAt: number;
  inflight: Promise<Overview> | null;
}

export async function startServer(cfg: LabViewConfig): Promise<void> {
  const app = Fastify({ logger: { level: process.env.LABVIEW_LOG_LEVEL ?? "info" } });
  const cache: Cache = { overview: null, builtAt: 0, inflight: null };
  // What each target's last logged outcome was. A long-running server rescans on a
  // timer and on demand, so repeating identical connection lines every time would bury
  // the one that changed — which is the only one worth a reader's attention.
  const lastConnections = new Map<string, string>();

  async function getOverview(force: boolean): Promise<Overview> {
    const ageMs = Date.now() - cache.builtAt;
    const fresh = cache.overview && !force && ageMs < cfg.cacheTtlSeconds * 1000;
    if (fresh) return cache.overview!;
    if (cache.inflight) return cache.inflight;

    cache.inflight = buildOverview(cfg, new Date())
      .then((ov) => {
        cache.overview = ov;
        cache.builtAt = Date.now();
        logConnections(app.log, lastConnections, ov.meta.connections);
        return ov;
      })
      .finally(() => {
        cache.inflight = null;
      });
    return cache.inflight;
  }

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
