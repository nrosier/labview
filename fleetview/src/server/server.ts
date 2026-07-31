import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import type { FleetViewConfig } from "../config.js";
import type { Overview } from "../model/types.js";
import { buildOverview } from "../analyze/index.js";

const here = dirname(fileURLToPath(import.meta.url));
// dist/server -> project root -> web/dist
const webRoot = join(here, "..", "..", "web", "dist");

interface Cache {
  overview: Overview | null;
  builtAt: number;
  inflight: Promise<Overview> | null;
}

export async function startServer(cfg: FleetViewConfig): Promise<void> {
  const app = Fastify({ logger: { level: process.env.FLEETVIEW_LOG_LEVEL ?? "info" } });
  const cache: Cache = { overview: null, builtAt: 0, inflight: null };

  async function getOverview(force: boolean): Promise<Overview> {
    const ageMs = Date.now() - cache.builtAt;
    const fresh = cache.overview && !force && ageMs < cfg.cacheTtlSeconds * 1000;
    if (fresh) return cache.overview!;
    if (cache.inflight) return cache.inflight;

    cache.inflight = buildOverview(cfg, new Date())
      .then((ov) => {
        cache.overview = ov;
        cache.builtAt = Date.now();
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
        "<h1>FleetView</h1><p>Web UI not built. Run <code>npm run build:web</code>. API is at <code>/api/overview</code>.</p>",
      );
    });
  }

  // Warm the cache in the background so the first page load is instant.
  getOverview(true).catch((err) => app.log.error(err, "initial scan failed"));

  await app.listen({ host: cfg.server.host, port: cfg.server.port });
  app.log.info(`FleetView scanning ${cfg.appsRoot}`);
}
