import { loadConfig } from "./config.js";
import { startServer } from "./server/server.js";

const cfg = loadConfig();
startServer(cfg).catch((err) => {
  console.error("[labview] failed to start:", err);
  process.exit(1);
});
