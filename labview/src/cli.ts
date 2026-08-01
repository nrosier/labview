/**
 * CLI: scan once and print the Overview as JSON.
 *   LABVIEW_APPS_ROOT=./fixtures/apps npm run scan
 *   npm run scan -- --summary
 */
import { loadConfig } from "./config.js";
import { buildOverview } from "./analyze/index.js";
import { formatConnection } from "./model/connections.js";

const cfg = loadConfig();
const summary = process.argv.includes("--summary");

const overview = await buildOverview(cfg, new Date());

if (summary) {
  const { stats, meta } = overview;
  console.log(`LabView scan @ ${meta.scannedAt} (${meta.durationMs}ms)`);
  console.log(`  apps root:        ${meta.appsRoot}`);
  // Every target, including the ones nobody switched on: `--summary` is run on purpose,
  // usually to find out why something is missing, and "not reading authentik" is an
  // answer to that. The same formatter the server logs through, so the two agree.
  for (const r of meta.connections) {
    for (const line of formatConnection(r)) console.log(`  ${line}`);
  }
  console.log(`  stacks/services:  ${stats.stacks}/${stats.services}  (running: ${stats.running})`);
  // The four ingress situations, named rather than slash-packed: they are disjoint
  // and they sum to `services`, so a reader can check the line against itself.
  console.log(
    `  by ingress:       public ${stats.publicServices}, traefik ${stats.traefikServices},` +
      ` lan ${stats.lanServices}, internal ${stats.internalServices}`,
  );
  console.log(`  auth protected:   ${stats.authProtected}`);
  console.log(`  EXPOSED, no auth: ${stats.exposedWithoutAuth}`);
  console.log(`  by auth method:   ${JSON.stringify(stats.byAuthMethod)}`);
  for (const w of meta.warnings) console.log(`  ! ${w}`);
} else {
  console.log(JSON.stringify(overview, null, 2));
}
