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
  console.log(
    `  public/local/int: ${stats.publicServices}/${stats.localOnlyServices}/${stats.internalServices}` +
      `  (host-port only: ${stats.hostPortServices})`,
  );
  console.log(`  auth protected:   ${stats.authProtected}`);
  console.log(`  EXPOSED, no auth: ${stats.exposedWithoutAuth}`);
  console.log(`  by auth method:   ${JSON.stringify(stats.byAuthMethod)}`);
  for (const w of meta.warnings) console.log(`  ! ${w}`);
} else {
  console.log(JSON.stringify(overview, null, 2));
}
