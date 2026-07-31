/**
 * CLI: scan once and print the Overview as JSON.
 *   FLEETVIEW_APPS_ROOT=./fixtures/apps npm run scan
 *   npm run scan -- --summary
 */
import { loadConfig } from "./config.js";
import { buildOverview } from "./analyze/index.js";

const cfg = loadConfig();
const summary = process.argv.includes("--summary");

const overview = await buildOverview(cfg, new Date());

if (summary) {
  const { stats, meta } = overview;
  console.log(`FleetView scan @ ${meta.scannedAt} (${meta.durationMs}ms)`);
  console.log(`  apps root:        ${meta.appsRoot}`);
  console.log(`  docker:           ${meta.dockerAvailable ? "available" : `unavailable (${meta.dockerError})`}`);
  console.log(`  stacks/services:  ${stats.stacks}/${stats.services}  (running: ${stats.running})`);
  console.log(`  public/local/int: ${stats.publicServices}/${stats.localOnlyServices}/${stats.internalServices}`);
  console.log(`  auth protected:   ${stats.authProtected}`);
  console.log(`  EXPOSED, no auth: ${stats.exposedWithoutAuth}`);
  console.log(`  by auth method:   ${JSON.stringify(stats.byAuthMethod)}`);
  for (const w of meta.warnings) console.log(`  ! ${w}`);
} else {
  console.log(JSON.stringify(overview, null, 2));
}
