/**
 * CLI: scan once and print the Overview as JSON.
 *   LABVIEW_APPS_ROOT=./fixtures/apps npm run scan
 *   npm run scan -- --summary
 */
import { loadConfig } from "./config.js";
import { buildOverview } from "./analyze/index.js";
import { formatConnection } from "./model/connections.js";
import { formatExposureCount } from "./model/declarations.js";

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
  // The five ingress kinds, each counted independently. They **overlap** — a service
  // behind the tunnel and the proxy is in both counts — so the line does not sum to
  // `services` and says so rather than leaving a reader to add it up and doubt the
  // scan. Only `none` is exclusive, by definition.
  console.log(
    `  by ingress:       public ${stats.publicServices}, traefik ${stats.traefikServices},` +
      ` lan ${stats.lanServices}, internal ${stats.internalServices},` +
      ` none ${stats.noIngressServices}  (a service can have several)`,
  );
  console.log(`  auth protected:   ${stats.authProtected}`);
  // `23/28` — needing attention over found. The denominator is the scan's count,
  // unaltered; the numerator drops the ones somebody declared intentional. Never
  // subtracted from the total — an accepted exposure is still reachable.
  console.log(
    `  EXPOSED, no auth: ${formatExposureCount(stats.exposedWithoutAuth, stats.exposureAccepted)}` +
      (stats.exposureAccepted > 0 ? `  (${stats.exposureAccepted} accepted in a sidecar)` : ""),
  );
  console.log(`  by auth method:   ${JSON.stringify(stats.byAuthMethod)}`);
  // Silent for a fleet with no sidecar, which is most of them — and the drift line is
  // the one worth printing loudly, since a stale declaration is the failure mode a
  // sidecar actually has.
  if (stats.declaredAuth > 0) {
    console.log(`  declared auth:    ${stats.declaredAuth}  (stated in a sidecar, not detected)`);
  }
  // The services kept out of the exposure count by a declaration. Printed separately
  // from `auth protected` above, which counts only what the scan could prove.
  if (stats.declaredAuthProtected > 0) {
    console.log(
      `  declared-protected: ${stats.declaredAuthProtected}  (reachable, no detected auth, declared self-authenticating — unverified)`,
    );
  }
  if (stats.declarationDrift > 0) {
    console.log(`  ! declaration drift: ${stats.declarationDrift} service(s) disagree with their sidecar`);
  }
  for (const w of meta.warnings) console.log(`  ! ${w}`);
} else {
  console.log(JSON.stringify(overview, null, 2));
}
