/**
 * CLI: scan once and print the Overview as JSON.
 *   LABVIEW_APPS_ROOT=./fixtures/apps npm run scan
 *   npm run scan -- --summary
 */
import { loadConfig, retiredSettings } from "./config.js";
import { buildOverview } from "./analyze/index.js";
import { formatConnection } from "./model/connections.js";
import { formatExposureCount } from "./model/declarations.js";

const cfg = loadConfig();
// To stderr, and whether or not `--summary` was asked for. A setting LabView stopped
// reading is the one thing a reader cannot deduce from the output — the scan below simply
// looks like the integration was never configured. stderr rather than stdout so the JSON
// on the other stream stays parseable by whatever is piping it.
for (const line of retiredSettings(cfg)) console.error(`config: ${line}`);
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
  // What connects those services to each other. The two qualified counts are the ones
  // that carry information — a network with a single service on it joins nothing, and
  // most of a fleet's networks are exactly that — so the total is printed beside them
  // rather than alone, where it would read as 52 connections.
  const verb = (n: number, plural: string) => `${n} ${plural}${n === 1 ? "s" : ""}`;
  console.log(
    `  networks:         ${stats.networks}  (${verb(stats.connectingNetworks, "connect")} 2+ services,` +
      ` ${verb(stats.crossStackNetworks, "span")} 2+ stacks)`,
  );
  // The five ingress kinds, each counted independently. The first three **overlap** — a
  // service behind the tunnel and the proxy is in both counts — so the line does not sum
  // to `services` and says so rather than leaving a reader to add it up and doubt the
  // scan. `internal` and `none` are exclusive: both mean nothing outside reaches it.
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
  // A subset of the line above: the ones the probe went and asked about and came back from
  // no wiser. Deliberately without the `!` prefix, which the drift line and the warnings
  // below use — this is an open question, not a finding, and putting it in the alarm channel
  // is exactly what this field exists to stop.
  if (stats.declaredAuthUnconfirmed > 0) {
    console.log(
      `  unconfirmed:      ${stats.declaredAuthUnconfirmed}  (of those, probed and no login page seen — neither confirmed nor contradicted)`,
    );
  }
  // Dependencies a sidecar stated, which is the only way one can cross stacks. Counted,
  // never verified: the scan cannot see the relation, and says so by naming where it came
  // from. A reference that resolved to nothing is not here — it is drift, below.
  if (stats.declaredDependencies > 0) {
    console.log(
      `  declared deps:    ${stats.declaredDependencies}  (stated in a sidecar, drawn through the network they share)`,
    );
  }
  if (stats.declarationDrift > 0) {
    console.log(`  ! declaration drift: ${stats.declarationDrift} service(s) disagree with their sidecar`);
  }
  for (const w of meta.warnings) console.log(`  ! ${w}`);
} else {
  console.log(JSON.stringify(overview, null, 2));
}
