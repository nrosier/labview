import type { ProbeReport, ProbeReportEntry } from "../model";
import { probeFormText, probeReasonText, probeReportSummaryText, probeVantageText } from "../model";
import { ProbeResult } from "./badges";
import { Panel } from "./Panel";
import { Section } from "./Section";

/**
 * What the active probe asked, what came back, and why each answer was or was not read as a
 * login page.
 *
 * `Login probe 12 · 8 gated · 4 open` states an outcome and hides every case behind it. The
 * cases were already collected — one `ServiceProbe` per service asked — but until now they
 * were reachable only by opening one drawer after another, which is exactly the search a
 * reader has to make when the count is not the one they expected.
 *
 * Nothing is re-worded here and nothing is decided here. `collectProbeReport` groups and
 * counts (in `model/probe.ts`, where it can be asserted), `probeOutcome` and
 * `probeReasonText` own what a result says, and every row is rendered from the same
 * functions the service drawer renders it from — so following a row through to its drawer
 * reads as the same result rather than a second account of it.
 *
 * **What cleared nothing leads.** The services that answered without a login page come first,
 * because asking them withdrew no finding and they are the reason to open this panel at all;
 * the gated ones are the half that did withdraw one, and they come second. The services that
 * did not answer come last and are neither: nothing was measured about them, and the section
 * says so in those words rather than leaving a reader to infer that silence meant no login
 * page.
 *
 * No section is tinted by severity. `probeOutcome` already decides which pill is critical,
 * and it is the only thing here entitled to — a row in the first section is not by itself an
 * exposure, since a service behind a detected gate that answered LabView from inside the fleet
 * lands there too.
 */
export function ProbeDetail({
  report,
  onClose,
  onOpenService,
}: {
  report: ProbeReport;
  onClose: () => void;
  onOpenService: (stackId: string, serviceName: string) => void;
}) {
  return (
    <Panel title="Login probe" sub={probeReportSummaryText(report)} onClose={onClose}>
      {/* Which direction the error runs in, before any of the results. A reader who takes a
          gate for proof of protection would read the first section as a to-do list and the
          second as a job finished, and it is the other way round: a signal that fired is a
          fact about one response, and a signal that did not fire is not a fact about
          anything. Said once here rather than repeated per row. */}
      <div class="note">
        Each service whose own labels showed an HTTP address was asked once, at{" "}
        <span class="mono">/</span>, with no credential and without following redirects. A login
        page answering is evidence and takes the service out of the exposed count; anything the
        rule does not recognise withdraws nothing, so a service listed as answering with no
        login page may still have one LabView cannot see — and may equally be one whose gate is
        already detected, since the request can go around the edge that gates real visitors.
        Each row gives the address tried, what came back and the fact the verdict rested on.
      </div>

      {report.probed === 0 ? (
        /* Reachable only by a payload that arrived while the panel was open — the tile that
           opens it is not drawn for a scan that probed nothing. A blank body would read as a
           panel that failed to load. */
        <div class="note">This scan asked no service, so there is nothing to report.</div>
      ) : (
        <>
          {report.open.length > 0 && (
            <Section title={`Answered with no login page — ${count(report.open.length)}`}>
              {report.open.map((e) => (
                <ProbeRow key={rowKey(e)} entry={e} onOpenService={onOpenService} />
              ))}
            </Section>
          )}
          {report.gated.length > 0 && (
            <Section title={`Answered with a login page — ${count(report.gated.length)}`}>
              {report.gated.map((e) => (
                <ProbeRow key={rowKey(e)} entry={e} onOpenService={onOpenService} />
              ))}
            </Section>
          )}
          {report.silent.length > 0 && (
            <Section title={`Did not answer — ${count(report.silent.length)}`}>
              {/* Its own sentence, because this section is the one a reader is most likely to
                  misread: an address that never answered measured nothing, and these services
                  are classified exactly as they were before the probe ran. */}
              <div class="note">
                Nothing arrived from these addresses, so the probe added nothing either way —
                their posture is whatever the configuration alone says it is. Every address
                tried is listed under each one.
              </div>
              {report.silent.map((e) => (
                <ProbeRow key={rowKey(e)} entry={e} onOpenService={onOpenService} />
              ))}
            </Section>
          )}
        </>
      )}
    </Panel>
  );
}

/**
 * One probed service: who it is, where it was asked, what came back, and why that was read
 * the way it was.
 *
 * The same four lines in every section, in the same order, whatever the outcome — the row is
 * a record of one exchange and it does not restate the section it is filed under. Severity is
 * the `ProbeResult` pill's alone, from `probeOutcome`.
 */
function ProbeRow({
  entry,
  onOpenService,
}: {
  entry: ProbeReportEntry;
  onOpenService: (stackId: string, serviceName: string) => void;
}) {
  const probe = entry.probe;
  return (
    <div class="proberow">
      <div class="probehead">
        {/* Straight to the service's own drawer, where this result is shown beside the
            evidence every other source produced for the same service — which is the context
            that decides whether an answer with no login page matters. */}
        <button class="linkbtn" onClick={() => onOpenService(entry.stackId, entry.service)}>
          {entry.stackName} / {entry.service}
        </button>
        <ProbeResult probe={probe} />
      </div>
      {/* The address, and what asking at *that* address was worth — a public hostname
          answering means something a published host port answering does not. */}
      <div class="muted-inline">
        <span class="mono">{probe.endpoint}</span> · {probeVantageText(probe.vantage)}
      </div>
      {probe.form && <div class="muted-inline">{probeFormText(probe.form)}</div>}
      <div class="probereason">{probeReasonText(probe)}</div>
      {/* Only where nothing answered, matching the drawer: on a success the earlier
          candidates are addresses that lost a race, and listing them would read as
          problems. */}
      {probe.phase !== "connected" && probe.attempts.length > 1 && (
        <ul class="evidence">
          {probe.attempts.map((a) => (
            <li class="mono">
              {a.endpoint}: {a.phase} — {a.detail}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** `1 service` / `4 services`, for a section heading. */
function count(n: number): string {
  return `${n} service${n === 1 ? "" : "s"}`;
}

/**
 * A key that is unique across the fleet, not just within a stack.
 *
 * `${stackId}/${service}` is the same key the payload uses for a service reference, so two
 * services with the same name in different stacks stay two rows.
 */
function rowKey(entry: ProbeReportEntry): string {
  return `${entry.stackId}/${entry.service}`;
}
