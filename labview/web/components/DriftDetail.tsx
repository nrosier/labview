import type { DeclarationDriftReport } from "../model";
import { driftSummaryText } from "../model";
import { Panel } from "./Panel";
import { Section } from "./Section";

/**
 * Which sidecars disagree with the scan, and what each disagreement says.
 *
 * `Declaration drift 3` states an outcome and hides the case behind it — which file, about
 * which service, and in which direction — and the answer is already written: the analyzer
 * puts one sentence in `svc.declared.drift` per disagreement, in the operator's own terms.
 * This panel is those sentences, gathered under the stack they belong to, so finding them
 * no longer means opening one service drawer after another.
 *
 * Nothing is re-worded here and nothing is decided here. `collectDeclarationDrift` groups
 * and counts (in `model/declarations.ts`, where it can be asserted), the analyzer wrote the
 * text, and each entry is rendered in the same `.note crit` the service drawer shows it in —
 * so a reader who follows a row through to its drawer reads the identical sentence rather
 * than a second version of it.
 */
export function DriftDetail({
  report,
  onClose,
  onOpenService,
}: {
  report: DeclarationDriftReport;
  onClose: () => void;
  onOpenService: (stackId: string, serviceName: string) => void;
}) {
  return (
    <Panel title="Declaration drift" sub={driftSummaryText(report)} onClose={onClose}>
      {/* What the panel is, before the list of what is wrong in it. A declaration is the
          one input to a scan that can go stale in silence, so every checkable field is
          re-checked on every scan — and the check never changes the verdict. Said here
          because a reader who takes drift for a downgrade would read every entry below as
          a service whose classification is in doubt, which is exactly what it is not. */}
      <div class="note">
        Every checkable field of a <span class="mono">.labview</span> file is compared against
        this scan, and each disagreement is listed below in the words of the file it came from.
        The classification always stands: drift is a report, never an override — the scan's
        verdict for these services is the one shown everywhere else in LabView.
      </div>

      {report.stacks.length === 0 ? (
        /* Reachable only by a fleet whose last drift was fixed while the panel was open.
           A blank body would read as a panel that failed to load. */
        <div class="note">No declaration disagrees with this scan.</div>
      ) : (
        report.stacks.map((stack) => (
          <Section
            key={stack.stackId}
            title={`${stack.stackName} — ${stack.services.length} service${stack.services.length === 1 ? "" : "s"}, ${stack.entries} disagreement${stack.entries === 1 ? "" : "s"}`}
          >
            {stack.services.map((svc) => (
              <div key={svc.service} style="margin-bottom:14px;">
                <div style="display:flex;align-items:baseline;gap:6px;flex-wrap:wrap;">
                  {/* Straight to the service's own drawer, where the declaration these
                      entries are about is shown in full beside the evidence the scan
                      collected — which is the other half of every sentence below. */}
                  <button class="linkbtn" onClick={() => onOpenService(stack.stackId, svc.service)}>
                    {stack.stackName} / {svc.service}
                  </button>
                  {/* The file, named per service rather than per stack: two services in one
                      stack can be declared in different sidecars, and the reader's next
                      action is to open the one that is out of date. */}
                  <span class="pill mono" title="The file this declaration was read from">
                    {svc.file}
                  </span>
                </div>
                {svc.entries.map((entry) => (
                  <div class="note crit">{entry}</div>
                ))}
              </div>
            ))}
          </Section>
        ))
      )}

      {report.stacks.length > 0 && (
        <div class="driftnote">
          The <span class="mono">⚠ Declaration drift</span> filter above the stack list holds
          the same {report.services === 1 ? "service" : "services"}, in place, with everything
          else the scan says about {report.services === 1 ? "it" : "them"}.
        </div>
      )}
    </Panel>
  );
}
