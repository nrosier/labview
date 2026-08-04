import type { ComponentChildren } from "preact";
import type { DeclarationNoteReport } from "../model";
import { driftSummaryText, unconfirmedSummaryText } from "../model";
import { Panel } from "./Panel";
import { Section } from "./Section";

/**
 * What the sidecars and the scan had to say about each other, in two variants.
 *
 * `Declaration drift 3` states an outcome and hides the case behind it — which file, about
 * which service, and in which direction — and the answer is already written: the analyzer
 * puts one sentence in `svc.declared.drift` per disagreement, in the operator's own terms.
 * This panel is those sentences, gathered under the stack they belong to, so finding them
 * no longer means opening one service drawer after another.
 *
 * Nothing is re-worded here and nothing is decided here. `collectDeclarationNotes` groups
 * and counts (in `model/declarations.ts`, where it can be asserted), the analyzer wrote the
 * text, and each entry is rendered in the same class the service drawer shows it in — so a
 * reader who follows a row through to its drawer reads the identical sentence rather than a
 * second version of it.
 *
 * **One component and two variants, rather than two components.** The layout, the grouping
 * and the route into a drawer are the same question asked of two fields, and a second copy
 * would be a second place for them to fall out of step. A `variant` union rather than a
 * handful of optional strings for the same reason the mechanism vocabulary is a union: the
 * wording of each variant is decided in one table below, so there is no way to render
 * drift's alarming intro over a list of open questions.
 */
export type DriftDetailVariant = "drift" | "unconfirmed";

interface VariantWording {
  title: string;
  summary: (report: DeclarationNoteReport) => string;
  /** Singular; the section heading adds the plural `s`. */
  noun: string;
  /** What the panel says when the list is empty. */
  empty: string;
  /**
   * The class each entry is rendered in, and the one visual difference between the two
   * variants that carries meaning: `crit` says *something here is wrong*, which is true of a
   * disagreement and false of a question the scan could not settle. It matches what
   * `AppDetail` uses for the same field, so the drawer and the panel agree.
   */
  entryClass: string;
  intro: ComponentChildren;
}

const WORDING: Record<DriftDetailVariant, VariantWording> = {
  drift: {
    title: "Declaration drift",
    summary: driftSummaryText,
    noun: "disagreement",
    empty: "No declaration disagrees with this scan.",
    entryClass: "note crit",
    /* What the panel is, before the list of what is wrong in it. A declaration is the one
       input to a scan that can go stale in silence, so every checkable field is re-checked on
       every scan — and the check never changes the verdict. Said here because a reader who
       takes drift for a downgrade would read every entry below as a service whose
       classification is in doubt, which is exactly what it is not. */
    intro: (
      <>
        Every checkable field of a <span class="mono">.labview</span> file is compared against
        this scan, and each disagreement is listed below in the words of the file it came from.
        The classification always stands: drift is a report, never an override — the scan's
        verdict for these services is the one shown everywhere else in LabView.
      </>
    ),
  },
  unconfirmed: {
    title: "Declared, not confirmed",
    summary: unconfirmedSummaryText,
    noun: "unconfirmed declaration",
    empty: "Every declaration this scan asked about was answered.",
    entryClass: "note",
    /* The intro that has to do the most work in the panel, because the list looks exactly
       like the drift list and means the opposite. Naming the confounders is what makes the
       difference readable: absence of a login page is a fact about one request, not about the
       service, and a reader who is not told that will read this as drift by another name. */
    intro: (
      <>
        Each of these services declares that it authenticates itself, and the login probe
        requested one address for it and got no login page back. That is not a disagreement:
        a login one route deeper, a sign-in screen the browser draws after the page loads, or
        a mechanism that does not sit in front of that address all answer exactly this way.
        Every declaration below still stands and still holds its service out of the exposed
        count — this is the list worth checking by hand, not a list of things that are wrong.
      </>
    ),
  },
};

export function DriftDetail({
  report,
  variant = "drift",
  onClose,
  onOpenService,
}: {
  report: DeclarationNoteReport;
  /** Defaults to `drift`, which is what this panel was built for and what most callers mean. */
  variant?: DriftDetailVariant;
  onClose: () => void;
  onOpenService: (stackId: string, serviceName: string) => void;
}) {
  const w = WORDING[variant];
  const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? "" : "s"}`;
  return (
    <Panel title={w.title} sub={w.summary(report)} onClose={onClose}>
      <div class="note">{w.intro}</div>

      {report.stacks.length === 0 ? (
        /* Reachable only by a fleet whose last entry was resolved while the panel was open.
           A blank body would read as a panel that failed to load. */
        <div class="note">{w.empty}</div>
      ) : (
        report.stacks.map((stack) => (
          <Section
            key={stack.stackId}
            title={`${stack.stackName} — ${plural(stack.services.length, "service")}, ${plural(stack.entries, w.noun)}`}
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
                  <div class={w.entryClass}>{entry}</div>
                ))}
              </div>
            ))}
          </Section>
        ))
      )}

      {/* Drift only, because the filter is drift only: `ViewState.driftOnly` has no
          counterpart for unconfirmed declarations, and pointing a reader at a control that
          is not there would be worse than pointing at nothing. */}
      {variant === "drift" && report.stacks.length > 0 && (
        <div class="driftnote">
          The <span class="mono">⚠ Declaration drift</span> filter above the stack list holds
          the same {report.services === 1 ? "service" : "services"}, in place, with everything
          else the scan says about {report.services === 1 ? "it" : "them"}.
        </div>
      )}
    </Panel>
  );
}
