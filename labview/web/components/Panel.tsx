/**
 * The drawer shell every side panel uses.
 *
 * The same markup as the service drawer — a `.drawer-scrim` under a `.drawer`, a sticky
 * `.dhead`, a scrolling `.dbody` — so a panel inherits its scroll behaviour, its close
 * affordance and the Escape handling in `App` without a second set of rules to keep in
 * step with the first.
 *
 * Its own module, like {@link Section}, because three panels now share it: the two
 * integration panels and the declaration-drift panel. A shell that stayed private to the
 * first of them would be copied into the next one, and the copy is what drifts.
 *
 * `useModal` supplies the rest of the dialog contract — focus in, focus trapped, focus
 * returned, page behind locked — which is the same for every panel and so belongs here
 * rather than in each of them.
 */
import { useModal } from "../lib/modal";

export function Panel({
  title,
  sub,
  onClose,
  children,
}: {
  title: string;
  sub: string;
  onClose: () => void;
  children: preact.ComponentChildren;
}) {
  const ref = useModal<HTMLElement>();
  return (
    <>
      <div class="drawer-scrim" onClick={onClose} />
      {/* `aria-modal` is what tells a screen reader the page behind this is unavailable —
          `role="dialog"` alone does not, and the scrim only says it visually. `tabIndex={-1}`
          makes the panel a focus target without making it a tab stop, for the case where its
          body is all text. */}
      <aside
        ref={ref}
        class="drawer"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        aria-label={`${title} detail`}
      >
        <div class="dhead">
          <div class="title">
            <h2>{title}</h2>
            <div class="sub">{sub}</div>
          </div>
          <button class="btn icon" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <div class="dbody">{children}</div>
      </aside>
    </>
  );
}
