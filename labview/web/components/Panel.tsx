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
 */
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
  return (
    <>
      <div class="drawer-scrim" onClick={onClose} />
      <aside class="drawer" role="dialog" aria-label={`${title} detail`}>
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
