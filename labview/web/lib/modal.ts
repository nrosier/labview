/**
 * The parts of "this is a modal" that `role="dialog"` does not give you.
 *
 * Both drawers — the service detail and the four side panels — already declared themselves
 * dialogs and already closed on Escape (the key handler lives in `App`, so the layering
 * order is decided in one place). What neither had was the rest of the contract, and the
 * missing half is the half a keyboard reader notices: focus stayed on whatever opened the
 * drawer, so the first Tab went to the *next control on the page behind the scrim*; there
 * was nothing to stop tabbing straight out of the panel and into a list the scrim says is
 * unavailable; closing left focus wherever it had wandered to, which for a drawer opened
 * from a tile means back at the top of the document; and the page underneath kept
 * scrolling, so a trackpad flick moved the fleet behind the sheet the reader was reading.
 *
 * A hook rather than a component so both drawer shells can adopt it without either of them
 * changing shape — `Panel` wraps three panels and `AppDetail` is its own markup, and a
 * wrapper component would have had to own the `<aside>` for both.
 *
 * Escape is deliberately *not* handled here. `App` dismisses one layer at a time in a
 * defined order, and a second Escape listener per open dialog would race it.
 */
import { useEffect, useRef } from "preact/hooks";

/**
 * Everything focusable, in document order, that is not disabled or deliberately removed
 * from the tab order.
 *
 * `[tabindex]:not([tabindex="-1"])` rather than `[tabindex]` because the dialog container
 * itself carries `tabindex={-1}` — it is a focus *target*, so that it can be focused when
 * there is nothing inside it to focus, but never a tab stop.
 */
const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function focusable(root: HTMLElement): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
    // `offsetParent` is null for anything `display: none`, which is how a control inside a
    // collapsed section is skipped without this needing to know which sections collapse.
    (el) => el.offsetParent !== null || el === document.activeElement,
  );
}

/**
 * Make an element behave as a modal dialog for as long as it is mounted.
 *
 * Returns the ref to put on the dialog element, which must also carry `tabindex={-1}` and
 * `aria-modal="true"` — the attributes are left to the caller because they belong in the
 * markup where a reader of that component can see them.
 */
export function useModal<T extends HTMLElement>() {
  const ref = useRef<T>(null);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;

    // Captured before focus moves, so it is the control that opened this — a tile, a table
    // row, a link inside another panel — and not whatever ends up focused inside.
    const opener = document.activeElement as HTMLElement | null;

    // First control if there is one, the dialog itself otherwise: a drawer whose body is
    // all text still has to take focus, or the reader's next Tab starts from the page.
    const first = focusable(node)[0];
    (first ?? node).focus();

    /**
     * Scroll lock, with the width the scrollbar was taking put back as padding.
     *
     * Without the compensation, hiding the document's scrollbar widens the viewport by
     * ~15px and the entire page — including the drawer's own left edge — jumps sideways as
     * it opens. Read from `window.innerWidth` rather than assumed, because an overlay
     * scrollbar (every touch device, and macOS by default) takes no width at all and the
     * padding must then be zero.
     */
    const body = document.body;
    const prevOverflow = body.style.overflow;
    const prevPadding = body.style.paddingRight;
    const gap = window.innerWidth - document.documentElement.clientWidth;
    body.style.overflow = "hidden";
    if (gap > 0) body.style.paddingRight = `${gap}px`;

    /**
     * Keep Tab inside. Wrapping at both ends rather than only at the last element, because
     * Shift+Tab from the first control is the same escape in the other direction and is the
     * one people actually hit — it is how you get back to a Close button.
     */
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      const items = focusable(node);
      if (!items.length) {
        // Nothing to move between, so the only correct answer is to stay put.
        e.preventDefault();
        node.focus();
        return;
      }
      const firstItem = items[0]!;
      const lastItem = items[items.length - 1]!;
      const active = document.activeElement;
      // `contains` rather than an index check: focus may be on the dialog container itself
      // (the no-focusable-children case above), which is in neither end of the list.
      if (!node.contains(active)) {
        e.preventDefault();
        (e.shiftKey ? lastItem : firstItem).focus();
        return;
      }
      if (e.shiftKey && active === firstItem) {
        e.preventDefault();
        lastItem.focus();
      } else if (!e.shiftKey && active === lastItem) {
        e.preventDefault();
        firstItem.focus();
      }
    };
    document.addEventListener("keydown", onKey);

    return () => {
      document.removeEventListener("keydown", onKey);
      body.style.overflow = prevOverflow;
      body.style.paddingRight = prevPadding;
      // Only if it is still there to focus. A drawer can be closed by an action that
      // removes its own opener — a rescan replaces every row — and calling `focus()` on a
      // detached node silently sends focus to `<body>`, which is where it would have gone
      // anyway; checking first lets the browser keep whatever it chose instead.
      if (opener && document.contains(opener)) opener.focus();
    };
  }, []);

  return ref;
}
