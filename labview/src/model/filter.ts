/**
 * The dashboard's tri-state tag filter, as pure functions.
 *
 * The UI has no test harness — the web bundle is never rendered by the smoke pass —
 * so anything that decides which services a reader sees lives here, in a module the
 * smoke test can call directly. `main.tsx` holds the state and does the clicking;
 * the semantics are asserted as a truth table.
 *
 * Generic over string tags rather than typed to `IngressKind`, because both filtered
 * dimensions want the same three states. Ingress is multi-valued and gets the
 * `any`/`all` switch as well; auth passes its single method as a one-element list and
 * stays on `any`, where the two modes agree.
 */

/** Whether the included tags are OR'd (`any`) or AND'd (`all`). */
export type TagMode = "any" | "all";

export interface TagFilter {
  /** Tags to require. Empty means "require nothing". */
  include: readonly string[];
  /** Tags to reject. Always AND-NOT, whatever the mode. */
  exclude: readonly string[];
  mode: TagMode;
}

export const EMPTY_TAG_FILTER: TagFilter = { include: [], exclude: [], mode: "any" };

/** Whether anything is being filtered at all — one place, so no caller guesses. */
export function tagFilterActive(f: TagFilter): boolean {
  return f.include.length > 0 || f.exclude.length > 0;
}

/**
 * Does this set of tags satisfy the filter?
 *
 * **Exclusion wins.** A tag that is both included and excluded rejects, because the
 * exclusion is the more specific statement and because a filter that quietly ignored
 * one of its own chips would be worse than one that returns nothing.
 *
 * An empty filter matches everything, which is what makes "no chips selected" mean
 * "show the fleet" rather than "show nothing".
 */
export function matchesTagFilter(tags: readonly string[], f: TagFilter): boolean {
  if (f.exclude.some((t) => tags.includes(t))) return false;
  if (!f.include.length) return true;
  return f.mode === "all"
    ? f.include.every((t) => tags.includes(t))
    : f.include.some((t) => tags.includes(t));
}

/**
 * Advance one tag through off → include → exclude → off.
 *
 * The cycle is the whole affordance: NOT is one more click on the chip you already
 * know, rather than a second control somewhere else. Returns a new filter; the caller
 * owns the state.
 */
export function cycleTag(f: TagFilter, tag: string): TagFilter {
  if (f.include.includes(tag)) {
    return { ...f, include: f.include.filter((t) => t !== tag), exclude: [...f.exclude, tag] };
  }
  if (f.exclude.includes(tag)) {
    return { ...f, exclude: f.exclude.filter((t) => t !== tag) };
  }
  return { ...f, include: [...f.include, tag] };
}

/**
 * The filter in words, e.g. `all of Public, LAN; not Internal`.
 *
 * Shown beside the chips because three parts — a set, a mode and an exclusion — cannot
 * be read reliably off which chips look bright, and a filter a reader misreads is a
 * conclusion they draw wrongly. `label` maps a tag to its display name so this module
 * needs no palette import.
 */
export function describeTagFilter(f: TagFilter, label: (tag: string) => string): string {
  const parts: string[] = [];
  if (f.include.length === 1) parts.push(label(f.include[0]!));
  else if (f.include.length > 1) {
    parts.push(`${f.mode === "all" ? "all of" : "any of"} ${f.include.map(label).join(", ")}`);
  }
  if (f.exclude.length) parts.push(`not ${f.exclude.map(label).join(", ")}`);
  return parts.join("; ");
}
