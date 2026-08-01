import type { ComponentChildren } from "preact";
import type { TagFilter, TagMode } from "../model";
import { tagFilterActive } from "../model";

export function StatTile({
  label,
  value,
  unit,
  sub,
  alert = false,
}: {
  label: string;
  value: number | string;
  unit?: string;
  sub?: ComponentChildren;
  alert?: boolean;
}) {
  return (
    <div class={`tile${alert ? " alert" : ""}`}>
      <div class="label">{label}</div>
      <div class="value">
        {value}
        {unit && <span class="unit">{unit}</span>}
      </div>
      {sub != null && <div class="sub">{sub}</div>}
    </div>
  );
}

export interface DistSegment {
  key: string;
  label: string;
  cssVar: string;
  count: number;
}

/** Which of the three states a chip is in, for the shared wording and ARIA below. */
type ChipState = "included" | "excluded" | "neutral";

function chipState(filter: TagFilter | undefined, key: string): ChipState {
  if (!filter) return "neutral";
  if (filter.exclude.includes(key)) return "excluded";
  if (filter.include.includes(key)) return "included";
  return "neutral";
}

/**
 * How a chip is announced and what a click will do next. Spelled out because the
 * cycle (include → exclude → off) is not guessable from the chip's appearance, and a
 * filter a reader misreads is a conclusion they draw wrongly.
 *
 * `aria-pressed="mixed"` for excluded: the chip is engaged but not in the affirmative
 * sense, which is exactly the distinction the third value exists for.
 */
function chipAria(state: ChipState, label: string): { pressed: "true" | "mixed" | "false"; title: string } {
  if (state === "included") return { pressed: "true", title: `${label}: included — click to exclude` };
  if (state === "excluded") return { pressed: "mixed", title: `${label}: excluded — click to clear` };
  return { pressed: "false", title: `${label}: click to include` };
}

/**
 * The tri-state legend both bars share: one chip per category, cycling
 * include → exclude → off, with a `¬` prefix and a struck-through label when excluded.
 *
 * No new colour: a filter state is not a category, so it is carried by the prefix, the
 * strikethrough and the existing `.off` dimming rather than by a new hue that would
 * compete with the five that mean something.
 */
function TagLegend({
  segments,
  filter,
  onCycle,
}: {
  segments: DistSegment[];
  filter?: TagFilter;
  onCycle?: (key: string) => void;
}) {
  const anyActive = filter ? tagFilterActive(filter) : false;
  return (
    <div class="legend">
      {segments.map((s) => {
        const state = chipState(filter, s.key);
        const { pressed, title } = chipAria(state, s.label);
        const cls = [
          "item",
          state === "excluded" ? "neg" : "",
          anyActive && state === "neutral" ? "off" : "",
        ]
          .filter(Boolean)
          .join(" ");
        return (
          <span
            key={s.key}
            class={cls}
            title={onCycle ? title : `${s.label}: ${s.count}`}
            role={onCycle ? "button" : undefined}
            tabIndex={onCycle ? 0 : undefined}
            aria-pressed={onCycle ? pressed : undefined}
            onClick={onCycle ? () => onCycle(s.key) : undefined}
            onKeyDown={
              onCycle
                ? (e: KeyboardEvent) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onCycle(s.key);
                    }
                  }
                : undefined
            }
          >
            <span class="swatch" style={`background:var(${s.cssVar})`} />
            {state === "excluded" && <span aria-hidden="true">¬</span>}
            <span class="tlabel">{s.label}</span> <span class="count">{s.count}</span>
          </span>
        );
      })}
    </div>
  );
}

/** `Any` / `All` for the included set — the OR/AND half of the filter expression. */
function ModeSwitch({ mode, onMode }: { mode: TagMode; onMode: (mode: TagMode) => void }) {
  return (
    <span class="modeswitch" role="group" aria-label="Combine the included kinds">
      {(["any", "all"] as const).map((m) => (
        <button
          key={m}
          type="button"
          class={`modebtn${mode === m ? " on" : ""}`}
          aria-pressed={mode === m}
          title={
            m === "any"
              ? "Any: a service matching at least one included kind"
              : "All: only services carrying every included kind"
          }
          onClick={() => onMode(m)}
        >
          {m === "any" ? "Any" : "All"}
        </button>
      ))}
    </span>
  );
}

/**
 * Part-to-whole horizontal bar, for a dimension where each service has exactly one
 * value. Segments follow the fixed categorical order, separated by a 2px surface gap.
 * The legend carries direct counts and doubles as the tri-state filter control.
 */
export function DistributionBar({
  title,
  segments,
  filter,
  onCycle,
}: {
  title: string;
  segments: DistSegment[];
  filter?: TagFilter;
  onCycle?: (key: string) => void;
}) {
  const total = segments.reduce((a, s) => a + s.count, 0) || 1;
  const shown = segments.filter((s) => s.count > 0);
  return (
    <div class="dist">
      <h3>{title}</h3>
      <div class="bar" role="img" aria-label={`${title}: ${shown.map((s) => `${s.label} ${s.count}`).join(", ")}`}>
        {shown.map((s) => (
          <div
            key={s.key}
            class="seg"
            style={`width:${(s.count / total) * 100}%;background:var(${s.cssVar})`}
            title={`${s.label}: ${s.count}`}
          />
        ))}
      </div>
      <TagLegend segments={segments} filter={filter} onCycle={onCycle} />
    </div>
  );
}

/**
 * One gauge per tag, for a dimension where a service can carry several at once.
 *
 * Deliberately *not* a part-to-whole bar. Once one service is both public and proxied,
 * the counts sum past the number of services, so a single bar would either misdraw the
 * widths or imply that clicking a 14%-wide segment returns 14% of the fleet. Each row
 * is instead read against the same denominator — `count / total` services — which is
 * the only claim the data supports.
 *
 * The rows *are* the tri-state chips, rather than a legend repeating them underneath:
 * each already carries the swatch, the label and the count a legend would, and two
 * controls for one tag would only leave a reader wondering whether they differ.
 */
export function TagBars({
  title,
  segments,
  total,
  filter,
  onCycle,
  onMode,
}: {
  title: string;
  segments: DistSegment[];
  /** Denominator for every row: the number of services in view, not the sum of counts. */
  total: number;
  filter?: TagFilter;
  onCycle?: (key: string) => void;
  onMode?: (mode: TagMode) => void;
}) {
  const denom = total || 1;
  const anyActive = filter ? tagFilterActive(filter) : false;
  return (
    <div class="dist">
      <div class="disthead">
        <h3>{title}</h3>
        {filter && onMode && <ModeSwitch mode={filter.mode} onMode={onMode} />}
      </div>
      <div class="tagrows">
        {segments.map((s) => {
          const state = chipState(filter, s.key);
          const { pressed, title: hint } = chipAria(state, s.label);
          const cls = [
            "tagrow",
            state === "excluded" ? "neg" : "",
            anyActive && state === "neutral" ? "off" : "",
          ]
            .filter(Boolean)
            .join(" ");
          return (
            <div
              key={s.key}
              class={cls}
              title={onCycle ? `${hint} (${s.count} of ${total})` : `${s.label}: ${s.count} of ${total}`}
              role={onCycle ? "button" : undefined}
              tabIndex={onCycle ? 0 : undefined}
              aria-pressed={onCycle ? pressed : undefined}
              onClick={onCycle ? () => onCycle(s.key) : undefined}
              onKeyDown={
                onCycle
                  ? (e: KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onCycle(s.key);
                      }
                    }
                  : undefined
              }
            >
              <span class="tagname">
                <span class="swatch" style={`background:var(${s.cssVar})`} />
                {state === "excluded" && <span aria-hidden="true">¬</span>}
                <span class="tlabel">{s.label}</span>
              </span>
              <span class="bar">
                <span
                  class="seg"
                  style={`width:${(s.count / denom) * 100}%;background:var(${s.cssVar})`}
                />
              </span>
              <span class="count">{s.count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
