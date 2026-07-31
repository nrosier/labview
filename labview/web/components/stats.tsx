import type { ComponentChildren } from "preact";

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

/**
 * Part-to-whole horizontal bar. Segments follow the fixed categorical order,
 * separated by a 2px surface gap. The legend carries direct counts and doubles
 * as a filter toggle (clicking a segment filters the grid to that category).
 */
export function DistributionBar({
  title,
  segments,
  active,
  onToggle,
}: {
  title: string;
  segments: DistSegment[];
  active?: Set<string>;
  onToggle?: (key: string) => void;
}) {
  const total = segments.reduce((a, s) => a + s.count, 0) || 1;
  const shown = segments.filter((s) => s.count > 0);
  return (
    <div class="dist">
      <h3>{title}</h3>
      <div class="bar" role="img" aria-label={`${title}: ${shown.map((s) => `${s.label} ${s.count}`).join(", ")}`}>
        {shown.map((s) => (
          <div
            class="seg"
            style={`width:${(s.count / total) * 100}%;background:var(${s.cssVar})`}
            title={`${s.label}: ${s.count}`}
          />
        ))}
      </div>
      <div class="legend">
        {segments.map((s) => {
          const off = active && active.size > 0 && !active.has(s.key);
          return (
            <span
              class={`item${off ? " off" : ""}`}
              role={onToggle ? "button" : undefined}
              tabIndex={onToggle ? 0 : undefined}
              onClick={onToggle ? () => onToggle(s.key) : undefined}
              onKeyDown={
                onToggle
                  ? (e: KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onToggle(s.key);
                      }
                    }
                  : undefined
              }
            >
              <span class="swatch" style={`background:var(${s.cssVar})`} />
              {s.label} <span class="count">{s.count}</span>
            </span>
          );
        })}
      </div>
    </div>
  );
}
