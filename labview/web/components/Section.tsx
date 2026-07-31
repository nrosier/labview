/**
 * A titled block inside a drawer.
 *
 * Lives here rather than in the one drawer that first needed it, because both drawers
 * present the same kind of content — a heading over a table or a list of evidence — and
 * two copies of four lines is two places for the markup the `.section` rule targets to
 * drift apart.
 */
export function Section({
  title,
  children,
}: {
  title: string;
  children: preact.ComponentChildren;
}) {
  return (
    <div class="section">
      <h3>{title}</h3>
      {children}
    </div>
  );
}
