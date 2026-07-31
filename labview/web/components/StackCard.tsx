import type { AppStack, AuthMethod, IngressKind, Service } from "../model";
import { ingressSummary, shortImage } from "../lib/format";
import { AUTH_META, INGRESS_META } from "../lib/palette";
import { AuthBadge, ExposedBadge, IngressBadge, StatusDot } from "./badges";

/**
 * One stack, the unit a compose fleet is actually organised in: a directory with a
 * compose file, which may define one service or a dozen.
 *
 * Collapsed, it rolls up its services — every distinct ingress and auth posture
 * present, and a count of anything reachable without auth. Nothing is averaged or
 * reduced to a "worst case", because a stack does not have one posture: a database
 * that is internal and a UI that is public are both true at once, and hiding either
 * behind a single badge would misreport the stack.
 *
 * Expanded, it lists the services themselves, each opening the same detail drawer
 * the flat cards used to.
 */
export function StackCard({
  stack,
  services,
  expanded,
  onToggle,
  onOpenService,
}: {
  stack: AppStack;
  /** The services to show — the filtered subset, which may be fewer than the stack has. */
  services: Service[];
  expanded: boolean;
  onToggle: () => void;
  onOpenService: (svc: Service) => void;
}) {
  const hidden = stack.services.length - services.length;
  const running = services.filter((s) => s.docker?.running).length;
  const liveKnown = services.some((s) => s.docker);
  const exposed = services.filter((s) => s.auth.exposedWithoutAuth).length;
  const hosts = [...new Set(services.map(ingressSummary).filter(Boolean))].join(", ");

  // Ordered by the shared palette metadata rather than by appearance, so the same
  // set of postures always reads the same way across stacks.
  const ingressKinds = INGRESS_META.map((m) => m.key).filter((k) =>
    services.some((s) => s.ingress === k),
  );
  const authMethods = AUTH_META.map((m) => m.key).filter((k) =>
    services.some((s) => s.auth.method === k),
  );

  return (
    <div class={`stack-card${expanded ? " open" : ""}`}>
      <div
        class="stack-head"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={onToggle}
        onKeyDown={(e: KeyboardEvent) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggle();
          }
        }}
      >
        <span class="chev" aria-hidden="true">
          {expanded ? "▾" : "▸"}
        </span>
        <div class="stack-title">
          <div class="line">
            <span class="name">{stack.name}</span>
            <span class="count">
              {services.length} service{services.length === 1 ? "" : "s"}
              {hidden > 0 && <span class="muted-inline"> of {stack.services.length}</span>}
              {liveKnown && <span class="muted-inline"> · {running} running</span>}
            </span>
            <span class="dots">
              {services.map((s) => (
                <StatusDot key={s.name} docker={s.docker} />
              ))}
            </span>
          </div>
          {hosts && (
            <div class="metaline" title={hosts}>
              🔗 {hosts}
            </div>
          )}
        </div>
        <div class="badges">
          {ingressKinds.map((k) => (
            <IngressBadge key={k} kind={k as IngressKind} />
          ))}
          {authMethods.map((m) => (
            <AuthBadge key={m} method={m as AuthMethod} />
          ))}
          {exposed > 0 && (
            <span class="badge exposed" title="Reachable with no detected proxy/SSO auth">
              ⚠ {exposed} exposed, no auth
            </span>
          )}
        </div>
      </div>

      {expanded && (
        <div class="svc-list">
          {services.map((svc) => (
            <div
              key={svc.name}
              class="svc-row"
              role="button"
              tabIndex={0}
              onClick={() => onOpenService(svc)}
              onKeyDown={(e: KeyboardEvent) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onOpenService(svc);
                }
              }}
            >
              <StatusDot docker={svc.docker} />
              <span class="name">{svc.name}</span>
              <span class="img mono">{shortImage(svc.image)}</span>
              <span class="badges">
                <IngressBadge kind={svc.ingress} />
                <AuthBadge method={svc.auth.method} />
                {svc.auth.exposedWithoutAuth && <ExposedBadge />}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
