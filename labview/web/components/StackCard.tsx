import type { AppStack, AuthMethod, IngressKind, Service } from "../model";
import { rollUpIngress } from "../model";
import { ingressSummary, shortImage } from "../lib/format";
import { AUTH_META } from "../lib/palette";
import {
  AcceptedBadge,
  AuthBadge,
  DeclaredAuthBadge,
  DeclaredProtectedBadge,
  ExposedBadge,
  IngressBadge,
  StatusDot,
} from "./badges";

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
  const exposedServices = services.filter((s) => s.auth.exposedWithoutAuth);
  const exposed = exposedServices.length;
  // Split rather than netted off: the roll-up still says how many are exposed, and says
  // separately how many of those someone has already signed off on.
  const accepted = exposedServices.filter((s) => s.declared?.unauthenticatedAccepted).length;
  const hosts = [...new Set(services.map(ingressSummary).filter(Boolean))].join(", ");
  const declared = stack.declared;
  const drift = services.reduce((n, s) => n + (s.declared?.drift.length ?? 0), 0);

  // The union of the services' kinds, in the same canonical order the palette rows use:
  // one public service and one internal one make the stack both, which is the whole
  // reason neither is reduced to a single verdict. `rollUpIngress` rather than a `some()`
  // here because it must *not* withhold `internal` the way a service's own set does —
  // see there.
  const ingressKinds = rollUpIngress(services.map((s) => s.ingress));
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
          {/* What the operator says this stack is, when they said so. One line: the full
              text is in the drawer, and a card that grows with the prose stops being
              scannable, which is the only thing the collapsed view is for. */}
          {declared?.description && (
            <div class="stack-desc" title={declared.description}>
              {declared.description}
            </div>
          )}
          {(hosts || declared?.owner || declared?.criticality) && (
            <div class="metaline" title={hosts}>
              {hosts && <>🔗 {hosts}</>}
              {declared?.owner && (
                <span class="pill" title={`Owner declared in ${declared.file}`}>
                  {declared.owner}
                </span>
              )}
              {declared?.criticality && (
                <span class="pill" title={`Criticality declared in ${declared.file}`}>
                  {declared.criticality}
                </span>
              )}
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
          {exposed - accepted > 0 && (
            <span class="badge exposed" title="Reachable with no detected proxy/SSO auth">
              ⚠ {exposed - accepted} exposed, no auth
            </span>
          )}
          {/* Beside the alarm, never subtracted from it: both counts are shown, so the
              stack's total exposure is still readable off the card. */}
          {accepted > 0 && (
            <span class="badge declared" title="Reachable with no detected auth, declared intentional">
              {accepted} exposed, accepted
            </span>
          )}
          {drift > 0 && (
            <span class="badge declared" title="A declaration in this stack disagrees with the scan">
              ⚠ {drift} declaration drift
            </span>
          )}
        </div>
      </div>

      {expanded && (
        <div class="svc-list">
          {/* Warnings about this stack's own files — a compose document that would not
              parse, an env var that resolved to nothing, a mistyped key in `.labview`.
              They live on the stack rather than in the top banner because that is where
              the file they are about is, and because hoisting them would bury the
              fleet-wide warnings the banner exists for. */}
          {stack.warnings.map((w) => (
            <div class="note">{w}</div>
          ))}
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
                {svc.ingress.map((k) => (
                  <IngressBadge key={k} kind={k} />
                ))}
                <AuthBadge method={svc.auth.method} />
                {/* One slot, three mutually exclusive outcomes — see `AppDetail`. */}
                {svc.auth.exposedWithoutAuth ? (
                  svc.declared?.unauthenticatedAccepted ? (
                    <AcceptedBadge
                      reason={svc.declared.unauthenticatedAccepted.reason}
                      file={svc.declared.file}
                    />
                  ) : (
                    <ExposedBadge />
                  )
                ) : svc.declared?.authAgreement === "supplies" ? (
                  <DeclaredProtectedBadge auth={svc.declared.auth} file={svc.declared.file} />
                ) : null}
                {svc.declared && (
                  <DeclaredAuthBadge
                    auth={svc.declared.auth}
                    file={svc.declared.file}
                    agreement={svc.declared.authAgreement}
                  />
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
