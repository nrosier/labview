import type { AuthMethod, DockerState, IngressKind } from "../model";
import { authLabel, authVar, ingressLabel, ingressVar } from "../lib/palette";
import { statusView } from "../lib/format";
import { IconGlobe, IconLan, IconLock, IconServer, IconShield, IconWarning } from "./icons";

/** Ingress badge — colored swatch + icon + label (identity, not color alone). */
export function IngressBadge({ kind }: { kind: IngressKind }) {
  const icon =
    kind === "internal" ? <IconServer /> : kind === "local" ? <IconLan /> : <IconGlobe />;
  return (
    <span class="badge soft" title={`Ingress: ${ingressLabel(kind)}`}>
      <span class="swatch" style={`background:var(${ingressVar(kind)})`} />
      <span class="icon">{icon}</span>
      {ingressLabel(kind)}
    </span>
  );
}

/** Auth method badge — colored swatch + shield/lock icon + label. */
export function AuthBadge({ method }: { method: AuthMethod }) {
  const icon = method === "none" ? null : method === "basic-auth" ? <IconLock /> : <IconShield />;
  return (
    <span class="badge soft" title={`Auth: ${authLabel(method)}`}>
      <span class="swatch" style={`background:var(${authVar(method)})`} />
      {icon && <span class="icon">{icon}</span>}
      {authLabel(method)}
    </span>
  );
}

/** Prominent warning shown when a reachable service has no detected auth. */
export function ExposedBadge() {
  return (
    <span class="badge exposed" title="Publicly reachable with no detected proxy/SSO auth">
      <span class="icon">
        <IconWarning />
      </span>
      Exposed, no auth
    </span>
  );
}

/** Live status dot + text (color reinforced by explicit label). */
export function StatusDot({ docker, withLabel = false }: { docker: DockerState | undefined; withLabel?: boolean }) {
  const s = statusView(docker);
  return (
    <span title={s.label} style="display:inline-flex;align-items:center;gap:6px;">
      <span
        class="status-dot"
        style={`background:var(${s.cssVar});${s.known ? "" : "box-shadow:inset 0 0 0 1.5px var(--baseline);background:transparent;"}`}
      />
      {withLabel && <span style="color:var(--ink-2);font-size:12px;">{s.label}</span>}
    </span>
  );
}
