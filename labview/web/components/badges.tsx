import type { AuthMethod, DeclaredAuth, DockerState, IngressKind } from "../model";
import { declaredAuthLabel, declaredAuthSummary } from "../model";
import { authLabel, authVar, ingressLabel, ingressVar } from "../lib/palette";
import { statusView } from "../lib/format";
import { IconCheck, IconGlobe, IconLan, IconLock, IconServer, IconShield, IconWarning } from "./icons";

/**
 * Ingress badge — colored swatch + icon + label (identity, not color alone).
 *
 * One badge per kind, and a service usually wears several: the kinds are independent,
 * so the caller maps over `svc.ingress` rather than asking this component to summarise
 * a set into one word.
 *
 * The icon answers "how far does this reach": a globe for what a tunnel publishes to
 * the internet, the LAN glyph for what is answerable on the server's own network, a
 * server for the container network and for nothing at all.
 */
export function IngressBadge({ kind }: { kind: IngressKind }) {
  const icon =
    kind === "internal" || kind === "none" ? (
      <IconServer />
    ) : kind === "traefik" || kind === "lan" ? (
      <IconLan />
    ) : (
      <IconGlobe />
    );
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

/**
 * The same finding as `ExposedBadge`, stated as reviewed rather than as an alarm.
 *
 * Shown when the operator declared the exposure intentional. The service is still
 * exposed and still counted as exposed — only the alarm styling is dropped, because an
 * exposure someone decided on does not need to compete for attention with the ones
 * nobody has looked at yet. The reason is the tooltip, so the badge never asks the
 * reader to open the drawer to find out why.
 */
export function AcceptedBadge({ reason, file }: { reason: string; file: string }) {
  return (
    <span class="badge declared" title={`Exposure declared intentional in ${file}: ${reason}`}>
      <span class="icon">
        <IconCheck />
      </span>
      Exposed, accepted
    </span>
  );
}

/**
 * Authentication the operator declared and this scan did not detect.
 *
 * Deliberately colourless: hue in this UI means a *detected* category, and a
 * declaration is a statement rather than an observation, so it is marked out by a
 * dashed outline and by saying so in words. It appears next to the detected
 * `AuthBadge` — usually next to "No proxy auth" — and the pair is the honest report:
 * the scan found nothing, the operator says otherwise.
 */
export function DeclaredAuthBadge({ auth, file }: { auth: DeclaredAuth[]; file: string }) {
  if (!auth.length) return null;
  return (
    <span
      class="badge declared"
      title={`Declared in ${file} — not detected by this scan:\n${declaredAuthSummary(auth)}`}
    >
      <span class="icon">
        <IconLock />
      </span>
      Declared: {auth.map((a) => declaredAuthLabel(a.mechanism)).join(" + ")}
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
