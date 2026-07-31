import type { AppStack, Service } from "../model";
import { ingressSummary, shortImage } from "../lib/format";
import { AuthBadge, ExposedBadge, IngressBadge, StatusDot } from "./badges";

export function AppCard({
  stack,
  svc,
  onOpen,
}: {
  stack: AppStack;
  svc: Service;
  onOpen: () => void;
}) {
  const hosts = ingressSummary(svc);
  return (
    <div
      class="card"
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e: KeyboardEvent) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen();
        }
      }}
    >
      <div class="head">
        <StatusDot docker={svc.docker} />
        <span class="name">{svc.name}</span>
        {stack.id !== svc.name && <span class="stacktag">{stack.name}</span>}
      </div>
      <div class="img mono">{shortImage(svc.image)}</div>
      <div class="metaline">
        {hosts && <span title={hosts}>🔗 {hosts}</span>}
        {svc.networks.length > 0 && <span>{svc.networks.length} net{svc.networks.length > 1 ? "s" : ""}</span>}
        {svc.mounts.length > 0 && <span>{svc.mounts.length} vol{svc.mounts.length > 1 ? "s" : ""}</span>}
      </div>
      <div class="badges">
        <IngressBadge kind={svc.ingress} />
        <AuthBadge method={svc.auth.method} />
        {svc.auth.exposedWithoutAuth && <ExposedBadge />}
      </div>
    </div>
  );
}
