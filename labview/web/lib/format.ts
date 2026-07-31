import type { DockerState, Service } from "../model";

/** Short "image:tag" without a long registry prefix, for compact display. */
export function shortImage(image: string | undefined): string {
  if (!image) return "—";
  const noDigest = image.split("@")[0] ?? image;
  return noDigest;
}

/** A stable per-service key: `${stackId}/${serviceName}`. */
export function serviceKey(stackId: string, serviceName: string): string {
  return `${stackId}/${serviceName}`;
}

export interface StatusView {
  label: string;
  /** CSS custom property name for the dot color. */
  cssVar: string;
  /** Whether docker state is known at all. */
  known: boolean;
}

/** Map live docker state (or its absence) to a status dot + label. */
export function statusView(docker: DockerState | undefined): StatusView {
  if (!docker) return { label: "No live state", cssVar: "--muted", known: false };
  if (docker.health === "unhealthy") return { label: "Unhealthy", cssVar: "--critical", known: true };
  if (docker.health === "starting") return { label: "Starting", cssVar: "--warning", known: true };
  if (docker.running) return { label: docker.status || "Running", cssVar: "--good", known: true };
  return { label: docker.status || docker.state || "Stopped", cssVar: "--muted", known: true };
}

/** One-line summary of how a service is reached, for card meta. */
export function ingressSummary(svc: Service): string {
  const hosts = [
    ...svc.cloudflare.map((r) => r.hostname).filter(Boolean),
    ...svc.traefik.flatMap((r) => r.hosts),
  ];
  const uniq = [...new Set(hosts)];
  if (uniq.length === 0) return "";
  if (uniq.length <= 2) return uniq.join(", ");
  return `${uniq.slice(0, 2).join(", ")} +${uniq.length - 2}`;
}

export function fmtTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
