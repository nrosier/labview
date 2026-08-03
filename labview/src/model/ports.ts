import type { PortMapping } from "./types.js";

/**
 * Reading a compose port mapping for the one thing two different questions need from
 * it: which port on the *host* does this publish.
 *
 * Here rather than beside either caller because there are two, they ask for opposite
 * reasons, and an answer that differed between them would be a contradiction rather
 * than a nuance. `analyze/origins.ts` matches a tunnel origin's port against published
 * ports to identify which service a proxy forwards to; `model/probe.ts` builds the LAN
 * address the active probe dials. If the first said a mapping publishes 8096 and the
 * second dialled something else, the dashboard would report a service the probe never
 * looked at.
 */

/**
 * The host port a mapping publishes, if it names exactly one.
 *
 * Compose keeps the bind address inside the published field for the three-part
 * form (`127.0.0.1:8096:8096`), so the port is the last segment and anything
 * before it is the interface. A range (`8000-8010`) identifies no single port and
 * is skipped rather than guessed at.
 */
export function publishedHostPort(p: PortMapping): { port: string; bindIp?: string } | undefined {
  if (!p.published) return undefined;
  const segs = p.published.split(":");
  const port = segs[segs.length - 1]!;
  if (!/^\d+$/.test(port)) return undefined;
  const bindIp = segs.length > 1 ? segs.slice(0, -1).join(":") : undefined;
  return bindIp ? { port, bindIp } : { port };
}
