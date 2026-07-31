/**
 * Resolve what each tunnel origin actually points at.
 *
 * A tunnel rarely terminates at the container whose labels declare it. The origin
 * normally names a reverse proxy, which then forwards to the container over a
 * shared network. Reporting the tunnel as reaching the container directly would
 * state a topology the configuration contradicts, so the origin is resolved from
 * evidence instead of assumed.
 *
 * Two kinds of evidence are usable, and which one applies depends on how the
 * origin addresses its target:
 *
 *  - **An IP literal addresses the host**, so the port in the origin is a
 *    *published host port*. Host ports are unique per host, so exactly one service
 *    can own one — the match identifies the target rather than suggesting it.
 *  - **A bare name addresses a container**, so the port is container-internal and
 *    says nothing about ownership. Here the *name* is the evidence: compose
 *    publishes a service's name and `container_name` as DNS aliases on its
 *    networks.
 *
 * Anything else — a FQDN, or a port nobody publishes — resolves to `unresolved`,
 * which keeps the direct edge and states the gap. Guessing a hop from a
 * likely-looking name is exactly what invariant I2 forbids; no image, vendor or
 * naming convention is consulted anywhere in this module.
 *
 * One wrinkle makes a second piece of evidence necessary. A compose file can
 * declare the same host port on several services even though only one can hold it
 * at a time, so a port match alone is not always unique. Network membership breaks
 * the tie: a candidate that shares no network with the service it supposedly
 * fronts cannot forward to it, so it is not the hop. That is the "proxy network"
 * leg of the path, and it is as observable as the port itself.
 */
import type { AppStack, OriginTarget, PortMapping, Service } from "../model/types.js";
import { realNetworks } from "./networks.js";

/** One service, as referenced by the fleet index. */
export interface ServiceRef {
  stackId: string;
  serviceName: string;
  /** Host interface the port is bound to, when the mapping names one. */
  bindIp?: string;
}

export interface FleetIndex {
  /** Published host port -> the service(s) declaring it. */
  byPort: Map<string, ServiceRef[]>;
  /** Lowercased compose service name and container name -> the service(s) using it. */
  byName: Map<string, ServiceRef[]>;
  /** `${stackId}/${serviceName}` -> the real docker networks it joins. */
  netsByKey: Map<string, string[]>;
}

/**
 * Index the whole fleet by published host port and by DNS-visible name.
 *
 * Built once across every stack, like `buildMiddlewareRegistry`, because an origin
 * routinely points at a proxy defined in a different stack than the service it
 * fronts.
 */
export function buildFleetIndex(stacks: AppStack[]): FleetIndex {
  const byPort = new Map<string, ServiceRef[]>();
  const byName = new Map<string, ServiceRef[]>();
  const netsByKey = new Map<string, string[]>();
  const push = (map: Map<string, ServiceRef[]>, key: string, ref: ServiceRef) => {
    const list = map.get(key);
    if (list) list.push(ref);
    else map.set(key, [ref]);
  };

  for (const stack of stacks) {
    for (const svc of stack.services) {
      for (const p of svc.ports) {
        const host = hostPort(p);
        if (!host) continue;
        push(byPort, host.port, { stackId: stack.id, serviceName: svc.name, bindIp: host.bindIp });
      }
      for (const name of [svc.name, svc.containerName]) {
        if (name) push(byName, name.toLowerCase(), { stackId: stack.id, serviceName: svc.name });
      }
      netsByKey.set(`${stack.id}/${svc.name}`, realNetworks(stack, svc));
    }
  }
  return { byPort, byName, netsByKey };
}

/** Attach an `origin` to every declared tunnel route, and note the ones that resolved to nothing. */
export function resolveOrigins(stacks: AppStack[], index: FleetIndex): void {
  for (const stack of stacks) {
    for (const svc of stack.services) {
      const unresolved = new Set<string>();
      for (const route of svc.cloudflare) {
        if (!route.service || !route.service.trim()) continue;
        route.origin = resolveOrigin(route.service.trim(), stack, svc, index);
        if (route.origin.kind === "unresolved") unresolved.add(route.origin.evidence);
      }
      // One note per distinct reason, not per route: several hostnames commonly
      // share a single origin, and repeating the same finding adds no information.
      for (const evidence of unresolved) {
        svc.notes.push(`Tunnel origin could not be resolved — ${evidence}`);
      }
    }
  }
}

function resolveOrigin(address: string, stack: AppStack, svc: Service, index: FleetIndex): OriginTarget {
  const parsed = parseOrigin(address);
  if (!parsed) {
    return {
      address,
      host: "",
      port: "",
      kind: "unresolved",
      evidence: `"${address}" could not be parsed as an origin address.`,
    };
  }
  const { host, port } = parsed;
  const base = { address, host, port };
  const hostLc = host.toLowerCase();

  // 1. The service's own DNS name: the tunnel reaches it directly over a network.
  if (hostLc === svc.name.toLowerCase()) {
    return {
      ...base,
      kind: "self-network",
      evidence: `origin host "${host}" is this service's own compose name, so the tunnel reaches it directly over a docker network.`,
    };
  }
  if (svc.containerName && hostLc === svc.containerName.toLowerCase()) {
    return {
      ...base,
      kind: "self-network",
      evidence: `origin host "${host}" is this service's own container name, so the tunnel reaches it directly over a docker network.`,
    };
  }

  const ownKey = `${stack.id}/${svc.name}`;

  // 2. An IP literal addresses the host, so the port identifies the target.
  if (isIpLiteral(host)) {
    if (!port) {
      return {
        ...base,
        kind: "unresolved",
        evidence: `origin "${address}" names a host address but no port, and its scheme implies none.`,
      };
    }
    const claimants = distinct((index.byPort.get(port) ?? []).filter((o) => bindReachableFrom(o, host)));
    if (claimants.length === 1 && refKey(claimants[0]!) === ownKey) {
      return {
        ...base,
        kind: "self-host-port",
        evidence: `this service publishes host port ${port} itself, so the tunnel reaches it directly at that port, bypassing any reverse proxy.`,
      };
    }
    return fromClaimants(base, claimants, ownKey, index, `host port ${port}`, `publishes host port ${port}`);
  }

  // 3. A bare name addresses a container: the name is the evidence, not the port.
  const named = distinct(index.byName.get(hostLc) ?? []);
  if (named.length === 1 && refKey(named[0]!) === ownKey) {
    return {
      ...base,
      kind: "self-network",
      evidence: `origin host "${host}" resolves to this service itself.`,
    };
  }
  if (named.length === 0) {
    return {
      ...base,
      kind: "unresolved",
      evidence: `origin host "${host}" is neither a host address nor the name of any scanned service.`,
    };
  }
  return fromClaimants(base, named, ownKey, index, `the name "${host}"`, `answers to "${host}"`);
}

/**
 * Pick the hop from the services a port or name could refer to.
 *
 * More than one candidate is normal and does not by itself defeat resolution: a
 * fleet may declare `443:443` on several stacks even though only one container can
 * hold the port. What settles it is reachability — a candidate sharing no network
 * with this service cannot forward traffic to it, so it is not the hop, whatever
 * the port table says. Only a genuine tie between reachable candidates is reported
 * as ambiguous.
 */
function fromClaimants(
  base: { address: string; host: string; port: string },
  claimants: ServiceRef[],
  ownKey: string,
  index: FleetIndex,
  subject: string,
  claims: string,
): OriginTarget {
  const others = claimants.filter((c) => refKey(c) !== ownKey);
  if (others.length === 0) {
    return {
      ...base,
      kind: "unresolved",
      evidence: `no scanned service ${claims}, so the origin points outside this scan.`,
    };
  }
  const reachable = others.filter((c) => sharesNetwork(index, refKey(c), ownKey));
  if (reachable.length === 1) {
    const hop = reachable[0]!;
    const shared = sharedNetworks(index, refKey(hop), ownKey).join(", ");
    const qualifier =
      others.length > 1
        ? `${others.length} services ${claims}, and it is the only one that shares a network with this service`
        : `it ${claims}`;
    return {
      ...base,
      kind: "fleet-service",
      hopKey: refKey(hop),
      evidence: `${subject} resolves to ${refKey(hop)}: ${qualifier} (${shared}), so the tunnel terminates there and that service forwards to this one over that network.`,
    };
  }
  if (reachable.length > 1) {
    return {
      ...base,
      kind: "unresolved",
      evidence: `${subject} could refer to ${reachable.length} services that each share a network with this one (${reachable.map(refKey).join(", ")}), so the hop is ambiguous.`,
    };
  }
  return {
    ...base,
    kind: "unresolved",
    evidence: `${others.length === 1 ? `${refKey(others[0]!)} ${claims}` : `${others.length} services ${claims}`}, but none shares a network with this service, so nothing observed could forward the tunnel to it.`,
  };
}

/**
 * Collapse index hits to one per service.
 *
 * A service reaches the index once per matching declaration, and one service
 * legitimately declares the same host port more than once — `443:443/tcp` beside
 * `443:443/udp` for HTTP/3, or a name that equals its own `container_name`. Those
 * are repeated evidence for a single candidate, not competing candidates, and
 * counting them as rivals would report a settled origin as ambiguous.
 */
function distinct(refs: ServiceRef[]): ServiceRef[] {
  const seen = new Set<string>();
  return refs.filter((r) => {
    const key = refKey(r);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function sharedNetworks(index: FleetIndex, a: string, b: string): string[] {
  const an = index.netsByKey.get(a) ?? [];
  const bn = index.netsByKey.get(b) ?? [];
  return an.filter((n) => bn.includes(n));
}

function sharesNetwork(index: FleetIndex, a: string, b: string): boolean {
  return sharedNetworks(index, a, b).length > 0;
}

/**
 * Parse an origin into host + effective port, tolerating a missing scheme.
 *
 * The port is taken from the address when given, otherwise from the scheme — an
 * `https://` origin with no port is port 443 as surely as if it said so. A scheme
 * that implies no port (say `tcp://`) yields an empty port rather than a guess.
 */
function parseOrigin(address: string): { host: string; port: string } | undefined {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(address) ? address : `http://${address}`;
  try {
    const u = new URL(withScheme);
    if (!u.hostname) return undefined;
    const implied = u.protocol === "https:" ? "443" : u.protocol === "http:" ? "80" : "";
    return { host: u.hostname, port: u.port || implied };
  } catch {
    return undefined;
  }
}

/**
 * The host port a mapping publishes, if it names exactly one.
 *
 * Compose keeps the bind address inside the published field for the three-part
 * form (`127.0.0.1:8096:8096`), so the port is the last segment and anything
 * before it is the interface. A range (`8000-8010`) identifies no single port and
 * is skipped rather than guessed at.
 */
function hostPort(p: PortMapping): { port: string; bindIp?: string } | undefined {
  if (!p.published) return undefined;
  const segs = p.published.split(":");
  const port = segs[segs.length - 1]!;
  if (!/^\d+$/.test(port)) return undefined;
  const bindIp = segs.length > 1 ? segs.slice(0, -1).join(":") : undefined;
  return bindIp ? { port, bindIp } : { port };
}

/**
 * Whether a published port is reachable at the address the origin used. A port
 * bound to a specific interface does not answer on another one, so a mismatch is
 * evidence *against* that service being the target.
 */
function bindReachableFrom(ref: ServiceRef, host: string): boolean {
  if (!ref.bindIp) return true;
  if (ref.bindIp === "0.0.0.0" || ref.bindIp === "::" || ref.bindIp === "*") return true;
  return ref.bindIp === host;
}

function isIpLiteral(host: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  // URL parsing strips the brackets from an IPv6 literal, leaving the colons.
  return host.includes(":");
}

/** The `${stackId}/${serviceName}` key used for `hopKey`, matching `serviceKey()` in the UI. */
function refKey(ref: ServiceRef): string {
  return `${ref.stackId}/${ref.serviceName}`;
}
