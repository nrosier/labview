import type { AppStack, NetworkScope, Service } from "../model/types.js";

/**
 * Resolve the real docker network names a service is attached to.
 *
 * Compose namespaces a declared network as `${project}_${key}` unless it is
 * `external`, in which case the name is used verbatim — which is what lets two
 * stacks share one network. Live docker state is preferred when available, since
 * it reports the names actually in use rather than the ones implied by the file.
 *
 * Shared here because network membership answers two different questions: which
 * services the graph should connect, and whether a resolved tunnel hop can
 * actually reach the service it fronts.
 */
export function realNetworks(stack: AppStack, svc: Service): string[] {
  if (svc.docker?.networks?.length) return svc.docker.networks;
  const keys = svc.networks.length ? svc.networks : ["default"];
  return keys.map((key) => {
    const decl = stack.declaredNetworks.find((n) => n.name === key);
    if (decl?.external) return decl.name;
    return `${stack.projectName}_${key}`;
  });
}

/** `${stackId}/${serviceName}` — how a service is referred to across the fleet. */
export function serviceKey(stack: AppStack, svc: Service): string {
  return `${stack.id}/${svc.name}`;
}

/** One real docker network and every scanned service found on it. */
export interface NetworkMembership {
  /** The real docker name, as `realNetworks` resolved it. */
  name: string;
  scope: NetworkScope;
  /** `${stackId}/${serviceName}`, in scan order, each service once. */
  members: string[];
  /** The distinct stacks those members belong to, in scan order. */
  stacks: string[];
}

/**
 * Network membership across the whole fleet, both ways round.
 *
 * One index rather than the three near-identical passes this replaces — the shared-name
 * count behind the `internal` ingress rule, `FleetIndex.netsByKey`, and the graph's own
 * per-service map. They all counted the same thing over `realNetworks`, and a fourth
 * copy for the connection view would have been the point at which two of them started
 * disagreeing about what "shared" means.
 */
export interface NetworkIndex {
  /** Real network name -> who is on it. */
  byName: Map<string, NetworkMembership>;
  /** Service key -> the real networks it joins, deduped, in compose order. */
  byService: Map<string, string[]>;
}

/**
 * Index every service's networks and every network's services.
 *
 * Must run **after** live docker state has been merged, since `realNetworks` prefers
 * the names docker reports over the ones the compose file implies; an index built
 * earlier would key a shared network under two different names.
 *
 * Scope is decided by ownership, not by the `external:` keyword — see
 * {@link NetworkScope}. A name explicitly declared `external:` by any stack wins
 * outright; otherwise a name matching `${projectName}_${key}` of a scanned stack is
 * that stack's own; anything else is a live network no scanned project created, which
 * this scan cannot see the far end of and must not present as private.
 */
export function buildNetworkIndex(stacks: AppStack[]): NetworkIndex {
  const declaredExternal = new Set<string>();
  const projectOwned = new Set<string>();
  for (const stack of stacks) {
    for (const decl of stack.declaredNetworks) {
      if (decl.external) declaredExternal.add(decl.name);
      else projectOwned.add(`${stack.projectName}_${decl.name}`);
    }
    // Compose gives a file that declares no network an implicit `default`, which is
    // what makes two services in one stack mutually reachable without either saying
    // so. It is owned by the stack exactly as a declared one is.
    projectOwned.add(`${stack.projectName}_default`);
  }
  const scopeOf = (name: string): NetworkScope => {
    if (declaredExternal.has(name)) return "external";
    return projectOwned.has(name) ? "stack-local" : "external";
  };

  const byName = new Map<string, NetworkMembership>();
  const byService = new Map<string, string[]>();
  for (const stack of stacks) {
    for (const svc of stack.services) {
      const key = serviceKey(stack, svc);
      // Deduped: one service listing a network twice is not two members of it.
      const names = [...new Set(realNetworks(stack, svc))];
      byService.set(key, names);
      for (const name of names) {
        let net = byName.get(name);
        if (!net) {
          net = { name, scope: scopeOf(name), members: [], stacks: [] };
          byName.set(name, net);
        }
        net.members.push(key);
        if (!net.stacks.includes(stack.id)) net.stacks.push(stack.id);
      }
    }
  }
  return { byName, byService };
}

/**
 * Every service on `name` other than `key`, in scan order.
 *
 * The peer relation the connection views are built on: two services on one network can
 * reach each other, whichever stacks they were declared in.
 */
export function networkPeers(nets: NetworkIndex, name: string, key: string): string[] {
  return (nets.byName.get(name)?.members ?? []).filter((m) => m !== key);
}

/**
 * The real networks two services share, in the first service's compose order.
 *
 * Empty means they share none — for a `depends_on` pair that is a finding, not a
 * drawing detail: compose will order startup and the two containers still cannot
 * talk to each other.
 */
export function sharedWith(nets: NetworkIndex, a: string, b: string): string[] {
  const other = new Set(nets.byService.get(b) ?? []);
  return (nets.byService.get(a) ?? []).filter((n) => other.has(n));
}
