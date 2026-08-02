import type { AppStack } from "../model/types.js";
import { serviceKey, sharedWith, type NetworkIndex } from "./networks.js";
import { serviceRefKey, type FleetIndex, type ServiceRef } from "./origins.js";

/**
 * Resolve the cross-stack dependencies an operator declared in a `.labview` sidecar.
 *
 * Compose cannot express this relation. `depends_on` names a service in the same
 * project, so a database and the service that backs it up — two stacks, one shared
 * network — have no way to state that they are related, and sharing a network does not
 * state it either: two containers on one network can reach each other, which is not the
 * same as one needing the other. The sidecar is the only place the fact can come from.
 *
 * **Declared on the dependent, drawn from both ends.** One entry on the database is
 * enough for the backup service to show that database among the things that need it —
 * the reverse direction is derived from the same edge, so a service everything points at
 * needs no sidecar of its own, however many point at it. That asymmetry is the whole
 * reason the key exists: a `required_by` list on the backup service would have to be
 * edited for every new database.
 *
 * **Resolution is never written back onto the declaration.** A resolved target is
 * derived from the *fleet*, and the declaration object is compared across rescans to
 * report an edited sidecar (§3.11) — so storing it there would make a rename in an
 * unrelated stack read as "someone edited this file". The resolved pairs go to the graph;
 * a reference that resolves to nothing, or to more than one thing, becomes a `drift`
 * entry, which that comparison already excludes.
 *
 * Nothing here changes a verdict. A declared dependency draws a relation; it is not
 * evidence, so it moves no ingress class, no exposure count and no auth posture
 * (invariant I1).
 */

/** One declared dependency, resolved to a service in the scan. */
export interface ResolvedDependency {
  /** `${stackId}/${serviceName}` of the service whose sidecar declared it. */
  from: string;
  /** `${stackId}/${serviceName}` of the service it named. */
  to: string;
  /** The sidecar the statement came from, e.g. `.labview`. Never a full path. */
  file: string;
  /** The operator's note about the dependency, when they wrote one. */
  detail?: string;
  /**
   * Real networks the pair shares, from {@link sharedWith} — the same helper the
   * compose `depends_on` edges use, so a declared dependency is drawn through a shared
   * network by exactly the rule an observed one is.
   *
   * **Empty means they share none.** Unlike a compose dependency that is not even
   * ordered, so it gets its own wording — see `flagUnreachableDependencies`.
   */
  via: string[];
}

/**
 * Resolve every `depends_on` reference in the fleet's sidecars, reporting the ones that
 * cannot be resolved as drift on the declaration that wrote them.
 *
 * Must run after {@link buildFleetIndex}, whose `byName` table is what a reference is
 * looked up in — compose service name *and* container name, which is how the operator
 * refers to a service anywhere else — and before the graph is drawn from the result.
 */
export function resolveDeclaredDependencies(
  stacks: AppStack[],
  fleet: FleetIndex,
  nets: NetworkIndex,
): ResolvedDependency[] {
  const out: ResolvedDependency[] = [];
  for (const stack of stacks) {
    for (const svc of stack.services) {
      const declared = svc.declared;
      if (!declared?.dependsOn.length) continue;
      const from = serviceKey(stack, svc);
      const seen = new Set<string>();

      for (const dep of declared.dependsOn) {
        const found = lookup(dep.ref, stack.id, fleet);
        if (found.length === 0) {
          declared.drift.push(
            `${declared.file} declares depends_on "${dep.ref}", which names no scanned service.`,
          );
          continue;
        }
        if (found.length > 1) {
          // Two candidates and no way to choose: guessing would draw a dependency on a
          // service the operator never meant, in a picture whose whole point is that a
          // line means something. So both are named and nothing is drawn.
          const names = found.map((r) => serviceRefKey(r)).join(", ");
          declared.drift.push(
            `${declared.file} declares depends_on "${dep.ref}", which names ${found.length} ` +
              `services (${names}) — qualify it as "stack/service".`,
          );
          continue;
        }
        const to = serviceRefKey(found[0]!);
        if (to === from) {
          declared.drift.push(
            `${declared.file} declares depends_on "${dep.ref}", which is this service itself.`,
          );
          continue;
        }
        // A target named twice — as `stack/service` and again bare, say — is one
        // dependency, so the second reference is dropped without a note: the file says
        // nothing wrong, it just says it twice.
        if (seen.has(to)) continue;
        seen.add(to);

        out.push({
          from,
          to,
          file: declared.file,
          ...(dep.detail ? { detail: dep.detail } : {}),
          via: sharedWith(nets, from, to),
        });
      }
    }
  }
  return out;
}

/**
 * The services a reference could mean, deduped.
 *
 * `stack/service` is exact, and resolving it needs no preference: the operator named the
 * stack. A bare name is read the way compose's own `depends_on` reads one — **the
 * sibling in this stack first** — because that is what an operator writing `postgres`
 * next to a `postgres` service means, and only then as a fleet-wide name. A bare name
 * matching two services in other stacks and none locally is genuinely ambiguous, and is
 * returned as both candidates so the caller can report it.
 *
 * Case-insensitive throughout: `byName` is keyed lowercase, and a stack id is compared
 * the same way rather than making the operator match a directory's capitalization.
 */
function lookup(ref: string, ownStack: string, fleet: FleetIndex): ServiceRef[] {
  const slash = ref.indexOf("/");
  if (slash >= 0) {
    const wantStack = ref.slice(0, slash).toLowerCase();
    const wantName = ref.slice(slash + 1).toLowerCase();
    return distinct(
      (fleet.byName.get(wantName) ?? []).filter((r) => r.stackId.toLowerCase() === wantStack),
    );
  }
  const all = distinct(fleet.byName.get(ref.toLowerCase()) ?? []);
  const local = all.filter((r) => r.stackId === ownStack);
  return local.length ? local : all;
}

/** One entry per service: `byName` lists a service twice when its container name matches. */
function distinct(refs: ServiceRef[]): ServiceRef[] {
  const seen = new Set<string>();
  return refs.filter((r) => {
    const key = serviceRefKey(r);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
