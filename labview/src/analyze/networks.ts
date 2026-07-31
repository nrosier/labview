import type { AppStack, Service } from "../model/types.js";

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
