/**
 * Tie the proxy's live routers to the services they serve.
 *
 * The API says what Traefik is routing; the compose scan says which services exist
 * and what they declared. Neither side carries the other's identifier — a live router
 * is `name@provider` and a service is a directory plus a compose key — so a match has
 * to rest on something both sides name independently. Three such things exist, in
 * descending strength:
 *
 *  1. **The backend address.** `loadBalancer.servers[].url` is the proxy stating where
 *     it forwards to. Nothing is stronger, and it works for routers the scan cannot
 *     see the labels for at all.
 *  2. **The router name**, for docker-provider routers only. Traefik derives that name
 *     from `traefik.http.routers.<name>` on the container's own labels, so an exact
 *     match is that label round-tripping through the proxy.
 *  3. **A hostname in the rule**, against the hostnames the service's own labels
 *     declare it serves.
 *
 * Ambiguity is discarded, never arbitrated, exactly as in
 * [authentik.ts](./authentik.ts): a wrong match here would attach one service's live
 * middleware chain — and therefore its auth posture — to another, so a missing match
 * is by far the cheaper error. A router that matches nothing is reported as unmatched,
 * which is how ingress configured outside the scanned stacks becomes visible.
 */
import type { AppStack, AuthentikProvider, Service, TraefikLiveRouter } from "../model/types.js";
import { providerEnforces, routerIsServing } from "../labels/auth.js";
import {
  lookupContainerAddress,
  normalizeHost,
  serviceRefKey,
  type FleetIndex,
  type ServiceRef,
} from "./origins.js";

export interface TraefikMatchOutcome {
  /** Number of services matched to at least one live router. */
  matchedServices: number;
  /** Qualified names of live routers no single service could be identified for. */
  unmatchedRouters: string[];
}

/**
 * Attach `svc.traefikLive` to every service a live router could be tied to.
 *
 * Mutates the stacks in place, like `resolveOrigins` and `matchAuthentik`, so pass 2
 * of the analyzer can read the result while deriving auth posture.
 */
export function matchTraefik(
  stacks: AppStack[],
  routers: TraefikLiveRouter[],
  index: FleetIndex,
): TraefikMatchOutcome {
  if (!routers.length) return { matchedServices: 0, unmatchedRouters: [] };

  const services = new Map<string, Service>();
  for (const stack of stacks) {
    for (const svc of stack.services) services.set(`${stack.id}/${svc.name}`, svc);
  }
  const byRouterName = buildRouterNameIndex(stacks);

  const unmatched: string[] = [];
  for (const router of routers) {
    const hit = matchOne(router, index, byRouterName);
    const target = hit ? services.get(hit.key) : undefined;
    if (!hit || !target) {
      unmatched.push(qualify(router));
      continue;
    }
    router.evidence.push(hit.evidence);
    (target.traefikLive ??= []).push(router);
  }

  let matchedServices = 0;
  for (const svc of services.values()) if (svc.traefikLive?.length) matchedServices++;
  return { matchedServices, unmatchedRouters: unmatched };
}

interface Hit {
  /** `${stackId}/${serviceName}` of the matched service. */
  key: string;
  evidence: string;
}

function matchOne(
  router: TraefikLiveRouter,
  index: FleetIndex,
  byRouterName: Map<string, ServiceRef[]>,
): Hit | undefined {
  const subject = `live Traefik router \`${qualify(router)}\``;

  // 1. The backend address: the proxy naming its target. Resolved against the
  //    container-IP index rather than the published-port one — a backend is addressed
  //    from inside the docker networks, where a port number belongs to the container
  //    and identifies nobody (see `lookupContainerAddress`).
  const backends = router.servers.map((s) => s.url);
  const byBackend = unique(backends.flatMap((url) => lookupContainerAddress(url, index)));
  if (byBackend.length === 1) {
    return {
      key: serviceRefKey(byBackend[0]!),
      evidence: `${subject}: the proxy forwards it to ${backends.join(", ")}, which is this service.`,
    };
  }

  // 2. The router name, docker provider only. Traefik takes the name from the
  //    container's own label, so equality is that label observed from the other side.
  //    For any other provider the name is operator-chosen on one side only and proves
  //    nothing about which container it refers to.
  if (router.provider === "docker") {
    const named = byRouterName.get(router.router.toLowerCase());
    if (named?.length === 1) {
      return {
        key: serviceRefKey(named[0]!),
        evidence: `${subject}: its name matches the \`routers.${router.router}\` label on this service, which is where Traefik took the name from.`,
      };
    }
  }

  // 3. A hostname in the rule, against what the service declared it serves.
  const hosts = router.hosts.map((h) => normalizeHost(h)).filter((h): h is string => Boolean(h));
  const byHost = unique(hosts.flatMap((h) => index.byHostname.get(h) ?? []));
  if (byHost.length === 1) {
    return {
      key: serviceRefKey(byHost[0]!),
      evidence: `${subject}: its rule serves ${hosts.join(", ")}, which this service's own labels declare.`,
    };
  }
  return undefined;
}

/**
 * Router name -> the service(s) whose labels declare a router of that name.
 *
 * Names are scoped per container by convention only, so two stacks can both declare a
 * router called `web`. That yields two candidates and no match, which is correct:
 * without more evidence there is nothing to distinguish them.
 */
function buildRouterNameIndex(stacks: AppStack[]): Map<string, ServiceRef[]> {
  const out = new Map<string, ServiceRef[]>();
  for (const stack of stacks) {
    for (const svc of stack.services) {
      for (const route of svc.traefik) {
        const key = route.router.toLowerCase();
        const list = out.get(key);
        if (list) list.push({ stackId: stack.id, serviceName: svc.name });
        else out.set(key, [{ stackId: stack.id, serviceName: svc.name }]);
      }
    }
  }
  for (const [key, refs] of out) out.set(key, unique(refs));
  return out;
}

/**
 * Collapse hits to one per service.
 *
 * Repeated evidence for a single service is not ambiguity: a load balancer commonly
 * lists several backends that all resolve to the same container, and a router
 * routinely serves several hostnames of one service.
 */
function unique(refs: ServiceRef[]): ServiceRef[] {
  const seen = new Set<string>();
  return refs.filter((r) => {
    const key = serviceRefKey(r);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function qualify(router: TraefikLiveRouter): string {
  return router.provider ? `${router.router}@${router.provider}` : router.router;
}

/** What the live read established, for the per-service report below. */
export interface TraefikLiveContext {
  /** Whether an endpoint answered and its runtime configuration was read. */
  reachable: boolean;
  /**
   * Whether that read also covered `/api/entrypoints`. Only then is "not in the live
   * chain" the same statement as "not enforced": an entrypoint-level middleware
   * appears in no router's own list, so without it a gate one level up looks absent.
   */
  chainComplete: boolean;
  /** Endpoint that answered, origin only. */
  endpoint?: string;
  /** Whether that read needed a credential. */
  credential: "none" | "basic";
  /** `${stackId}/${serviceName}` of the proxy whose API answered, when identified. */
  proxyKey?: string;
  /**
   * Bare lowercased names of **every** router in the snapshot, matched or not.
   *
   * A label router is only reported as absent when no live router of that name exists
   * anywhere. Checking only the routers matched to *this* service would report an
   * ambiguous router — one the matcher could not attribute — as missing from the proxy
   * when the proxy is in fact serving it.
   */
  liveRouterNames: Set<string>;
  /** Whether a label-referenced middleware would have counted as an auth gate. */
  isAuthMiddleware(mw: string): boolean;
  /** Which scanned service an address on a container network belongs to, if one. */
  resolveDelegate(address: string): string | undefined;
}

/**
 * Report what the proxy's live configuration says that the labels do not.
 *
 * Every note here is a difference between two accounts of the same subject, which is
 * the only reason to read the API at all. None of them is derivable from either source
 * alone, and all of them are stated as observations with both sides named, so a reader
 * can see which account they are being asked to trust.
 *
 * Nothing is claimed when the API was not read: with `reachable` false this function
 * emits nothing at all, leaving the label-only report exactly as it was.
 */
export function noteTraefikLive(svc: Service, key: string, ctx: TraefikLiveContext): void {
  if (!ctx.reachable) return;

  const live = svc.traefikLive ?? [];
  const serving = live.filter(routerIsServing);

  // 1. A router the proxy is holding but not serving. It is neither ingress nor
  //    protection, and its errors are Traefik's own words for why.
  for (const router of live) {
    if (routerIsServing(router)) continue;
    const why = router.errors.length
      ? `: ${router.errors.join("; ")}`
      : router.status
        ? ` (status \`${router.status}\`)`
        : "";
    svc.notes.push(
      `Traefik is not serving router \`${qualify(router)}\`${why} — the route it describes does not reach this service, and any middleware on it enforces nothing.`,
    );
  }

  // 2. A router the labels declare that the proxy has no counterpart for at all.
  const absent = svc.traefik.filter((r) => !ctx.liveRouterNames.has(r.router.toLowerCase()));
  if (absent.length) {
    svc.notes.push(
      `Traefik router(s) ${absent.map((r) => `\`${r.router}\``).join(", ")} are declared in this service's labels, but the proxy is serving no router by that name — the label is present, the route is not.`,
    );
  }

  // 3. Declared auth middlewares the proxy did not attach. The sharp edge of this
  //    feature: it is the one finding that moves a service *towards* exposed, so it
  //    says exactly what was in the live chain, and says so differently when the read
  //    was incomplete.
  for (const route of svc.traefik) {
    const counterpart = serving.find((r) => r.router.toLowerCase() === route.router.toLowerCase());
    if (!counterpart) continue;
    const attached = new Set(counterpart.middlewares.map((m) => bareName(m.name).toLowerCase()));
    const missing = route.middlewares.filter(
      (m) => ctx.isAuthMiddleware(m) && !attached.has(bareName(m).toLowerCase()),
    );
    if (!missing.length) continue;
    const chain = counterpart.middlewares.length
      ? counterpart.middlewares.map((m) => `\`${m.name}\` (${m.type})`).join(" -> ")
      : "empty";
    const subject = `Label on router \`${route.router}\` declares auth middleware ${missing
      .map((m) => `\`${m}\``)
      .join(", ")}, but the chain Traefik built for it is ${chain}`;
    svc.notes.push(
      ctx.chainComplete
        ? `${subject}. The proxy's live configuration is what enforces requests, so the posture above follows it and not the label.`
        : `${subject}. Entrypoint middlewares could not be read, so a gate attached to the entrypoint cannot be ruled out and the label is still counted — the discrepancy is reported rather than acted on.`,
    );
  }

  // 4. Backend health, straight from the proxy's own view of it.
  const down = serving.flatMap((r) =>
    r.servers.filter((s) => (s.status ?? "").toUpperCase() === "DOWN").map((s) => ({ r, s })),
  );
  if (down.length) {
    svc.notes.push(
      `Traefik reports backend(s) ${down.map((d) => d.s.url).join(", ")} DOWN for router(s) ${[
        ...new Set(down.map((d) => `\`${qualify(d.r)}\``)),
      ].join(", ")} — the route is live but the proxy cannot currently reach this service.`,
    );
  }

  // 5. On the proxy itself: how LabView got in. An API that answered with no
  //    credential is the direct evidence that `api.insecure` is on — the question the
  //    operator could not answer from the config alone.
  if (ctx.proxyKey === key && ctx.credential === "none") {
    svc.notes.push(
      `This service's Traefik API answered at ${ctx.endpoint ?? "the discovered endpoint"} with no credential, so anything that can reach that address can read the proxy's entire runtime configuration — routers, services and middleware addresses.`,
    );
  }

  crossCheck(svc, serving, ctx);
}

/**
 * Hold the labels, the proxy and the identity provider against each other.
 *
 * Each says something about the same gate and none can be checked against itself. Two
 * outcomes are worth a note: all three agreeing, which is the only way a reader learns
 * the gate is real end to end; and the identity provider claiming a gate the proxy's
 * live chain does not implement, which is the failure mode neither source can reveal on
 * its own — Authentik reports a healthy outpost either way, and the labels look right.
 */
function crossCheck(svc: Service, serving: TraefikLiveRouter[], ctx: TraefikLiveContext): void {
  const gates = serving.flatMap((r) =>
    r.middlewares.filter((m) => m.type === "forwardauth" && !m.errors.length).map((m) => ({ r, m })),
  );
  const proxied = (svc.authentik?.applications ?? [])
    .flatMap((app) => app.providers.map((p) => ({ app, p })))
    .filter(({ p }) => p.kind === "proxy" && providerEnforces(p));

  if (gates.length && proxied.length) {
    const first = gates[0]!;
    const delegate = first.m.address ? ctx.resolveDelegate(first.m.address) : undefined;
    const labelled = svc.traefik.some((r) => r.middlewares.some((m) => ctx.isAuthMiddleware(m)));
    const parties = labelled ? "The labels, the proxy and Authentik agree" : "The proxy and Authentik agree";
    svc.notes.push(
      `${parties} on this service's gate: the proxy's live chain for \`${qualify(first.r)}\` delegates to \`${first.m.name}\`${
        first.m.address ? ` -> ${first.m.address}` : ""
      }${delegate ? ` (which is ${delegate})` : ""}, and Authentik ${proxied
        .map(({ app, p }) => `serves ${describeProvider(p)} for application "${app.name}"`)
        .join(", ")}.`,
    );
    return;
  }

  // Only a provider in one of the forward-auth modes belongs in the check below. In
  // Authentik's `proxy` mode the outpost *is* the backend — it terminates the request
  // and forwards upstream itself — so there is no forward-auth middleware to look for
  // and its absence says nothing at all. Reading it as a bypass would invent a finding
  // on a correctly configured deployment, so a mode that does not forward, or that the
  // API did not report, produces no note.
  const forwarding = proxied.filter(({ p }) => /^forward/i.test(p.mode ?? ""));
  if (forwarding.length && ctx.chainComplete && serving.length && !gates.length) {
    svc.notes.push(
      `Authentik ${forwarding
        .map(({ app, p }) => `${describeProvider(p)} for application "${app.name}"`)
        .join(", ")} is meant to gate this service in \`${forwarding[0]!.p.mode}\` mode, but the chain Traefik built for router(s) ${serving
        .map((r) => `\`${qualify(r)}\``)
        .join(", ")} contains no forward-auth — a request through the proxy never reaches the outpost.`,
    );
  }
}

function describeProvider(p: AuthentikProvider): string {
  return `proxy provider "${p.name}" (outpost ${p.outposts.join(", ")})`;
}

/** A middleware reference without its provider suffix, for comparing the two sides. */
function bareName(name: string): string {
  return name.replace(/@.*$/, "");
}
