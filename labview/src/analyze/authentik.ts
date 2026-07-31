/**
 * Tie Authentik applications to the services they protect.
 *
 * The API says which applications exist and how they are gated; the compose scan
 * says which services exist and what addresses they answer on. Neither side carries
 * the other's identifier, so a match has to be established from something both sides
 * name independently. Three such things exist, in descending strength:
 *
 *  1. **A proxy provider's internal host.** This is the address the outpost forwards
 *     authenticated traffic to — the strongest possible evidence, because it is
 *     literally the provider pointing at the service. Resolved with the same rules
 *     `origins.ts` applies to a tunnel origin, since it is the same kind of address.
 *  2. **A hostname.** An application's launch URL, a proxy provider's external host
 *     or an OAuth2 redirect URI names a public hostname; a service's DockFlare or
 *     Traefik labels name the hostnames it serves. Equality of those is an
 *     observation about one hostname, not a guess.
 *  3. **The slug.** Authentik slugs are operator-chosen and frequently equal the
 *     stack directory, the compose service name or the container name. Weakest of
 *     the three, and therefore tried last.
 *
 * Ambiguity is discarded, never arbitrated — the discipline `origins.ts` already
 * applies to a contested port. An application whose slug matches a stack holding
 * three services identifies no one service, so it stays unmatched and is reported as
 * such. A wrong match here would move a service between "protected" and "exposed",
 * so a missing match is by far the cheaper error.
 */
import type { AppStack, AuthentikApplication, Service } from "../model/types.js";
import {
  lookupAddress,
  normalizeHost,
  serviceRefKey,
  type FleetIndex,
  type ServiceRef,
} from "./origins.js";

export interface AuthentikMatchOutcome {
  /** Number of services matched to at least one application. */
  matchedServices: number;
  /** Slugs of applications no single service could be identified for. */
  unmatchedApplications: string[];
}

/**
 * Attach `svc.authentik` to every service an application could be tied to.
 *
 * Mutates the stacks in place, like `resolveOrigins`, so pass 2 of the analyzer can
 * read the result while deriving auth posture.
 */
export function matchAuthentik(
  stacks: AppStack[],
  applications: AuthentikApplication[],
  index: FleetIndex,
): AuthentikMatchOutcome {
  if (!applications.length) return { matchedServices: 0, unmatchedApplications: [] };

  const services = new Map<string, { stack: AppStack; svc: Service }>();
  for (const stack of stacks) {
    for (const svc of stack.services) services.set(`${stack.id}/${svc.name}`, { stack, svc });
  }
  const bySlugCandidate = buildNameIndex(stacks);

  const unmatched: string[] = [];
  for (const app of applications) {
    const hit = matchOne(app, index, index.byHostname, bySlugCandidate);
    if (!hit) {
      unmatched.push(app.slug);
      continue;
    }
    const target = services.get(hit.key);
    if (!target) {
      unmatched.push(app.slug);
      continue;
    }
    const match = (target.svc.authentik ??= { applications: [], evidence: [] });
    match.applications.push(app);
    match.evidence.push(hit.evidence);
  }

  let matchedServices = 0;
  for (const { svc } of services.values()) if (svc.authentik) matchedServices++;
  return { matchedServices, unmatchedApplications: unmatched };
}

interface Hit {
  /** `${stackId}/${serviceName}` of the matched service. */
  key: string;
  evidence: string;
}

function matchOne(
  app: AuthentikApplication,
  index: FleetIndex,
  byHostname: Map<string, ServiceRef[]>,
  byName: Map<string, ServiceRef[]>,
): Hit | undefined {
  // 1. A proxy provider's internal host is the provider naming the service outright.
  for (const provider of app.providers) {
    if (!provider.internalHost) continue;
    const refs = lookupAddress(provider.internalHost, index);
    if (refs.length !== 1) continue;
    return {
      key: serviceRefKey(refs[0]!),
      evidence: `Authentik application "${app.name}" (${app.slug}): its ${describe(provider)} forwards authenticated traffic to ${provider.internalHost}, which is this service.`,
    };
  }

  // 2. A hostname both sides name. In `forward_domain` mode the external host is the
  //    Authentik domain shared by every application in that domain, so it identifies
  //    no single service and is excluded — the launch URL is what distinguishes them.
  for (const [url, why] of urlEvidence(app)) {
    const host = hostname(url);
    if (!host) continue;
    const refs = byHostname.get(host);
    if (refs?.length !== 1) continue;
    return {
      key: serviceRefKey(refs[0]!),
      evidence: `Authentik application "${app.name}" (${app.slug}): ${why} names ${host}, a hostname this service is configured to serve.`,
    };
  }

  // 3. The slug. Operator-chosen on both sides, so equality is suggestive rather
  //    than addressed — last resort, and only when it points at exactly one service.
  const refs = byName.get(app.slug.toLowerCase());
  if (refs?.length === 1) {
    return {
      key: serviceRefKey(refs[0]!),
      evidence: `Authentik application "${app.name}": its slug "${app.slug}" matches this service's stack, compose or container name.`,
    };
  }
  return undefined;
}

/** URLs worth matching on, each with the wording for the evidence line. */
function urlEvidence(app: AuthentikApplication): [string, string][] {
  const out: [string, string][] = [];
  if (app.launchUrl) out.push([app.launchUrl, "its launch URL"]);
  for (const provider of app.providers) {
    if (provider.externalHost && provider.mode !== "forward_domain") {
      out.push([provider.externalHost, `the external host of its ${describe(provider)}`]);
    }
    for (const uri of provider.redirectUris ?? []) {
      out.push([uri, `a redirect URI of its ${describe(provider)}`]);
    }
  }
  return out;
}

function describe(provider: { kind: string; name: string; backchannel: boolean }): string {
  return `${provider.kind} provider "${provider.name}"${provider.backchannel ? " (backchannel)" : ""}`;
}

/**
 * Names a slug could plausibly equal: the stack directory, the compose service name
 * and the container name.
 *
 * The stack name is included deliberately even though it usually maps to several
 * services — a multi-service stack then yields several candidates and the match is
 * discarded, which is the honest outcome. For the very common single-service stack it
 * is the name the operator would have used in Authentik.
 */
function buildNameIndex(stacks: AppStack[]): Map<string, ServiceRef[]> {
  const out = new Map<string, ServiceRef[]>();
  for (const stack of stacks) {
    for (const svc of stack.services) {
      const ref = { stackId: stack.id, serviceName: svc.name };
      for (const name of [stack.id, stack.name, svc.name, svc.containerName]) {
        if (name) push(out, name.toLowerCase(), ref);
      }
    }
  }
  // Collapse repeats: a stack whose directory, name and single service all agree is
  // one candidate, not four.
  for (const [key, refs] of out) out.set(key, dedupe(refs));
  return out;
}

function push(map: Map<string, ServiceRef[]>, key: string, ref: ServiceRef): void {
  const list = map.get(key);
  if (list) list.push(ref);
  else map.set(key, [ref]);
}

function dedupe(refs: ServiceRef[]): ServiceRef[] {
  const seen = new Set<string>();
  return refs.filter((r) => {
    const key = serviceRefKey(r);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Hostname of a URL, tolerating a bare host with no scheme. */
function hostname(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    return normalizeHost(new URL(withScheme).hostname);
  } catch {
    return undefined;
  }
}
