/**
 * Tie Authentik applications to the services they protect.
 *
 * The API says which applications exist and how they are gated; the compose scan
 * says which services exist and what addresses they answer on. Neither side carries
 * the other's identifier, so a match has to be established from something both sides
 * name independently. Four such things exist, in descending strength:
 *
 *  1. **A proxy provider's internal host.** This is the address the outpost forwards
 *     authenticated traffic to — the strongest possible evidence, because it is
 *     literally the provider pointing at the service. Resolved with the same rules
 *     `origins.ts` applies to a tunnel origin, since it is the same kind of address.
 *  2. **An address inside a URL the provider hands out.** A launch URL, an external
 *     host or an OAuth2 redirect URI whose host is a bare name is the provider
 *     addressing a container: `http://app:3000/oauth/callback` is not a coincidence
 *     of wording, it is a pointer, and compose publishes that name as the container's
 *     DNS alias. This is the rule that reaches a service with no public hostname at
 *     all, which for OIDC is the common case — an OIDC gate leaves no trace in the
 *     compose file, so the API is the only place it can be seen.
 *  3. **A hostname.** The same URLs also name public hostnames; a service's DockFlare
 *     or Traefik labels name the hostnames it serves. Equality of those is an
 *     observation about one hostname, not a guess.
 *  4. **A name** — the slug, the application name, or a provider name. All are
 *     operator-chosen on both sides, so equality is suggestive rather than addressed:
 *     weakest of the four, tried last, and reported at lower confidence than the rest
 *     (`AuthentikMatchStrength`). Compared after normalizing away separators and the
 *     words that describe the *mechanism* rather than the application, because
 *     Authentik's own wizard names things "Provider for X" and an operator writing
 *     "Home Assistant" means the `home-assistant` stack.
 *
 * Ambiguity is discarded, never arbitrated — the discipline `origins.ts` already
 * applies to a contested port. A name matching a stack holding three services
 * identifies no one service, so it stays unmatched and is reported as such. A wrong
 * match here would move a service between "protected" and "exposed", so a missing
 * match is by far the cheaper error.
 */
import type {
  AppStack,
  AuthentikApplication,
  AuthentikMatchStrength,
  Service,
  UnmatchedApplication,
  UnmatchedReason,
} from "../model/types.js";
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
  /**
   * Applications no single service could be identified for, each carrying why.
   *
   * The reason is part of the answer, not decoration. "Two services answer to this
   * name" is the operator's to fix by making one name distinct; "nothing named or
   * addressed anything" usually is not. Reporting both as a bare slug — which is all
   * this used to carry — hides the actionable one behind the inert one.
   */
  unmatchedApplications: UnmatchedApplication[];
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
  const names = buildNameIndex(stacks);

  const unmatched: UnmatchedApplication[] = [];
  for (const app of applications) {
    const outcome = matchOne(app, index, index.byHostname, names);
    if (!("key" in outcome)) {
      unmatched.push({ application: app, ...outcome });
      continue;
    }
    const target = services.get(outcome.key);
    if (!target) {
      // Defensive only: every key a rule can produce comes from an index built from
      // these same stacks. Report it rather than dropping the application silently,
      // so a future index that outlives its stacks is visible instead of invisible.
      unmatched.push({
        application: app,
        reason: "internal",
        detail: `matched ${outcome.key}, which this scan does not hold`,
        considered: [outcome.evidence],
      });
      continue;
    }
    const match = (target.svc.authentik ??= { applications: [], evidence: [], strength: [] });
    match.applications.push(app);
    match.evidence.push(outcome.evidence);
    match.strength.push(outcome.strength);
  }

  let matchedServices = 0;
  for (const { svc } of services.values()) if (svc.authentik) matchedServices++;
  return { matchedServices, unmatchedApplications: unmatched };
}

interface Hit {
  /** `${stackId}/${serviceName}` of the matched service. */
  key: string;
  evidence: string;
  strength: AuthentikMatchStrength;
}

/** No rule placed the application, and why — everything but the application itself. */
type Unplaced = Omit<UnmatchedApplication, "application">;

function matchOne(
  app: AuthentikApplication,
  index: FleetIndex,
  byHostname: Map<string, ServiceRef[]>,
  names: NameIndex,
): Hit | Unplaced {
  // Every rule that does not fire says so. Two of those outcomes are worth telling
  // apart from a plain miss, because they are the ones an operator can act on or would
  // otherwise report as a bug:
  //
  //  * **contested** — the rule pointed at more than one service and was discarded
  //    rather than arbitrated. Actionable: make one of the names distinct.
  //  * **blocked** — there was evidence, and LabView deliberately declined to resolve
  //    it (an address literal, a residue too short to mean anything, a host shared by
  //    every application in a domain). Without saying so, refusing looks like failing.
  //
  // The strongest rule runs first, so the first of each is the one worth leading with.
  const considered: string[] = [];
  let contested: string | undefined;
  let blocked: string | undefined;
  const note = (line: string, kind?: "contested" | "blocked"): void => {
    if (!considered.includes(line)) considered.push(line);
    if (kind === "contested") contested ??= line;
    if (kind === "blocked") blocked ??= line;
  };

  // 1. A proxy provider's internal host is the provider naming the service outright.
  let addressed = false;
  for (const provider of app.providers) {
    if (!provider.internalHost) continue;
    addressed = true;
    const refs = lookupAddress(provider.internalHost, index);
    if (refs.length === 1) {
      return {
        key: serviceRefKey(refs[0]!),
        strength: "address",
        evidence: `Authentik application "${app.name}" (${app.slug}): its ${describe(provider)} forwards authenticated traffic to ${provider.internalHost}, which is this service.`,
      };
    }
    note(
      `its ${describe(provider)} forwards authenticated traffic to ${provider.internalHost}, which resolves to ${tally(refs)}.`,
      refs.length > 1 ? "contested" : undefined,
    );
  }
  if (!addressed) note("no proxy provider, so there is no forwarded address to resolve.");

  // The URLs the provider hands out serve rules 2 and 3, read two different ways: as
  // an address of a container, then as a public hostname. In `forward_domain` mode
  // the external host is the Authentik domain shared by every application in that
  // domain, so it identifies no single service and is excluded from both — the launch
  // URL is what distinguishes them.
  const { urls, excluded } = urlEvidence(app);
  for (const line of excluded) note(line, "blocked");
  if (!urls.length && !excluded.length) {
    note("no launch URL, external host or redirect URI, so there is no URL to read.");
  }

  // 2. A bare-name host inside one of those URLs. Only a name form is resolved: an IP
  //    literal in a redirect URI addresses the *host*, and on a host running a reverse
  //    proxy the standard ports belong to the proxy rather than to the application, so
  //    resolving it through the published-port table would attach the application to
  //    whatever answers on 443. That is worse than no answer — the same reason
  //    `lookupContainerAddress` refuses to read a container IP as a published port.
  for (const [url, why] of urls) {
    const host = hostname(url);
    if (!host) {
      note(`${why} is ${JSON.stringify(url)}, which no host can be read from.`);
      continue;
    }
    if (!isNameHost(host)) {
      note(
        `${why} points at ${host}, an address literal rather than a name: it addresses the host, whose standard ports belong to whatever reverse proxy answers on them, so it is not resolved through the published-port table.`,
        "blocked",
      );
      continue;
    }
    const refs = lookupAddress(url, index);
    if (refs.length === 1) {
      return {
        key: serviceRefKey(refs[0]!),
        strength: "address",
        evidence: `Authentik application "${app.name}" (${app.slug}): ${why} points at ${host}, this service's compose or container name.`,
      };
    }
    note(
      `${why} points at ${host}, which resolves to ${tally(refs)}.`,
      refs.length > 1 ? "contested" : undefined,
    );
  }

  // 3. A hostname both sides name.
  for (const [url, why] of urls) {
    const host = hostname(url);
    if (!host) continue;
    const refs = byHostname.get(host);
    if (refs?.length === 1) {
      return {
        key: serviceRefKey(refs[0]!),
        strength: "hostname",
        evidence: `Authentik application "${app.name}" (${app.slug}): ${why} names ${host}, a hostname this service is configured to serve.`,
      };
    }
    // An address literal was already reported by rule 2; repeating it here would pad
    // the trace with the same fact worded differently.
    if (isNameHost(host)) {
      note(
        refs?.length
          ? `${why} names the hostname ${host}, declared by ${tally(refs)}.`
          : `${why} names the hostname ${host}, which no scanned service declares.`,
        refs && refs.length > 1 ? "contested" : undefined,
      );
    }
  }

  // 4. A name — the slug first, then the application's own name, then its providers'.
  //    Operator-chosen on both sides, so equality is suggestive rather than addressed:
  //    last resort, and only when it points at exactly one service.
  for (const [value, why] of nameCandidates(app)) {
    const found = resolveName(value, names);
    if (found.ref) {
      return {
        key: serviceRefKey(found.ref),
        strength: "name",
        evidence: `Authentik application "${app.name}": ${why} matches this service's stack, compose or container name.`,
      };
    }
    note(
      nameNote(why, found),
      found.contested ? "contested" : found.tooShort.length ? "blocked" : undefined,
    );
  }

  const reason: UnmatchedReason = contested ? "ambiguous" : "no-candidate";
  return {
    reason,
    detail:
      contested ??
      blocked ??
      "no address, hostname or name in this application identifies a scanned service.",
    considered,
  };
}

/** How a candidate list reads in a `considered` line. Only ever 0 or ≥ 2 — one is a match. */
function tally(refs: ServiceRef[]): string {
  if (!refs.length) return "no scanned service";
  const keys = refs.map(serviceRefKey).sort().join(", ");
  return `${refs.length} scanned services — ${keys} — so it identifies none of them`;
}

/** One `considered` line for a name candidate that did not place the application. */
function nameNote(why: string, found: NameResolution): string {
  const parts: string[] = [];
  if (found.contested) {
    parts.push(`${why} matches ${tally(found.contested)}`);
  } else if (found.tried.length) {
    parts.push(
      `no stack, compose or container name equals ${found.tried.map((k) => JSON.stringify(k)).join(" or ")}, tried for ${why}`,
    );
  } else {
    parts.push(`${why} is empty`);
  }
  if (found.tooShort.length) {
    parts.push(
      `the residue ${found.tooShort
        .map((k) => JSON.stringify(k))
        .join(", ")} left after dropping the words that name the mechanism is under ${MIN_DERIVED_KEY} characters, too short to identify a service`,
    );
  }
  return `${parts.join("; ")}.`;
}

/**
 * URLs worth matching on, each with the wording for the evidence line — and the ones
 * deliberately left out, worded for the report, so an exclusion is visible as a
 * decision rather than as an absence.
 */
function urlEvidence(app: AuthentikApplication): {
  urls: [string, string][];
  excluded: string[];
} {
  const out: [string, string][] = [];
  const excluded: string[] = [];
  if (app.launchUrl) out.push([app.launchUrl, "its launch URL"]);
  for (const provider of app.providers) {
    if (provider.externalHost) {
      if (provider.mode === "forward_domain") {
        excluded.push(
          `the external host of its ${describe(provider)} is ${provider.externalHost}, the Authentik domain shared by every application in \`forward_domain\` mode, so it names no single service and is not matched on.`,
        );
      } else {
        out.push([provider.externalHost, `the external host of its ${describe(provider)}`]);
      }
    }
    for (const uri of provider.redirectUris ?? []) {
      out.push([uri, `a redirect URI of its ${describe(provider)}`]);
    }
  }
  return { urls: out, excluded };
}

function describe(provider: { kind: string; name: string; backchannel: boolean }): string {
  return `${provider.kind} provider "${provider.name}"${provider.backchannel ? " (backchannel)" : ""}`;
}

/** The names of an application worth comparing, each with the wording for the evidence line. */
function nameCandidates(app: AuthentikApplication): [string, string][] {
  const out: [string, string][] = [[app.slug, `its slug "${app.slug}"`]];
  if (app.name && app.name !== app.slug) out.push([app.name, `its name "${app.name}"`]);
  for (const provider of app.providers) {
    out.push([provider.name, `the name of its ${describe(provider)}`]);
  }
  return out;
}

/**
 * The one service a name identifies, or nothing.
 *
 * Three forms are tried, narrowing only when the wider one found nobody: the name as
 * written, the name with separators removed, and the name with the words describing
 * the *mechanism* removed as well. Each form is a separate index rather than one
 * merged map, so adding the looser forms can never take away a match the exact form
 * already had — a stack `foo-bar` and a service `foobar` would otherwise collide into
 * a contested key and both be discarded.
 *
 * The first form that the fleet has *any* entry for decides, and a contested entry
 * decides against a match. Falling through from a contested key to a looser one would
 * be arbitrating ambiguity, and could not help anyway: every looser form pools at
 * least the same services.
 */
function resolveName(value: string, names: NameIndex): NameResolution {
  const raw = value.trim().toLowerCase();
  if (!raw) return { tried: [], tooShort: [] };
  const attempts: [Map<string, ServiceRef[]>, string][] = [[names.raw, raw]];
  const tooShort: string[] = [];
  for (const derived of [tighten(value), withoutGenericTokens(value)]) {
    // A one- or two-character residue carries no information: a provider named "DB"
    // would otherwise pin an application to whichever service happens to be short.
    if (derived.length >= MIN_DERIVED_KEY) attempts.push([names.tight, derived]);
    // A residue that came out empty is not a refusal — the name consisted only of
    // words describing the mechanism, so there was never anything to compare.
    else if (derived) tooShort.push(derived);
  }
  const seen = new Set<string>();
  const tried: string[] = [];
  for (const [map, key] of attempts) {
    if (seen.has(key)) continue;
    seen.add(key);
    tried.push(key);
    const refs = map.get(key);
    if (!refs) continue;
    return refs.length === 1
      ? { ref: refs[0], tried, tooShort }
      : { contested: refs, tried, tooShort };
  }
  return { tried, tooShort };
}

/** What a name lookup found, including the two ways it can find nothing usable. */
interface NameResolution {
  /** The one service the name identifies, when exactly one does. */
  ref?: ServiceRef;
  /** The services a key matched when more than one did — discarded, not arbitrated. */
  contested?: ServiceRef[];
  /** Keys looked up, in order, up to and including the one that decided. */
  tried: string[];
  /** Keys not looked up because the residue was too short to be conclusive. */
  tooShort: string[];
}

/**
 * The names of the fleet, indexed the two ways `resolveName` looks them up: exactly as
 * declared, and with separators removed.
 *
 * Both cover the stack directory, the stack name, the compose service name and the
 * container name. The stack name is included deliberately even though it usually maps
 * to several services — a multi-service stack then yields several candidates and the
 * match is discarded, which is the honest outcome. For the very common single-service
 * stack it is the name the operator would have used in Authentik.
 *
 * Only separators are removed on this side. The generic-token pass belongs to the
 * Authentik side, where names are decorated with the mechanism ("Provider for X"); a
 * service literally named `authentik-proxy` means that, and stripping `proxy` from it
 * would invent a collision with the identity provider's own stack.
 */
function buildNameIndex(stacks: AppStack[]): NameIndex {
  const raw = new Map<string, ServiceRef[]>();
  const tight = new Map<string, ServiceRef[]>();
  for (const stack of stacks) {
    for (const svc of stack.services) {
      const ref = { stackId: stack.id, serviceName: svc.name };
      for (const name of [stack.id, stack.name, svc.name, svc.containerName]) {
        if (!name) continue;
        push(raw, name.toLowerCase(), ref);
        const squeezed = tighten(name);
        if (squeezed) push(tight, squeezed, ref);
      }
    }
  }
  // Collapse repeats: a stack whose directory, name and single service all agree is
  // one candidate, not four.
  for (const map of [raw, tight]) {
    for (const [key, refs] of map) map.set(key, dedupe(refs));
  }
  return { raw, tight };
}

interface NameIndex {
  /** Names exactly as the fleet declares them, lowercased. */
  raw: Map<string, ServiceRef[]>;
  /** The same names with every separator removed. */
  tight: Map<string, ServiceRef[]>;
}

/**
 * Words that describe the authentication *mechanism* rather than the application, and
 * so carry no information about which service is meant. Authentik's own wizard names
 * providers after the protocol, and operators label them "… Provider" or "Provider for
 * …", which is why a name has to be compared with these removed as well as with them.
 *
 * Protocol and English words only — nothing here is specific to any fleet, and
 * `authentik` is deliberately absent: a stack named after the identity provider means
 * exactly that service.
 */
const GENERIC_NAME_TOKENS = new Set([
  "and",
  "app",
  "application",
  "auth",
  "authentication",
  "authorization",
  "client",
  "connect",
  "for",
  "forward",
  "ldap",
  "oauth",
  "oauth2",
  "oidc",
  "openid",
  "provider",
  "providers",
  "proxy",
  "radius",
  "saml",
  "scim",
  "sso",
  "the",
]);

/** Shortest residue allowed to identify a service by name. */
const MIN_DERIVED_KEY = 3;

/** Lowercased with every run of non-alphanumeric characters removed. */
function tighten(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

/** `tighten`, minus the whole words that only name the mechanism. */
function withoutGenericTokens(value: string): string {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token && !GENERIC_NAME_TOKENS.has(token))
    .join("");
}

/**
 * Whether a URL host is a name rather than an address literal — the only form rule 2
 * resolves. An IPv6 literal keeps its colons after URL parsing, and an IPv4 literal is
 * all digits and dots, so both fail this.
 */
function isNameHost(host: string): boolean {
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(host)) return false;
  return !/^\d{1,3}(\.\d{1,3}){3}$/.test(host);
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
