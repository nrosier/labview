import { readFileSync, statSync } from "node:fs";
import { basename } from "node:path";
import { parse as parseYaml } from "yaml";
import type {
  Declaration,
  DeclaredAuth,
  DeclaredDependency,
  DeclaredLink,
  DeclaredServiceDependency,
  IngressKind,
  ServiceDeclaration,
} from "../model/types.js";
import { DECLARED_AUTH_MECHANISMS, isDeclaredAuthMechanism } from "../model/declarations.js";
import { INGRESS_KINDS, isIngressKind, normalizeIngress } from "../model/ingress.js";
import { redactUriCredentials } from "../secrets.js";
import { resolveContained } from "./paths.js";
import type { DiscoveredStack } from "./discover.js";

/**
 * The `.labview` sidecar: what the operator declares about a stack that no scan can
 * observe — what a service is, that it authenticates itself, that it is deliberately
 * left open.
 *
 * Two rules shape this whole module.
 *
 * **Nothing here is evidence.** The parser produces declarations and only
 * declarations; it never touches an `AuthPosture` and never decides an exposure. What
 * the analyzer then does with them is equally hands-off — see `noteDeclarations`.
 *
 * **A sidecar is untrusted input, like the compose file beside it.** Its contents are
 * served verbatim on `/api/overview`, so every string is length-capped, every list is
 * entry-capped, the file itself is size-capped, and the path is containment-checked
 * before it is read. A malformed or hostile sidecar produces warnings and a partial
 * result — never a failed scan (invariant I4).
 *
 * Deliberately *not* interpolated with the stack's `.env`: declarations are prose, so
 * `${VAR}` is left exactly as written rather than silently resolved or blanked.
 */

/** Refuse anything larger; a sidecar is prose, and this is already generous. */
export const MAX_SIDECAR_BYTES = 64 * 1024;
/** Truncate any single declared string to this many characters. */
export const MAX_TEXT_CHARS = 2000;
/** Cap on `links`, `dependencies` and `depends_on`, each counted separately. */
export const MAX_LIST_ENTRIES = 32;
/** Cap on declared auth mechanisms for one service. */
export const MAX_AUTH_ENTRIES = 8;

export interface SidecarResult {
  /** Stack-level declarations, absent when the file declared none. */
  stack?: Declaration;
  /** Service-level declarations by compose service name. */
  services: Map<string, ServiceDeclaration>;
  /** Everything wrong with the file, in the operator's terms. Never fatal. */
  warnings: string[];
}

/** Keys accepted at the top level of the file. */
const STACK_KEYS = [
  "description",
  "owner",
  "criticality",
  "notes",
  "data",
  "links",
  "dependencies",
  "services",
] as const;

/** Keys accepted under `services.<name>`. */
const SERVICE_KEYS = [
  "description",
  "owner",
  "criticality",
  "notes",
  "data",
  "links",
  "dependencies",
  "depends_on",
  "auth",
  "unauthenticated",
  "expected",
] as const;

function emptyResult(warnings: string[] = []): SidecarResult {
  return { services: new Map(), warnings };
}

/**
 * Read the stack's sidecar, if it has one. `serviceNames` is what the compose file
 * defines, so a declaration for a service that does not exist can be reported
 * instead of silently doing nothing.
 *
 * `appsRoot` is the containment boundary, exactly as for `env_file`. LabView builds
 * the path itself, so the only way out of the tree is a symlink — and the contents of
 * whatever it pointed at would be echoed back as a `description`.
 */
export function readSidecar(
  disc: DiscoveredStack,
  appsRoot: string,
  serviceNames: string[],
): SidecarResult {
  if (!disc.sidecarFile) return emptyResult();
  const file = basename(disc.sidecarFile);

  const path = resolveContained(disc.dir, appsRoot, file);
  if (path === null) {
    return emptyResult([`ignored ${file}: it resolves outside the apps root`]);
  }

  let text: string;
  try {
    const { size } = statSync(path);
    if (size > MAX_SIDECAR_BYTES) {
      return emptyResult([
        `ignored ${file}: ${size} bytes exceeds the ${MAX_SIDECAR_BYTES}-byte limit for a sidecar`,
      ]);
    }
    text = readFileSync(path, "utf8");
  } catch (err) {
    return emptyResult([`could not read ${file}: ${(err as Error).message}`]);
  }

  return parseSidecar(text, serviceNames, file);
}

/**
 * Parse sidecar text. Pure — no I/O, no clock — so every validation rule below can be
 * asserted directly without committing a fixture file for it.
 */
export function parseSidecar(text: string, serviceNames: string[], file: string): SidecarResult {
  const warnings: string[] = [];
  const services = new Map<string, ServiceDeclaration>();

  let doc: unknown;
  try {
    doc = parseYaml(text) ?? {};
  } catch (err) {
    return emptyResult([`${file}: YAML parse error: ${(err as Error).message}; declarations ignored`]);
  }
  if (!isMapping(doc)) {
    // An empty file is a normal thing to have; anything else at the top level is not.
    if (text.trim() !== "") {
      warnings.push(`${file}: expected a mapping at the top level; declarations ignored`);
    }
    return emptyResult(warnings);
  }

  // A service-level key written at the top level. Named rather than lumped in with the
  // unknown keys, because it is spelled correctly and would parse — "unknown key" would
  // send the operator hunting for a typo instead of telling them what is actually wrong:
  // one entry here could not say *which* of the stack's services depends on the target.
  const stackKeys: readonly string[] =
    "depends_on" in doc ? [...STACK_KEYS, "depends_on"] : STACK_KEYS;
  if ("depends_on" in doc) {
    warnings.push(
      `${file}: "depends_on" is a service-level key — at stack level it cannot say which ` +
        `service depends on the target; ignored`,
    );
  }
  warnUnknownKeys(doc, stackKeys, file, file, warnings);
  const stack = readCommon(doc, file, file, warnings);

  const rawServices = doc.services;
  if (rawServices !== undefined && rawServices !== null) {
    if (!isMapping(rawServices)) {
      warnings.push(`${file}: "services" must be a mapping of service name to declaration; ignored`);
    } else {
      for (const [name, value] of Object.entries(rawServices)) {
        const where = `${file} services.${name}`;
        if (!serviceNames.includes(name)) {
          warnings.push(
            `${file}: declares service "${name}", which this compose file does not define; ignored`,
          );
          continue;
        }
        if (!isMapping(value)) {
          warnings.push(`${where}: expected a mapping; ignored`);
          continue;
        }
        warnUnknownKeys(value, SERVICE_KEYS, file, where, warnings);

        const decl: ServiceDeclaration = {
          ...readCommon(value, file, where, warnings),
          dependsOn: readDependsOn(value.depends_on, where, warnings),
          auth: readAuth(value.auth, where, warnings),
          unauthenticatedAccepted: readUnauthenticated(value.unauthenticated, where, warnings),
          expectedIngress: readExpected(value.expected, where, warnings),
          drift: [],
        };
        if (hasServiceContent(decl)) services.set(name, decl);
      }
    }
  }

  return { stack: hasContent(stack) ? stack : undefined, services, warnings };
}

/* -------------------------------------------------------------------------- */
/* field readers                                                              */
/* -------------------------------------------------------------------------- */

/** The fields both levels share. */
function readCommon(
  node: Record<string, unknown>,
  file: string,
  where: string,
  warnings: string[],
): Declaration {
  return {
    file,
    description: readText(node.description, `${where}.description`, warnings),
    owner: readText(node.owner, `${where}.owner`, warnings),
    criticality: readText(node.criticality, `${where}.criticality`, warnings),
    notes: readText(node.notes, `${where}.notes`, warnings),
    data: readText(node.data, `${where}.data`, warnings),
    links: readLinks(node.links, where, warnings),
    dependencies: readDependencies(node.dependencies, where, warnings),
  };
}

/**
 * One declared string, trimmed, capped and reported when capped. Numbers and
 * booleans are accepted as written (`criticality: 1`, `owner: true` are unambiguous);
 * a list or mapping where prose was expected is a mistake worth naming.
 */
function readText(value: unknown, where: string, warnings: string[]): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "object") {
    warnings.push(`${where}: expected text; ignored`);
    return undefined;
  }
  const text = String(value).trim();
  if (text === "") return undefined;
  if (text.length > MAX_TEXT_CHARS) {
    warnings.push(`${where}: truncated to ${MAX_TEXT_CHARS} characters`);
    return `${text.slice(0, MAX_TEXT_CHARS)}…`;
  }
  return text;
}

function readLinks(value: unknown, where: string, warnings: string[]): DeclaredLink[] {
  const items = readList(value, `${where}.links`, warnings);
  const out: DeclaredLink[] = [];
  for (const [index, item] of items.entries()) {
    const at = `${where}.links[${index}]`;
    if (!isMapping(item)) {
      warnings.push(`${at}: expected {label, url}; ignored`);
      continue;
    }
    warnUnknownKeys(item, ["label", "url"] as const, where, at, warnings);
    const url = readText(item.url, `${at}.url`, warnings);
    if (!url) {
      warnings.push(`${at}: needs a "url"; ignored`);
      continue;
    }
    // A link list is the one place a URL with an inline password plausibly lands, and
    // unlike an env value it is never masked downstream — so mask it here. Redact
    // *before* the label falls back to it: the label is the visible link text, so a
    // fallback to the raw URL would put the password back on the page.
    const safe = redactUriCredentials(url) ?? url;
    out.push({ label: readText(item.label, `${at}.label`, warnings) ?? safe, url: safe });
  }
  return capList(out, `${where}.links`, warnings);
}

function readDependencies(value: unknown, where: string, warnings: string[]): DeclaredDependency[] {
  const items = readList(value, `${where}.dependencies`, warnings);
  const out: DeclaredDependency[] = [];
  for (const [index, item] of items.entries()) {
    const at = `${where}.dependencies[${index}]`;
    // A bare string is the common case: "the NAS share".
    if (typeof item === "string") {
      const name = readText(item, at, warnings);
      if (name) out.push({ name });
      continue;
    }
    if (!isMapping(item)) {
      warnings.push(`${at}: expected a name or {name, detail}; ignored`);
      continue;
    }
    warnUnknownKeys(item, ["name", "detail"] as const, where, at, warnings);
    const name = readText(item.name, `${at}.name`, warnings);
    if (!name) {
      warnings.push(`${at}: needs a "name"; ignored`);
      continue;
    }
    out.push({ name, detail: readText(item.detail, `${at}.detail`, warnings) });
  }
  return capList(out, `${where}.dependencies`, warnings);
}

/**
 * `depends_on`: references to other scanned services.
 *
 * Nothing is resolved here — the parser sees one stack and the target usually lives in
 * another — so the reference is kept exactly as written and checked only for a shape that
 * could name a service at all. `stack/service` and a bare `service` both can;
 * `a/b/c` cannot, and neither can a name with a blank half, so those are refused here
 * rather than travelling on to the resolver as references that can never match.
 *
 * The long form's key is `service` rather than `dependencies`' `name`, because that is
 * what it has to be: a compose service, named as the scan names it.
 */
function readDependsOn(
  value: unknown,
  where: string,
  warnings: string[],
): DeclaredServiceDependency[] {
  const items = readList(value, `${where}.depends_on`, warnings);
  const out: DeclaredServiceDependency[] = [];
  for (const [index, item] of items.entries()) {
    const at = `${where}.depends_on[${index}]`;
    let ref: string | undefined;
    let detail: string | undefined;
    if (typeof item === "string" || typeof item === "number") {
      ref = readText(item, at, warnings);
    } else if (isMapping(item)) {
      warnUnknownKeys(item, ["service", "detail"] as const, where, at, warnings);
      ref = readText(item.service, `${at}.service`, warnings);
      if (!ref) {
        warnings.push(`${at}: needs a "service"; ignored`);
        continue;
      }
      detail = readText(item.detail, `${at}.detail`, warnings);
    } else {
      warnings.push(`${at}: expected "stack/service" or {service, detail}; ignored`);
      continue;
    }
    if (!ref) continue;
    if (!isServiceRefShape(ref)) {
      warnings.push(
        `${at}: "${ref}" is not a service reference — write "stack/service", or the ` +
          `service name on its own; ignored`,
      );
      continue;
    }
    out.push({ ref, ...(detail ? { detail } : {}) });
  }
  return capList(out, `${where}.depends_on`, warnings);
}

/**
 * Whether a reference could name a scanned service: one name, or a stack and a name,
 * with nothing blank and no whitespace inside. Says nothing about whether it *does* —
 * that is the resolver's answer, and its four outcomes are reported as drift.
 */
function isServiceRefShape(ref: string): boolean {
  const parts = ref.split("/");
  if (parts.length > 2) return false;
  return parts.every((p) => p.length > 0 && !/\s/.test(p));
}

function readAuth(value: unknown, where: string, warnings: string[]): DeclaredAuth[] {
  const items = readList(value, `${where}.auth`, warnings);
  const out: DeclaredAuth[] = [];
  for (const [index, item] of items.entries()) {
    const at = `${where}.auth[${index}]`;
    // Shorthand: `auth: [app-local-accounts, app-ldap]` when there is nothing to add.
    const shorthand = typeof item === "string";
    const raw: unknown = shorthand ? { mechanism: item } : item;
    if (!isMapping(raw)) {
      warnings.push(`${at}: expected a mechanism name or {mechanism, detail}; ignored`);
      continue;
    }
    if (!shorthand) warnUnknownKeys(raw, ["mechanism", "detail"] as const, where, at, warnings);
    const mechanism = readText(raw.mechanism, `${at}.mechanism`, warnings);
    if (!mechanism) {
      warnings.push(`${at}: needs a "mechanism"; ignored`);
      continue;
    }
    if (!isDeclaredAuthMechanism(mechanism)) {
      warnings.push(
        `${at}: "${mechanism}" is not a known mechanism (${DECLARED_AUTH_MECHANISMS.join(", ")}); ignored`,
      );
      continue;
    }
    const detail = readText(raw.detail, `${at}.detail`, warnings);
    // "other" says only that something exists; without the explanation it reports
    // nothing a reader can act on, so it is refused rather than shown empty.
    if (mechanism === "other" && !detail) {
      warnings.push(`${at}: mechanism "other" needs a "detail" saying what it is; ignored`);
      continue;
    }
    out.push({ mechanism, detail });
  }
  if (out.length > MAX_AUTH_ENTRIES) {
    warnings.push(`${where}.auth: more than ${MAX_AUTH_ENTRIES} entries; the rest ignored`);
    return out.slice(0, MAX_AUTH_ENTRIES);
  }
  return out;
}

/**
 * The acceptance of an unauthenticated service. Both halves are required: an
 * acceptance with no reason cannot be told apart from a stray key, and it would
 * quiet a real finding on the strength of a typo. So it is refused, loudly.
 */
function readUnauthenticated(
  value: unknown,
  where: string,
  warnings: string[],
): { reason: string } | undefined {
  if (value === undefined || value === null) return undefined;
  const at = `${where}.unauthenticated`;
  if (!isMapping(value)) {
    warnings.push(`${at}: expected {intentional, reason}; ignored`);
    return undefined;
  }
  warnUnknownKeys(value, ["intentional", "reason"] as const, where, at, warnings);

  if (value.intentional !== true) {
    warnings.push(`${at}: needs "intentional: true" to apply; ignored`);
    return undefined;
  }
  const reason = readText(value.reason, `${at}.reason`, warnings);
  if (!reason) {
    warnings.push(
      `${at}: "intentional: true" needs a "reason" — an acceptance with no reason cannot be told from a mistake; ignored`,
    );
    return undefined;
  }
  return { reason };
}

/**
 * The declared expectation, which the analyzer compares against and never applies.
 *
 * `ingress` accepts either one kind or a list of them, because a service can have
 * several at once and the expectation has to be able to say so — `ingress: lan` and
 * `ingress: [public, traefik]` are both valid. A list with one bad entry keeps the
 * good ones and warns about the rest, rather than discarding the whole expectation
 * over a typo.
 */
function readExpected(value: unknown, where: string, warnings: string[]): IngressKind[] | undefined {
  if (value === undefined || value === null) return undefined;
  const at = `${where}.expected`;
  if (!isMapping(value)) {
    warnings.push(`${at}: expected {ingress}; ignored`);
    return undefined;
  }
  warnUnknownKeys(value, ["ingress"] as const, where, at, warnings);
  if (value.ingress === undefined || value.ingress === null) return undefined;

  // The list branch comes first: `readText` refuses anything that is not a scalar,
  // so a list reaching it would be reported as the wrong type instead of read.
  const entries = Array.isArray(value.ingress) ? value.ingress : [value.ingress];
  const kinds: IngressKind[] = [];
  for (const [i, entry] of entries.entries()) {
    const label = Array.isArray(value.ingress) ? `${at}.ingress[${i}]` : `${at}.ingress`;
    const kind = readText(entry, label, warnings);
    if (!kind) continue;
    if (!isIngressKind(kind)) {
      warnings.push(`${label}: "${kind}" is not one of ${INGRESS_KINDS.join(", ")}; ignored`);
      continue;
    }
    kinds.push(kind);
  }
  // Nothing survived: report no expectation at all rather than an empty one, which
  // `normalizeIngress` would turn into an expectation of `none` nobody wrote.
  if (!kinds.length) return undefined;
  // Normalized through the same constructor the classifier uses, so the two sides of the
  // comparison are built by one rule. That also silently drops an `internal` written
  // beside an external kind: it is implied there, the scan will never report it, and
  // drifting against a rule the file cannot know would punish an accurate sidecar.
  return normalizeIngress(kinds);
}

/* -------------------------------------------------------------------------- */
/* helpers                                                                    */
/* -------------------------------------------------------------------------- */

function isMapping(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readList(value: unknown, where: string, warnings: string[]): unknown[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    warnings.push(`${where}: expected a list; ignored`);
    return [];
  }
  return value;
}

function capList<T>(items: T[], where: string, warnings: string[]): T[] {
  if (items.length <= MAX_LIST_ENTRIES) return items;
  warnings.push(`${where}: more than ${MAX_LIST_ENTRIES} entries; the rest ignored`);
  return items.slice(0, MAX_LIST_ENTRIES);
}

/**
 * Report a key nobody will read. Without this a typo (`descripton:`) is dropped in
 * silence and the operator believes the declaration took effect — the one failure
 * mode of an optional-everything format.
 */
function warnUnknownKeys(
  node: Record<string, unknown>,
  allowed: readonly string[],
  file: string,
  where: string,
  warnings: string[],
): void {
  const unknown = Object.keys(node).filter((k) => !allowed.includes(k));
  if (!unknown.length) return;
  const scope = where === file ? file : where;
  warnings.push(`${scope}: unknown key(s) ${unknown.map((k) => `"${k}"`).join(", ")}; ignored`);
}

function hasContent(d: Declaration): boolean {
  return Boolean(
    d.description || d.owner || d.criticality || d.notes || d.data || d.links.length || d.dependencies.length,
  );
}

function hasServiceContent(d: ServiceDeclaration): boolean {
  return (
    hasContent(d) ||
    d.dependsOn.length > 0 ||
    d.auth.length > 0 ||
    Boolean(d.unauthenticatedAccepted) ||
    Boolean(d.expectedIngress)
  );
}
