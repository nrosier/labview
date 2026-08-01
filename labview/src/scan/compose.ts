import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { parse as parseYaml } from "yaml";
import type {
  AppStack,
  Service,
  PortMapping,
  MountSpec,
  EnvVar,
  NetworkDecl,
  VolumeDecl,
} from "../model/types.js";
import { parseEnvFile, interpolate } from "./env.js";
import { resolveContained } from "./paths.js";
import { readSidecar } from "./sidecar.js";
import type { DiscoveredStack } from "./discover.js";

/**
 * Parse and normalize a single stack's compose file into an AppStack.
 *
 * `appsRoot` is the containment boundary for any file the compose document asks
 * us to read (currently `env_file`). Compose documents are untrusted input as
 * far as LabView is concerned — a `env_file: ../../../../etc/shadow` entry must
 * not be able to pull arbitrary host files into the API response.
 */
export function parseStack(disc: DiscoveredStack, appsRoot: string): AppStack {
  const warnings: string[] = [];
  const dir = disc.dir;
  const raw = readFileSync(disc.composeFile, "utf8");

  // Interpolation source: the stack's .env file (Compose's variable substitution).
  const lookup = disc.envFile ? parseEnvFile(disc.envFile) : new Map<string, string>();

  let doc: any;
  try {
    doc = parseYaml(raw) ?? {};
  } catch (err) {
    warnings.push(`YAML parse error: ${(err as Error).message}`);
    doc = {};
  }
  doc = interpolateDeep(doc, lookup, warnings);

  const projectName =
    (typeof doc.name === "string" && doc.name) || sanitizeProject(disc.id);

  const servicesRaw = (doc.services ?? {}) as Record<string, any>;
  const services: Service[] = [];
  for (const [name, svc] of Object.entries(servicesRaw)) {
    if (svc == null || typeof svc !== "object") continue;
    services.push(normalizeService(name, svc, { dir, appsRoot, projectName, lookup, warnings }));
  }

  // The operator's `.labview`, read last because it is validated against the service
  // names this file defines. Declarations are attached beside the parsed facts and
  // never merged into them — see src/scan/sidecar.ts.
  const sidecar = readSidecar(disc, appsRoot, services.map((s) => s.name));
  warnings.push(...sidecar.warnings);
  for (const svc of services) {
    const declared = sidecar.services.get(svc.name);
    if (declared) svc.declared = declared;
  }

  return {
    id: disc.id,
    name: disc.id,
    dir,
    composeFile: basename(disc.composeFile),
    hasEnvFile: Boolean(disc.envFile),
    projectName,
    services,
    declaredNetworks: normalizeDeclared(doc.networks) as NetworkDecl[],
    declaredVolumes: normalizeDeclared(doc.volumes) as VolumeDecl[],
    declared: sidecar.stack,
    warnings,
  };
}

interface Ctx {
  dir: string;
  /** Containment boundary for files referenced by the compose document. */
  appsRoot: string;
  projectName: string;
  lookup: Map<string, string>;
  warnings: string[];
}

function normalizeService(name: string, svc: any, ctx: Ctx): Service {
  const notes: string[] = [];
  const containerName =
    typeof svc.container_name === "string" ? svc.container_name : `${ctx.projectName}-${name}`;

  return {
    name,
    containerName,
    image: typeof svc.image === "string" ? svc.image : undefined,
    restart: typeof svc.restart === "string" ? svc.restart : undefined,
    command: normalizeCommand(svc.command),
    dependsOn: normalizeDependsOn(svc.depends_on),
    networks: normalizeNetworks(svc.networks),
    ports: normalizePorts(svc.ports, notes),
    expose: normalizeExpose(svc.expose),
    mounts: normalizeVolumes(svc.volumes),
    env: normalizeEnv(name, svc, ctx, notes),
    labels: normalizeKvMap(svc.labels),
    cloudflare: [],
    traefik: [],
    ingress: ["none"],
    auth: { method: "none", detail: "", evidence: [], confidence: "observed", exposedWithoutAuth: false },
    notes,
  };
}

/* -------------------------------------------------------------------------- */
/* env                                                                        */
/* -------------------------------------------------------------------------- */

function normalizeEnv(_name: string, svc: any, ctx: Ctx, notes: string[]): EnvVar[] {
  const byKey = new Map<string, EnvVar>();

  // 1. env_file entries (literal, not interpolated) — lowest precedence.
  const envFiles = toEnvFileList(svc.env_file);
  for (const ef of envFiles) {
    const path = resolveContained(ctx.dir, ctx.appsRoot, ef);
    if (path === null) {
      notes.push(`ignored env_file outside the apps root: ${ef}`);
      continue;
    }
    const parsed = parseEnvFile(path);
    for (const [key, value] of parsed) {
      byKey.set(key, { key, value, masked: false, source: "env_file" });
    }
  }

  // 2. environment block — higher precedence, interpolated with the stack .env.
  const env = svc.environment;
  if (Array.isArray(env)) {
    for (const item of env) {
      if (typeof item !== "string") continue;
      const eq = item.indexOf("=");
      if (eq === -1) {
        // Bare `KEY` -> value comes from the (compose) environment.
        const key = item.trim();
        const resolved = ctx.lookup.get(key);
        byKey.set(key, {
          key,
          value: resolved ?? "",
          masked: false,
          source: "shell-default",
        });
      } else {
        const key = item.slice(0, eq).trim();
        const { value, missing } = interpolate(item.slice(eq + 1), ctx.lookup);
        if (missing.length) notes.push(`unresolved var(s) in ${key}: ${missing.join(", ")}`);
        byKey.set(key, { key, value, masked: false, source: "environment" });
      }
    }
  } else if (env && typeof env === "object") {
    for (const [key, rawVal] of Object.entries(env)) {
      const str = rawVal == null ? "" : String(rawVal);
      const { value } = interpolate(str, ctx.lookup);
      byKey.set(key, { key, value, masked: false, source: "environment" });
    }
  }

  return [...byKey.values()].sort((a, b) => a.key.localeCompare(b.key));
}

/* -------------------------------------------------------------------------- */
/* ports                                                                      */
/* -------------------------------------------------------------------------- */

function normalizePorts(ports: any, notes: string[]): PortMapping[] {
  if (!Array.isArray(ports)) return [];
  const out: PortMapping[] = [];
  for (const p of ports) {
    if (typeof p === "number") {
      out.push({ target: String(p), protocol: "tcp", raw: String(p) });
      continue;
    }
    if (p && typeof p === "object") {
      out.push({
        published: p.published != null ? String(p.published) : undefined,
        target: String(p.target ?? ""),
        protocol: String(p.protocol ?? "tcp"),
        raw: JSON.stringify(p),
      });
      continue;
    }
    if (typeof p !== "string") continue;
    const raw = p;
    let protocol = "tcp";
    let body = raw;
    const slash = body.lastIndexOf("/");
    if (slash !== -1) {
      protocol = body.slice(slash + 1);
      body = body.slice(0, slash);
    }
    const parts = body.split(":");
    let published: string | undefined;
    let target: string;
    if (parts.length === 1) {
      target = parts[0]!;
    } else if (parts.length === 2) {
      published = parts[0];
      target = parts[1]!;
    } else {
      // host_ip:published:target
      published = parts.slice(0, parts.length - 1).join(":");
      target = parts[parts.length - 1]!;
    }
    if (target === "") notes.push(`could not parse port "${raw}"`);
    out.push({ published, target, protocol, raw });
  }
  return out;
}

/**
 * `expose:` entries, kept verbatim.
 *
 * Not parsed into `PortMapping` on purpose: these ports are never published, so there
 * is no host side to split off, and a range (`3000-3005`) is a normal entry that a
 * port parser would mangle. What the classifier needs is only whether the list is
 * non-empty — a container port the operator declared for other containers — and what
 * a reader needs is the string they wrote.
 */
function normalizeExpose(expose: any): string[] {
  if (!Array.isArray(expose)) return [];
  return expose
    .filter((e) => typeof e === "string" || typeof e === "number")
    .map((e) => String(e).trim())
    .filter((e) => e !== "");
}

/* -------------------------------------------------------------------------- */
/* volumes                                                                    */
/* -------------------------------------------------------------------------- */

function normalizeVolumes(volumes: any): MountSpec[] {
  if (!Array.isArray(volumes)) return [];
  const out: MountSpec[] = [];
  for (const v of volumes) {
    if (v && typeof v === "object") {
      out.push({
        type: (v.type as MountSpec["type"]) ?? "unknown",
        source: v.source != null ? String(v.source) : undefined,
        target: String(v.target ?? ""),
        readOnly: Boolean(v.read_only),
        raw: JSON.stringify(v),
      });
      continue;
    }
    if (typeof v !== "string") continue;
    const parts = v.split(":");
    let type: MountSpec["type"] = "volume";
    let source: string | undefined;
    let target: string;
    let readOnly = false;
    if (parts.length === 1) {
      target = parts[0]!;
      type = "volume";
    } else {
      source = parts[0];
      target = parts[1]!;
      if (parts[2] && /(^|,)ro(,|$)/.test(parts[2])) readOnly = true;
      type = source?.startsWith("/") || source?.startsWith(".") || source?.startsWith("~") ? "bind" : "volume";
    }
    out.push({ type, source, target, readOnly, raw: v });
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* misc normalizers                                                           */
/* -------------------------------------------------------------------------- */

function normalizeDependsOn(dep: any): string[] {
  if (Array.isArray(dep)) return dep.filter((x) => typeof x === "string");
  if (dep && typeof dep === "object") return Object.keys(dep);
  return [];
}

function normalizeNetworks(nets: any): string[] {
  if (Array.isArray(nets)) return nets.filter((x) => typeof x === "string");
  if (nets && typeof nets === "object") return Object.keys(nets);
  return [];
}

function normalizeCommand(cmd: any): string | undefined {
  if (typeof cmd === "string") return cmd;
  if (Array.isArray(cmd)) return cmd.map(String).join(" ");
  return undefined;
}

/** Normalize a labels/kv structure that may be a list of `k=v` or a map. */
function normalizeKvMap(input: any): Record<string, string> {
  const out: Record<string, string> = {};
  if (Array.isArray(input)) {
    for (const item of input) {
      if (typeof item !== "string") continue;
      const eq = item.indexOf("=");
      if (eq === -1) out[item.trim()] = "true";
      else out[item.slice(0, eq).trim()] = item.slice(eq + 1);
    }
  } else if (input && typeof input === "object") {
    for (const [k, v] of Object.entries(input)) out[k] = v == null ? "" : String(v);
  }
  return out;
}

function normalizeDeclared(input: any): Array<{ name: string; external: boolean; driver?: string }> {
  if (!input || typeof input !== "object") return [];
  const out: Array<{ name: string; external: boolean; driver?: string }> = [];
  for (const [name, def] of Object.entries(input)) {
    if (def && typeof def === "object") {
      const d = def as any;
      const external = d.external === true || (d.external && typeof d.external === "object");
      out.push({
        name: typeof d.name === "string" ? d.name : name,
        external: Boolean(external),
        driver: typeof d.driver === "string" ? d.driver : undefined,
      });
    } else {
      out.push({ name, external: false });
    }
  }
  return out;
}

function toStringArray(v: any): string[] {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.filter((x) => typeof x === "string");
  return [];
}

/**
 * Collect `env_file` references in both Compose forms: the short form
 * (`env_file: a.env` / `env_file: [a.env, b.env]`) and the long form
 * (`env_file: [{path: a.env, required: false}]`).
 */
function toEnvFileList(v: any): string[] {
  if (typeof v === "string") return [v];
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const item of v) {
    if (typeof item === "string") out.push(item);
    else if (item && typeof item === "object" && typeof item.path === "string") out.push(item.path);
  }
  return out;
}

function sanitizeProject(id: string): string {
  return id.toLowerCase().replace(/[^a-z0-9_-]/g, "");
}

/** Recursively interpolate every string leaf using the stack's .env lookup. */
function interpolateDeep(node: any, lookup: Map<string, string>, warnings: string[]): any {
  if (typeof node === "string") {
    const { value } = interpolate(node, lookup);
    return value;
  }
  if (Array.isArray(node)) return node.map((n) => interpolateDeep(n, lookup, warnings));
  if (node && typeof node === "object") {
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(node)) out[k] = interpolateDeep(v, lookup, warnings);
    return out;
  }
  return node;
}
