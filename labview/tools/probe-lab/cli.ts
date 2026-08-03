/**
 * `npm run probe-lab -- <url…>` — ask an address what it answers, and write down what
 * LabView's login rule made of it.
 *
 * The I/O half, split from `report.ts` the way `buildStamp` is split from
 * `resolveBuildStamp`: argv, the network, and two files per target. Every judgement is in
 * `report.ts`, and every rule `report.ts` applies is imported from `src/model/probe.ts`.
 *
 * **The transport is the pipeline's transport too.** This does not call `fetch` directly —
 * it calls {@link getResponse}, the same function `enrich/probe.ts` calls, through a
 * `FetchLike` wrapper whose only job is to keep the response headers that `getResponse`
 * discards. So the timeout, `redirect: "manual"`, the `Accept` header, the HTML-only body
 * read and the `MAX_BODY_BYTES` cap are not restated here; they are inherited, and a change
 * to any of them changes this tool in the same commit.
 *
 * **What it will and will not do** (invariant **I8**, which applies with full force: this
 * sends requests at somebody's services, at addresses a person typed):
 *
 *  - `GET`, at the address given, and nothing else. No method flag exists.
 *  - **No credential, ever.** Nothing on the call path into `getResponse` has one in scope,
 *    and there is no option to supply one. What an unauthenticated visitor gets is the whole
 *    measurement.
 *  - **No redirect followed** unless `--follow`, and then exactly one hop, reported as its
 *    own target. Where a 3xx points is the evidence.
 *  - **Nothing discovered on a page is ever fetched.** No asset, no form action, no link.
 *    `--paths` exists so that an extra address is something the operator typed rather than
 *    something a scanned page suggested.
 *  - One request per target, sequentially by default (`--concurrency`), each with a timeout.
 *  - **Header values are redacted by default.** A report is a file somebody pastes into an
 *    issue; `Set-Cookie` is reduced to names and anything that names a credential is elided
 *    before the observation record is built, so a value the tool decided not to keep cannot
 *    reach a report by another route. `--raw-headers` opts out.
 *  - Writes only under `--out`, and nothing else anywhere.
 *
 * Not shipped: the `Dockerfile` COPYs named paths, so `tools/` never enters the image.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve as resolvePath } from "node:path";
import { getResponse, type FetchLike, type HttpResponse } from "../../src/enrich/http.js";
import { hasDetectedAuth } from "../../src/labels/auth.js";
import { probeTargets } from "../../src/model/probe.js";
import type { ConnectionPhase, Overview } from "../../src/model/types.js";
import {
  buildReport,
  renderJson,
  renderMarkdown,
  type ProbeLabObservation,
  type ProbeLabReport,
} from "./report.js";

/** Everything argv can say. Every default is the cautious end of the choice. */
interface Options {
  /** Addresses given on the command line. */
  urls: string[];
  /** A file of addresses, one per line. Read in `main`, since parsing is synchronous. */
  urlFile?: string;
  /** A saved `/api/overview` to take addresses from. See {@link targetsFromScan}. */
  fromScan?: string;
  /** `probe.lanHost`'s equivalent for `--from-scan`; empty means no LAN vantage. */
  lanHost: string;
  /** Extra paths per origin, e.g. `/login`. Operator-supplied, never page-derived. */
  paths: string[];
  /** Follow one hop of a 3xx, as its own target. Off by default. */
  follow: boolean;
  timeoutMs: number;
  concurrency: number;
  out: string;
  /** Keep header values verbatim. Off by default — see {@link redactHeaders}. */
  rawHeaders: boolean;
}

/** One address to ask, and where it came from — which goes in the report's index. */
interface Target {
  url: string;
  why: string;
}

const USAGE = `
probe-lab — see what LabView's login rule reads at a URL, and what it would take to read more.

  npm run probe-lab -- <url> [url…] [options]
  npm run probe-lab -- --urls targets.txt
  npm run probe-lab -- --from-scan overview.json --lan-host 192.168.1.10

Options
  --urls <file>        one URL per line; blank lines and # comments ignored
  --from-scan <file>   a saved GET /api/overview; takes every service that scan found
                       neither authentication nor a login page for, at the same addresses
                       the scan itself would ask (probeTargets)
  --lan-host <host>    host address for --from-scan's LAN vantage (default: none)
  --paths a,b          also ask these paths on each origin (default: only the URL given)
  --follow             follow one hop of a 3xx, as its own target (default: off)
  --timeout <ms>       per request (default: 8000)
  --concurrency <n>    requests in flight (default: 1)
  --out <dir>          report directory (default: tools/probe-lab/reports)
  --raw-headers        do not redact header values (default: redacted)
  -h, --help           this

It sends one unauthenticated GET per target and nothing else: no credential, no method
other than GET, no redirect followed unless asked, and nothing a page suggests is ever
fetched. Two files per target under --out, plus an index.
`.trimStart();

/* -------------------------------------------------------------------------- */
/* argv                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Parse argv, or explain what was wrong with it.
 *
 * Throws rather than exiting, so `main` owns the one exit point — the same reason
 * `parseConfig` does not call `process.exit`.
 */
export function parseArgs(argv: readonly string[]): Options {
  const opts: Options = {
    urls: [],
    lanHost: "",
    paths: [],
    follow: false,
    timeoutMs: 8_000,
    concurrency: 1,
    out: resolvePath(import.meta.dirname, "reports"),
    rawHeaders: false,
  };
  const need = (i: number, flag: string): string => {
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`${flag} needs a value`);
    return value;
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(USAGE);
      process.exit(0);
    }
    switch (arg) {
      case "--urls":
        opts.urlFile = need(i, arg);
        i++;
        break;
      case "--from-scan":
        opts.fromScan = need(i, arg);
        i++;
        break;
      case "--lan-host":
        opts.lanHost = need(i, arg).trim();
        i++;
        break;
      case "--paths":
        opts.paths.push(
          ...need(i, arg)
            .split(",")
            .map((p) => p.trim())
            .filter(Boolean),
        );
        i++;
        break;
      case "--follow":
        opts.follow = true;
        break;
      case "--timeout":
        opts.timeoutMs = positive(need(i, arg), arg);
        i++;
        break;
      case "--concurrency":
        opts.concurrency = positive(need(i, arg), arg);
        i++;
        break;
      case "--out":
        opts.out = resolvePath(process.cwd(), need(i, arg));
        i++;
        break;
      case "--raw-headers":
        opts.rawHeaders = true;
        break;
      default:
        if (arg.startsWith("-")) throw new Error(`unknown option ${arg}`);
        opts.urls.push(arg);
    }
  }
  return opts;
}

function positive(raw: string, flag: string): number {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`${flag} needs a positive number, got ${raw}`);
  return Math.floor(n);
}

/* -------------------------------------------------------------------------- */
/* Targets                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Every address to ask, deduped, in the order it was arrived at.
 *
 * An address is only ever something the operator gave: a URL on the command line, a line in
 * `--urls`, a path in `--paths`, or a service address out of `--from-scan`. Nothing read off a
 * fetched page is ever added here, which is the difference between a diagnostic and a crawler.
 */
async function collectTargets(opts: Options): Promise<Target[]> {
  const out: Target[] = [];
  const seen = new Set<string>();
  const push = (raw: string, why: string): void => {
    const url = normalize(raw);
    if (!url || seen.has(url)) return;
    seen.add(url);
    out.push({ url, why });
  };

  for (const url of opts.urls) push(url, "given on the command line");
  if (opts.urlFile) {
    const text = await readFile(resolvePath(process.cwd(), opts.urlFile), "utf8");
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      push(trimmed, `listed in ${opts.urlFile}`);
    }
  }
  if (opts.fromScan) {
    for (const t of await targetsFromScan(opts.fromScan, opts.lanHost)) push(t.url, t.why);
  }
  // `--paths` is applied to every origin gathered above, and only to those — so a path list
  // never invents an origin of its own.
  if (opts.paths.length) {
    for (const origin of [...new Set(out.map((t) => originOf(t.url)))]) {
      if (!origin) continue;
      for (const path of opts.paths) push(`${origin}${path.startsWith("/") ? path : `/${path}`}`, "--paths");
    }
  }
  return out;
}

/** A bare host becomes `https://host/`, on the convention `probeTargets` uses for a tunnel. */
function normalize(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const url = new URL(withScheme);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    // Query and fragment are dropped for `readRedirect`'s reason: neither changes whether a
    // page is a login page, and either can carry a token that has no business in a file.
    return `${url.origin}${url.pathname}`;
  } catch {
    return undefined;
  }
}

function originOf(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

/**
 * The services a saved scan found neither authentication nor a login page for, at the
 * addresses that scan would have asked.
 *
 * This is the request answered directly: *the URLs belonging to the services and stacks for
 * which you do not detect authentication or a login page*. Both halves of that sentence are
 * read from the payload with the pipeline's own predicates — `hasDetectedAuth` for the first
 * and `svc.probe.gate` for the second — so the target list is exactly the set of services the
 * dashboard shows as unexplained, and never a hand-rolled approximation of it.
 *
 * Addresses come from **`probeTargets`**, the same function the scan uses, so the lab asks
 * what the scan asked. That also means the LAN vantage needs `--lan-host` here for the same
 * reason the scan needs `probe.lanHost`: a container cannot see its host's LAN address, and a
 * saved payload does not carry the one it was given.
 */
async function targetsFromScan(file: string, lanHost: string): Promise<Target[]> {
  const path = resolvePath(process.cwd(), file);
  const raw: unknown = JSON.parse(await readFile(path, "utf8"));
  const stacks = isObject(raw) ? raw["stacks"] : undefined;
  if (!Array.isArray(stacks)) {
    throw new Error(`${file} is not a LabView overview payload (no stacks array)`);
  }
  // One field claimed rather than the whole payload, because one field is what this reads:
  // `hasDetectedAuth` and `probeTargets` each take a `Pick` of a service, so a payload saved
  // by an older LabView still yields a target list instead of failing at an assertion about
  // `graph` or `stats` that nothing here would have looked at.
  const scanned = stacks as Overview["stacks"];
  const out: Target[] = [];
  for (const stack of scanned) {
    for (const svc of stack.services ?? []) {
      // Detected authentication is out: those are the services the scan already explains, and
      // asking about them is what Part A of this change stopped the scan itself from doing.
      if (hasDetectedAuth(svc)) continue;
      // A probe that already found a gate is out too. What is left is the actual question:
      // reachable, no configured gate, and either not asked or asked and nothing found.
      if (svc.probe?.gate) continue;
      for (const target of probeTargets(svc, lanHost)) {
        out.push({ url: target.url, why: `${stack.name}/${svc.name} — ${target.why}` });
      }
    }
  }
  return out;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/* -------------------------------------------------------------------------- */
/* The request                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Ask one address, through the pipeline's own `getResponse`.
 *
 * The wrapper around `fetch` exists for one thing: `getResponse` keeps the three headers the
 * gate rule reads and discards the rest, and section 3 of the report is largely about the
 * rest. So the real `Response` is stashed on the way through and its headers read afterwards.
 * Everything else about the request — method, `Accept`, `redirect: "manual"`, the timeout, the
 * HTML-only capped body — is `getResponse`'s and is not restated here.
 */
async function observe(url: string, opts: Options): Promise<ProbeLabObservation> {
  let headers: Record<string, string> = {};
  const doFetch: FetchLike = async (target, init) => {
    const res = await fetch(target, init as RequestInit);
    headers = opts.rawHeaders ? headerMap(res.headers) : redactHeaders(headerMap(res.headers));
    return res as unknown as HttpResponse;
  };
  const started = performance.now();
  const res = await getResponse(doFetch, url, { timeoutMs: opts.timeoutMs });
  const elapsedMs = Math.round(performance.now() - started);
  return {
    requestUrl: url,
    ...(res.status !== undefined ? { status: res.status } : {}),
    headers,
    ...(res.body !== undefined ? { body: res.body } : {}),
    ...(res.truncated ? { truncated: true } : {}),
    ...(res.body !== undefined ? { bodyBytes: Buffer.byteLength(res.body) } : {}),
    ...(res.error ? { error: res.error } : {}),
    phase: res.phase as ConnectionPhase,
    elapsedMs,
  };
}

/** A `Headers` as a plain record, names lowercased, repeats joined the way `Headers` does. */
function headerMap(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, name) => {
    out[name.toLowerCase()] = value;
  });
  return out;
}

/**
 * Header names whose *value* is a credential or is close enough to one.
 *
 * `set-cookie` is not here because it is not redacted — it is reduced to names in the report
 * and its value never appears at all, which is stronger. `www-authenticate` is deliberately
 * absent the other way: its value is a challenge rather than a secret, and it is the fact the
 * `challenge` clause turns on, so eliding it would hide the evidence for a verdict.
 */
const CREDENTIAL_HEADERS = /authorization|token|secret|password|passwd|credential|api[-_]?key|signature/i;

/**
 * Replace a credential-shaped header value with its length.
 *
 * Applied in the fetch wrapper, before an observation record exists — so there is no window in
 * which a raw value is in a structure something else could serialise. The length is kept
 * because "this header was present and 512 characters long" is the diagnostic part, and none
 * of the value is needed to say it.
 */
function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    out[name] = CREDENTIAL_HEADERS.test(name) ? `«redacted, ${value.length} chars»` : value;
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* Output                                                                     */
/* -------------------------------------------------------------------------- */

/** `https://app.example.com/login` -> `app.example.com_login`. Stable across runs. */
function slug(url: string): string {
  const cleaned = url.replace(/^https?:\/\//, "").replace(/[^a-z0-9._-]+/gi, "_");
  return (cleaned.replace(/^_+|_+$/g, "") || "target").slice(0, 96);
}

/**
 * The index — one row per target, so a run over twenty services is readable at a glance.
 *
 * The `Next` column is the count of section-4 lines rather than their text: a row per target
 * is a map, and the reason it points at is in the target's own file.
 */
function renderIndex(rows: { target: Target; report: ProbeLabReport; file: string }[], at: string): string {
  const L = [
    "# probe-lab",
    "",
    `${rows.length} target${rows.length === 1 ? "" : "s"}, ${at}.`,
    "",
    "| Target | Verdict | Signal | Withdraws exposure | Next steps | Report |",
    "| --- | --- | --- | --- | --- | --- |",
  ];
  for (const { target, report, file } of rows) {
    L.push(
      `| ${target.url} | ${report.verdict.label} | ${report.verdict.gate ?? "—"} | ${
        report.verdict.withdrawsExposure ? "yes" : "no"
      } | ${report.next.length} | [${file}](${file}) |`,
    );
  }
  L.push("", "## Where each target came from", "");
  for (const { target } of rows) L.push(`- ${target.url} — ${target.why}`);
  return `${L.join("\n")}\n`;
}

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const targets = await collectTargets(opts);
  if (!targets.length) {
    process.stderr.write(`no targets\n\n${USAGE}`);
    process.exitCode = 1;
    return;
  }

  await mkdir(opts.out, { recursive: true });
  const rows: { target: Target; report: ProbeLabReport; file: string }[] = [];
  // A worklist rather than a fixed fan-out, because `--follow` appends to it: one hop, and the
  // hop is a target in its own right with its own report, so nothing is followed twice.
  const queue = [...targets];
  const asked = new Set<string>();
  const inFlight: Promise<void>[] = [];

  const ask = async (target: Target): Promise<void> => {
    const obs = await observe(target.url, opts);
    const report = buildReport(obs);
    const file = `${slug(target.url)}.md`;
    await writeFile(resolvePath(opts.out, file), renderMarkdown(report), "utf8");
    await writeFile(resolvePath(opts.out, `${slug(target.url)}.json`), renderJson(report), "utf8");
    rows.push({ target, report, file });
    process.stdout.write(
      `${report.verdict.gate ? "gated " : obs.status === undefined ? "silent" : "open  "} ${
        obs.status ?? "—"
      }  ${target.url}  ${report.verdict.label}\n`,
    );
    // One hop, and only where the operator asked for it. The hop's own report says where it
    // went, so following further would add pages nobody named.
    if (opts.follow && report.read.redirect) {
      const next = normalize(new URL(report.read.location!, target.url).toString());
      if (next && !asked.has(next)) {
        queue.push({ url: next, why: `--follow, one hop from ${target.url}` });
      }
    }
  };

  while (queue.length || inFlight.length) {
    while (queue.length && inFlight.length < Math.max(1, opts.concurrency)) {
      const target = queue.shift()!;
      if (asked.has(target.url)) continue;
      asked.add(target.url);
      const task = ask(target).finally(() => {
        inFlight.splice(inFlight.indexOf(task), 1);
      });
      inFlight.push(task);
    }
    if (inFlight.length) await Promise.race(inFlight);
  }

  // Sorted by address rather than by completion, so two runs over one fleet produce comparable
  // files however the network behaved in between — the same reason the scan preserves order.
  rows.sort((a, b) => a.target.url.localeCompare(b.target.url));
  const at = new Date().toISOString();
  await writeFile(resolvePath(opts.out, "index.md"), renderIndex(rows, at), "utf8");
  // The same three-way split the scan's own read line makes, and the third is not a milder
  // second: an address nothing answered at was not measured, and a summary that folded it into
  // "no login page found" would report a conclusion about a service nothing was learned about.
  const gated = rows.filter((r) => r.report.verdict.gate).length;
  const silent = rows.filter((r) => r.report.read.status === undefined).length;
  process.stdout.write(
    `\n${rows.length} asked — ${gated} gated, ${rows.length - gated - silent} with no login page found${
      silent ? `, ${silent} did not answer` : ""
    }\nreports in ${opts.out}\n`,
  );
}

main().catch((err: unknown) => {
  process.stderr.write(`probe-lab: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
