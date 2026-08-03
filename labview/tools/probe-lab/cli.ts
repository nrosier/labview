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
 *  - **A redirect chain is followed to its end** (`--max-hops`, default 5, `--no-follow` to
 *    stop at the first answer) — but **only while no gate has been found**. A 3xx that already
 *    satisfies a clause is where following stops, which is what keeps this tool from sending a
 *    request at somebody's identity provider: a cross-origin redirect *is* `redirect-origin`,
 *    so the hand-off is recognised and never walked into.
 *  - **The auth-state sweep is the one place more is asked than was given.** Where a page came
 *    back with no gate and no `<form>` at all — the client-rendered shell, where reading the
 *    body cannot work even in principle — the eight fixed addresses in `AUTH_STATE_PATHS` are
 *    asked as well. Fixed list, `GET`, no credential, sequential, and `--no-sweep` turns it off.
 *  - **Nothing discovered on a page is ever fetched.** No asset, no form action, no link. Both
 *    additions above are addresses the *service* named in a `Location` header or that this tool
 *    holds in a reviewed constant — never something parsed out of a page's markup.
 *  - Each request has a timeout, and targets are asked sequentially by default
 *    (`--concurrency`).
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
  AUTH_STATE_PATHS,
  buildReport,
  firstRefusal,
  refusalIsPipelineGate,
  renderJson,
  renderMarkdown,
  wantsSweep,
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
  /**
   * Walk a redirect chain past the first answer. **On by default**, which is the change a real
   * fleet forced: a service that hands an anonymous visitor three same-origin 3xx before showing
   * its sign-in screen is invisible to a rule that reads one response, and the only way to know
   * that is what happened is to walk it once, in a diagnostic, on purpose.
   */
  follow: boolean;
  /** How far. Bounds the walk whatever a service does, including a redirect loop. */
  maxHops: number;
  /**
   * Whether to ask {@link AUTH_STATE_PATHS} as well.
   *
   * `auto` — only where `wantsSweep` says reading the body could not have worked: a page served,
   * no gate, no `<form>`. `always` — every target that answered, for when the shape is not
   * obviously a shell but the suspicion is there. `never` — the older bound, one address per
   * target, for a run against services somebody else operates.
   */
  sweep: "auto" | "always" | "never";
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
  --no-follow          stop at the first answer (default: follow the redirect chain)
  --max-hops <n>       how far to follow a chain (default: 5)
  --sweep              ask the auth-state addresses on every target that answered
  --no-sweep           never ask them (default: only where a page had no gate and no form)
  --timeout <ms>       per request (default: 8000)
  --concurrency <n>    targets in flight (default: 1)
  --out <dir>          report directory (default: tools/probe-lab/reports)
  --raw-headers        do not redact header values (default: redacted)
  -h, --help           this

Every request is an unauthenticated GET with a timeout, and no credential exists anywhere on
the call path. Beyond the address given it will follow a redirect chain while no gate has been
found, and — where a page came back with no gate and no form at all, the one case reading the
body cannot solve — ask ${AUTH_STATE_PATHS.length} fixed current-user addresses. Nothing parsed
out of a page is ever fetched. Two files per target under --out, plus an index.
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
    follow: true,
    maxHops: 5,
    sweep: "auto",
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
      // `--follow` is kept and still means what it said: follow. It is now the default, so the
      // flag is a no-op rather than an error — a command somebody has in their shell history
      // should not start failing to say it asked for what it already gets.
      case "--follow":
        opts.follow = true;
        break;
      case "--no-follow":
        opts.follow = false;
        break;
      case "--max-hops":
        opts.maxHops = positive(need(i, arg), arg);
        i++;
        break;
      case "--sweep":
        opts.sweep = "always";
        break;
      case "--no-sweep":
        opts.sweep = "never";
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

/**
 * Ask an address, then keep asking where it says to go, until it stops saying.
 *
 * Returns the whole chain, first response first. **The first element is the only one the verdict
 * is ever built from** — everything after it is the answer to "and then what happened", which is a
 * question the scan does not ask and this tool exists to answer.
 *
 * Four things stop the walk, and each is a bound rather than a heuristic:
 *
 *  - **A gate.** `buildReport(...).verdict.gate` is the pipeline's own rule, so following stops
 *    exactly where the scan would already have concluded something. This is what keeps a
 *    cross-origin hand-off from being walked: an off-origin `Location` *is* `redirect-origin`, so
 *    the request at somebody's identity provider is never sent.
 *  - **Anything that is not a 3xx with a readable `Location`.** There is nowhere to go.
 *  - **`--max-hops`.** Whatever the service does, including a loop that varies its path.
 *  - **A repeat.** A `Location` already asked in this chain is a loop, and asking it twice would
 *    describe the loop by growing the report instead of by naming it.
 */
async function observeChain(url: string, opts: Options): Promise<ProbeLabObservation[]> {
  const chain: ProbeLabObservation[] = [await observe(url, opts)];
  if (!opts.follow) return chain;
  const asked = new Set([url]);
  for (let hop = 0; hop < opts.maxHops; hop++) {
    const last = chain[chain.length - 1]!;
    if (last.status === undefined || last.status < 300 || last.status >= 400) break;
    if (buildReport(last).verdict.gate !== undefined) break;
    const location = last.headers["location"];
    if (!location?.trim()) break;
    let next: string | undefined;
    try {
      next = normalize(new URL(location.trim(), last.requestUrl).toString());
    } catch {
      break;
    }
    if (!next || asked.has(next)) break;
    asked.add(next);
    chain.push(await observe(next, opts));
  }
  return chain;
}

/**
 * Ask the fixed auth-state addresses on one origin.
 *
 * Sequential regardless of `--concurrency`, which applies to targets: eight requests at one
 * service in parallel is a burst somebody's rate limiter is entitled to read as an attack, and
 * there is nothing here worth being in a hurry about.
 *
 * The list is `AUTH_STATE_PATHS` and nothing else. No expansion, no path read off the page, and
 * the same eight every run — so what this sent is knowable from the constant rather than from the
 * report.
 */
async function sweepAuthState(url: string, opts: Options): Promise<ProbeLabObservation[]> {
  const origin = originOf(url);
  if (!origin) return [];
  const out: ProbeLabObservation[] = [];
  for (const path of AUTH_STATE_PATHS) out.push(await observe(`${origin}${path}`, opts));
  return out;
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
function renderIndex(rows: Row[], at: string): string {
  const L = [
    "# probe-lab",
    "",
    `${rows.length} target${rows.length === 1 ? "" : "s"}, ${at}.`,
    "",
    "| Target | Verdict | Signal | Withdraws exposure | Chain | Auth-state | Next steps | Report |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const { target, report, file } of rows) {
    // Two columns for the two ways a login page hides from the verdict beside them, so a run over
    // twenty services shows at a glance which rows are worth opening. Both read `—` when there
    // was nothing to say, and neither is ever the same cell as a gate: the verdict column is what
    // LabView concluded and these are what it could not see.
    const ahead = report.chain.find((h) => h.gate !== undefined);
    const refused = firstRefusal(report.sweep);
    L.push(
      `| ${target.url} | ${report.verdict.label} | ${report.verdict.gate ?? "—"} | ${
        report.verdict.withdrawsExposure ? "yes" : "no"
      } | ${
        report.chain.length === 0
          ? "—"
          : `${report.chain.length} hop${report.chain.length === 1 ? "" : "s"}${ahead ? ` → \`${ahead.gate}\`` : ""}`
      } | ${
        report.sweep.length === 0
          ? "—"
          : refused
            ? `**${refused.status} at ${refused.path}**${refusalIsPipelineGate(refused) ? "" : " (evidence only)"}`
            : `${report.sweep.length} asked, none refused`
      } | ${report.next.length} | [${file}](${file}) |`,
    );
  }
  L.push("", "## Where each target came from", "");
  for (const { target } of rows) L.push(`- ${target.url} — ${target.why}`);
  return `${L.join("\n")}\n`;
}

/** One finished target: where it came from, what it answered, and the file that says so. */
interface Row {
  target: Target;
  report: ProbeLabReport;
  file: string;
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
  const rows: Row[] = [];
  const queue = [...targets];
  const asked = new Set<string>();
  const inFlight: Promise<void>[] = [];
  // Counted rather than derived from the rows, because what a run *sent* is the number that
  // matters for I8 and two of the three kinds of request do not become a row of their own.
  let hopRequests = 0;
  let sweptTargets = 0;
  let sweepRequests = 0;

  /**
   * The report for one answer, with the auth-state sweep attached if this run calls for it.
   *
   * The sweep decision is `wantsSweep`'s, which is in `report.ts` — so what got asked is a
   * function of the report rather than of a condition written twice, and the smoke pass can pin
   * it without a network.
   */
  const reportOn = async (
    obs: ProbeLabObservation,
    hops: ProbeLabObservation[],
  ): Promise<ProbeLabReport> => {
    const first = buildReport(obs, { chain: hops });
    const wanted =
      opts.sweep === "always" ? obs.status !== undefined : opts.sweep === "auto" && wantsSweep(first);
    if (!wanted) return first;
    const sweep = await sweepAuthState(obs.requestUrl, opts);
    sweptTargets++;
    sweepRequests += sweep.length;
    return buildReport(obs, { chain: hops, sweep });
  };

  const emit = async (target: Target, report: ProbeLabReport): Promise<void> => {
    const file = `${slug(target.url)}.md`;
    await writeFile(resolvePath(opts.out, file), renderMarkdown(report), "utf8");
    await writeFile(resolvePath(opts.out, `${slug(target.url)}.json`), renderJson(report), "utf8");
    rows.push({ target, report, file });
    const ahead = report.chain.find((h) => h.gate !== undefined);
    const refused = firstRefusal(report.sweep);
    process.stdout.write(
      `${report.verdict.gate ? "gated " : report.read.status === undefined ? "silent" : "open  "} ${
        report.read.status ?? "—"
      }  ${target.url}  ${report.verdict.label}${
        report.chain.length ? ` [+${report.chain.length} hop${report.chain.length === 1 ? "" : "s"}]` : ""
      }${ahead ? ` [${ahead.gate} down the chain]` : ""}${
        refused ? ` [${refused.status} at ${refused.path}]` : ""
      }\n`,
    );
  };

  const ask = async (target: Target): Promise<void> => {
    const chain = await observeChain(target.url, opts);
    const obs = chain[0]!;
    const hops = chain.slice(1);
    hopRequests += hops.length;
    await emit(target, await reportOn(obs, hops));
    // The end of a chain gets a report of its own, built from the answer already in hand rather
    // than from a second request. It is the page an operator's browser actually shows them, so it
    // is the one they will want the signal rows for — and where the chain ended on a shell, it is
    // also the observation the sweep has something to say about.
    const end = hops[hops.length - 1];
    if (end && !asked.has(end.requestUrl)) {
      asked.add(end.requestUrl);
      await emit(
        { url: end.requestUrl, why: `the end of ${target.url}'s redirect chain` },
        await reportOn(end, []),
      );
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
  const L = [
    `\n${rows.length} reported — ${gated} gated, ${rows.length - gated - silent} with no login page found${
      silent ? `, ${silent} did not answer` : ""
    }`,
  ];
  // What was sent, in full. The one address per target this tool started with is no longer the
  // whole story, so a run says how much more it asked and for what — I8 is a claim somebody has to
  // be able to check against the output rather than against the source.
  if (hopRequests) L.push(`${hopRequests} redirect hop${hopRequests === 1 ? "" : "s"} followed`);
  if (sweptTargets) {
    L.push(
      `${sweptTargets} form-less page${sweptTargets === 1 ? "" : "s"} asked ${sweepRequests} auth-state address${
        sweepRequests === 1 ? "" : "es"
      }`,
    );
  }
  // The findings this whole tool exists to surface, and the reason they are last: they are what
  // somebody scrolls back for. Each names a login page LabView cannot see from where it looks —
  // one further down a chain than it reads, one at an address it does not ask, one it asked and
  // decided on purpose not to act on.
  const aheadRows = rows.filter((r) => r.report.chain.some((h) => h.gate !== undefined));
  for (const r of aheadRows) {
    const h = r.report.chain.find((x) => x.gate !== undefined)!;
    L.push(`gated further down the chain: ${r.target.url} → ${h.gate} at ${h.url}`);
  }
  // A refusal that already became the verdict is in the `gated` count above and is not a finding
  // about a blind spot any more — it is the eighth clause working. What is left divides in two,
  // and the two are wildly different sizes of change, so they are not one list: a scheme named at
  // an address outside `STATE_PATHS` is one entry short of a fix, while a bare refusal is a
  // deliberate non-gate that a reader must not mistake for an oversight.
  for (const r of rows) {
    if (r.report.verdict.gate === "state-challenge") continue;
    const s = firstRefusal(r.report.sweep);
    if (!s) continue;
    L.push(
      s.wwwAuthenticate?.trim()
        ? `gated at an address the probe does not ask: ${r.target.url} → ${s.status} at ${s.path} — one entry in STATE_PATHS away`
        : `refused with no scheme named, so deliberately not a gate: ${r.target.url} → ${s.status} at ${s.path}`,
    );
  }
  L.push(`reports in ${opts.out}`);
  process.stdout.write(`${L.join("\n")}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`probe-lab: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
