/**
 * Ask each HTTP service what it answers, and read a login page as evidence.
 *
 * Every other enrichment client reads an API LabView was given the address of. This one
 * sends a request to a *scanned service*, at an address taken from that service's own
 * labels — which is to say, from a document LabView did not write. That single difference
 * is what shapes the whole file, so the bounds are here rather than left implicit
 * (invariant **I8**):
 *
 *  - **Off unless the operator turns it on.** `probe.enabled` is the only integration
 *    flag that defaults to `false`.
 *  - **GET, at `/`, and nothing else.** No other method, no path from a label, no query.
 *  - **No credential, ever.** Not by omission — no call path into `getResponse` has one
 *    in scope. What an *unauthenticated* request gets is the entire measurement, so a
 *    credential would destroy it as surely as following a redirect would.
 *  - **No redirect followed.** Where a 3xx points is the evidence; following it would
 *    report what was at the far end instead, and would let a scanned label send LabView
 *    somewhere of its choosing.
 *  - **A capped number of addresses per service** (`MAX_PROBE_TARGETS`), so a compose
 *    file with thirty published ports cannot turn one scan into thirty requests.
 *  - **A per-request timeout**, and a bounded number of requests in flight.
 *  - **The body read only when it is HTML**, and then only to `MAX_BODY_BYTES`, with the
 *    stream cancelled at the cap.
 *  - **Only where HTTP was observed.** `probeTargets` decides that from the labels, and
 *    a service that merely publishes a port yields no address at all — which is what
 *    keeps this off a database without consulting a port number or an image name.
 *
 * And the same rule as every other client: it **cannot throw and cannot fail a scan**
 * (**I4**). Disabled, nothing eligible, nothing answering: every path returns a report
 * that explains itself, and the fleet keeps whatever posture its configuration implies.
 *
 * The recognition rule itself is not here. `readGate` and `probeTargets` are pure
 * functions in `model/probe.ts`, because a rule that lives in an I/O module can only be
 * tested by mocking the I/O — this file is the part that has to be mocked.
 */
import type {
  AppStack,
  ConnectionAttempt,
  ConnectionReport,
  ServiceProbe,
  Service,
} from "../model/types.js";
import type { LabViewConfig } from "../config.js";
import { dominantAttempt, hintFor, phaseText, plural } from "../model/connections.js";
import {
  probeGateText,
  probeTargets,
  readGate,
  readLoginForm,
  type ProbeTarget,
} from "../model/probe.js";
import { getResponse, safeOrigin, type FetchLike, type HttpResponse } from "./http.js";
import { mapWithConcurrency } from "./pool.js";

/** What the probe stage observed, keyed the way the analyzer looks services up. */
export interface ProbeSnapshot {
  /** `${stackId}/${serviceName}` -> what that service answered. Eligible services only. */
  byKey: Map<string, ServiceProbe>;
  connection: ConnectionReport;
}

/**
 * How many failed attempts the fleet-wide report carries.
 *
 * Per-service attempts are already on each {@link ServiceProbe}, where the drawer shows
 * them against the service they belong to. This list exists for the one startup line the
 * CLI and the server print, and `formatConnection` prints every entry of it — so an
 * uncapped list would put one line per address per service into a log. Truncation is
 * stated in the detail rather than left silent.
 */
const MAX_REPORTED_ATTEMPTS = 8;

/**
 * Probe every eligible service, in scan order.
 *
 * Shaped like `snapshotTraefik`: candidates in order, every attempt recorded, one
 * `ConnectionReport` out. Services are walked in scan order and `mapWithConcurrency`
 * preserves it, so the same fleet produces the same report twice however the network
 * behaved in between (**I7**).
 */
export async function probeServices(
  cfg: LabViewConfig,
  stacks: AppStack[],
  fetchImpl?: FetchLike,
): Promise<ProbeSnapshot> {
  const attempts: ConnectionAttempt[] = [];
  const report = (over: Partial<ConnectionReport>): ConnectionReport => ({
    target: "probe",
    ok: false,
    phase: "not-configured",
    attempts,
    ...over,
  });
  const empty = (conn: Partial<ConnectionReport>): ProbeSnapshot => ({
    byKey: new Map(),
    connection: report(conn),
  });

  if (!cfg.probe.enabled) {
    return empty({
      phase: "disabled",
      detail: "active probing is disabled in configuration",
    });
  }

  const work: { key: string; targets: ProbeTarget[] }[] = [];
  for (const stack of stacks) {
    for (const svc of stack.services) {
      const targets = probeTargets(svc, cfg.probe.lanHost);
      if (targets.length) work.push({ key: serviceKey(stack, svc), targets });
    }
  }
  if (!work.length) {
    // Enabled and nothing to ask. Worth saying rather than passing over in silence: the
    // operator switched the stage on and expects it to have done something, and "no
    // service was eligible" is a fact about their labels, not about LabView.
    return empty({
      phase: "not-found",
      detail:
        "no scanned service showed an HTTP address to ask: probing needs a tunnel route with an http/https origin, or a Traefik HTTP router label",
      hint: hintFor("probe", "not-found"),
    });
  }

  const doFetch: FetchLike = fetchImpl ?? ((url, init) => fetch(url, init) as Promise<HttpResponse>);
  const probed = await mapWithConcurrency(work, Math.max(1, cfg.probe.maxConcurrency), async (w) => ({
    key: w.key,
    probe: await probeOne(doFetch, w.targets, cfg.probe.timeoutMs),
  }));

  const byKey = new Map<string, ServiceProbe>();
  let gated = 0;
  let open = 0;
  const silent: ServiceProbe[] = [];
  for (const { key, probe } of probed) {
    byKey.set(key, probe);
    if (probe.phase === "connected") {
      if (probe.gate) gated++;
      else open++;
    } else {
      silent.push(probe);
      for (const a of probe.attempts) attempts.push(a);
    }
  }
  if (attempts.length > MAX_REPORTED_ATTEMPTS) attempts.length = MAX_REPORTED_ATTEMPTS;

  const read = [
    `${plural(work.length, "service")} probed`,
    [
      `${gated} gated`,
      `${open} open`,
      ...(silent.length ? [`${silent.length} did not answer`] : []),
    ].join(", "),
  ].join(" — ");

  // Three outcomes, and the middle one is the ordinary case in any real fleet: some
  // services answer and some do not. `partial` is the phase for exactly that — connected,
  // with part of the read missing — and it stays `ok`, because what was read is sound.
  if (!silent.length) {
    return { byKey, connection: report({ ok: true, phase: "connected", read }) };
  }
  if (gated || open) {
    return {
      byKey,
      connection: report({
        ok: true,
        phase: "partial",
        read,
        detail: `${silent.length} of ${work.length} services did not answer, so their posture rests on configuration alone${
          attempts.length < countAttempts(silent) ? ` (first ${attempts.length} addresses listed)` : ""
        }`,
        hint: hintFor("probe", "partial"),
      }),
    };
  }
  // Nothing answered at all. Not a fleet-shaped problem — far more likely one thing wrong
  // between LabView and every address it tried, which is what the dominant attempt names.
  const worst = dominantAttempt(attempts) ?? attempts[0];
  const phase = worst?.phase ?? "connect";
  return {
    byKey,
    connection: report({
      ok: false,
      phase,
      endpoint: worst?.endpoint,
      source: "discovered",
      code: worst?.code,
      detail: `none of the ${plural(work.length, "eligible service")} answered — ${worst?.detail ?? phaseText(phase)}`,
      hint: hintFor("probe", phase),
    }),
  };
}

/**
 * Ask one service, at each of its addresses in turn, and stop at the first that answers.
 *
 * "Answers" means an HTTP response arrived, whatever its status — a 401 is the best
 * outcome there is here, so it ends the walk rather than continuing to a weaker vantage.
 * Only a transport failure falls through to the next address, and a service whose public
 * hostname does not resolve from inside the container is precisely why there is a next
 * address to fall through to.
 */
async function probeOne(
  doFetch: FetchLike,
  targets: ProbeTarget[],
  timeoutMs: number,
): Promise<ServiceProbe> {
  const tried: ConnectionAttempt[] = [];
  for (const target of targets) {
    const endpoint = safeOrigin(target.url);
    const res = await getResponse(doFetch, target.url, { timeoutMs });
    if (!res.ok || res.status === undefined) {
      tried.push({
        endpoint,
        why: target.why,
        phase: res.phase,
        ...(res.code ? { code: res.code } : {}),
        detail: res.error ?? phaseText(res.phase),
      });
      continue;
    }
    const gate = readGate({
      requestUrl: target.url,
      status: res.status,
      ...(res.location ? { location: res.location } : {}),
      ...(res.wwwAuthenticate ? { wwwAuthenticate: res.wwwAuthenticate } : {}),
      ...(res.body ? { body: res.body } : {}),
    });
    // Read independently of the verdict, and reported even when nothing was cleared: it is
    // what lets a reader see *why* — a form of username plus a button and no login action
    // is the case where the answer is arguable, and hiding it would make the verdict
    // something they have to take on trust.
    const form = res.body ? readLoginForm(res.body, target.url) : undefined;
    const detail = gate
      ? `HTTP ${res.status} — ${lowerFirst(probeGateText(gate).label)}`
      : `HTTP ${res.status} — answered with no login page`;
    tried.push({ endpoint, why: target.why, phase: "connected", code: String(res.status), detail });
    return {
      endpoint,
      vantage: target.vantage,
      phase: "connected",
      status: res.status,
      ...(gate ? { gate } : {}),
      ...(form ? { form } : {}),
      detail,
      attempts: tried,
    };
  }

  // Nothing answered. The most informative failure is reported as *the* outcome, on the
  // same reasoning `dominantAttempt` exists for: a name that would not resolve says less
  // than a certificate that was not trusted, and the operator's problem is the latter.
  const worst = dominantAttempt(tried);
  const at = worst ? tried.indexOf(worst) : -1;
  const target = at >= 0 ? targets[at]! : targets[0]!;
  return {
    endpoint: worst?.endpoint ?? safeOrigin(target.url),
    vantage: target.vantage,
    phase: worst?.phase ?? "connect",
    detail: worst?.detail ?? "nothing was tried",
    attempts: tried,
  };
}

function countAttempts(probes: ServiceProbe[]): number {
  return probes.reduce((n, p) => n + p.attempts.length, 0);
}

/**
 * `Credential requested` -> `credential requested`, for a label used mid-sentence.
 *
 * Only the first character, so an acronym in a label would survive one. The wording
 * itself stays in `probeGateText` — one place, so a note and a badge cannot drift.
 */
function lowerFirst(s: string): string {
  return s.charAt(0).toLowerCase() + s.slice(1);
}

/** `${stackId}/${serviceName}`, the key `serviceRefKey` and the UI both use. */
function serviceKey(stack: AppStack, svc: Service): string {
  return `${stack.id}/${svc.name}`;
}
