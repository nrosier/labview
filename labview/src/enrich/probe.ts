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
 *  - **Only where no authentication was found.** A service this scan already detected a
 *    gate on is not asked — see `hasDetectedAuth`. The request could not have changed its
 *    verdict (`hasEdgeAuth` is already true), so all it would do is put an unauthenticated
 *    GET on somebody's SSO endpoint. The count of withheld requests is on the snapshot,
 *    because "not asked" and "no address to ask" are different facts about a fleet.
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
  ProbeState,
  ServiceProbe,
  Service,
} from "../model/types.js";
import type { LabViewConfig } from "../config.js";
import { dominantAttempt, hintFor, phaseText, plural } from "../model/connections.js";
import {
  STATE_PATHS,
  probeGateText,
  probeTargets,
  readAnonAccess,
  readGate,
  readLoginForm,
  readMediaType,
  readRedirect,
  readRefresh,
  readState,
  readStateGate,
  stateTargets,
  wantsStateProbe,
  type ProbeTarget,
  type StateAnswer,
} from "../model/probe.js";
import { getResponse, safeOrigin, type FetchLike, type HttpResponse } from "./http.js";
import { mapWithConcurrency } from "./pool.js";

/** What the probe stage observed, keyed the way the analyzer looks services up. */
export interface ProbeSnapshot {
  /** `${stackId}/${serviceName}` -> what that service answered. Eligible services only. */
  byKey: Map<string, ServiceProbe>;
  /**
   * How many services *would* have been asked but were not, because this scan had already
   * detected authentication for them.
   *
   * Carried out of the stage rather than left in the report text because the payload has to
   * state it: a service that was not asked has no `ServiceProbe`, so without this number the
   * `Login probe` tile would simply count fewer services than the fleet has HTTP addresses
   * and leave a reader to guess which of the two reasons applied.
   */
  skipped: number;
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
 *
 * @param detectedAuth Keys (`${stackId}/${serviceName}`) this scan already found
 * authentication for — see `hasDetectedAuth`. Those are not asked. A `ReadonlySet` rather
 * than a predicate so the stage stays deterministic and has no callback to mock, and
 * decided by the analyzer rather than here because it needs the two API reads this module
 * knows nothing about.
 */
export async function probeServices(
  cfg: LabViewConfig,
  stacks: AppStack[],
  detectedAuth: ReadonlySet<string>,
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
  const empty = (conn: Partial<ConnectionReport>, skipped = 0): ProbeSnapshot => ({
    byKey: new Map(),
    skipped,
    connection: report(conn),
  });

  if (!cfg.probe.enabled) {
    return empty({
      phase: "disabled",
      detail: "active probing is disabled in configuration",
    });
  }

  const work: { key: string; targets: ProbeTarget[] }[] = [];
  let skipped = 0;
  for (const stack of stacks) {
    for (const svc of stack.services) {
      // `probeTargets` first, and the order is the point: a service with a gate and no HTTP
      // address was never a candidate, so counting it as withheld would inflate a number
      // whose whole job is to say how many questions LabView decided not to ask.
      const targets = probeTargets(svc, cfg.probe.lanHost);
      if (!targets.length) continue;
      const key = serviceKey(stack, svc);
      if (detectedAuth.has(key)) {
        skipped++;
        continue;
      }
      work.push({ key, targets });
    }
  }
  if (!work.length) {
    // Two ways to have nothing to ask, and they are different facts about the fleet.
    //
    // Everything eligible already authenticated is a *success*, so it does not wear
    // `ok: false`: the stage ran, made a decision about every candidate, and the decision
    // was that none of them needed asking.
    if (skipped) {
      return empty(
        {
          ok: true,
          phase: "connected",
          read: `${plural(skipped, "service")} not asked — authentication was already detected for every service with an HTTP address`,
        },
        skipped,
      );
    }
    // Enabled and nothing eligible at all. Worth saying rather than passing over in
    // silence: the operator switched the stage on and expects it to have done something,
    // and "no service was eligible" is a fact about their labels, not about LabView.
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
  let second = 0;
  const silent: ServiceProbe[] = [];
  for (const { key, probe } of probed) {
    byKey.set(key, probe);
    second += probe.state?.asked ?? 0;
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
    // Only when some were. A zero here would put "0 not asked" on the startup line of every
    // fleet whose services are all unauthenticated, which is a fact about nothing.
    ...(skipped ? [`${plural(skipped, "service")} not asked (authentication already detected)`] : []),
    // Every run says what it sent, and this is the only stage that can send more than one
    // request per service — so a fleet of form-less shells must not be able to quietly cost
    // four times what the line implies. Summed from `ServiceProbe.state.asked` rather than
    // carried on `ProbeRun`, and that is the difference from `skipped`: this number is
    // derivable from the payload the UI already has, so duplicating it onto the run would be
    // two places to keep true instead of one.
    ...(second ? [`${plural(second, "extra request")} at current-user addresses`] : []),
  ].join(" — ");

  // Three outcomes, and the middle one is the ordinary case in any real fleet: some
  // services answer and some do not. `partial` is the phase for exactly that — connected,
  // with part of the read missing — and it stays `ok`, because what was read is sound.
  if (!silent.length) {
    return { byKey, skipped, connection: report({ ok: true, phase: "connected", read }) };
  }
  if (gated || open) {
    return {
      byKey,
      skipped,
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
    skipped,
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
    // The rest of what the gate rule read, kept rather than discarded. Every one of these is
    // the reason a *negative* verdict came out the way it did, and the same functions
    // `readGate` consults produce them — so `probeReasonText` explains the observation the
    // verdict was actually reached on, and not a second reading of the response.
    const mediaType = readMediaType(res.contentType);
    const redirect = res.location ? readRedirect(res.location.trim(), target.url) : undefined;
    const refresh = res.body ? readRefresh(res.body, target.url) : undefined;
    // The second request, and the only one in this file. Sent for one shape of answer — a 200
    // that served HTML with no form anywhere in it, having gated nothing — because that is the
    // one page whose markup cannot answer the question even in principle. Everything else is
    // decided by the response already in hand.
    const state = wantsStateProbe({ gate, status: res.status, mediaType, body: res.body })
      ? await probeState(doFetch, target.url, timeoutMs)
      : undefined;
    // The same body read the other way round: not *what stood in front of this page* but *what
    // this page showed somebody who sent nothing*. No request of its own, and no path to
    // `verdict` below — `readAnonAccess` is called after the gate is decided and its answer is
    // not among `readGate`'s inputs, which is what keeps a sign-in link from ever becoming one.
    const anon = res.body ? readAnonAccess(res.body, target.url) : undefined;
    // `??` and not `||`: the state gate can only fill an absence, never replace a finding. By
    // `wantsStateProbe`'s first condition `gate` is undefined wherever `state` exists, so the
    // fallback is unreachable — and it is written this way so that stops being something a
    // reader has to go and check.
    const verdict = gate ?? (state ? readStateGate(state) : undefined);
    const detail = verdict
      ? `HTTP ${res.status} — ${lowerFirst(probeGateText(verdict).label)}`
      : `HTTP ${res.status} — answered with no login page`;
    tried.push({ endpoint, why: target.why, phase: "connected", code: String(res.status), detail });
    return {
      endpoint,
      vantage: target.vantage,
      phase: "connected",
      status: res.status,
      ...(verdict ? { gate: verdict } : {}),
      ...(mediaType ? { mediaType } : {}),
      ...(redirect ? { redirect } : {}),
      ...(refresh ? { refresh } : {}),
      ...(res.truncated ? { truncated: true } : {}),
      ...(form ? { form } : {}),
      ...(state ? { state } : {}),
      ...(anon ? { anon } : {}),
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

/**
 * Ask the current-user addresses, in order, and stop at the first refusal.
 *
 * The only place in LabView that sends a second request to a scanned service, so every bound
 * in the file header applies again and two more besides:
 *
 *  - **Sequential, always**, regardless of `probe.maxConcurrency`. Concurrency there is a
 *    fleet-wide budget across *services*; four addresses fired at once at one service would
 *    spend it inside a single one. And a parallel walk cannot short-circuit: the ordinary case
 *    is one request precisely because the second is never sent once the first refuses.
 *  - **Nothing parsed from the page.** The addresses come from `stateTargets`, which builds
 *    them from `STATE_PATHS` and the origin that answered — see its doc comment for why that
 *    is the line that matters.
 *
 * The addresses are deliberately kept **out of `attempts`**. That list is the reachability
 * record — which addresses of this service LabView tried before one answered, and it is what
 * the drawer shows and what `dominantAttempt` reasons over. A `/api/me` that 404s is not a
 * vantage that failed; folding it in would make a service look like it took five tries to
 * answer when it answered on the first. What the walk found is on `ServiceProbe.state`, which
 * exists for exactly this and says how many were asked.
 */
async function probeState(
  doFetch: FetchLike,
  requestUrl: string,
  timeoutMs: number,
): Promise<ProbeState | undefined> {
  const urls = stateTargets(requestUrl);
  if (!urls.length) return undefined;
  const answers: StateAnswer[] = [];
  for (const [i, url] of urls.entries()) {
    const res = await getResponse(doFetch, url, { timeoutMs });
    const path = STATE_PATHS[i]!;
    answers.push({
      path,
      ...(res.ok && res.status !== undefined ? { status: res.status } : {}),
      ...(res.wwwAuthenticate ? { wwwAuthenticate: res.wwwAuthenticate } : {}),
    });
    // Short-circuit here as well as in `readState`. The pure rule decides what the walk *is*,
    // so it has to truncate whatever a caller did; this stops the requests actually going out,
    // and the two agreeing is what makes `asked` a count of the wire and not of the intent.
    if (res.status === 401 || res.status === 407) break;
  }
  return readState(answers);
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
