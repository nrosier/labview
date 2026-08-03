import { useMemo } from "preact/hooks";
import type {
  AppStack,
  AuthentikApplication,
  AuthentikMatchStrength,
  AuthentikSummary,
  ConnectionReport,
  TraefikLiveRouter,
  TraefikSummary,
  UnmatchedApplication,
  UnmatchedReason,
  UnmatchedRouter,
} from "../model";
import { phaseText } from "../model";
import { qualifyRouter, serviceKey } from "../lib/format";
import { Panel } from "./Panel";
import { Section } from "./Section";

/**
 * What the topbar counts stand for, in full.
 *
 * `authentik: 13 apps · 9 matched` states an outcome and hides the two questions behind
 * it: which application was tied to which service and on what evidence, and — the one
 * only LabView can answer — why the rest were not. Both sides are shown here, because a
 * list of matches without the failures reads as completeness it has not earned.
 *
 * The matched side is derived from `ov.stacks` rather than duplicated into `ScanMeta`:
 * the per-service drawer already reads `svc.authentik` / `svc.traefikLive`, and a second
 * copy of the same pairs in the metadata is a second thing to keep in step.
 */

/** How a caller opens a service's own drawer from a matched row. */
type OpenService = (stackId: string, serviceName: string) => void;

/**
 * One subject in a list: a title line, then whatever describes it.
 *
 * Blocks rather than table rows because the descriptions are uneven — a rule, a chain,
 * a backend with a health status, a sentence of reasoning — and a table wide enough for
 * the longest of them wastes the width of every other row.
 */
function Entry({ title, children }: { title: preact.ComponentChildren; children?: preact.ComponentChildren }) {
  return (
    <div style="margin-bottom:12px;">
      <div style="font-weight:600;display:flex;align-items:baseline;gap:6px;flex-wrap:wrap;">{title}</div>
      {children}
    </div>
  );
}

/** The `kv` proportions used inside an {@link Entry}, matching the service drawer's. */
const KV = "grid-template-columns:120px 1fr;margin-top:4px;";

/** One line per rule tried, in the same voice as the auth and origin evidence. */
function Evidence({ lines }: { lines: string[] }) {
  if (lines.length === 0) return null;
  return (
    <ul class="evidence" style="margin-top:4px;">
      {lines.map((l) => (
        <li>{l}</li>
      ))}
    </ul>
  );
}

/**
 * Where LabView sent the request, and whether that address was configured or worked out.
 *
 * The source belongs next to the address: a discovered endpoint that turned out to be
 * the wrong one is a different problem from a configured one that stopped answering, and
 * the address alone does not say which of the two a reader is looking at.
 */
function EndpointRows({ endpoint, source }: { endpoint?: string; source?: "config" | "discovered" | "default" }) {
  const SOURCE: Record<"config" | "discovered" | "default", string> = {
    config: "configuration",
    discovered: "discovered from the scanned fleet",
    default: "the built-in default",
  };
  return (
    <>
      <dt>Endpoint</dt>
      <dd class="mono">{endpoint ?? <span class="masked">none — nothing was dialled</span>}</dd>
      {source && (
        <>
          <dt>Address from</dt>
          <dd>{SOURCE[source]}</dd>
        </>
      )}
    </>
  );
}

const REASON_LABEL: Record<UnmatchedReason, string> = {
  ambiguous: "ambiguous",
  "no-candidate": "no candidate",
  internal: "internal",
};

/**
 * The reason as a pill, with the distinction between the three on hover.
 *
 * `--warning`, never `--critical`: an unplaced entry is a gap in what LabView can say,
 * and the critical tint is reserved for the exposure warning — a service reachable from
 * the internet with no gate — which must not have to compete with a reporting gap for
 * the reader's alarm. `no-candidate` is left untinted for the same reason: it is the
 * ordinary case, and usually LabView's to explain rather than the operator's to fix.
 */
function ReasonPill({ reason, noun }: { reason: UnmatchedReason; noun: string }) {
  const WHY: Record<UnmatchedReason, string> = {
    ambiguous: `The evidence pointed at more than one scanned service, so it was discarded rather than arbitrated. Making one of the names distinct is what resolves it.`,
    "no-candidate": `Nothing in this ${noun} identified a scanned service. Usually a gap in what LabView can see rather than something misconfigured.`,
    internal: `A matcher named a service this scan does not hold — a LabView defect rather than a configuration problem.`,
  };
  return (
    <span class={`pill${reason === "no-candidate" ? "" : " warn"}`} title={WHY[reason]}>
      {REASON_LABEL[reason]}
    </span>
  );
}

/**
 * Why a match is reported at the confidence it is.
 *
 * The three kinds are not degrees of the same thing: an address is the provider naming
 * this service, a hostname is both sides naming the same third thing, and a name is only
 * that the operator chose similar words twice. The posture built on the last of those is
 * reported as `observed` instead of `confirmed`, and this is where that is said.
 */
const STRENGTH_WHY: Record<AuthentikMatchStrength, string> = {
  address:
    "The provider points at this service's own address. The posture built on it is reported as confirmed.",
  hostname:
    "This service and the application declare the same hostname independently. The posture built on it is reported as confirmed.",
  name: "Only the names are alike — nothing addresses this service. The posture built on it is reported as observed rather than confirmed.",
};

/**
 * Marks an application the applications endpoint withheld and a provider named.
 *
 * Worth its own pill in both lists: the record behind it is thinner than a listed one —
 * no launch URL, no group, only the providers this token may read — so a match made on
 * it rests on less, and a miss may be the missing fields rather than a missing service.
 */
function RebuiltPill({ app }: { app: AuthentikApplication }) {
  if (app.discoveredVia !== "provider") return null;
  return (
    <span
      class="pill warn"
      title="The applications endpoint did not return this application to LabView's token — it filters its list to what that user may launch. It was rebuilt from the provider assigned to it, so it carries no launch URL and no group."
    >
      rebuilt
    </span>
  );
}

/** The providers behind an application, each with the kind that decides what it enforces. */
function ProviderRows({ app }: { app: AuthentikApplication }) {
  if (app.providers.length === 0) {
    return (
      <>
        <dt>Providers</dt>
        <dd>
          <span class="masked">none — the application gates nothing</span>
        </dd>
      </>
    );
  }
  return (
    <>
      <dt>Providers</dt>
      <dd>
        {app.providers.map((p) => (
          <div>
            <span class="pill">{p.kind}</span>
            <span class="mono masked">{p.name}</span>
            {p.internalHost && <span class="mono masked"> → {p.internalHost}</span>}
          </div>
        ))}
      </dd>
    </>
  );
}

/**
 * What a live router is, as the proxy reports it.
 *
 * Shared by the matched and the unmatched lists deliberately: the same facts are what
 * explain a tie and what explain the absence of one, and the reader of the second list
 * needs them most — a router nothing could be matched to is only diagnosable from its
 * rule, its chain and where it points.
 */
function RouterRows({ router }: { router: TraefikLiveRouter }) {
  return (
    <>
      {router.rule && (
        <>
          <dt>Rule</dt>
          <dd class="mono">{router.rule}</dd>
        </>
      )}
      {router.hosts.length > 0 && (
        <>
          <dt>Hosts</dt>
          <dd>
            {router.hosts.map((h) => (
              <span class="pill">{h}</span>
            ))}
          </dd>
        </>
      )}
      {router.entryPoints.length > 0 && (
        <>
          <dt>Entrypoints</dt>
          <dd>{router.entryPoints.join(", ")}</dd>
        </>
      )}
      <>
        <dt>Chain</dt>
        <dd>
          {router.middlewares.length === 0 ? (
            <span class="masked">none</span>
          ) : (
            router.middlewares.map((m) => <span class={`pill${m.errors.length ? " crit" : ""}`}>{m.name}</span>)
          )}
        </dd>
      </>
      {router.servers.length > 0 && (
        <>
          {/* Where the route ends up. On an unmatched router this is the single most
              useful line: an address that resolves to nothing LabView scanned is what
              the first matching rule was looking for and did not find. */}
          <dt>Backends</dt>
          <dd>
            {router.servers.map((sv) => (
              <div>
                <span class="mono">{sv.url}</span>
                {sv.status && (
                  <span class={`pill${sv.status.toUpperCase() === "DOWN" ? " crit" : ""}`}>{sv.status}</span>
                )}
              </div>
            ))}
          </dd>
        </>
      )}
      {router.errors.length > 0 && (
        <>
          <dt>Errors</dt>
          <dd class="mono">{router.errors.join("; ")}</dd>
        </>
      )}
    </>
  );
}

/** Traefik's own verdict on a router: anything but `enabled` is in no request path. */
function StatusPill({ status }: { status?: string }) {
  const serving = !status || status.toLowerCase() === "enabled";
  return <span class={`pill${serving ? "" : " crit"}`}>{status ?? "enabled"}</span>;
}

/**
 * The body when the API was not read.
 *
 * The pill shows a phase instead of a count in this state, and the detail behind it —
 * the stage that failed, the address, every candidate tried with its own phase, and the
 * fix — was reachable only by hovering. A discovery failure in particular is undiagnosable
 * without the candidate list: "no endpoint answered" is unactionable, three named
 * addresses with a phase each is not.
 */
function Failure({ target, conn, error }: { target: string; conn?: ConnectionReport; error?: string }) {
  if (!conn) {
    return (
      <Section title="Not read">
        <div class="note">
          {error ?? `LabView did not read the ${target} API, and recorded no detail about why.`}
        </div>
      </Section>
    );
  }

  return (
    <>
      <Section title="What failed">
        <dl class="kv">
          <dt>Stage</dt>
          <dd>
            <span class="pill warn">{conn.phase}</span> {phaseText(conn.phase)}
          </dd>
          <EndpointRows endpoint={conn.endpoint} source={conn.source} />
          {conn.code && (
            <>
              {/* Next to the phase it produced, so an inferred phase is
                  distinguishable from a reported one. */}
              <dt>Code</dt>
              <dd class="mono">{conn.code}</dd>
            </>
          )}
          {conn.detail && (
            <>
              <dt>Detail</dt>
              <dd>{conn.detail}</dd>
            </>
          )}
        </dl>
        {conn.hint && <div class="note">{conn.hint}</div>}
      </Section>

      {conn.attempts.length > 0 && (
        <Section title={`Candidates tried (${conn.attempts.length})`}>
          <table class="data">
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>Why tried</th>
                <th>Stage</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {conn.attempts.map((a) => (
                <tr>
                  <td class="mono">{a.endpoint}</td>
                  <td>{a.why}</td>
                  <td>
                    {a.phase}
                    {a.code && <span class="mono masked"> {a.code}</span>}
                  </td>
                  <td>{a.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}
    </>
  );
}

/** One matched (service, application) pair, flattened out of the per-service payload. */
interface MatchedApp {
  stackId: string;
  stackName: string;
  serviceName: string;
  key: string;
  app: AuthentikApplication;
  evidence: string;
  strength: AuthentikMatchStrength;
}

export function AuthentikDetail({
  summary,
  stacks,
  conn,
  onClose,
  onOpenService,
}: {
  summary: AuthentikSummary;
  stacks: AppStack[];
  conn?: ConnectionReport;
  onClose: () => void;
  onOpenService: OpenService;
}) {
  const matched = useMemo<MatchedApp[]>(() => {
    const rows: MatchedApp[] = [];
    for (const stack of stacks) {
      for (const svc of stack.services) {
        const m = svc.authentik;
        if (!m) continue;
        m.applications.forEach((app, i) => {
          rows.push({
            stackId: stack.id,
            stackName: stack.name,
            serviceName: svc.name,
            key: serviceKey(stack.id, svc.name),
            app,
            evidence: m.evidence[i] ?? "",
            // Parallel arrays. A missing entry means the weakest reading, never the
            // strongest — the same rule the posture builder applies.
            strength: m.strength[i] ?? "name",
          });
        });
      }
    }
    rows.sort((a, b) => a.key.localeCompare(b.key) || a.app.slug.localeCompare(b.app.slug));
    return rows;
  }, [stacks]);

  const unmatched: UnmatchedApplication[] = summary.unmatchedApplications;

  // What the applications endpoint holds against what it handed over. It filters its own
  // list to the applications the token's user may launch, so these three numbers are the
  // difference between "LabView read everything" and "LabView read a slice".
  const configured = summary.applicationsConfigured ?? summary.applications;
  const withheld = summary.applicationsWithheld;
  const recovered = summary.applicationsRecovered;
  const unaccounted = Math.max(0, withheld - recovered);

  return (
    <Panel
      title="Authentik"
      sub={
        summary.reachable
          ? withheld
            ? `${summary.applications} of ${configured} applications read from its API`
            : `${summary.applications} application${summary.applications === 1 ? "" : "s"} read from its API`
          : "the API was not read"
      }
      onClose={onClose}
    >
      {summary.reachable ? (
        <>
          <Section title="Source">
            <dl class="kv">
              <EndpointRows endpoint={summary.endpoint} source={summary.endpointSource} />
              <dt>Read</dt>
              <dd>
                {withheld ? `${summary.applications} of ${configured} applications` : `${summary.applications} applications`} ·{" "}
                {summary.providers} providers · {summary.outposts} outposts
              </dd>
              <dt>Matched</dt>
              <dd>
                {matched.length} application{matched.length === 1 ? "" : "s"} to {summary.matchedServices} service
                {summary.matchedServices === 1 ? "" : "s"}
              </dd>
            </dl>
            {/* Stated here rather than left to a tooltip, because it changes what the rest
                of the panel is worth: a service protected by an application this token
                never received reads as unprotected, and no list below can show that. */}
            {withheld > 0 && (
              <div class="note">
                Authentik reports {configured} applications and returned {summary.applications - recovered}. Its
                applications endpoint filters the list to what this token's user may launch.{" "}
                {recovered > 0 && (
                  <>
                    {recovered} of the withheld ones were rebuilt from providers, which are not filtered that way —
                    those carry no launch URL or group and are tagged <span class="pill">rebuilt</span> below.{" "}
                  </>
                )}
                {unaccounted > 0
                  ? `${unaccounted} could not be rebuilt: no provider LabView may read names them, so a service they protect reads as unprotected here. Making the token's user a superuser returns the exact list.`
                  : "Nothing is missing after that."}
              </div>
            )}
          </Section>

          <Section title={`Matched (${matched.length})`}>
            {matched.length === 0 ? (
              <div class="note">
                No application could be tied to a scanned service. Every one of them is listed below with the
                reason.
              </div>
            ) : (
              matched.map((row) => (
                <Entry
                  title={
                    <>
                      {row.app.name}
                      <span class="mono masked">{row.app.slug}</span>
                      <span class="pill" title={STRENGTH_WHY[row.strength]}>
                        {row.strength}
                      </span>
                      <RebuiltPill app={row.app} />
                      {row.app.group && <span class="pill">{row.app.group}</span>}
                    </>
                  }
                >
                  <dl class="kv" style={KV}>
                    <dt>Service</dt>
                    <dd>
                      {/* Straight to the service's own drawer, where the posture this
                          match fed into is spelled out in full. */}
                      <button class="linkbtn" onClick={() => onOpenService(row.stackId, row.serviceName)}>
                        {row.stackName} / {row.serviceName}
                      </button>
                    </dd>
                    <ProviderRows app={row.app} />
                    {row.app.launchUrl && (
                      <>
                        <dt>Launch URL</dt>
                        <dd class="mono">{row.app.launchUrl}</dd>
                      </>
                    )}
                  </dl>
                  <Evidence lines={row.evidence ? [row.evidence] : []} />
                </Entry>
              ))
            )}
          </Section>

          <Section title={`Not matched (${unmatched.length})`}>
            {unmatched.length === 0 ? (
              <div class="note">Every application Authentik reported was tied to a scanned service.</div>
            ) : (
              unmatched.map((u) => (
                <Entry
                  title={
                    <>
                      {u.application.name}
                      <span class="mono masked">{u.application.slug}</span>
                      <ReasonPill reason={u.reason} noun="application" />
                      <RebuiltPill app={u.application} />
                    </>
                  }
                >
                  <dl class="kv" style={KV}>
                    <dt>Why</dt>
                    <dd>{u.detail}</dd>
                    <ProviderRows app={u.application} />
                    {u.application.launchUrl && (
                      <>
                        <dt>Launch URL</dt>
                        <dd class="mono">{u.application.launchUrl}</dd>
                      </>
                    )}
                  </dl>
                  {/* Every rule that was tried, in the order tried. The point is that a
                      reader can see which rule came closest rather than take "unmatched"
                      on trust. */}
                  <Evidence lines={u.considered} />
                </Entry>
              ))
            )}
          </Section>
        </>
      ) : (
        <Failure target="Authentik" conn={conn} error={summary.error} />
      )}
    </Panel>
  );
}

/** One matched (service, live router) pair, flattened out of the per-service payload. */
interface MatchedRouter {
  stackId: string;
  stackName: string;
  serviceName: string;
  key: string;
  router: TraefikLiveRouter;
}

export function TraefikDetail({
  summary,
  stacks,
  conn,
  onClose,
  onOpenService,
}: {
  summary: TraefikSummary;
  stacks: AppStack[];
  conn?: ConnectionReport;
  onClose: () => void;
  onOpenService: OpenService;
}) {
  const matched = useMemo<MatchedRouter[]>(() => {
    const rows: MatchedRouter[] = [];
    for (const stack of stacks) {
      for (const svc of stack.services) {
        for (const router of svc.traefikLive ?? []) {
          rows.push({
            stackId: stack.id,
            stackName: stack.name,
            serviceName: svc.name,
            key: serviceKey(stack.id, svc.name),
            router,
          });
        }
      }
    }
    rows.sort((a, b) => a.key.localeCompare(b.key) || qualifyRouter(a.router).localeCompare(qualifyRouter(b.router)));
    return rows;
  }, [stacks]);

  const unmatched: UnmatchedRouter[] = summary.unmatchedRouters;

  return (
    <Panel
      title="Traefik"
      sub={
        summary.reachable
          ? `${summary.routers} router${summary.routers === 1 ? "" : "s"} read from its API`
          : "the API was not read"
      }
      onClose={onClose}
    >
      {summary.reachable ? (
        <>
          <Section title="Source">
            <dl class="kv">
              <EndpointRows endpoint={summary.endpoint} source={summary.endpointSource} />
              {summary.version && (
                <>
                  <dt>Version</dt>
                  <dd class="mono">{summary.version}</dd>
                </>
              )}
              <dt>Credential</dt>
              <dd>
                <span class={`pill${summary.credential === "none" ? " warn" : ""}`}>{summary.credential}</span>
              </dd>
              <dt>Read</dt>
              <dd>
                {summary.routers} routers · {summary.middlewares} middlewares · {summary.services} services
                {summary.entrypointsRead ? " · entrypoints" : ""}
              </dd>
              <dt>Matched</dt>
              <dd>
                {matched.length} router{matched.length === 1 ? "" : "s"} to {summary.matchedServices} service
                {summary.matchedServices === 1 ? "" : "s"}
              </dd>
            </dl>
            {/* Both of these change what the rest of the panel is worth, so they are
                stated here rather than left to a tooltip: one is a finding about the
                proxy, the other a limit on what LabView can conclude from it. */}
            {summary.credential === "none" && (
              <div class="note">
                The API answered without a credential, which is direct evidence that <span class="mono">api.insecure</span>{" "}
                is on — anything that can reach this address can read the proxy's whole runtime configuration.
              </div>
            )}
            {!summary.entrypointsRead && (
              <div class="note">
                Entrypoints were not read. An entrypoint can carry auth middlewares no router lists, so a
                missing gate cannot be told apart from a gate attached one level up.
              </div>
            )}
          </Section>

          <Section title={`Matched (${matched.length})`}>
            {matched.length === 0 ? (
              <div class="note">
                No live router could be identified for a scanned service. Every one of them is listed below with
                the reason.
              </div>
            ) : (
              matched.map((row) => (
                <Entry
                  title={
                    <>
                      {row.router.router}
                      <span class="mono masked">@{row.router.provider}</span>
                      <StatusPill status={row.router.status} />
                    </>
                  }
                >
                  <dl class="kv" style={KV}>
                    <dt>Service</dt>
                    <dd>
                      <button class="linkbtn" onClick={() => onOpenService(row.stackId, row.serviceName)}>
                        {row.stackName} / {row.serviceName}
                      </button>
                    </dd>
                    <RouterRows router={row.router} />
                  </dl>
                  <Evidence lines={row.router.evidence} />
                </Entry>
              ))
            )}
          </Section>

          <Section title={`Not matched (${unmatched.length})`}>
            {unmatched.length === 0 ? (
              <div class="note">Every router the proxy is serving was identified for a scanned service.</div>
            ) : (
              unmatched.map((u) => (
                <Entry
                  title={
                    <>
                      {u.router.router}
                      <span class="mono masked">@{u.router.provider}</span>
                      <StatusPill status={u.router.status} />
                      <ReasonPill reason={u.reason} noun="router" />
                    </>
                  }
                >
                  <dl class="kv" style={KV}>
                    <dt>Why</dt>
                    <dd>{u.detail}</dd>
                    <RouterRows router={u.router} />
                  </dl>
                  <Evidence lines={u.considered} />
                </Entry>
              ))
            )}
          </Section>
        </>
      ) : (
        <Failure target="Traefik" conn={conn} error={summary.error} />
      )}
    </Panel>
  );
}
