/**
 * Turning a `ConnectionReport` into words, and deciding when it is worth saying.
 *
 * Pure, and deliberately separate from the clients that produce the reports: the
 * server logs them, the CLI prints them and the web UI renders them, and all three
 * must agree on what a phase means. A second copy of this wording in `cli.ts` is
 * exactly the drift this module exists to prevent.
 *
 * Nothing here has a credential in scope. Reports arrive with endpoints already
 * reduced to an origin by `safeOrigin`, and a phase is a constant.
 */
import type { ConnectionAttempt, ConnectionPhase, ConnectionReport } from "./types.js";

/**
 * What to change, for one target and one failed stage.
 *
 * Keyed by both because the stage alone does not name the fix: a name that will not
 * resolve means "LabView is not on the socket proxy's network" for the Docker
 * endpoint and "point `LABVIEW_AUTHENTIK_URL` somewhere real" for Authentik, and a
 * 403 means "the socket proxy is refusing this endpoint" in one case and "the identity
 * provider gate rejected these credentials" in the other. Wording is always the likely
 * fix — "check that…", "set…" — never a diagnosis of the operator's network, because a
 * hint is a guess about a deployment this process cannot see.
 *
 * A target with no entry for a phase simply gets no hint, which is better than a
 * generic one: the detail line already says what happened.
 */
const HINTS: Record<string, Partial<Record<ConnectionPhase, string>>> = {
  docker: {
    resolve:
      "The endpoint's hostname did not resolve. If it is a socket proxy, LabView has to be on a network the proxy is also on — check `networks:` on both, or set LABVIEW_DOCKER_HOST.",
    connect:
      "Nothing accepted the connection. Check the socket proxy is running and its port matches LABVIEW_DOCKER_PORT, or unset LABVIEW_DOCKER_HOST to use the local socket.",
    tls: "The endpoint's certificate was not trusted. A docker socket proxy is normally plain HTTP on an internal network; a TLS endpoint needs its CA in NODE_EXTRA_CA_CERTS.",
    timeout:
      "The endpoint accepted the connection and never answered. Raise LABVIEW_DOCKER_TIMEOUT if the host is slow, otherwise check the proxy is forwarding to a live docker socket.",
    authenticate: "The endpoint asked for a credential. LabView sends none — put it behind a network boundary rather than an authenticating one.",
    authorize:
      "The socket proxy accepted the request and refused this endpoint. LabView reads containers only: set CONTAINERS=1 (and PING=1) on the proxy.",
    path: "No docker API answered at this address. Check the port belongs to the socket proxy and not to another service.",
    partial: "Some containers could not be inspected. The socket proxy allows the container list but not each container's detail — set CONTAINERS=1 rather than a narrower rule.",
  },
  authentik: {
    "not-found":
      "A token is configured but no address to use it against. Set LABVIEW_AUTHENTIK_URL — discovery only recognises an Authentik that is itself one of the scanned stacks.",
    credential:
      "LABVIEW_AUTHENTIK_TOKEN is set and carries nothing. Most often it is an unresolved ${…} in a compose file with no matching entry in the .env beside it — compose passes an empty value through without complaining.",
    resolve:
      "No candidate hostname resolved. Set LABVIEW_AUTHENTIK_URL to the API's address — LabView only guesses from the scanned fleet, and an instance outside it has to be named.",
    connect: "Nothing accepted the connection. Check the port in LABVIEW_AUTHENTIK_URL, and that LabView can reach it from its own network.",
    tls: "The certificate was not trusted. Add the issuing CA with NODE_EXTRA_CA_CERTS; LabView does not skip verification.",
    timeout: "The endpoint accepted the connection and never answered. Raise LABVIEW_AUTHENTIK_TIMEOUT, or check the address points at Authentik and not at something holding the request open.",
    authenticate:
      "Authentik rejected the token. It needs to be an API token for a user that can read applications, providers and outposts — check the value in LABVIEW_AUTHENTIK_TOKEN.",
    authorize: "The token was accepted and the read refused. Give the token's user read access to applications, providers and outposts.",
    path: "No Authentik API answered here. LABVIEW_AUTHENTIK_URL should be the instance's base URL, without `/api/v3`.",
    protocol:
      "Something answered that is not Authentik's API — most often its own login page, or a proxy in front of it. Point LABVIEW_AUTHENTIK_URL at an address that reaches Authentik directly, typically its container on the internal network.",
    partial:
      "Either part of the read failed, or the applications endpoint returned only the applications this token's user may launch — it filters its own list, so a service protected by an application LabView cannot see reads as unprotected. LabView rebuilds what the readable providers name; to receive the exact list instead, make the token's user a superuser. Otherwise check the token's permissions.",
  },
  traefik: {
    "not-found":
      "A credential is configured but no address to use it against. Set LABVIEW_TRAEFIK_URL — discovery only recognises a Traefik that is itself one of the scanned stacks.",
    credential:
      "LABVIEW_TRAEFIK_PASSWORD is set and carries nothing. Most often it is an unresolved ${…} in a compose file with no matching entry in the .env beside it — compose passes an empty value through without complaining.",
    resolve:
      "No candidate hostname resolved. Set LABVIEW_TRAEFIK_URL to the API's address — usually the proxy's own container on the internal network, e.g. http://traefik:8080.",
    connect: "Nothing accepted the connection. Traefik serves its API only when `api: {}` is enabled and an entrypoint is listening for it.",
    tls: "The certificate was not trusted. Add the issuing CA with NODE_EXTRA_CA_CERTS, or read the API over the internal network where it is plain HTTP.",
    timeout: "The endpoint accepted the connection and never answered. Raise LABVIEW_TRAEFIK_TIMEOUT, or check the address is the API's and not a routed application's.",
    authenticate:
      "The API is gated. Behind an Authentik proxy provider, HTTP Basic needs a user plus an *app password* (not an API token), and the provider must have header authentication enabled — set LABVIEW_TRAEFIK_USERNAME and LABVIEW_TRAEFIK_PASSWORD.",
    authorize: "The credential was accepted and the access refused. Grant the user LabView authenticates as access to the application in front of the API.",
    path: "No Traefik API answered here. Enable `api: {}` in the static configuration, and check the URL has no path of its own.",
    protocol:
      "Something answered that is not Traefik's API — most often an SSO login page. Prefer the proxy's internal address, which is not behind the gate.",
    partial: "Part of the runtime configuration could not be read, so entrypoint-level middlewares are unknown and a gate attached there cannot be ruled out.",
  },
  // The probe's addresses are not configured, so no hint here can be "check the URL".
  // Each one instead names the thing the operator can actually change: what makes a
  // service eligible, whether LabView can reach the address its labels declare, and the
  // two knobs (`LABVIEW_PROBE_TIMEOUT`, `LABVIEW_PROBE_LAN_HOST`) that exist at all.
  probe: {
    "not-found":
      "Probing is on and no service was eligible. Only a service whose labels show it speaks HTTP is asked — a Cloudflare tunnel route with an http/https origin, or a `traefik.http.routers.*` label. A service that merely publishes a port is never probed, and LABVIEW_PROBE_LAN_HOST does not change that: it adds an address for services already eligible.",
    resolve:
      "No probed hostname resolved. These are the hostnames your own labels declare, so LabView has to be able to resolve them from inside its container — with split-horizon DNS the public names may only resolve outside. Set LABVIEW_PROBE_LAN_HOST to probe published ports instead.",
    connect:
      "Nothing accepted the connection. If this is the LAN vantage, LABVIEW_PROBE_LAN_HOST has to be an address the container can reach — the host's LAN IP, not 127.0.0.1, which inside a container is the container.",
    tls: "The certificate was not trusted. Add the issuing CA with NODE_EXTRA_CA_CERTS; LabView does not skip verification, here least of all — a probe that ignored certificates would report a gate it never really reached.",
    timeout:
      "The address accepted the connection and never answered. Raise LABVIEW_PROBE_TIMEOUT, or lower LABVIEW_PROBE_MAX_CONCURRENCY if the requests are arriving faster than one reverse proxy will serve them.",
    partial:
      "Some services did not answer. Those keep the posture their configuration implies — nothing was measured for them, and nothing was assumed either.",
  },
};

export function hintFor(target: string, phase: ConnectionPhase): string | undefined {
  return HINTS[target]?.[phase];
}

/** `3 routers`, `1 router` — the `read` line is prose, so it agrees with itself. */
export function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}

/** One attempt as a sentence, for a client that also joins them into a summary string. */
export function attemptText(a: ConnectionAttempt): string {
  return `${a.endpoint} (${a.why}): ${a.detail}`;
}

/** Short human wording for a phase, for the one-line summary. */
const PHASE_TEXT: Record<ConnectionPhase, string> = {
  disabled: "disabled in configuration",
  "not-configured": "not configured",
  "not-found": "no endpoint was configured or discovered",
  credential: "the configured credential arrived empty",
  resolve: "the name did not resolve",
  connect: "the connection did not succeed",
  tls: "the certificate was not trusted",
  timeout: "no answer before the timeout",
  authenticate: "authentication was rejected",
  authorize: "access was refused",
  path: "no API answered at that path",
  status: "answered with an error status",
  protocol: "answered, but not as this API",
  partial: "connected, with part of the read missing",
  connected: "connected",
};

export function phaseText(phase: ConnectionPhase): string {
  return PHASE_TEXT[phase];
}

/**
 * How much a phase tells you about where the real endpoint is.
 *
 * A client that tries several discovered candidates ends with one failure each, and the
 * report can only carry one phase. The right one is not the first or the last — it is
 * the furthest any candidate got: a host that answered 401 exists, is listening, and is
 * speaking the right protocol, so "authentication was rejected" is the operator's actual
 * problem even if two other candidates never resolved. Reporting `resolve` there would
 * send them to DNS over a working endpoint with a wrong token.
 */
const PHASE_RANK: Partial<Record<ConnectionPhase, number>> = {
  resolve: 1,
  connect: 2,
  timeout: 3,
  tls: 4,
  status: 5,
  path: 6,
  protocol: 7,
  authorize: 8,
  authenticate: 9,
};

/**
 * The phase of the most informative attempt, or `undefined` when there were none.
 *
 * Ties keep the earlier attempt, so a candidate list's own order — configured first,
 * then discovered — decides which of two equally informative failures is reported.
 */
export function dominantAttempt(attempts: ConnectionAttempt[]): ConnectionAttempt | undefined {
  let best: ConnectionAttempt | undefined;
  for (const a of attempts) {
    if (!best || (PHASE_RANK[a.phase] ?? 0) > (PHASE_RANK[best.phase] ?? 0)) best = a;
  }
  return best;
}

export function dominantPhase(attempts: ConnectionAttempt[]): ConnectionPhase | undefined {
  return dominantAttempt(attempts)?.phase;
}

/**
 * Whether a report is worth putting in front of the operator.
 *
 * An optional integration nobody switched on is not a fault, and a banner for it
 * would be permanent furniture — so `disabled` and `not-configured` are silent even
 * though they are not `ok`. A `partial` read *is* shown despite having connected,
 * because a gap in what was read is a gap in what LabView can conclude.
 */
export function shouldBanner(r: ConnectionReport): boolean {
  if (r.phase === "disabled" || r.phase === "not-configured") return false;
  return !r.ok || r.phase === "partial";
}

/** The log level a report belongs at, by the same reasoning as `shouldBanner`. */
export function levelFor(r: ConnectionReport): "info" | "warn" | "debug" {
  if (r.phase === "disabled" || r.phase === "not-configured") return "debug";
  return r.ok && r.phase !== "partial" ? "info" : "warn";
}

/**
 * The lines for one report: a summary, then one line per candidate that was tried.
 *
 * The success line is shaped after the `LabView scanning <root>` line the server
 * already prints, so a startup block reads as one story. The candidate lines are what
 * make a discovery failure diagnosable — "no endpoint answered" is unactionable, and
 * three named addresses with a phase each is not.
 */
export function formatConnection(r: ConnectionReport): string[] {
  const where = r.endpoint ? ` at ${r.endpoint}` : "";
  const how = r.source ? ` (${r.source})` : "";
  const lines: string[] = [];

  if (r.ok) {
    const what = r.read ? ` — ${r.read}` : "";
    const gap = r.phase === "partial" && r.detail ? ` (${r.detail})` : "";
    lines.push(`LabView connected to ${r.target}${where}${how}${what}${gap}`);
  } else if (r.phase === "disabled" || r.phase === "not-configured") {
    lines.push(`LabView is not reading ${r.target} — ${r.detail ?? phaseText(r.phase)}`);
  } else {
    const why = r.detail ?? phaseText(r.phase);
    // "could not connect … at nothing" is what the endpoint-less phases would read as,
    // so they say `read` instead: nothing was dialled, and claiming otherwise sends the
    // operator looking at the network when the gap is in the configuration.
    const verb = r.endpoint ? `connect to ${r.target}${where}${how}` : `read ${r.target}`;
    lines.push(`LabView could not ${verb} — ${r.phase}: ${why}`);
  }
  if (r.hint) lines.push(`  ${r.hint}`);
  // Only on a failure: on success the attempts are candidates that lost a race, and
  // naming them would read as problems when the connection is working.
  if (!r.ok) {
    for (const a of r.attempts) {
      lines.push(`  · ${a.endpoint} (${a.why}): ${a.phase} — ${a.detail}`);
    }
  }
  return lines;
}

/**
 * Which reports say something different from last time.
 *
 * The signature is the target, whether it worked, the stage and the address — and
 * deliberately not what was read: a container count changes on nearly every scan, and
 * including it would turn "log on change" back into "log every scan", which is the
 * noise this exists to avoid. Anything absent from `prev` is a change, so the first
 * scan reports everything.
 */
export function changedConnections(
  prev: Map<string, string>,
  next: ConnectionReport[],
): ConnectionReport[] {
  return next.filter((r) => prev.get(r.target) !== signature(r));
}

/** Record the reports as seen, for the next comparison. */
export function rememberConnections(prev: Map<string, string>, next: ConnectionReport[]): void {
  for (const r of next) prev.set(r.target, signature(r));
}

function signature(r: ConnectionReport): string {
  return [r.target, r.ok ? "ok" : "fail", r.phase, r.endpoint ?? ""].join("|");
}
