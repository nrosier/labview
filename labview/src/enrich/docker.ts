import Docker from "dockerode";
import { accessSync, constants as fsConstants, statSync } from "node:fs";
import { DEFAULT_DOCKER_SOCKET, type LabViewConfig } from "../config.js";
import type { ConnectionPhase, ConnectionReport, DockerState, PortMapping } from "../model/types.js";
import { hintFor, plural } from "../model/connections.js";
import { phaseForCode, phaseForStatus } from "./http.js";
import { mapWithConcurrency } from "./pool.js";

export interface DockerSnapshot {
  available: boolean;
  error?: string;
  /** What happened on the way to the endpoint, for the operator to read. */
  connection: ConnectionReport;
  /** Keyed by `project\u0000service`, by container name, and by short id. */
  byKey: Map<string, DockerState>;
}

const COMPOSE_PROJECT = "com.docker.compose.project";
const COMPOSE_SERVICE = "com.docker.compose.service";

export function composeKey(project: string, service: string): string {
  return `${project}\u0000${service}`;
}

/**
 * The three calls LabView makes of the Engine, and nothing else (I5).
 *
 * Narrow on purpose: it is the entire surface this module is allowed to use, and it lets
 * a test drive an outcome a real daemon cannot be asked for on demand — a refused
 * `inspect` in particular, which is reported as a `partial` read and is otherwise
 * unreachable without breaking a live socket proxy mid-scan.
 */
export interface DockerLike {
  ping(): Promise<unknown>;
  listContainers(opts: { all: boolean }): Promise<Docker.ContainerInfo[]>;
  getContainer(id: string): { inspect(): Promise<Docker.ContainerInspectInfo> };
}

export interface DockerDeps {
  /** Engine factory. Defaults to dockerode, the only implementation shipped. */
  createDocker?: (opts: Docker.DockerOptions) => DockerLike;
}

/** Snapshot every container from the Docker Engine. Never throws. */
export async function snapshotDocker(cfg: LabViewConfig, deps: DockerDeps = {}): Promise<DockerSnapshot> {
  const byKey = new Map<string, DockerState>();
  // Named the way an operator writes it, so the log line is unambiguous about which
  // of the two transports was used — `unix://` and `tcp://` fail for entirely
  // different reasons and the bare path or `host:port` did not say which was which.
  const usingSocket = !cfg.docker.host;
  const endpoint = usingSocket
    ? `unix://${cfg.docker.socketPath}`
    : `tcp://${cfg.docker.host}:${cfg.docker.port}`;
  // A socket path nobody chose is worth distinguishing from one that was: silently
  // falling back to the conventional path when a socket proxy was meant to be
  // configured is a real mistake, and the source is where it shows.
  const source: ConnectionReport["source"] =
    usingSocket && cfg.docker.socketPath === DEFAULT_DOCKER_SOCKET ? "default" : "config";
  const report = (over: Partial<ConnectionReport>): ConnectionReport => ({
    target: "docker",
    ok: false,
    phase: "connect",
    endpoint,
    source,
    attempts: [],
    ...over,
  });
  const failed = (phase: ConnectionPhase, detail: string, code?: string): DockerSnapshot => ({
    available: false,
    error: `docker endpoint ${endpoint} unreachable: ${detail}`,
    connection: report({ phase, detail, code, hint: hintFor("docker", phase) }),
    byKey,
  });

  if (!cfg.docker.enabled) {
    return {
      available: false,
      error: "docker enrichment disabled in config",
      connection: report({ phase: "disabled", detail: "docker enrichment is disabled in configuration" }),
      byKey,
    };
  }

  // The filesystem can tell four socket situations apart that all reach dockerode as
  // one opaque connect error, and each has a different fix — so it is asked first.
  if (usingSocket) {
    const trouble = phaseForSocket(probeSocketPath(cfg.docker.socketPath), cfg.docker.socketPath);
    if (trouble) {
      return {
        available: false,
        error: `docker endpoint ${endpoint} unreachable: ${trouble.detail}`,
        connection: report({ phase: trouble.phase, detail: trouble.detail, hint: trouble.hint }),
        byKey,
      };
    }
  }

  // Connect over TCP (the docker-socket-proxy) when a host is configured,
  // otherwise fall back to the local unix socket.
  const opts: Docker.DockerOptions = {
    ...(usingSocket
      ? { socketPath: cfg.docker.socketPath }
      : { host: cfg.docker.host, port: cfg.docker.port }),
    // Socket inactivity, reset whenever bytes arrive — so a slow but progressing
    // listing is untouched while an endpoint that accepts the connection and then
    // says nothing is reported instead of hanging the scan indefinitely.
    timeout: cfg.docker.timeoutMs,
  };
  const docker = deps.createDocker ? deps.createDocker(opts) : new Docker(opts);
  // Timed, because a request that hit our own deadline is indistinguishable from a peer
  // reset by its error alone — see `classifyDockerError`. Each awaited call is timed
  // separately so a large fleet's total scan time can never be read as one slow request.
  const pingStart = Date.now();
  try {
    await docker.ping();
  } catch (err) {
    const c = classifyDockerError(err, { elapsedMs: Date.now() - pingStart, timeoutMs: cfg.docker.timeoutMs });
    return failed(c.phase, c.detail, c.code);
  }

  const listStart = Date.now();
  try {
    const list = await docker.listContainers({ all: true });
    const summaryStatus = new Map<string, string>();
    for (const c of list) summaryStatus.set(c.Id, c.Status);

    // One inspect per container is the bulk of a scan's latency, and each is an
    // independent round-trip to the socket proxy. Run them with a bounded
    // concurrency so a large fleet does not serialize, while still not opening
    // hundreds of simultaneous connections to the proxy.
    const inspected = await mapWithConcurrency(
      list,
      Math.max(1, cfg.docker.maxConcurrency),
      async (c) => {
        try {
          return await docker.getContainer(c.Id).inspect();
        } catch {
          return null;
        }
      },
    );
    // A refused inspect leaves that container out of every conclusion drawn below —
    // its ports, networks and health simply are not there — so the gap is counted and
    // reported rather than absorbed. A count and nothing else: which container failed
    // is a fleet identifier, and the number is what tells the operator this happened.
    const notInspected = inspected.filter((i) => i === null).length;

    // Applied in list order so that, when two containers collide on a key, the
    // winner does not depend on which inspect finished first.
    for (const [idx, inspect] of inspected.entries()) {
      if (!inspect) continue;
      const state = toState(inspect, summaryStatus.get(list[idx]!.Id) ?? "");
      const labels = inspect.Config?.Labels ?? {};
      const project = labels[COMPOSE_PROJECT];
      const service = labels[COMPOSE_SERVICE];
      if (project && service) byKey.set(composeKey(project, service), state);
      byKey.set(state.name, state);
      byKey.set(state.id, state);
    }
    const read = plural(list.length, "container");
    return {
      available: true,
      connection: report(
        notInspected
          ? {
              ok: true,
              phase: "partial",
              read: `${read}, ${notInspected} could not be inspected`,
              detail: `${notInspected} of ${list.length} containers could not be inspected, so their ports, networks and health are missing`,
              hint: hintFor("docker", "partial"),
            }
          : { ok: true, phase: "connected", read },
      ),
      byKey,
    };
  } catch (err) {
    // Only `listContainers` can reach here — the per-container inspects swallow their
    // own errors — so the elapsed time is one request's, not the whole fleet's.
    const c = classifyDockerError(err, { elapsedMs: Date.now() - listStart, timeoutMs: cfg.docker.timeoutMs });
    return {
      available: false,
      error: `docker query failed: ${c.detail}`,
      connection: report({
        phase: c.phase,
        detail: `the endpoint answered the ping and then refused the container query: ${c.detail}`,
        code: c.code,
        hint: hintFor("docker", c.phase),
      }),
      byKey,
    };
  }
}

/** What the filesystem says about a socket path, before dockerode is handed it. */
export interface SocketProbe {
  exists: boolean;
  isSocket: boolean;
  /** Whether this process may open it. */
  readable: boolean;
}

/** Ask the filesystem about a socket path. The only I/O in this classification. */
export function probeSocketPath(path: string): SocketProbe {
  let stat;
  try {
    stat = statSync(path);
  } catch {
    return { exists: false, isSocket: false, readable: false };
  }
  let readable = false;
  try {
    // Read *and* write: the Docker API is HTTP over this socket, so a request has to
    // be written to it. A read-only mount of the socket still permits that — the `:ro`
    // applies to the mount, not to the socket's own mode — so a failure here is a
    // permission problem on the socket itself.
    accessSync(path, fsConstants.R_OK | fsConstants.W_OK);
    readable = true;
  } catch {
    readable = false;
  }
  return { exists: true, isSocket: stat.isSocket(), readable };
}

/**
 * Which stage a socket path fails at, or nothing when it looks usable.
 *
 * Pure, so the four situations are assertable without a docker daemon. Each says what
 * the filesystem observed and what to change — dockerode's own words for all four are
 * a single `connect ENOENT`, which names none of them.
 */
export function phaseForSocket(
  probe: SocketProbe,
  path: string,
): { phase: ConnectionPhase; detail: string; hint: string } | undefined {
  if (!probe.exists) {
    return {
      phase: "connect",
      detail: `the unix socket ${path} does not exist`,
      hint: `Mount the docker socket into this container (\`${path}:${path}:ro\`), or set LABVIEW_DOCKER_HOST to a socket proxy instead.`,
    };
  }
  if (!probe.isSocket) {
    return {
      phase: "connect",
      detail: `${path} exists but is not a socket`,
      hint: "Bind-mounting a host path that does not exist creates an empty directory in its place — check the socket really is at that path on the host.",
    };
  }
  if (!probe.readable) {
    return {
      phase: "authorize",
      detail: `the unix socket ${path} is not accessible to this process (uid ${typeof process.getuid === "function" ? process.getuid() : "unknown"})`,
      hint: "The container's user is not in the socket's group. Prefer a socket proxy over widening the socket's mode — LabView only needs to read.",
    };
  }
  return undefined;
}

/**
 * Codes dockerode reports when *it* tore the socket down, rather than the peer.
 *
 * `timeout` in `DockerOptions` is implemented by destroying the socket on inactivity,
 * so the error that surfaces is an ordinary reset — the deadline is nowhere in it.
 */
const TEARDOWN_CODES = new Set(["ECONNRESET", "EPIPE", "ETIMEDOUT", "ERR_SOCKET_TIMEOUT", "ESOCKETTIMEDOUT"]);

/**
 * The stage a dockerode failure belongs to.
 *
 * dockerode puts a transport failure's libuv code on the error itself rather than on a
 * `cause`, and an HTTP failure's status on `statusCode` — so the same two tables the
 * HTTP clients use apply, read from different properties. The 403 case is the one that
 * matters most in practice: a socket proxy answers it when the endpoint LabView asked
 * for is not enabled, which is a one-line fix on the proxy and looks nothing like a
 * network problem.
 *
 * `elapsed` exists because an endpoint that accepts the connection and then says
 * nothing is the case `docker.timeoutMs` was added for, and it is the one case the
 * error object cannot describe: dockerode destroys the socket itself, so a black hole
 * arrives as `ECONNRESET`/"socket hang up" — indistinguishable from a peer reset except
 * by the clock. Reporting it as `connect` would print "nothing accepted the connection"
 * about an endpoint that demonstrably did, and send the operator to the wrong place. So
 * when a request with no HTTP status died at or after its own deadline, the clock is
 * believed over the code.
 */
export function classifyDockerError(
  err: unknown,
  elapsed?: { elapsedMs: number; timeoutMs: number },
): {
  phase: ConnectionPhase;
  detail: string;
  code?: string;
} {
  const e = err as { message?: string; code?: unknown; statusCode?: unknown; reason?: unknown };
  const message = typeof e.message === "string" && e.message ? e.message : String(err);
  const status = typeof e.statusCode === "number" ? e.statusCode : undefined;
  if (status !== undefined && status >= 400) {
    const reason = typeof e.reason === "string" && e.reason ? ` (${e.reason})` : "";
    return { phase: phaseForStatus(status), detail: `HTTP ${status}${reason}`, code: String(status) };
  }
  const code = typeof e.code === "string" ? e.code : undefined;
  if (
    elapsed &&
    elapsed.timeoutMs > 0 &&
    elapsed.elapsedMs >= elapsed.timeoutMs &&
    (code === undefined || TEARDOWN_CODES.has(code))
  ) {
    return {
      phase: "timeout",
      detail: `no answer within ${elapsed.timeoutMs}ms (${message})`,
      code,
    };
  }
  return { phase: phaseForCode(code), detail: message, code };
}

function toState(i: Docker.ContainerInspectInfo, summary: string): DockerState {
  const networks = i.NetworkSettings?.Networks ?? {};
  const ipAddresses: Record<string, string> = {};
  for (const [net, def] of Object.entries(networks)) {
    if (def?.IPAddress) ipAddresses[net] = def.IPAddress;
  }
  const healthStatus = i.State?.Health?.Status as DockerState["health"] | undefined;
  return {
    id: i.Id.slice(0, 12),
    name: (i.Name ?? "").replace(/^\//, ""),
    image: i.Config?.Image ?? "",
    imageDigest: pickDigest(i),
    state: i.State?.Status ?? "unknown",
    status: summary,
    health: healthStatus ?? "none",
    running: Boolean(i.State?.Running),
    restartCount: i.RestartCount,
    createdAt: i.Created,
    startedAt: i.State?.StartedAt,
    networks: Object.keys(networks),
    ipAddresses,
    publishedPorts: extractPorts(i),
  };
}

function pickDigest(i: Docker.ContainerInspectInfo): string | undefined {
  const image = i.Image;
  if (typeof image === "string" && image.startsWith("sha256:")) return image.slice(0, 19);
  return undefined;
}

function extractPorts(i: Docker.ContainerInspectInfo): PortMapping[] {
  const out: PortMapping[] = [];
  const ports = i.NetworkSettings?.Ports ?? {};
  for (const [key, bindings] of Object.entries(ports)) {
    const [target, protocol] = key.split("/");
    if (bindings && bindings.length) {
      for (const b of bindings) {
        out.push({
          published: b.HostPort,
          target: target ?? "",
          protocol: protocol ?? "tcp",
          raw: `${b.HostIp ? b.HostIp + ":" : ""}${b.HostPort}->${key}`,
        });
      }
    } else {
      out.push({ target: target ?? "", protocol: protocol ?? "tcp", raw: key });
    }
  }
  return out;
}
