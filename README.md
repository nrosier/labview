# LabView

[![Security Checks](https://github.com/nrosier/labview/actions/workflows/security.yml/badge.svg)](https://github.com/nrosier/labview/actions/workflows/security.yml)
[![Docker Build and Push](https://github.com/nrosier/labview/actions/workflows/docker-image.yml/badge.svg)](https://github.com/nrosier/labview/actions/workflows/docker-image.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A self-hosted overview of a Docker Compose homelab.**

Point LabView at the directory where your per-container stacks live and it
produces a structured website showing every app, how it's configured, how it's
reached, what protects it, and how everything is wired together — read-only, with
no agent inside each container.

It reads what you already have: `compose.yml` files, adjacent `.env` files, and
(optionally) live state from the Docker API. Nothing to instrument, nothing to
annotate.

---

## Why

A homelab accumulates. Twenty stacks in, the questions that matter are hard to
answer from the filesystem alone:

- Which services are reachable from the internet, and which are LAN-only?
- Which of those are actually **behind SSO**, and which just *feel* protected?
- What talks to what — which networks, which shared volumes, which `depends_on`?

LabView answers those by deriving them from your compose files and showing the
evidence for each conclusion, so you can check its reasoning instead of trusting
it.

It targets a specific, common TrueNAS Scale pattern:

- **Public ingress** through a Cloudflare tunnel, configured with **DockFlare**
  labels (`dockflare.hostname`, `dockflare.service`, …).
- **Local ingress** through **Traefik**, configured with `traefik.*` labels
  (routers, rules, entrypoints, TLS, middlewares).
- **SSO** through **Authentik** — as a Traefik forward-auth middleware
  (`authentik@docker`), or via OAuth/OIDC or LDAP wired through a service's
  environment.

---

## Features

| | |
|---|---|
| **Dashboard** | Stat tiles (stacks, services, running, public, local-only, auth-protected, and a highlighted **exposed-without-auth** count) plus part-to-whole bars for ingress exposure and auth method. Legends double as filters. |
| **App grid** | One card per service: live status dot, image, hostnames, colored ingress/auth badges. Search and filter across the fleet. |
| **Detail drawer** | Per service: a Mermaid diagram of its connections, Cloudflare routes, Traefik routers, the derived auth posture **with its evidence**, networks, ports, volumes, environment (secrets masked), and live container state. |
| **Relationship graph** | Interactive cytoscape graph of the whole fleet — services colored by exposure, plus network, volume, and tunnel/proxy/SSO hub nodes, linked by network membership, `depends_on`, shared volumes, ingress, and auth. |
| **Ingress classification** | Every service resolves to `public`, `public+host-port`, `public+local`, `local`, `host-port`, or `internal`. A `ports:` mapping publishes on the host (unlike `expose:`), so it counts as reachability — with no proxy and no SSO in the path. |
| **Auth posture** | `authentik-forward-auth`, `authentik-oauth`, `authentik-ldap`, `forward-auth`, `other-oauth`, `ldap`, `basic-auth`, or `none` — each with the labels or env keys that produced it, and whether the conclusion was `observed` in the config or only `inferred` from a name. |
| **Names nothing it can't prove** | A provider is only named when a value says so — a forward-auth address, an issuer URL, an LDAP host. A gate whose provider can't be identified is reported as the mechanism (`forward-auth`) rather than as the most likely vendor. |
| **Offline-first** | The web bundle is fully self-contained (mermaid + cytoscape inlined). No CDN, no external calls. |
| **Light / dark** | Follows the OS, with a manual toggle. Colorblind-safe palette validated in both modes. |

---

## Repository layout

```text
labview/              the application (see labview/README.md for full docs)
  src/                scanner, label parsers, analyzer, docker enrichment, server
  web/                preact UI
  fixtures/           apps/ (happy path) + edge/ (regression cases)
  scripts/smoke.ts    end-to-end pipeline assertions
  compose.yml         deployment example
  Dockerfile          two-stage node:22-alpine build, runs as non-root
.github/workflows/    CI: security scanning, image build/push, dependabot auto-merge
truenas-apps/         local sample lab configuration (gitignored, not part of the app)
IMPLEMENTATION.md     architecture, requirements and invariants — read before changing code
LICENSE               MIT
```

`truenas-apps/` is a **gitignored** copy of a real lab's stacks, kept locally only
as realistic input to develop and test the scanner against. It is not shipped, not
published, and not part of the application.

---

## Quick start

Requires Node.js 20 or newer.

```bash
git clone https://github.com/nrosier/labview.git
cd labview/labview
npm install
npm run build                                   # bundles the UI + compiles the server
LABVIEW_APPS_ROOT=/path/to/your/apps npm start   # -> http://localhost:8080
```

`LABVIEW_APPS_ROOT` is the directory containing one subdirectory per stack, each
with a `compose.yml` (and optionally a `.env`):

```text
/mnt/apps/
  jellyfin/compose.yml
  paperless/compose.yml + .env
  authentik/compose.yml + .env
```

Live container state comes from `/var/run/docker.sock` by default, so running
locally needs no extra setup — and if the socket isn't reachable the scan degrades
cleanly to config-only. To read the Engine over TCP instead (a
[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy), typically),
name the endpoint:

```bash
LABVIEW_APPS_ROOT=/path/to/apps LABVIEW_DOCKER_HOST=tcp://your-proxy:2375 npm start
```

One-shot terminal report, no server:

```bash
LABVIEW_APPS_ROOT=/path/to/apps npm run scan -- --summary
```

### Docker

```bash
docker run --rm -p 8459:8080 \
  -v /mnt/apps:/data/apps:ro \
  -e LABVIEW_APPS_ROOT=/data/apps \
  -e LABVIEW_DOCKER_ENABLED=false \
  niqck/labview:latest
```

That `-p` publishes LabView on your LAN with no authentication, which is fine for
a look but not for a permanent install. For a real deployment — live Docker state
via [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy),
behind Traefik + Authentik with no published port — see
[labview/README.md](labview/README.md#deploy-on-truenas-scale) and
[labview/compose.yml](labview/compose.yml).

---

## Configuration

Everything works out of the box. Environment variables override
[labview/config.example.yml](labview/config.example.yml). The essentials:

| Variable | Default | Purpose |
|---|---|---|
| `LABVIEW_APPS_ROOT` | `/data/apps` | Root directory of your stacks |
| `LABVIEW_DOCKER_ENABLED` | `true` | Enrich with live Docker state |
| `LABVIEW_DOCKER_HOST` | *(unset)* | Docker API endpoint, `DOCKER_HOST` syntax (`tcp://host:2375`, `/path/to.sock`). The standard `DOCKER_HOST` is honoured too. Unset = the socket below |
| `LABVIEW_DOCKER_SOCKET` | `/var/run/docker.sock` | Socket path; always wins over a TCP host |
| `LABVIEW_PORT` | `8080` | HTTP port (container-internal) |
| `LABVIEW_CACHE_TTL` | `60` | Seconds a scan is cached before refresh |
| `LABVIEW_MASK_SECRETS` | `true` | Mask secret-looking env values |

The full table — including `LABVIEW_HOST`, `LABVIEW_DOCKER_PORT`,
`LABVIEW_DOCKER_MAX_CONCURRENCY` and `LABVIEW_CONFIG` — plus the secret patterns,
label prefixes and Authentik hints, is documented in
[labview/README.md](labview/README.md#configuration).

---

## How it works

```text
discover stacks → parse compose (+ .env interpolation) → enrich from Docker
      → build middleware registry → classify ingress → discover Authentik
      → derive auth posture → build graph → serve /api/overview
```

Compose parsing handles both label/env syntaxes (list `- k=v` and map `k: v`),
YAML anchors, `env_file` precedence, `${VAR}` / `${VAR:-default}` interpolation
including nested forms like `${A:-${B:-fallback}}`, and the full port/volume short
and long forms. A cross-stack middleware registry means
`middlewares=authentik@docker` is recognized as SSO even when the middleware is
defined in a different stack.

SSO hostnames are **discovered from your fleet**, not configured: LabView finds
whichever stack actually runs Authentik and adopts the hostnames it answers on, so
an OIDC issuer pointing at `sso.example.com` is attributed correctly even though
the string "authentik" never appears in it. The same mechanism is what keeps it
honest on a fleet that runs something else — with no Authentik to discover,
nothing is learned and every issuer stays generic. No naming convention is
assumed: `oauth.bigcorp.example.com` is not Authentik, and a middleware named
`authentik` that points somewhere else isn't either.

See [labview/README.md](labview/README.md#how-it-works) for the details, and
[IMPLEMENTATION.md](IMPLEMENTATION.md) for the design rules behind them.

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/overview` | GET | The full analyzed model (JSON) |
| `/api/rescan` | POST | Force a fresh scan, returns the rebuilt overview |
| `/api/healthz` | GET | Liveness probe |

The UI is a static SPA served from the same origin. The JSON contract is
[labview/src/model/types.ts](labview/src/model/types.ts), imported directly by
both backend and frontend.

---

## Security

LabView is a read-only observer, and it is designed on the assumption that its own
output is sensitive.

- **Read-only by construction.** Stacks are mounted `:ro`; Docker is reached
  through the socket proxy with read endpoints only (`CONTAINERS`, `NETWORKS`,
  `VOLUMES`, `IMAGES`, `INFO`, `PING`). LabView never writes anything.
- **Secret masking.** Values whose keys look secret (`*PASS*`, `*SECRET*`,
  `*TOKEN*`, `*KEY*`, …) are replaced with a placeholder in both the API and the
  UI. Keys stay visible so you can see *that* a secret is set.
- **Credentials in URLs.** Independently of the key name, values shaped like
  `scheme://user:password@host` have the password stripped — this is what catches
  connection strings such as `DATABASE_URL` and `REDIS_URL`, whose keys match none
  of the patterns above. Scheme, user and host stay readable.
- **File access confinement.** `env_file` references are confined to the apps
  root. An entry like `../../../secrets.env` is refused and noted on the service
  rather than read — for lexical `..` escapes and for symlinks pointing out of the
  tree alike.
- **Published ports count as exposure.** A service with a `ports:` mapping and no
  proxy in front is classified `host-port` and flagged exposed-without-auth — it
  answers on the LAN regardless of what the Traefik labels say. When a proxy *is*
  in front, the service keeps its kind and gains a note that the published port
  bypasses the proxy and its SSO.
- **No built-in authentication.** LabView exposes your topology and (masked)
  config, so **do not publish it raw.** Put it behind your own edge — the compose
  example includes ready-to-adapt Traefik + Authentik forward-auth labels, and it
  deliberately publishes no host port for the same reason.
- **Non-root container.** The image runs as the `node` user.

CI runs on every push and PR touching `labview/**`, plus a daily scheduled sweep:
`npm audit` (informational for all deps, **gating** at `high` for production
deps), GitHub dependency review (fails at `moderate`), CodeQL with
`security-extended`, Trivy filesystem and image scans (vulns, Dockerfile
misconfig, secrets) uploading SARIF to GitHub Security, and TruffleHog verified
secret scanning. The image build is gated behind typecheck + smoke tests.
Dependabot keeps dependencies current, with minor/patch updates grouped and
auto-merged once checks pass; majors are raised individually for review.

Found something? Please open an issue rather than a PR for anything
security-sensitive.

---

## Development

```bash
cd labview
npm install
npm run dev          # esbuild --watch for the UI + tsx server with reload

npm run typecheck    # tsc for both server and web
npm run smoke        # runs the full pipeline against fixtures/ and asserts results
npm run build        # web bundle + server compile
```

`npm run smoke` runs the whole pipeline twice: once over `fixtures/apps` for the
expected classifications, once over `fixtures/edge` for regression cases (URL
credential redaction, `env_file` containment, `dockflare.enable=false`, LDAP
attribution, nested interpolation, host-port exposure, provider attribution). Each
edge fixture is written so that it fails if the corresponding fix is reverted.

No Docker daemon is needed for either — set `LABVIEW_DOCKER_ENABLED=false` and the
pipeline runs config-only.

TypeScript is `strict` with `noUncheckedIndexedAccess`; there is no lint config,
CodeQL covers static analysis in CI.

Before changing the scanner or analyzer, read
**[IMPLEMENTATION.md](IMPLEMENTATION.md)** — it documents the requirements, the
pipeline, and the invariants that keep the output trustworthy (evidence-only
conclusions, no fleet-specific identifiers, mechanism vs. provider, degrade-never-fail).

---

## Limitations

- Reads Compose stacks laid out as `appsRoot/<stack>/compose.yml`. Swarm and
  Kubernetes manifests are out of scope.
- Live state (status, health, IPs) requires access to the Docker API; without it
  the scan degrades cleanly to config-only.
- Auth detection is heuristic and label/env-driven. It is honest about *proxy*
  auth only: an app with its own built-in login (Emby, Home Assistant, Authentik
  itself) will show up as exposed-without-auth, and the note says exactly that.
- Single-host. There is no aggregation across multiple Docker hosts.

---

## License

[MIT](LICENSE) © 2026 NiQck
