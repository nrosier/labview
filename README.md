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
  (routers, rules, entrypoints, TLS, middlewares). Optionally **verified against
  Traefik's own API**, which is the only way to see what the proxy actually built
  from those labels.
- **SSO** through **Authentik** — as a Traefik forward-auth middleware
  (`authentik@docker`), or via OAuth/OIDC or LDAP wired through a service's
  environment. Optionally **read back from the Authentik API** with a read-only
  token, which turns inference into the provider's own account of each gate.

---

## Features

| | |
|---|---|
| **Dashboard** | Stat tiles (stacks, services, running, public, local-only, auth-protected, and a highlighted **exposed-without-auth** count) plus part-to-whole bars for ingress exposure and auth method. Legends double as filters. |
| **Stack list** | One card per stack — the unit you deploy — rolling up the live status, hostnames and every distinct ingress/auth badge of its services, with a count of anything reachable without auth. Click to expand the services underneath. Search and filters work per service and open the stacks that matched. |
| **Detail drawer** | Per service: a Mermaid diagram of its connections, Cloudflare routes **with the origin each resolves to**, Traefik routers, the derived auth posture **with its evidence**, networks, ports, volumes, environment (secrets masked), and live container state. |
| **Relationship graph** | Interactive cytoscape graph of the whole fleet — services colored by exposure, plus network, volume and SSO/tunnel nodes, linked by network membership, `depends_on`, shared volumes, ingress and auth. Tunnel ingress is drawn as the path the config describes: where a route's origin resolves to another service, that service appears as the hop (`tunnel → proxy → service`) instead of the tunnel being drawn straight at the container. |
| **Ingress classification** | Every service resolves to `public`, `public+host-port`, `public+local`, `local`, `host-port`, or `internal`. A `ports:` mapping publishes on the host (unlike `expose:`), so it counts as reachability — with no proxy and no SSO in the path. |
| **Auth posture** | `authentik-forward-auth`, `authentik-oauth`, `authentik-ldap`, `forward-auth`, `other-oauth`, `ldap`, `basic-auth`, or `none` — each with the labels or env keys that produced it, and whether the conclusion was `confirmed` — the provider's API reported the gate *and* named the service it belongs to — `observed`, meaning the config states it or the API could only tie the gate to the service by name, or merely `inferred` from a middleware name. |
| **Authentik API (optional)** | Given a read-only token, LabView reads applications, providers and outposts and ties each application to a service by the provider's internal host, a container name inside a redirect URI, a hostname both sides declare, or a name — slug, application name or provider name — that identifies exactly one service. This is the only way an **OIDC** gate can be found at all: an OAuth2 application appears in no label and no env key, so a service with no hostname of its own is reachable only through the redirect URI or the name. And it finds the reverse, more usefully: an application whose provider **no outpost is serving**, which looks protected in the admin UI and enforces nothing. |
| **Traefik API (optional, on by default)** | The proxy is located among the scanned stacks and its runtime config read, so the labels are checked against what Traefik actually serves: a router the labels declare that isn't live, an auth middleware named in a label that isn't in the chain the proxy built (the service reads "protected" and answers without a login), a middleware defined in a Traefik *file* provider that a compose scan can't see at all. A live chain replaces inference with `confirmed`, and can also **downgrade** a posture the labels overstate. Also reports backend health per Traefik's own `serverStatus`, and the routers no scanned service could be identified for. |
| **Integration panel** | The `authentik: 13 apps · 9 matched` and `traefik: 10 routers · 8 matched` counts in the topbar are buttons. Click one and you get the whole join: every matched pair with the evidence behind it and how strongly it was established, and every application or router LabView could **not** place — with the reason (`ambiguous` where two services claim it, `no-candidate` where nothing did), plus the rule-by-rule trace of what was tried. Clicking a matched row jumps to that service's drawer. When an integration is unreachable the same panel shows the failure instead: the stage that failed, the address, every candidate that was tried, and the suggested fix. |
| **Names nothing it can't prove** | A provider is only named when a value says so — a forward-auth address, an issuer URL, an LDAP host. A gate whose provider can't be identified is reported as the mechanism (`forward-auth`) rather than as the most likely vendor. An application that could match two services matches neither. |
| **Rescan that tells you what it found** | The button re-reads every `compose.yml` and `.env` under the apps root — new stacks, deleted stacks, added services, edited files — and then says what moved, beside `scanned <time>`: `+1 stack, 2 services changed`, hover for the names. When nothing moved it says **`no config changes`**, so "LabView re-read everything and your files are the same" is never confused with "LabView didn't look". |
| **Offline-first** | The web bundle is fully self-contained (mermaid + cytoscape inlined). No CDN, no external calls. |
| **Light / dark** | Follows the OS, with a manual toggle. Colorblind-safe palette validated in both modes. |

---

## Repository layout

```text
labview/              the application (see labview/README.md for full docs)
  src/                scanner, label parsers, analyzer, docker + authentik +
                      traefik enrichment, server
  web/                preact UI
  fixtures/           apps/ (happy path), edge/ (regression cases),
                      authentik/ + authentik-api.json (identity provider integration),
                      traefik/ + traefik-api.json (reverse proxy integration)
  scripts/smoke.ts    end-to-end pipeline assertions
  compose.yml         deployment example
  Dockerfile          two-stage node:22-alpine build, runs as non-root
.github/
  workflows/          CI: security scanning, test-gated image build/push
  dependabot.yml      weekly dependency updates (npm, base image, Actions)
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
| `LABVIEW_CACHE_TTL` | `60` | Seconds a scan is cached before refresh; Rescan ignores it |
| `LABVIEW_MASK_SECRETS` | `true` | Mask secret-looking env values |
| `LABVIEW_AUTHENTIK_TOKEN_FILE` | *(unset)* | Path to a file holding a **read-only** Authentik API token. Set it to confirm auth posture from the provider itself; leave it unset and nothing is requested |
| `LABVIEW_AUTHENTIK_URL` | *(discovered)* | Authentik base URL, e.g. `http://authentik-server:9000`. Only needed when Authentik is outside `appsRoot` |
| `LABVIEW_TRAEFIK_URL` | *(discovered)* | Traefik API base URL, e.g. `http://traefik:8080`. Only needed when the proxy is outside `appsRoot`, or when discovery picks the wrong endpoint |
| `LABVIEW_TRAEFIK_USERNAME` | *(unset)* | Only for an API reachable solely through a hostname Authentik gates: an Authentik user, or the reserved `goauthentik.io/token`. An unauthenticated endpoint is used with no credential |
| `LABVIEW_TRAEFIK_PASSWORD_FILE` | *(unset)* | Path to a file holding that user's **app password** (not an API token — see [config.example.yml](labview/config.example.yml)) |

The full table — including `LABVIEW_HOST`, `LABVIEW_DOCKER_PORT`,
`LABVIEW_DOCKER_MAX_CONCURRENCY`, `LABVIEW_DOCKER_TIMEOUT`, `LABVIEW_CONFIG` and
the rest of the `LABVIEW_AUTHENTIK_*` and `LABVIEW_TRAEFIK_*` sets — plus the
secret patterns, label prefixes and Authentik hints, is documented in
[labview/README.md](labview/README.md#configuration).

### When something doesn't connect

Every outbound read reports the **stage** it stopped at, so "unreachable" is never
the whole answer:

```text
LabView scanning /data/apps
LabView connected to docker at tcp://dockerproxy:2375 (config) — 86 containers
LabView could not connect to authentik at https://sso.example.com (config) — protocol: HTTP 200 but the body was not JSON — an HTML login page answers exactly like this
  Something answered that is not Authentik's API — most often its own login page…
LabView read 56 stacks, 86 services from /data/apps
```

The same phase and reason appear in a banner under the topbar, under
`npm run scan -- --summary`, and in `meta.connections` on `/api/overview`. The
phases — `resolve`, `connect`, `tls`, `timeout`, `authenticate`, `authorize`,
`path`, `protocol`, `partial` and the rest — are tabulated with what to check for
each in [labview/README.md](labview/README.md#when-a-connection-fails). The two
that most often look like a network problem and aren't: a socket proxy answering
`403` because it was never given `CONTAINERS=1`, and a URL that reaches an SSO
login page instead of the API behind it.

---

## How it works

```text
discover stacks → parse compose (+ .env interpolation) → enrich from Docker
      → build middleware registry → classify ingress → resolve tunnel origins
      → read the Authentik API ∥ read the Traefik API   (concurrently)
      → discover Authentik hostnames
      → match Authentik applications ∥ match live routers to services
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

Tunnel origins get the same treatment. A tunnel usually terminates at a reverse
proxy, not at the container whose labels declare the route, so LabView reads the
origin address and works out where it actually leads: an IP literal addresses the
host, so its port is a published host port and identifies exactly one service; a
bare name addresses a container, so the DNS name is the evidence. A tie between two
services declaring one port is broken by network membership — a candidate sharing
no network with the service it supposedly fronts cannot forward to it. When that
proves a hop, the graph draws `tunnel → proxy → service`. When nothing proves one,
the direct edge stays and the service says why the hop is unknown.

Two things compose files genuinely cannot tell you. The first is whether a gate
defined in Authentik is actually standing in the request path — and for OIDC, whether
there is a gate at all: an OAuth2 application leaves no trace in the compose file, so
the identity provider is the only place it can be seen. Give LabView a read-only
Authentik token and it asks. Each application is tied to a service by one of four
things: a proxy provider's internal host resolving to that service; a bare-name host
inside a URL the provider hands out, such as a redirect URI `http://app:3000/callback`
naming the container itself — the rule that reaches a service with no public hostname
at all; a hostname both the application's URLs and the service's labels declare; or,
last, a name — the slug, the application name or a provider name — when it identifies
exactly one service, compared with separators removed and with the words naming the
mechanism dropped, so `Provider for ledger` finds `ledger` and `Home Assistant` finds
`home-assistant`. Anything that could name two services names neither and is reported
as unmatched rather than guessed. A match made by name alone reports `observed` rather
than `confirmed` and says so in the detail, because a posture resting on a name should
not read like one resting on a resolved address. Then the provider's account replaces
the inference: the provider named, and a proxy or LDAP provider with no outpost
assigned reported as protecting nothing, because nothing is in the path to enforce
it. Without a token this stage does not run and no request is made.

One Authentik behaviour shows through here and is worth knowing, because it decides how
much of that is even visible. `/core/applications/` filters its own answer through the
policy engine as the requesting user, so a least-privilege service account is handed
only the applications it may launch — and a service whose only gate is one of the others
would read as having no gate at all. LabView therefore keeps the total that endpoint
reports next to the subset it received, and rebuilds the missing applications from the
providers assigned to them, which the provider endpoints do give out. Those are marked
`rebuilt`, since the record is thinner — no launch URL, no group, only the providers this
token can read. Whatever is neither returned nor rebuildable is reported as a count in
the banner. Making the token's account a superuser gets the exact list instead; it is
optional, and the three read permissions remain the recommendation.

The second is what the reverse proxy built from those labels. Labels are a request;
the running config is the answer, and the two differ more often than is comfortable
— a rule with a typo, a reference to a middleware that doesn't exist, a gate
attached at the entrypoint rather than the router, a middleware defined in a file
provider the scan can never see. So LabView locates the proxy among the scanned
stacks — a service whose own labels route to `api@internal`, the hop a tunnel
origin resolved to, or, last resort, the Traefik image — and reads `/api/rawdata`
and `/api/entrypoints` from it, preferring its container address so the call stays
on the container network. Live routers are matched to services on addressed
evidence only: the backend URL the proxy itself names, a `@docker` router name
round-tripping from that service's own labels, or a host rule resolving to exactly
one service. Where a router matched, the chain Traefik built **is** the chain — a
resolved `forwardAuth` becomes `confirmed`, retiring the `inferred` verdict that
file-provider middlewares were stuck with, and a label claiming a gate the live
chain does not contain is **downgraded** to `none`, which moves the service into
exposed-without-auth with a note saying exactly what was and wasn't in the chain.
That downgrade requires both reads to have succeeded, because a gate can sit on the
entrypoint instead of the router; a partial read records the gap and changes no
posture. This stage is on by default and needs no configuration — if nothing
answers, the scan continues from the labels alone and reports what it tried.

See [labview/README.md](labview/README.md#how-it-works) for the details, and
[IMPLEMENTATION.md](IMPLEMENTATION.md) for the design rules behind them.

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/overview` | GET | The full analyzed model (JSON) |
| `/api/rescan` | POST | Re-read the apps root and return the rebuilt overview |
| `/api/healthz` | GET | Liveness probe |

The UI is a static SPA served from the same origin. The JSON contract is
[labview/src/model/types.ts](labview/src/model/types.ts), imported directly by
both backend and frontend.

One shape is worth calling out if you consume that JSON yourself:
`meta.authentik.unmatchedApplications` and `meta.traefik.unmatchedRouters` are
**objects, not names**. Each carries the whole application or live router, a
`reason` (`ambiguous`, `no-candidate` or `internal`), a one-line `detail`, and
`considered` — one line per matching rule that ran. They were `string[]` before,
so this is a **breaking change** for any external consumer. It was made rather
than adding a second, parallel list so that why a match did not happen has exactly
one home instead of a name in one place and an explanation in another.

Also **breaking**: `meta.authentik.applications` now counts the applications
Authentik's list endpoint withheld and LabView rebuilt from their providers, so the
number moves for an unchanged Authentik. The alternative was to add the new counts
beside a headline figure that under-reports, which is the defect being fixed.
`applicationsConfigured` is what Authentik says exists, `applicationsWithheld` what its
policy filter removed, `applicationsRecovered` how many of those were rebuilt, and
`discoveredVia` on each application says which read produced it.

`GET /api/overview` is served from a cache for `LABVIEW_CACHE_TTL` seconds.
`POST /api/rescan` ignores that cache and is guaranteed to be answered by a scan
that started *after* the request arrived — so a rescan issued a second after you
saved a file can never hand back a scan that read the old one. Concurrent requests
still coalesce into a single sweep, so holding the button down does not multiply the
load on the socket proxy. What the rescan found is logged too:

```text
LabView rescanned /data/apps — +1 stack, 1 stack changed, +1 service (57 stacks, 87 services)
  · added: monitoring (1 service)
  · changed: wiki — services added: search-sidecar
```

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
- **The Authentik token is optional, read-only, and never speculatively sent.**
  LabView issues GETs only, so the token needs `view_application`,
  `view_provider` and `view_outpost` on a service account with no groups. When the
  endpoint is discovered rather than configured, each candidate is first probed on
  an endpoint that needs no authentication, and the token is sent only to one that
  answers as an Authentik API — a guessed host never receives it. Prefer
  `LABVIEW_AUTHENTIK_TOKEN_FILE` over the env var, which is readable by anyone who
  can run `docker inspect`. There is no flag to skip TLS verification; use
  `NODE_EXTRA_CA_CERTS` for a private CA. Keeping the token that narrow costs
  visibility, and LabView says so instead of absorbing it: Authentik withholds the
  applications the account may not launch, so the banner names how many were withheld
  and how many were rebuilt from their providers.
- **The Traefik API is read without a credential wherever possible.** Discovered
  endpoints are probed on `/api/version`, which needs no authentication, and an
  endpoint that answers is used as-is with nothing sent. A credential is only ever
  sent to an endpoint you configured by hand or to a hostname this scan proved
  belongs to the service whose own labels declare `api@internal` — never to a
  guessed host. The recommended setup involves no credential at all: give Traefik
  `api: {}` plus a dedicated entrypoint on the container network that is **not**
  published to the host. If the API is only reachable through an Authentik-gated
  hostname, note that an Authentik *API token* is not a valid credential — a proxy
  provider wants HTTP Basic with a user and an **app password**, or the reserved
  username `goauthentik.io/token`, and needs "Intercept header authentication"
  enabled. Prefer `LABVIEW_TRAEFIK_PASSWORD_FILE`; `LABVIEW_TRAEFIK_PASSWORD` is in
  the always-masked key list, so LabView scanning its own stack will not print its
  own credential, and no credential is ever interpolated into an error message.
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
secret scanning. Separately, every push to `main` builds and pushes the image —
gated behind typecheck + smoke tests, so a broken build or a reverted regression
fix cannot reach Docker Hub. Dependabot keeps dependencies current — npm, the
Dockerfile base image, and the Actions themselves — with minor/patch bumps
grouped into one PR per ecosystem and majors raised individually; merging is
manual.

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

`npm run smoke` runs the whole pipeline over four fixture fleets: `fixtures/apps`
for the expected classifications, `fixtures/edge` for regression cases (URL
credential redaction, `env_file` containment, `dockflare.enable=false`, LDAP
attribution, nested interpolation, host-port exposure, provider attribution),
`fixtures/authentik` for the identity-provider integration, and
`fixtures/traefik` for the reverse-proxy integration. The two API integrations are
driven through an injected `fetchImpl` serving `fixtures/authentik-api.json` and
`fixtures/traefik-api.json`, so no network or live service is involved — including
a stub that demands Basic auth on the gated hostname and answers unauthenticated
only on the internal one, which is how the credential rule is asserted on the
recorded calls. Each edge fixture is written so that it fails if the corresponding
fix is reverted.

The connection taxonomy is asserted the same way: every transport code, HTTP status
and socket-file state mapped to its phase, the two that most invite conflation
(`401` vs `403`, an unreadable socket vs a refused connection) each with an
assertion that fails if they are merged, and the socket states driven against real
paths made under `os.tmpdir()`.

No Docker daemon is needed for any of them — set `LABVIEW_DOCKER_ENABLED=false`
and the pipeline runs config-only.

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
- Auth detection is label/env-driven, and heuristic wherever neither API is
  available to confirm it. It is honest about *edge* auth only: an app with its own
  built-in login (Emby, Home Assistant, Authentik itself) will show up as
  exposed-without-auth, and the note says exactly that.
- Authentik's applications endpoint filters itself by what the token's user may
  launch, so a least-privilege token is not shown every application. LabView reports
  the total and rebuilds the withheld ones from their providers, but an application
  whose only provider is a kind LabView does not read (SAML, LDAP-only) cannot be
  rebuilt and stays a count — a `partial` banner no scan will clear until the account
  is widened or made a superuser.
- The reverse-proxy integration reads Traefik's API. Another proxy (Caddy, nginx,
  HAProxy) is still classified from its labels; only Traefik's runtime config is
  read back. Its response shapes come from Traefik v3's runtime model, not a
  published schema — a mismatch degrades to "unreachable, with a reason" rather
  than breaking the scan. Traefik's static config file is not parsed.
- Single-host. There is no aggregation across multiple Docker hosts.
- No filesystem watcher. A change to a compose file is picked up on the next scan —
  the `LABVIEW_CACHE_TTL` refresh, or Rescan — not the moment you save it.

---

## License

[MIT](LICENSE) © 2026 NiQck
