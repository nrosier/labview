# LabView — Implementation Guide

This document is the reference for **changing** LabView: what it is required to do,
what it is required *not* to do, where each concern lives, and which invariants a
change must preserve. `README.md` explains how to run it; this explains how it is
built and why.

Read §2 (requirements) and §4 (invariants) before touching anything in
`labview/src/analyze/` or `labview/src/labels/` — those two directories are where
every subtle correctness rule lives, and most of the rules are not obvious from
the code alone.

---

## 1. What LabView is

LabView is a read-only documentation generator for a Docker Compose homelab. It
reads a tree of compose files, optionally enriches them with live container state
from the Docker Engine, derives how each service is reached and what authenticates
it, and serves the result as a JSON API plus a self-contained web UI.

It **generates documentation from evidence**. It is not a config manager, an
orchestrator, or a security scanner with opinions: it reports what the
configuration says, marks what it could not establish, and never edits anything.

- Backend: Node ≥ 20, TypeScript (ESM, `NodeNext`), Fastify 5, `dockerode`, `yaml`.
- Frontend: Preact bundled by esbuild into one self-contained `app.js`.
- Distribution: a two-stage Alpine image, run as an unprivileged user.

---

## 2. Requirements

These are the requirements LabView was built against — a TrueNAS Scale host
running Docker, fronted by a Cloudflare tunnel and Traefik, with Authentik as the
SSO provider. Each is listed with where it is satisfied.

| # | Requirement | Where it is satisfied |
|---|---|---|
| **R1** | Run on TrueNAS Scale with plain Docker containers | `labview/Dockerfile`, `labview/compose.yml` (installable via *Apps → Custom App → Install via YAML*) |
| **R2** | All configuration lives at `<apps-root>/<container>/compose.yml` (+ optional `.env`) | [discover.ts](labview/src/scan/discover.ts) — one stack per immediate subdirectory containing a compose file |
| **R3** | Read Cloudflare tunnel ingress configured by DockFlare labels | [dockflare.ts](labview/src/labels/dockflare.ts) — flat and indexed multi-route label forms, `enable` honoured |
| **R4** | Read local ingress via Traefik labels, and cope with services that bypass it | [traefik.ts](labview/src/labels/traefik.ts) + `classifyIngress` in [analyze/index.ts](labview/src/analyze/index.ts) |
| **R5** | Report SSO posture, whether wired as a reverse-proxy gate or as OAuth/OIDC/LDAP | [auth.ts](labview/src/labels/auth.ts) |
| **R6** | Build the documentation dynamically, and use the Docker socket proxy for live state when available | [enrich/docker.ts](labview/src/enrich/docker.ts); every scan is fresh, nothing is persisted |
| **R7** | Serve the documentation from a built-in webserver, itself exposable through the same tunnel/proxy/SSO chain | [server/server.ts](labview/src/server/server.ts), labelled example in `labview/compose.yml` |
| **R8** | Be generic: the above is an *example* of a fleet, never a description of one | §4 I1–I3, enforced by the fixtures in §8 |

### 2.1 What must not be assumed

R8 is the requirement most easily broken by a well-meaning change. Concretely, the
following are **not** available to the code and must never be hard-coded:

- Hostnames, domains, container names, network names or IP addresses from any
  particular fleet — including in defaults, doc comments, UI copy and fixtures.
- That a reverse proxy exists, that a tunnel exists, or that SSO exists at all.
- That a naming convention identifies a role (`auth.*` is not Authentik, `db` is
  not a database, `proxy` is not Traefik).
- That the Docker Engine is reachable, or reachable at a particular address.

Anything derived from the operator's fleet is *discovered at scan time* from that
fleet, not configured in advance. The only names that ship as defaults are ones
the upstream projects themselves publish: the label prefixes `dockflare` and
`traefik`, the string `authentik`, the domain `goauthentik.io`, and the
conventional socket path `/var/run/docker.sock`.

---

## 3. Architecture

### 3.1 Layout

```
labview/
  src/
    index.ts          entrypoint: loadConfig() -> startServer()
    cli.ts            one-shot scan to stdout (`npm run scan [-- --summary]`)
    config.ts         defaults, config.yml merge, env overrides
    secrets.ts        env masking + URI credential redaction
    model/types.ts    THE contract between backend and frontend
    scan/
      discover.ts     appsRoot -> stack directories
      compose.ts      compose YAML -> normalized AppStack/Service
      env.ts          dotenv parsing + Compose-compatible interpolation
      index.ts        scanStacks(): discover + parse, collecting warnings
    labels/
      dockflare.ts    labels -> CloudflareRoute[]
      traefik.ts      labels -> TraefikRoute[]
      auth.ts         routes + env + registry -> AuthPosture
    analyze/
      middlewares.ts  cross-stack Traefik middleware registry
      origins.ts      cross-stack tunnel-origin resolution (what an origin points at)
      networks.ts     real docker network names for a service (shared by graph + origins)
      index.ts        the pipeline; ingress classification; stats
      graph.ts        nodes/edges for the relationship graph
    enrich/docker.ts  Docker Engine snapshot (never throws)
    server/server.ts  Fastify: /api/* + static UI, with a TTL cache
  web/                Preact UI (see §3.7)
  scripts/
    build-web.mjs     esbuild bundle
    smoke.ts          pipeline assertions over the fixtures
  fixtures/
    apps/             a representative happy-path fleet
    edge/             one stack per previously-fixed defect
```

Repo root holds the README, LICENSE, CI workflows and this document. All code is
under `labview/`, which is why every workflow scopes its paths there.

### 3.2 The pipeline

`buildOverview(cfg, now)` in [analyze/index.ts](labview/src/analyze/index.ts) is
the whole program. It is a pure function of `(config, filesystem, docker, now)`.

| Stage | Owner | Produces |
|---|---|---|
| 1. Discover | `scan/discover.ts` | one `DiscoveredStack` per subdirectory with a compose file, sorted by id |
| 2. Parse | `scan/compose.ts` + `scan/env.ts` | `AppStack[]` — services, ports, mounts, env (interpolated), labels |
| 3. Docker snapshot | `enrich/docker.ts` | `DockerSnapshot` keyed by `"project service"`, container name and short id |
| 4. Middleware registry | `analyze/middlewares.ts` | every Traefik middleware *defined* anywhere, by bare name |
| 5. Pass 1 — routes | `labels/dockflare.ts`, `labels/traefik.ts` | `svc.cloudflare`, `svc.traefik`, `svc.docker`, `svc.ingress` |
| 6. Provider discovery | `discoverAuthentikHints` | hint strings that identify the SSO provider *in this fleet* |
| 7. Origin resolution | `analyze/origins.ts` | `route.origin` — what each tunnel origin points at, and notes where it could not be told |
| 8. Pass 2 — auth | `labels/auth.ts` | `svc.auth`, `exposedWithoutAuth`, notes; then secrets masked |
| 9. Graph | `analyze/graph.ts` | `Graph` of services, networks, shared volumes, resolved ingress paths, auth hubs |
| 10. Stats | `computeStats` | `OverviewStats` for the dashboard header |

**Why two passes.** Steps 6–7 cannot run per-service inside step 5. Three
conclusions are only available once the *whole* fleet is parsed:

1. A Traefik middleware referenced as `authentik@docker` is usually defined in a
   different stack than the service using it, so classifying the reference
   requires the global registry (step 4).
2. Which hostnames represent the SSO provider is learned from whichever stack
   *runs* the provider — so its routes must already be parsed (step 6 after 5).
3. A tunnel origin routinely names a reverse proxy defined in a *different* stack,
   so resolving it needs a fleet-wide index of published host ports and DNS names
   (step 7, after the routes exist and before the graph is drawn from them).

A change that needs fleet-wide knowledge belongs in a new pass or in step 4/6,
not in a per-service function reaching for global state.

### 3.3 Provider discovery (step 6)

`discoverAuthentikHints` walks the parsed fleet for a service that is
identifiably Authentik — its image mentions `authentik`, or one of its labels
defines a forward-auth address containing `goauthentik.io` — and adopts that
service's container name and every Traefik/DockFlare hostname it answers on as
*hints*.

Two properties matter and must be preserved:

- **It cannot invent a provider.** With no such service in the fleet, nothing is
  learned, and every issuer stays generic. This is what makes a non-Authentik
  fleet report honestly.
- **A hint must be specific enough to be safe.** Hints are matched against
  arbitrary values downstream, so `isSpecificHint` rejects short or bare words.
  Upstream Authentik names its services `server` and `worker`; learning `server`
  verbatim would make every `OIDC_ISSUER=https://server.example.com` look like
  Authentik.

### 3.4 Tunnel origin resolution (step 7)

A tunnel rarely terminates at the container whose labels declare it. The origin
(`dockflare.service`) normally names a reverse proxy, which forwards to the
container over a shared network. Drawing `tunnel → container` would state a
topology the configuration contradicts, so `analyze/origins.ts` resolves the
origin from evidence and records the conclusion on `route.origin`.

Which evidence applies depends on how the origin addresses its target:

- **An IP literal addresses the host.** The port is therefore a *published host
  port*, and a host port can only be held by one service, so a match identifies
  the target rather than suggesting it.
- **A bare name addresses a container.** The port is container-internal and says
  nothing about ownership, so the *name* is the evidence: compose publishes a
  service's name and `container_name` as DNS aliases on its networks.

One wrinkle needs a second kind of evidence. A fleet may declare the same host
port on several services even though only one can hold it at a time, so a port
match is not always unique. **Network membership breaks the tie**: a candidate
sharing no network with the service it supposedly fronts cannot forward to it.
That is the second leg of the path — and it is as observable as the port.

Two rules keep this honest, and both have fixtures:

- **Repeated declarations by one service are not rivals.** `443:443/tcp` beside
  `443:443/udp` (HTTP/3), or a name equal to the service's own `container_name`,
  reach the index twice. `distinct()` collapses them by service key; without it a
  settled origin gets reported as ambiguous.
- **A genuine tie stays unresolved.** Two reachable services claiming one port
  yields `unresolved` with the ambiguity as its stated reason, never a winner
  picked by order. Likewise a FQDN, or a port nobody publishes.

No image, vendor or naming convention is consulted anywhere in the module — the
proxy is identified structurally, by what it publishes and what it can reach.

### 3.5 The data contract

[model/types.ts](labview/src/model/types.ts) is the single contract between
backend and frontend, and `/api/overview` serves exactly an `Overview`. Rules:

- It must stay free of Node-only imports — the web build imports it directly.
- `web/model.ts` re-exports it so UI files have one import surface. Add new
  exported types there too.
- Adding a member to a union (`AuthMethod`, `IngressKind`) is a **breaking UI
  change**: the palette in `web/lib/palette.ts` maps every member to a colour and
  a label, and an unmapped member silently renders grey. See §10.

### 3.6 Serving

Fastify with three routes and a static mount:

| Route | Behaviour |
|---|---|
| `GET /api/overview` | cached scan; rebuilds when older than `cacheTtlSeconds` |
| `POST /api/rescan` | forces a rebuild, returns it |
| `GET /api/healthz` | `{ok: true}`, no scan |
| `GET /*` | the built UI from `web/dist`, SPA-style fallback to `index.html`; a 404 under `/api/` stays JSON |

Concurrent requests during a rebuild share one in-flight promise, so a burst of
traffic cannot start N scans. The cache is warmed in the background at startup so
the first page load is instant. If `web/dist` is absent the server still runs and
says how to build it — the API is the primary product, the UI is a view of it.

### 3.7 Frontend

Preact + esbuild, bundled to a single `web/dist/app.js` with mermaid and cytoscape
inlined; `web/index.html` and `web/styles.css` are copied verbatim. There is no
CDN dependency and no network access beyond same-origin `api/*` (relative, so it
works under a path prefix).

**View hierarchy.** The Stacks tab lists one card per stack — the unit a compose
fleet is organised in — which expands to its services, each opening the detail
drawer. Two rules hold it together:

- **Filtering stays service-level.** "Public" is a property of a service, not of a
  directory. The predicate runs over the flat service list; a stack renders when at
  least one of its services matches, and shows only the matching ones. A
  stack-level predicate would have to reduce a stack to one posture, which it does
  not have.
- **A collapsed stack rolls up, it does not summarise.** Every distinct ingress and
  auth posture present is shown, plus a count of services reachable without auth. A
  stack with an internal database and a public UI is both at once; picking a "worst
  case" badge would misreport it.

`web/lib/palette.ts` is the single source of truth for categorical colour: every
`IngressKind` and `AuthMethod` maps to a CSS custom property from the validated
palette in `styles.css`. DOM nodes use `var(--…)` directly; canvas-based views
(cytoscape, mermaid) call `resolveVar()` so both follow the light/dark toggle from
one definition.

---

## 4. Invariants

These are the rules that make the output trustworthy. A change that breaks one is
a bug even if every test passes.

### I1 — Documentation rests on observable evidence

Every statement in the output must trace to a value read from a compose file, an
`.env` file, or the Docker Engine. Not from a name, not from a convention, not
from what is statistically likely.

Where a conclusion cannot be established, the correct output is the weaker,
truthful one — plus a note saying what was missing. `AuthPosture.evidence` exists
so a reader can check the derivation, and `AuthPosture.confidence` exists so they
can tell a fact from a guess without re-deriving it.

### I2 — No fleet-specific identifiers in shipped artifacts

Defaults, doc comments, example configs, UI copy and fixtures use
`example.com`-style placeholders and role words (`<reverse-proxy-host>`,
`<access-group>`). The operator's real fleet is input, never source.

This includes UI copy: a stat tile may say "tunnel route", not "Cloudflare" — the
routes' own labels say which tunnel, and a fleet using none should not be told
otherwise by a hard-coded caption.

### I3 — Mechanism and provider are separate conclusions

The mechanism is usually certain; the provider usually is not. A `forwardauth`
middleware definition proves a gate exists. Naming *whose* gate it is requires a
value that says so — the forward-auth address, an issuer URL, or an LDAP host
matching a discovered provider identity.

So each family has a generic member alongside the attributed one:

| Mechanism | Provider identified | Provider not identified |
|---|---|---|
| Reverse-proxy gate | `authentik-forward-auth` | `forward-auth` |
| OAuth / OIDC | `authentik-oauth` | `other-oauth` |
| LDAP | `authentik-ldap` | `ldap` |

Corollaries that are easy to break:

- **The address outranks the name.** A middleware called `authentik` that points
  at something else is not Authentik. `classifyMiddleware` reads the registry
  definition first and only falls back to the name when no definition was found
  anywhere — and then marks the result `inferred`.
- **Hints match at token boundaries, never as bare substrings.** `auth` must not
  match `oauth.bigcorp.example.com`. See `identifies()` in
  [auth.ts](labview/src/labels/auth.ts).
- **No host-naming convention ships as a default.** `auth.`, `sso.` and friends
  are guesses about someone else's DNS. Real hostnames are discovered (§3.3).
- **The graph obeys this too.** Only an identified provider hangs off the
  `ext:authentik` hub; a mechanism-only detection gets the generic `ext:auth`
  hub, labelled "SSO (unidentified)".

### I4 — Degrade, never fail

A single malformed stack must not break the scan. Failures become warnings on the
object they belong to and the pipeline continues:

- YAML parse error → `stack.warnings`, stack still listed.
- Unresolved `${VAR}` → `service.notes`.
- Unreadable stack → `meta.warnings` via `scanStacks`.
- Docker unreachable → `snapshotDocker` returns `available: false` with the
  reason; it never throws, and the scan proceeds config-only.
- A single container `inspect` failing → that container is skipped, not the scan.

### I5 — Read-only, least privilege

LabView reads. It never writes to the fleet, never calls a mutating Docker
endpoint, and needs no privileged access:

- Apps root is mounted read-only.
- Docker access goes through a socket proxy with only read endpoints enabled
  (`CONTAINERS`, `NETWORKS`, `VOLUMES`, `IMAGES`, `INFO`, `PING`). Only `ping`,
  `listContainers` and `inspect` are ever called.
- The image runs as `USER node`.
- Its own compose example publishes **no `ports:`** — see §7.

### I6 — Secrets never reach the API

Masking is the last step of pass 2, after analysis, so the analyzer can read raw
values while the API never sees them. Two independent mechanisms, both in
[secrets.ts](labview/src/secrets.ts):

1. **Key-pattern masking** — a key matching `keyPatterns` has its value replaced
   with `null` and `masked: true`. `keysNever` un-masks false positives
   (`PUBLIC_KEY_URL`), `keysAlways` adds explicit ones.
2. **URI credential redaction** — independently of the key name, the password in
   any `scheme://user:password@host` value is replaced with `***`. This is what
   catches `DATABASE_URL`, `REDIS_URL`, `AMQP_URL`, whose keys match no pattern.
   Scheme, user and host stay visible; only the password goes.

A new field that could carry a secret must be routed through `maskEnv` or given
equivalent treatment. Note that `labels` are **not** masked — they are routing
metadata by design; if a future label carries a credential it needs handling.

### I7 — Determinism

Same inputs, same output. `now` is injected into `buildOverview` rather than read
from the clock, stacks are sorted by id, routers are sorted by name, env is sorted
by key, and Docker keys are applied in list order so two containers colliding on a
key do not race. Keep it that way: the smoke test and any future golden-file test
depend on it.

### I8 — Containment for anything the config asks us to read

A compose document is untrusted input. `env_file` is currently the only directive
that makes LabView open another file, and `resolveContained()` in
[compose.ts](labview/src/scan/compose.ts) confines it to the apps root — against
both lexical escapes (`../../etc/shadow`) and symlinks pointing out of the tree.
A refusal is reported as a service note rather than silently ignored.

Both the literal and the fully-resolved apps root are accepted, because an apps
root is often reached through a symlink or bind mount and a legitimate path must
not be rejected for failing to match textually.

**Any future directive that reads a path must go through `resolveContained`.**

---

## 5. Definitions

**Stack** — one immediate subdirectory of `appsRoot` containing a compose file.
Its directory name is its id and its default compose project name.

**Service** — one entry under `services:` in a stack. Identified in the graph as
`svc:<stack>/<service>`; matched to a live container by
`com.docker.compose.project`+`service` labels first, then by container name.

**`ports:` vs `expose:`** — the whole basis of ingress classification.
`ports:` publishes on the host; `expose:` does not. Any entry under `ports:` is
reachability, including the short form with no host side (`ports: ["9100"]`),
which still publishes — on an ephemeral host port. So the *presence* of a mapping
is the signal, not a parsed host port number.

**IngressKind**

| Kind | Meaning |
|---|---|
| `public` | a tunnel route exists |
| `public+host-port` | tunnel route, and it also publishes a host port |
| `public+local` | tunnel route and a proxy route |
| `local` | a proxy route only |
| `host-port` | publishes a host port with nothing in front of it |
| `internal` | not reachable from outside its networks |

`host-port` is a **fallback kind**: it is only reported when no proxy route
exists. A proxied service that *also* publishes a port keeps its `local` /
`public+local` kind and gets a note from `noteHostPortBypass` instead. This is
deliberate — most services in a typical fleet publish a port, so folding that into
the kind would collapse the whole distribution into one bucket. The note is not
cosmetic: it is the difference between "protected by SSO" and "protected by SSO
unless you use the port".

**OriginTarget / OriginKind** — where a tunnel route's origin address was found to
lead (§3.4). Attached to every `CloudflareRoute` whose `service` is non-empty, and
carrying an `evidence` string in the same spirit as `AuthPosture.evidence`.

| Kind | Meaning | Graph |
|---|---|---|
| `self-network` | the origin host is this service's own name or `container_name` | direct `tunnel → service` |
| `self-host-port` | the origin port is a host port *this* service publishes | direct `tunnel → service` |
| `fleet-service` | the origin resolves to another scanned service, which shares a network with this one — `hopKey` names it | chained `tunnel → hop → service` |
| `unresolved` | nothing observable settles it: no match, a FQDN, or a tie between reachable candidates | direct `tunnel → service`, plus a service note |

`unresolved` keeps the direct edge on purpose. It is the one shape that is not a
claim about the path — an invented hop would be, and dropping the edge would hide
a route that exists. The note states which of the reasons applied.

**Proxy role** — `GraphNode.role: "proxy"` is set on a service another service's
origin resolved to. It stays an ordinary service node (same kind, same drawer, same
click target); the role only lets the UI colour it as infrastructure. Nothing else
reads it, and no service is ever *declared* a proxy — the role is a consequence of
having been resolved as a hop at least once.

**AuthMethod / AuthConfidence** — see §4 I3. `confidence: "inferred"` means the
method rests on a middleware *name* because no definition was found in any scanned
stack; it also produces a service note saying so.

**`detail` vs `evidence` vs `notes`** — `detail` is the prose summary of the
primary detection plus any secondary ones; `evidence` is the flat list of raw
signals (`middleware x`, `env OIDC_ISSUER`, `forwardauth -> …`,
`provider not identified from the scanned config`); `notes` are per-service
warnings for a human (bypasses, refusals, unresolved references, inferences).

**`exposedWithoutAuth`** — `ingress !== "internal"` and no auth detected (proxy
gate, OIDC/LDAP, basic-auth, or a Cloudflare Access policy). Note this counts a
`host-port`-only service as exposed, because it is.

**Middleware registry** — every `traefik.http.middlewares.<name>.<type>` label
found in *any* stack, keyed by bare name (references carry a `@docker` /`@file`
provider suffix that is stripped). On a name collision an auth type wins over a
non-auth type, so a `headers` middleware cannot shadow a `forwardauth` one.

**Hint** — a string that identifies the SSO provider, either configured
(`labels.authentik.hostHints`) or discovered (§3.3). Matched at token boundaries
against forward-auth addresses, issuer URLs and LDAP hosts.

---

## 6. Configuration

Precedence, lowest to highest: **defaults** in `config.ts` → **`config.yml`**
(path from `LABVIEW_CONFIG`, default `./config.yml`) → **environment variables**.
Arrays replace rather than merge. A malformed config file logs and falls back to
defaults rather than exiting.

`merge()` deep-copies rather than spreading, because `applyEnvOverrides` mutates
nested objects in place — a shallow merge would leak one `loadConfig()` call's
overrides into the next.

Key knobs (`labview/config.example.yml` documents all of them):

| Env | Config | Notes |
|---|---|---|
| `LABVIEW_APPS_ROOT` | `appsRoot` | the scan root and the containment boundary (I8) |
| `LABVIEW_DOCKER_HOST` / `DOCKER_HOST` | `docker.host` + `port` | `tcp://host:port`, `host:port`, `unix:///path` or `/path`. A socket form clears `host`. `LABVIEW_DOCKER_HOST` wins, being the more specific of the two |
| `LABVIEW_DOCKER_SOCKET` | `docker.socketPath` | always wins and disables the TCP host |
| `LABVIEW_DOCKER_ENABLED` | `docker.enabled` | `false` = config-only scan |
| `LABVIEW_DOCKER_MAX_CONCURRENCY` | `docker.maxConcurrency` | bounded `inspect` fan-out; raise for big fleets, lower if the proxy drops connections |
| `LABVIEW_MASK_SECRETS` | `secrets.maskValues` | leave on |
| `LABVIEW_CACHE_TTL` | `cacheTtlSeconds` | |
| `LABVIEW_PORT` / `LABVIEW_HOST` | `server.port` / `host` | |

**Docker endpoint resolution order:** explicit socket → configured/env TCP host →
default socket path. The default is the conventional local socket, the one
endpoint that requires no assumption about the operator's container names; a
socket proxy is opted into. Neither the Dockerfile nor `config.ts` may ship a
default TCP hostname (I2) — `compose.yml` sets it, as an example.

---

## 7. Security model

**Trust boundaries.** Compose files, `.env` files and container labels are
untrusted input parsed with no code execution. The Docker Engine is trusted but
reached read-only through a proxy. The HTTP surface is trusted to the extent the
operator's own edge makes it so — LabView has no authentication of its own, by
design; it is deployed behind the same tunnel/proxy/SSO chain as the rest of the
fleet, which is exactly what it documents.

**Why LabView's own compose example publishes no `ports:`.** A published host port
answers directly at `<host-ip>:<port>`, bypassing the reverse proxy and therefore
any SSO middleware on it. For a dashboard that lists the whole topology — every
hostname, every exposed service, every env key — that is precisely the wrong
default. The same reasoning applies to its DockFlare example, which points the
tunnel origin at the reverse proxy rather than at the container, so the request
still traverses the auth middleware. LabView reports this class of mistake in
other people's stacks; it must not ship one.

**Handled:** path traversal and symlink escape via `env_file` (I8); secret
exposure via key patterns and URI credentials (I6); privileged Docker access
(socket proxy, read-only endpoints, `USER node`); denial by malformed input (I4);
scan stampede (in-flight coalescing).

**Deliberate non-goals:** no authentication, authorization or rate limiting in
LabView itself; no TLS termination (the proxy does it); no persistence, so
nothing to leak at rest; no writes of any kind; no outbound network calls.

---

## 8. Testing contract

`npm run smoke` runs the entire pipeline against two fixture roots with Docker
disabled and asserts on the resulting `Overview`. It exits non-zero on any
failure and gates CI.

**`fixtures/apps`** — a representative happy-path fleet: a tunnel + proxy service,
a proxy-bypassing service, cross-stack middleware resolution, LDAP and OIDC
services, a stack with an `.env`, shared binds across stacks, and a `proxy` stack
that is the resolved hop for another stack's tunnel origin (§3.4). Asserts the
normal output is right.

**`fixtures/edge`** — one stack per previously-fixed defect. The contract:

> **Each edge fixture must fail the smoke test if its fix is reverted.**

A test that passes either way documents nothing. When adding a fix, verify this
explicitly: back the fix out, confirm the new assertion fails, restore it. Current
stacks:

| Stack | Pins |
|---|---|
| `dbstack` | URI credential redaction; `env_file` containment |
| `cfdisabled` | `dockflare.enable=false` yields no route (and truthy variants still do) |
| `ldapapp` | LDAP against a non-Authentik directory stays generic |
| `interp` | nested `${A:-${B:-lit}}` defaults, `$$`, unused-branch handling |
| `hostport` | published ports are reachability; `expose:` is not; bypass notes |
| `tunnelorigin` | an origin that cannot be resolved stays unresolved: a port nothing publishes, and a tie between two reachable claimants. Neither may invent a hop |
| `otherprovider` | provider attribution needs proof, on both the env and the address path |
| `authentik` | upstream's generic service names (`server`, `worker`) must not become fleet-wide hints — `isSpecificHint`. Doubles as the definition site for the cross-stack `authentik@docker` references |

Two caveats worth knowing when writing these:

- **Assert on the primary conclusion, not a secondary one.** A misattribution can
  hide inside `detail` when a higher-precedence detection wins. `otherprovider`
  has an `oidconly` service carrying *only* the third-party OIDC env for exactly
  this reason — nothing can outrank it there.
- **Belt-and-braces fixes need honest tests.** Token-boundary matching and the
  removal of the `auth.` default hint each independently prevent the
  `oauth.bigcorp.example.com` misattribution. Reverting one changes no observable
  behaviour, so no behavioural test can catch it; the fixture fails when the
  *class* of bug returns (both reverted), which is the strongest true statement
  available.

`fixtures/outside-root.env` sits outside both roots on purpose: it is the target
of the `env_file` escape attempt that must be refused.

Fixtures are also subject to I2 — they use `example.com` and RFC-1918 addresses,
never anything from a real fleet.

---

## 9. Build, CI, release

```
npm run typecheck   # tsc --noEmit for server (tsconfig.json) AND web (tsconfig.web.json)
npm run smoke       # pipeline assertions over the fixtures
npm run build       # esbuild web bundle + tsc server -> dist/
npm run dev         # build web once, then tsx watch on the server
npm run scan        # one-shot JSON to stdout; --summary for the digest
```

`tsc` runs with `strict` and `noUncheckedIndexedAccess`; the web tsconfig uses
`moduleResolution: Bundler` since esbuild resolves. **Both** projects must
typecheck — the web build imports backend types directly, so a model change can
break the UI without touching a `.tsx` file.

The gate before any commit:

```
npm run typecheck && npm run smoke && npm audit --omit=dev --audit-level=high && npm run build
```

CI lives in `.github/workflows/`:

- **docker-image.yml** — runs on every push to `main`. The `test` job runs
  typecheck + smoke and the build `needs:` it, so a broken build or a reverted
  fixture fix cannot reach Docker Hub. The build context is `./labview`, not the
  repo root: the Dockerfile and every path it copies are context-relative, so a
  root context finds none of them.
- **security.yml** — `npm audit` at moderate (informational) and at high for
  production deps (**gating**), dependency-review at moderate on PRs, CodeQL
  `security-extended`, Trivy filesystem *and* image scans, TruffleHog
  `--only-verified`. Path-scoped to `labview/**` plus its own file, and also runs
  daily at 03:17 UTC regardless of the filter.

Dependency updates are configured in **`.github/dependabot.yml`** — npm, the
Dockerfile base image, and the Actions used by these workflows, weekly, with
minor/patch bumps grouped into one PR per ecosystem and majors raised
individually. That file is config for GitHub's hosted Dependabot service, **not**
a workflow: it is read only from `.github/dependabot.yml`, and moving it into
`workflows/` both breaks Actions (no `jobs:` key) and silently stops Dependabot.
Merging its PRs is manual — there is no auto-merge workflow.

---

## 10. Playbooks

**Add an `IngressKind` or `AuthMethod`.** The union in `model/types.ts` is only
the start; the compiler will not catch the UI half.

1. Add the member with a doc comment saying what evidence justifies it.
2. Emit it — `classifyIngress` / `deriveAuth`. For an auth method, place it in the
   precedence `order` array in `deriveAuth`: a proxy-level gate ranks first
   because it is what actually stops a request at the edge.
3. `computeStats` if it needs a counter (add the field to `OverviewStats`).
4. `analyze/graph.ts` if it changes which hub a service hangs off (I3).
5. `web/lib/palette.ts` — add a `RoleMeta` entry, keeping the ordering meaning
   (ingress: most→least exposed; auth: identified providers before generic ones).
6. `web/styles.css` — define the CSS custom property in both themes, from the
   validated palette; do not invent a colour.
7. `web/lib/mermaidDef.ts` if the static diagram labels it.
8. A fixture and an assertion (§8).

**Add a config knob.** `LabViewConfig` interface → `DEFAULTS` → an
`applyEnvOverrides` line if it needs an env var → document it in
`config.example.yml` *and* the README table. Defaults must satisfy I2.

**Support another label provider.** New file in `src/labels/`, called from
`parseRoutes`, prefix configurable under `labels.*` like the existing two. If it
implies reachability, extend `classifyIngress`; if it implies an auth gate, return
detections through `deriveAuth` rather than writing `svc.auth` directly, so
precedence and confidence stay in one place.

**Change how auth is detected.** Re-read §4 I3 first, then add a fixture that
fails before your change and passes after.

---

## 11. Known limitations

Not bugs — bounded scope, stated so nobody assumes otherwise:

- **Traefik dynamic-file config is invisible.** Only label-defined middlewares are
  in the registry. A middleware from a file provider resolves to nothing, which is
  why the name-based fallback and `confidence: "inferred"` exist.
- **Compose `extends`, `include` and profiles are not resolved.** The file is read
  as written.
- **Only `<appsRoot>/<dir>/compose.yml` is discovered** — one level deep, no
  nesting (R2).
- **Interpolation uses the stack `.env` only**, not the shell environment of
  whoever ran `docker compose up`. Bare `KEY` entries are marked
  `source: "shell-default"` and left empty if the `.env` does not define them.
- **`env_file` values are not interpolated**, matching Docker's own behaviour.
- **Auth posture describes configuration, not enforcement.** A middleware
  reference proves it was configured; whether Traefik is actually running with
  that config is outside what a file scan can know.
- **No history.** Every scan is a snapshot; nothing is persisted, so there is no
  drift detection or change log.
- **The Docker snapshot lists all containers**, including ones with no compose
  file under `appsRoot`; those simply do not match a service and are not reported.

---

## 12. Decision log

Why the non-obvious choices are what they are. Read before reversing one.

| Decision | Rationale |
|---|---|
| Published ports are reachability, not metadata | `ports:` makes a service answerable at `hostIP:port` with no proxy and no SSO. Treating it as decoration under-reported exposure on real fleets. |
| `host-port` is a fallback kind, the bypass is a note | Most services publish a port; folding that into the kind would flatten the distribution. The distinction that matters is whether anything is *in front*. |
| Generic `forward-auth` / `other-oauth` / `ldap` members | The mechanism is provable, the provider often is not. Without a generic member the classifier has to either guess a vendor or report "no auth" — both are wrong. |
| Hints match at token boundaries | A substring match labelled `oauth.bigcorp.example.com` as Authentik on four shared letters. |
| No `auth.` / `sso.` host convention in defaults | A convention is a guess about someone else's DNS. Real hostnames are discovered from the fleet instead. |
| The forward-auth *address* outranks the middleware *name* | A middleware named after one provider can point at another. The address is the statement of fact. |
| `confidence` on `AuthPosture` | Callers were otherwise unable to distinguish a resolved definition from a name-based guess without re-deriving it. |
| Default Docker endpoint is the local socket | Any default TCP host would bake in a guess about the operator's container names. The socket needs no such assumption; the proxy is opted into. |
| `DOCKER_HOST` honoured alongside `LABVIEW_DOCKER_HOST` | It is the variable every other Docker client already reads. The `LABVIEW_`-prefixed one wins, being more specific. |
| Masking runs last in pass 2 | The analyzer needs raw values (an LDAP host, an issuer URL) that must never reach the API. |
| URI credential redaction is key-independent | `DATABASE_URL` matches no secret key pattern but carries a password. |
| `now` injected into `buildOverview` | Determinism (I7) — required for fixture-based assertions. |
| Bounded `inspect` concurrency instead of unbounded `Promise.all` | Per-container `inspect` is the bulk of scan latency, but hundreds of simultaneous connections can overwhelm a socket proxy. |
| Cross-stack middleware registry keyed by bare name | Services reference `x@docker` while `x` is defined in another stack; a per-stack view could not classify the reference at all. |
| A tunnel origin is resolved by *published port and shared network*, never by a name convention | The port is unique per host and the network membership is what makes forwarding possible, so both are facts. "The service called `proxy` is probably the proxy" is a guess about someone else's naming, and would break I2 the moment a fleet named it anything else. |
| An unresolved origin keeps the direct edge | Two alternatives, both worse: inventing a plausible hop states a path that was never observed, and dropping the edge hides a route that exists. The direct edge plus a note is the only shape that claims nothing untrue. |
| A hop is a role on a service node, not a node of its own | The proxy is a scanned service with its own image, mounts, auth posture and drawer. Synthesising a separate node beside it would duplicate it in the graph and make it unclickable. |
| Edges deduped by (kind, source, target, label) | A tunnel hostname and the proxy router serving it describe one link. Emitting both drew dozens of parallel identical lines between the same two nodes. |
| Auth type wins a registry name collision | A `headers` middleware sharing a name must not shadow a `forwardauth` one and erase a real gate. |
| Compose files treated as untrusted | `env_file: ../../../../etc/shadow` would otherwise pull host files into a public API response. |
| No `ports:` in LabView's own compose example | It would bypass the very SSO the dashboard documents (§7). |
| Single self-contained JS bundle, no CDN | An air-gapped or egress-filtered homelab must still render the UI. |
| Stack cards that expand, with service-level filters | The stack is the unit an operator deploys and thinks in; a flat service grid scattered a stack's parts alphabetically. But exposure and auth are per-service, so the filter predicate stays per-service and the grouping is applied to its results. |
| Fastify + `@fastify/static` over a hand-rolled server | Correct static handling, SPA fallback and structured logging without writing any of it. |
