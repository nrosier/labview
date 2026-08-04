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
- Frontend: Preact bundled by Vite into `web/dist` — one self-contained `app.js`.
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
| **R4b** | Optionally verify that ingress against the reverse proxy's own runtime API, discovering the endpoint from the fleet | [enrich/traefik.ts](labview/src/enrich/traefik.ts) + [analyze/traefik.ts](labview/src/analyze/traefik.ts); §3.6 |
| **R5** | Report SSO posture, whether wired as a reverse-proxy gate or as OAuth/OIDC/LDAP | [auth.ts](labview/src/labels/auth.ts) |
| **R5b** | Optionally confirm that posture against the identity provider's own API, using a read-only credential the operator supplies | [enrich/authentik.ts](labview/src/enrich/authentik.ts) + [analyze/authentik.ts](labview/src/analyze/authentik.ts); §3.5 |
| **R6** | Build the documentation dynamically, and use the Docker socket proxy for live state when available | [enrich/docker.ts](labview/src/enrich/docker.ts); every scan is fresh, nothing is persisted |
| **R7** | Serve the documentation from a built-in webserver, itself exposable through the same tunnel/proxy/SSO chain | [server/server.ts](labview/src/server/server.ts), labelled example in `labview/compose.yml` |
| **R8** | Be generic: the above is an *example* of a fleet, never a description of one | §4 I1–I3, enforced by the fixtures in §8 |
| **R9** | When one of those optional reads does not work, say which stage failed and what to change — for every target, present and future | [model/connections.ts](labview/src/model/connections.ts); §3.10, surfaced in the startup log, `--summary`, `meta.connections` and a banner |
| **R10** | Be able to require a login of its own — a password form over `/config/passwd`, optionally switched off, plus optional OIDC — without changing the behaviour of a deployment that configures neither | [model/access.ts](labview/src/model/access.ts) + [src/auth/](labview/src/auth/) + [server/auth.ts](labview/src/server/auth.ts); §3.13 |

R10 arrived after R7 and partly reverses the posture R7 assumed. R7 says the
dashboard is exposable *through* the operator's tunnel/proxy/SSO chain, and that
remains the recommended deployment; R10 says LabView must not *depend* on that chain,
because the two ways it is bypassed — a published host port, a tunnel origin pointed at
the container instead of the proxy — are exactly the mistakes LabView reports in other
people's stacks. The reconciliation is **open unless configured** (§3.13): configure
nothing and the surface is as open as R7 always left it, with one line in the log
saying so.

### 2.1 What must not be assumed

R8 is the requirement most easily broken by a well-meaning change. Concretely, the
following are **not** available to the code and must never be hard-coded:

- Hostnames, domains, container names, network names or IP addresses from any
  particular fleet — including in defaults, doc comments, UI copy and fixtures.
- That a reverse proxy exists, that a tunnel exists, or that SSO exists at all.
- That a naming convention identifies a role (`auth.*` is not Authentik, `db` is
  not a database, `proxy` is not Traefik).
- That the Docker Engine is reachable, or reachable at a particular address.
- That the edge in front of LabView authenticates anything, or that a request
  carrying `X-Forwarded-User`, `X-authentik-username` or any similar header has been
  authenticated by it. A header is proof only if the edge is guaranteed to strip an
  inbound copy, which LabView cannot verify — so it is never read as identity (§3.13).

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
    build.ts          which build is running: the env stamp, else the checkout's HEAD
                      (resolveBuildStamp is pure; the fs read is separate)
    model/types.ts    THE contract between backend and frontend
    model/build.ts    what the topbar and the startup line say about the build, one
                      sentence per source (pure, web-safe)
    model/connections.ts  connection-report wording, hints, log/banner rules (pure)
    model/changes.ts  what changed between two scans, and its wording (pure)
    model/access.ts   access-control vocabulary: posture line, failure text, username rule (pure, web-safe)
    model/auth.ts     when a missing gate may be reported at all, and its wording (pure, web-safe)
    model/networks.ts which network nodes are drawn, dependency vs. membership, the two
                      caps and all of the wording (pure, web-safe)
    model/ingress.ts  the ingress vocabulary and every pure operation on it (pure, web-safe)
    model/declarations.ts  the values a `.labview` may use, and how each is worded (pure, web-safe)
    model/ports.ts    reading a compose port mapping for the published host port (pure)
    model/probe.ts    which addresses a service may be asked at, what counts as a
                      login page answering, what a login form is made of, which fact
                      each verdict rested on, and the fleet roll-up the Login probe
                      panel lists (pure, web-safe)
    model/filter.ts   the dashboard's tri-state tag filter (pure, web-safe)
    hashpw.ts         CLI: password -> a `user:hash` line for the passwd file
    scan/
      discover.ts     appsRoot -> stack directories
      compose.ts      compose YAML -> normalized AppStack/Service
      env.ts          dotenv parsing + Compose-compatible interpolation
      paths.ts        path containment for every file read out of a stack directory (I8)
      sidecar.ts      the `.labview` file: parse, clamp, refuse anything outside the root
      index.ts        scanStacks(): discover + parse, collecting warnings
    labels/
      dockflare.ts    labels -> CloudflareRoute[]
      traefik.ts      labels -> TraefikRoute[]
      auth.ts         routes + env + registry -> AuthPosture
    analyze/
      middlewares.ts  cross-stack Traefik middleware registry
      origins.ts      cross-stack tunnel-origin resolution (what an origin points at)
      authentik.ts    cross-stack matching of identity-provider applications to services
      traefik.ts      cross-stack matching of live proxy routers to services + its notes
      networks.ts     real docker network names + the fleet membership index (graph, origins, stats)
      dependencies.ts sidecar-declared dependencies -> resolved pairs + drift for the rest
      index.ts        the pipeline; ingress classification; stats
      graph.ts        nodes/edges for the relationship graph
    enrich/
      http.ts         fetch wrapper: timeouts, JSON, injectable fetchImpl (no I/O policy)
      pool.ts         bounded concurrency for many independent round-trips (no I/O policy)
      docker.ts       Docker Engine snapshot (never throws)
      authentik.ts    Authentik REST API snapshot (never throws; all network I/O)
      traefik.ts      Traefik runtime-API snapshot (never throws; all network I/O)
      probe.ts        asks each scanned HTTP service what it answers, and reads a login
                      page as evidence (never throws; all network I/O)
    auth/
      hash.ts         modular-crypt dispatch over bcryptjs (`$2a$`/`$2b$`/`$2y$`)
      passwd.ts       parsePasswd (pure) + readPasswd (fs, re-read on stat change)
      session.ts      signed session cookie, revocations, Origin/scheme rules (now injected)
      oidc.ts         discovery, PKCE, token exchange, ID-token verification (now + fetch injected)
      throttle.ts     failed sign-ins per username (now injected)
      index.ts        resolveAccessMode, isPublicPath, requiresSession, config resolution
    server/cache.ts   scan cache: TTL, coalescing, force semantics, and the per-request
                      value a forced build is given (§3.11)
    server/auth.ts    the gate: one onRequest hook, one onSend hook, five routes (§3.13)
    server/server.ts  Fastify: buildApp() -> /api/* + static UI, with a TTL cache
  web/                Preact UI (see §3.9)
    vite.config.ts    the web build: root, single-bundle output, dev-server proxy
  scripts/
    smoke.ts          pipeline assertions over the fixtures
  tools/
    probe-lab/        a diagnostic, not part of the scan: point it at a URL and it reports
      report.ts       what the login rule read there, why each of the eight signals did or
      cli.ts          did not fire, and what a ninth would have to be. `report.ts` is
      README.md       pure and imports the real rules; `cli.ts` is argv and one GET, on the
                      pipeline's own transport. Not in the image (§3.6b)
  fixtures/
    apps/             a representative happy-path fleet
    edge/             one stack per previously-fixed defect
    authentik/        a fleet with an identity provider in it
    nets/             what connects two services vs. what only lets them reach each
                      other: shared networks, declared dependencies, bad references
    authentik-api.json  canned API responses driven through an injected fetch
    traefik/          a fleet whose labels and live proxy config disagree
    traefik-api.json    canned proxy + identity responses, same injected fetch
    probe/            what a service answers when it is asked, one address per stack —
                      including the pages that gate without a password field, and the
                      two near-misses that must stay ungated
    auth/             passwd files the access-control assertions parse: ok, messy, empty
    outside-root.env      the `env_file` escape target; outside every scan root on purpose
    outside-root.labview  the sidecar-symlink escape target, same reason (I8)
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
| — | each `enrich/*` client | a `ConnectionReport` per target, collected into `meta.connections` (§3.10) |
| 4. Middleware registry | `analyze/middlewares.ts` | every Traefik middleware *defined* anywhere, by bare name |
| 5. Pass 1 — routes | `labels/dockflare.ts`, `labels/traefik.ts` | `svc.cloudflare`, `svc.traefik`, `svc.docker` |
| 5b. Ingress classification | `sharedNetworks` + `classifyIngress` | `svc.ingress` — the set of kinds, over the whole fleet at once |
| 6. Fleet index + origin resolution | `analyze/origins.ts` | `FleetIndex` (host ports, DNS names, container IPs, hostnames); `route.origin` — what each tunnel origin points at, and notes where it could not be told |
| 6b. Declared dependencies | `analyze/dependencies.ts` | resolved `.labview` `depends_on` pairs, each with the network they share; `declared.drift` for every reference that named nothing, two things or itself |
| 7. Identity provider API | `enrich/authentik.ts` | `AuthentikSnapshot` — applications with their providers and outposts, or a reason it is absent. Skipped entirely without a token |
| 8. Reverse proxy API | `enrich/traefik.ts` | `TraefikSnapshot` — the routers the proxy is serving with their resolved middleware chains and backends, or a reason it is absent. Runs concurrently with step 7 |
| 8b. Active probe | `enrich/probe.ts` | `ProbeSnapshot` — `svc.probe` for each service where HTTP was *observed* **and this scan found no authentication**: which address answered, and whether a login page did. Off unless switched on; runs between the halves of step 12, which is what lets it skip (§3.6b) |
| 9. Provider discovery | `discoverAuthentikHints` | hint strings that identify the SSO provider *in this fleet* |
| 10. Application matching | `analyze/authentik.ts` | `svc.authentik` — which applications belong to which service, and which matched nothing |
| 11. Live router matching | `analyze/traefik.ts` | `svc.traefikLive` — which live routers belong to which service, and which matched nothing |
| 12. Pass 2 — auth | `labels/auth.ts` | **2a** `svc.auth` for every service, and the set of keys with detected authentication — the probe's eligibility (§3.6b). **2b**, after the probe: `exposedWithoutAuth`, notes; then secrets masked |
| 13. Graph | `analyze/graph.ts` | `Graph` of services, networks, shared volumes, resolved ingress paths, auth hubs — with every dependency, observed or declared, tied to the network it travels over |
| 14. Stats | `computeStats` | `OverviewStats` for the dashboard header |

**Why two passes.** Steps 5b–11 cannot run per-service inside step 5. Six
conclusions are only available once the *whole* fleet is parsed:

1. A Traefik middleware referenced as `authentik@docker` is usually defined in a
   different stack than the service using it, so classifying the reference
   requires the global registry (step 4).
2. Which hostnames represent the SSO provider is learned from whichever stack
   *runs* the provider — so its routes must already be parsed (step 9 after 5).
3. A tunnel origin routinely names a reverse proxy defined in a *different* stack,
   so resolving it needs a fleet-wide index of published host ports and DNS names
   (step 6, after the routes exist and before the graph is drawn from them).
4. An identity provider's application is matched against the fleet as a whole —
   its provider's internal host, or a hostname declared by any service — so it
   needs the same index (step 10, reusing step 6's).
5. A live proxy router names its backend by container address and its hosts by
   rule, neither of which is scoped to a stack, so tying it to a service needs that
   index too (step 11).
6. The `internal` ingress kind is a claim about *other* containers — that one of
   them shares a real network with this one — so it needs every service's networks
   counted before any service is classified, and it needs the live names pass 1 has
   only just attached (step 5b, after 5 and before the graph). A service classified
   mid-loop would be judged against a half-built fleet. The `NetworkIndex` built there
   is the same one the graph draws its network nodes and their counts from, so the
   `internal` rule and the connections on screen are provably one relation rather than
   two implementations of it (§5).

A seventh is why step 6b sits where it does: a sidecar's `depends_on` names a service by
compose name or container name, in any stack, so resolving it needs the same fleet index the
origins pass built (step 6) — and the edge it becomes has to know which network the pair
shares, which is the `NetworkIndex` from step 5b. It runs before the graph because the graph
is where a resolved pair lands, and it deliberately writes nothing back into the declaration
it read (§3.7).

A change that needs fleet-wide knowledge belongs in a new pass or in step 4/9,
not in a per-service function reaching for global state.

**Where the two API reads sit, and why.** A *configured* endpoint depends on
nothing in the scan, so that request is started before the docker snapshot and
awaited after, overlapping the two. A *discovered* endpoint cannot be found until
pass 1 has parsed the routes, so it runs after. Either way the result is one value
with the same shape.

**The probe does not join them**, and the reason is ordering rather than politeness. It only
asks services for which this scan found *no* authentication (§3.6b), and whether it found any
is not known until both reads have landed and `deriveAuth` has run over them — so pass 2 splits
in two and the probe goes between the halves. Pass 2a derives every `svc.auth` and collects the
keys with detected authentication; the probe runs; pass 2b attaches each result and settles
exposure. The price is stated rather than hidden: an enabled probe now adds its own wall-clock
to a scan instead of overlapping the two API reads. What it buys is not asking an SSO endpoint a
question whose answer could not have changed anything.

Origin resolution runs **ahead** of the discovered reads for two reasons. A
resolved origin structurally identifies the service acting as reverse proxy, which
is one of the three signals Traefik endpoint discovery rests on; and with the index
already built, both discovered exchanges go out under one `Promise.all` — one round
trip rather than two. An endpoint that answered the Authentik API then becomes an
input to step 9: having answered as an Authentik API is stronger evidence of
identity than any name match, and it is what attributes an OIDC issuer correctly
when the provider runs outside the scanned root.

### 3.3 Provider discovery (step 9)

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

### 3.4 Tunnel origin resolution (step 6)

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

### 3.5 The identity provider API (steps 7 and 10)

Compose files show a gate being *wired up*. They cannot show a gate that exists
only in the identity provider, and — more importantly — they cannot distinguish an
application that has a provider from one whose provider **nothing is serving**.
Given a read-only token, LabView asks the provider directly.

Two modules, deliberately split along the I/O boundary:

- [enrich/authentik.ts](labview/src/enrich/authentik.ts) — all network access, no
  knowledge of the fleet. Locates a candidate endpoint, authenticates, reads
  `core/applications/`, `providers/proxy/`, `providers/oauth2/` and
  `outposts/instances/`, and returns an `AuthentikSnapshot`. Mirrors
  `enrich/docker.ts`: it never throws, and a failure becomes a reason string.
- [analyze/authentik.ts](labview/src/analyze/authentik.ts) — no network access.
  Matches applications onto services using the fleet index built for step 6.

**Endpoint selection.** A configured `authentik.url` is used verbatim. Otherwise
candidates are collected from services whose image identifies Authentik, ordered
**internal addresses before public hostnames** so the exchange stays on the
container network, and capped. Each is probed on `/api/v3/root/config/`, which
upstream declares `AllowAny`; only a candidate that answers with a JSON object
receives the token. This ordering is a security property, not an optimisation: a
discovered endpoint is a guess, and a guess must never be handed a credential. On
a candidate that *did* answer, a 401/403 is conclusive — the token is wrong, so
later candidates are not tried and nothing further is sent.

**Enumerating applications is not a plain list read.** `ApplicationViewSet.list()`
upstream does three things, in this order: it drops every application with
`meta_hide = True`, it **paginates**, and only *then* does it run the policy engine over
the page **as the token's own user**, keeping the applications that user is allowed to
launch. The filter is skipped only when `superuser_full_list=true` is sent *and* the
token belongs to a superuser. So the default answer to a least-privilege token is "what
may this user launch", not "what exists" — and a service protected by an application the
token cannot launch would read as having no gate at all, which is exactly the failure
**I1** exists to prevent.

Two properties of that ordering make it recoverable without asking for more permission:

- **Pagination runs before the filter, so `pagination.count` is the *unfiltered* total.**
  `getList` keeps it (`ListResult.count`) for every Authentik read. It stays optional:
  the DRF-shaped `outposts/instances/` envelope carries no `pagination` block, and a
  non-numeric or negative count is treated as no count at all rather than propagated
  into four derived numbers.
- **`providers/proxy/` and `providers/oauth2/` — both already read — name the
  application each provider is assigned to.** `ProviderSerializer.Meta.fields` carries
  `assigned_application_slug` / `_name` and the backchannel pair, both subclasses extend
  it, and neither viewset applies a policy filter (they are RBAC-only). The providers
  this token can read therefore name applications the applications endpoint withheld,
  and they carry the very fields rules 1–2 match on.

`buildApplications` is therefore two passes. Pass one is the listed applications, tagged
`discoveredVia: "list"`. Pass two walks the two provider lists, skips any slug pass one
already produced — the list response always wins, since it alone carries `launch_url`
and `group` — and rebuilds the rest as `discoveredVia: "provider"`, in slug order
(**I7**). A rebuilt record is deliberately thinner: no launch URL, no group, and only
the providers this token may read, so it can be tied by address or by name but never by
a launch URL. `matchOne` states that basis as the first line of its `considered` trace,
and the UI tags the row `rebuilt`.

`superuser_full_list=true` is sent unconditionally on that one request. It is ignored for
a non-superuser, so it can only ever widen the answer; there is no config knob for it.

Four counts are reported, and only the last is a warning:

| Count | Meaning |
|---|---|
| `applications` | what LabView knows about: listed **plus** recovered |
| `applicationsConfigured` | `pagination.count` — what Authentik says exists |
| `applicationsWithheld` | configured minus listed: what the policy filter removed |
| `applicationsRecovered` | of those, how many a readable provider let LabView rebuild |

`withheld - recovered` is derived where needed rather than stored, so the four cannot
contradict each other. **The connection is `partial` only when that difference is
non-zero**: a gap fully closed from the providers is reported through the counts, while
applications LabView knows it cannot see must never be silent. The hint names both
fixes — make the token's user a superuser for the exact list, or check the token's
permissions.

**Matching (step 10).** Neither side carries the other's identifier, so a match must
come from something both sides name independently. Four such things exist, tried in
descending order of strength:

1. **A proxy provider's `internal_host`**, resolved through the same `lookupAddress`
   used for tunnel origins — the provider naming its own target.
2. **A bare-name host inside a URL the provider hands out** — a launch URL, an
   `external_host`, or an OAuth2 redirect URI — resolved through the fleet index.
   `http://app:3000/oauth/callback` is not a coincidence of wording; it is a pointer,
   and compose publishes that name as the container's network alias. This is the rule
   that reaches a service with no public hostname, which for OIDC is the common case.
3. **A hostname** named by one of those same URLs and declared by the service in a
   DockFlare or Traefik label — one hostname, observed on both sides.
4. **A name** — the application slug, the application name, or any of its providers'
   names — when it identifies exactly one service's stack, compose or container name.

Rules 1–3 are *addressed*: the provider points at the service. Rule 4 is only that the
operator chose similar words on each side. That difference is recorded per match in
`AuthentikMatch.strength` (`"address" | "hostname" | "name"`) and is what makes a
name-only tie report at `observed` rather than `confirmed` — see **Confidence** below.

Rule 2 resolves **only** a name host. An IP literal in a redirect URI addresses the
*host*, and on a host running a reverse proxy the standard ports belong to the proxy,
so reading it through the published-port table would attach the application to
whatever answers on 443 — worse than no answer, and the same reason
`lookupContainerAddress` refuses to read a container IP as a published port.

Rule 4 compares three forms, narrowing only when the wider one found nobody: the name
as written, the name with separators removed, and the name with the words naming the
*mechanism* removed as well (`GENERIC_NAME_TOKENS` — protocol and English words only,
nothing fleet-specific, and `authentik` deliberately absent). Authentik's own wizard
names providers `Provider for X`, and an operator writing `Home Assistant` means the
`home-assistant` stack. Three constraints keep this from inventing matches:

- **Separate raw and tight indexes.** Adding the looser forms must never take away a
  match the exact form already had; merged into one map, a stack `foo-bar` and a
  service `foobar` would collide into a contested key and both be discarded.
- **The first form with any entry decides**, and a contested entry decides *against* a
  match. Falling through from a contested key to a looser one would be arbitrating
  ambiguity, and could not help anyway — every looser form pools at least the same
  services.
- **`MIN_DERIVED_KEY = 3`.** A one- or two-character residue carries no information; a
  provider named `DB` would otherwise pin an application to whichever service happens
  to be short.

Generic-token stripping is applied to the **Authentik side only**. A service literally
named `authentik-proxy` means that, and stripping `proxy` from it would invent a
collision with the identity provider's own stack.

Each rule requires **exactly one** candidate; an ambiguous match is discarded and
the application reported as unmatched.

**Why it was not matched is part of the answer.** "Unmatched" alone hides the one case
the operator can act on. An application whose slug names *two* services is a naming
collision they can resolve; an application nothing pointed at is usually LabView's gap
to explain. So `matchOne` returns `Hit | Unplaced`, and every unplaced application
carries an `UnmatchedReason` (`ambiguous` | `no-candidate` | `internal`), a one-line
`detail`, and a `considered` trace with one line per rule tried, in the order tried
(§5). Three properties make the trace trustworthy:

- **The headline is the most actionable line, not the last one.** A rule that found
  more than one service sets `contested`; a rule that found usable evidence and
  deliberately declined to resolve it — an IP literal, a `forward_domain` external host
  — sets `blocked`. `detail` is the first of `contested`, `blocked`, then the generic
  fallback, and `reason` is `ambiguous` exactly when something was contested.
- **A rule that could not run says so.** "No proxy provider, so there is no forwarded
  address to resolve" is a different statement from "the address resolved to nothing",
  and a trace that silently omitted the first would read as if rule 1 had been tried.
- **The trace carries only what the payload already holds** — slugs, provider names,
  service keys, hostnames. Never an env value (**I2**, **I6**), which smoke asserts
  over every `detail` and `considered` string.

The five unplaced fixture applications in `fixtures/authentik` exist to produce five
distinguishable answers: a contested slug (`ambiguous`), an excluded `forward_domain`
host, a name residue under the 3-character floor, an IP-literal redirect URI, and one
that was withheld by the policy filter and then rebuilt from a provider addressing
nothing in the fleet. If a future rule stops reporting, those assertions fail — see §10.

Three details are easy to get wrong and all have fixtures:

- `meta_launch_url` may contain `%(username)s` and similar placeholders. A
  per-user template is not a hostname anyone serves, so it is not matched on.
- `external_host` is matched **except** in `forward_domain` mode, where it is the
  authentication domain shared by every application in that domain — typically the
  provider's own hostname. Matching it there attaches unrelated gates to whichever
  service serves the SSO domain.
- One service naming one hostname in both DockFlare *and* Traefik labels is the
  normal case, not two rival candidates. The hostname index dedupes by service key;
  without that, the commonest configuration in a fleet is unmatchable.

**What a provider means.** Reading a provider is not the same as finding a gate:

| Provider | Enforced by | Gate exists when |
|---|---|---|
| proxy, ldap, radius | an **outpost** in the request path | ≥ 1 outpost lists it |
| oauth2, saml | the Authentik server itself | always |
| scim | nothing — it provisions users outbound | never |

A proxy provider assigned to no outpost is reported as protecting nothing, with
that as the stated reason. This is the single most valuable output of the
integration: in the admin UI such an application looks complete.

LDAP and SCIM are **backchannel** providers, so `backchannel_providers_obj` must be
read as well as `provider_obj` — reading only the latter misses every LDAP gate.

A provider Authentik records is taken as **being in use** by the service it matched.
For OAuth2 that is the whole of the available evidence: no outpost is involved, and the
application's own client configuration lives in the application, not in the compose
file, so there is nothing in the scan to corroborate it with. The identity provider's
own record is the authority on its own configuration. On a fleet where no service
declares an OIDC environment key at all, this is the only way an OIDC gate can be seen.

**Confidence follows the match, not the provider.** What the provider's record cannot
establish is *which* service it belongs to, so `AuthentikMatch.strength` sets the
confidence of the derived posture:

| Strength | How the tie was made | Confidence |
|---|---|---|
| `address` | rules 1–2 — the provider points at this service | `confirmed` |
| `hostname` | rule 3 — one hostname both sides declare | `confirmed` |
| `name` | rule 4 — similar words on each side | `observed`, and the detail says `— tied to this service by name alone` |

This is deliberately visible in the UI and the payload, and it changes **no** posture
roll-up: `AuthMethod` precedence sorts by mechanism before confidence, and
`hasEdgeAuth`/`exposedWithoutAuth` do not read confidence at all (§3.7). A weaker tie
therefore reads as weaker without moving a service between "protected" and "exposed".

**Where the results go.** `svc.authentik` carries the matched applications for the
drawer. `labels/auth.ts` merges the API's account with the label-derived one by
confidence rank (`confirmed` > `observed` > `inferred`), keeping the loser as
evidence rather than discarding it. And `meta.authentik` reports the summary —
endpoint, whether it came from config or discovery, counts, matched services,
unmatched applications with their reason and trace, and any error. The two sides meet
in the UI in the integration panel (§3.9), which reads the matches back off the
services rather than from a second copy in the metadata.

### 3.6 The reverse proxy API (steps 8 and 11)

Labels are a request to the proxy; the runtime config is its answer. Three
differences are invisible to a file scan, and each of them can only be resolved by
asking the proxy:

1. a **router the labels declare that Traefik is not serving** — a typo in a rule, a
   missing entrypoint, a container it never picked up;
2. a **middleware named in a label that is not in the chain the proxy built**, so a
   service reads "protected" and answers without a login;
3. a **middleware defined in a Traefik file provider**, which has no definition in
   any scanned stack and is therefore only ever `inferred` (§11's first limitation;
   this stage removes it when the API is readable, and only then).

Same two-module split as §3.5:

- [enrich/traefik.ts](labview/src/enrich/traefik.ts) — all network access, no
  knowledge of the fleet beyond the candidate list handed to it. Reads
  `/api/version`, `/api/rawdata` and `/api/entrypoints`; returns a
  `TraefikSnapshot`; never throws.
- [analyze/traefik.ts](labview/src/analyze/traefik.ts) — no network access. Matches
  live routers onto services using step 6's index, and derives the notes.

**Endpoint selection.** A configured `traefik.url` is used verbatim. Otherwise a
scanned service becomes a candidate on one of three signals, and each candidate
carries the `why` that produced it:

| Signal | Why it is evidence |
|---|---|
| a router of its own whose service is `api@internal` | the operator's own label saying "this container serves the proxy API" — structural, vendor-neutral, and it also yields the exact public hostname |
| another service's tunnel origin resolved to it (§3.4) | an observed reverse proxy, established without consulting any image or name |
| it runs the Traefik image | last resort, same precedent as `isAuthentikService` |

Per candidate the URLs are `http://<name|container_name>:<port>` for each declared
`ports[].target` plus `8080` — the port the dedicated `traefik` entrypoint
conventionally serves — followed by its Traefik/DockFlare hostnames. Internal before
public, deduped, capped, exactly as `discoverAuthentikEndpoints`.

**The credential rule**, which is the security core of this stage:

- Every candidate is probed on `/api/version`, which needs no authentication. A
  candidate that answers is used **with no credential at all**, and none is sent.
- A credential is sent only to a candidate that is either configured by hand
  (`mayAuthenticate` set at construction — the operator naming the API themselves)
  or a hostname the scan proved belongs to the service whose own labels declare
  `api@internal`. That is ownership evidence; a hostname that merely *looks* like a
  proxy never receives one.
- A 401/403 or a redirect on such a host is what triggers the authenticated retry.
  Cookies set during that exchange are replayed on its remaining requests, because
  the Authentik outpost expects its session cookie echoed.
- **An Authentik API token is not a valid credential here** — see the decision log.

**Matching (step 11).** Exactly one candidate or no match, same discipline as
§3.5:

1. **The backend address** — `loadBalancer.servers[].url` is the proxy naming its
   own target. An IP-form URL resolves **only** through `FleetIndex.byContainerIp`;
   a name-form URL through the name branch of `lookupAddress`.
2. **The router name**, `@docker` routers only. Traefik derives those names from the
   labels of the container it found them on, so an exact match against
   `svc.traefik[].router` is that label round-tripping. A `@file` router's name was
   typed by hand in a file this scan cannot read, so a resemblance there is a
   coincidence with no evidentiary weight and this rule does not apply.
3. **The host rule** — through the same hostname index the Authentik matcher uses.

Unmatched routers are reported in `meta.traefik.unmatchedRouters`, the mirror of
`unmatchedApplications` in every respect including the reason model above: each entry
carries the whole `TraefikLiveRouter` — rule, hosts, entrypoints, resolved chain,
backends, status — plus its `reason`, `detail` and `considered` trace. It is how
ingress LabView could not attribute — file provider routes especially — becomes
diagnosable instead of silently absent: a backend address that resolves to nothing
scanned is exactly what rule 1 was looking for and did not find, and the trace says so.

One deliberate asymmetry with §3.5: this matcher tracks `contested` but not `blocked`.
The skip in rule 2 applies to *every* non-docker router, so promoting it to the
headline would make "its name proves nothing about which container it refers to" the
stated reason for each one — displacing the answer a reader needs. It stays a trace
line, and `detail` falls through to what was actually looked at.

**Why the backend address needs its own index.** A docker-provider backend is
`http://<container-ip>:<container-port>`. `lookupAddress` reads an IP literal's port
as a *published host port* (§3.4), which is the correct rule for a tunnel origin and
the wrong table entirely for a container IP — it would match whichever unrelated
service happens to publish that number. `byContainerIp` is built from
`svc.docker.ipAddresses`, and an IP-form backend resolves through it and nothing
else. With no Docker state the rule is skipped rather than guessed; rules 2 and 3
still cover the docker provider.

**What the live read is allowed to conclude** is decided once per scan, in
`TraefikLiveContext`, because it is a property of the read and not of any service:

- `reachable` — the API answered at all.
- `chainComplete` — `reachable` **and** `entrypointsRead`. Only a complete read lets
  a live chain supersede a label list, because a gate attached at an *entrypoint*
  does not appear in a router's own middleware list. Mistaking that for an absent
  gate would invert the finding, so a partial read notes the gap and changes no
  posture.

Where a router matched and `chainComplete` holds, the live chain **is** the chain: a
resolved `forwardAuth` whose address resolves to a provider identity yields
`authentik-forward-auth` at `confirmed`, `basicAuth`/`digestAuth` yields
`basic-auth`, a `chain` middleware is resolved recursively (depth-capped, each entry
recording `viaChain` so the evidence says how the gate was reached), and a label
declaring an auth middleware the live chain does not contain is **downgraded** — the
detection suppressed, the service free to land in `exposedWithoutAuth`, and a note
naming the discrepancy. A router the proxy reports as `disabled`, or carrying
`error[]`, counts as neither protection nor working ingress, with its errors quoted
verbatim.

The declared-but-absent check runs against **every router in the snapshot**, not
only the ones matched to the service. A router the proxy is demonstrably serving but
that LabView could not attribute must not be reported as missing.

**Three-way cross-check.** When the live `forwardAuth` address resolves to the
service the Authentik API answered on, and Authentik reports an outpost serving a
provider for an application matched to *this* service, the note records labels,
proxy and identity provider agreeing. Disagreement is the finding: a forward-auth
address pointing at an instance with no matching application, or a matched provider
whose `mode` means the request never reaches the outpost. A provider in `proxy` mode
is exempt — there the outpost *is* the backend, so no forward-auth middleware exists
and none should be expected.

**Where the results go.** `svc.traefikLive` carries the matched routers for the
drawer. `meta.traefik` reports the summary — endpoint, whether it came from config or
discovery, whether a credential was used, whether the API answered unauthenticated,
version, counts, matched services, unmatched routers, and any error. The proxy
service itself gets `role: "proxy"` in the graph and every matched router is drawn
from it, so the hop is named rather than left to the reader.

### 3.6b The active probe (step 8b)

Every other source in this document says what a service is *configured* to do. This one says
what it **answers**, and it exists for one blind spot: an application with its own login page
carries no label, no env key and no entry in anybody's API, so no amount of reading
configuration can see it. Until this stage the only way to keep such a service out of the
exposed count was a `.labview` declaration — a claim LabView cannot check (§3.12). So the scan
asks: one GET to the service's own address, and a login page answering is evidence in the
sense I1 means it, because LabView made the request and read the answer.

It is the only integration that **defaults to off**, the only one that sends a request to
something the fleet's own documents named, and the only one a reader can turn on from the UI
for a single rescan. All three facts drive the design.

**Every rule is pure, in [model/probe.ts](labview/src/model/probe.ts).** None lives in the
client that does the fetching, because a rule inside an I/O module can only be tested by
mocking the I/O. They divide into five jobs: what may be asked (`probeTargets`), what an answer
means (`readGate`, `readLoginForm`, `isLoginPath`), whether a *second* question is worth asking
and what its answers add up to (`wantsStateProbe`, `stateTargets`, `readState`,
`readStateGate` — see below), what the page showed a caller who sent nothing (`readAnonAccess`,
`saysLogin`, `servedAnonContent` — §3.6c, and the only one of the five that answers the opposite
question), and which fact a decision rested on (`probeReasonText`).

**Only services this scan found no authentication for are asked.** Two questions decide whether
a request goes out, and they are separate on purpose: `probeTargets` says whether there is an
HTTP address to ask at, and `hasDetectedAuth` says whether asking could tell anyone anything.

`hasDetectedAuth(svc)` in [labels/auth.ts](labview/src/labels/auth.ts) is true when
authentication was **detected** — a mechanism `deriveAuth` read from the labels or the live
Traefik chain (`svc.auth.method !== "none"`), a Cloudflare Access policy on the tunnel route, or
an Authentik provider the API reports as enforced. It is deliberately not one of the terms in
`finalizeAuth`; it *is* that term. The `configuredEdgeAuth` expression there was replaced by a
call to this function, so eligibility and the notes that explain the outcome cannot come apart —
a service can never be skipped for a reason its own notes contradict.

Neither a probe result nor a `.labview` declaration counts. The first is the measurement being
decided about, and the second is a claim LabView cannot check (§3.12) — which is exactly the
case worth asking about, and `fixtures/probe/declared-open` is that case. What the answer is
worth is a separate question, settled in §3.12: an address that returns no login page does not
contradict such a declaration, so the result is recorded as *unconfirmed* rather than as drift.

An `inferred` posture counts as detected. A router naming `authentik@docker` whose definition
was never found is still authentication detected *through Traefik*, and since
`svc.auth.method !== "none"` its verdict already rests on that mechanism rather than on anything
a request could return. `fixtures/probe/gated-open` is that case.

**Why this is free of I1 risk, in the only direction that matters.** `finalizeAuth` computes
`hasEdgeAuth = configuredEdgeAuth || probeGate`. Where `configuredEdgeAuth` is true the probe
term cannot change the result, so withholding the request can only ever leave a service *in*
the exposed count — never take one out. The two terms stay written as two even though they are
now provably disjoint, because that is what keeps `probeGated` a subtractable statistic (§11);
the disjointness gets an assertion in the smoke pass instead of a rewrite.

The cost is the reordering in §3.2 — an enabled probe no longer overlaps the two API reads — and
one real loss: a service behind a detected gate is no longer *measured*, so a gate that has
silently stopped working is no longer visible as an open answer behind a configured mechanism.
That was never reported as a finding (the posture won either way); it was only ever visible in
the drawer's probe block, and it is the price of not sending requests at somebody's SSO
endpoint on every scan.

**Not asked and no address are different facts**, and they read differently. `probeTargets` runs
first, so a service with no HTTP address is not counted as skipped — it was never a candidate.
`ProbeRun.skipped` counts the candidates that were withheld, and the connection report says so:
`13 services probed — 4 gated, 8 open, 1 did not answer — 1 service not asked (authentication
already detected) — 6 extra requests at current-user addresses`. A run whose candidates were
*all* skipped is `ok: true`, not the `not-found`
failure it would otherwise be mistaken for. The `Login probe` tile carries the same number
through `ProbeReport.notAsked`, so a fleet of 14 HTTP services showing a probe count of 13 says
where the fourteenth went.

No new `NoAuthReason`: a skipped service has detected authentication, so `noAuthReason` is never
asked about it.

`probeTargets(svc, lanHost)` decides the other half — the addresses and their try-order, from
evidence already on the service, never from a port number and never from an image name:

| Vantage | Eligible on | Asked at |
|---|---|---|
| `public` | a tunnel route with a resolved hostname whose `service:` origin is `http`, `https` or absent | `https://<hostname>/` — the tunnel terminates TLS at the edge, so there is no other scheme it could be |
| `traefik` | a `traefik.http.routers.*` route's own host. `parseTraefik` reads only HTTP routers, so a non-empty route list *is* the evidence that this is an HTTP service | `https://<host>/` when the router declares TLS, `http://<host>/` otherwise |
| `lan` | a service one of the two above already found HTTP, **and** `probe.lanHost` set, **and** a published port whose bind address answers there | `http://<lanHost>:<published port>/` |

Order is most- to least-exposed, the same order `INGRESS_KINDS` uses, and the walk stops at
the first address that *answers*. "Answers" means an HTTP response arrived, whatever its
status — a 401 is the best outcome available here, so it ends the walk rather than continuing
to a weaker vantage. Only a transport failure falls through, and a public hostname that does
not resolve from inside the container is precisely why there is somewhere to fall through to.

**A service with `ports:` and no route of either kind yields no address at all.** That single
line is what keeps the probe off a database without consulting a port number or an image name,
and it has a real cost, stated rather than hidden: a LAN-only web UI stays inferred from its
configuration rather than measured. `lanHost` is the operator's answer to a question LabView
cannot answer for itself — it runs in a container and cannot see its host's LAN address. Empty
means no LAN vantage, not a guessed one.

`readGate(res)` is the recognition rule, and it reads **one response**. Seven signals, strongest
first. There is an eighth — `state-challenge` — and it is deliberately not here, because it
rests on a fact from a second request; it has its own subsection below.

| Signal | Fires on | Why it is a fact |
|---|---|---|
| `challenge` | 401 or 407 **with** a `WWW-Authenticate` header | The header *is* a request for a credential |
| `redirect-origin` | a 3xx whose `Location` resolves to a different origin | This origin declined to serve the request itself — the shape of every external SSO hand-off |
| `redirect-login` | a 3xx that stayed on the origin and landed on a `LOGIN_PATHS` entry (prefix match, see below) | It sent the browser to its own login instead of serving |
| `meta-refresh-login` | a 200 whose HTML carries `<meta http-equiv="refresh">` whose `url=` resolves cross-origin or onto one of those same paths | A redirect written in markup. The page served no content; the 200 is an accident of *how* it redirected, and `readRefresh` resolves the target through the same `readRedirect` a `Location` goes through |
| `sso-form` | a 200 carrying a hidden `SAMLRequest` or `SAMLResponse` input | Those are the SAML 2.0 POST binding's own parameter names. Nothing else emits one |
| `password-form` | a 200 whose HTML carries `<input type="password">` or `autocomplete="current-password"`, **anywhere on the page** | A password input is unambiguous alone, which is why it outranks the composite below |
| `credential-form` | a 200 where **one** form has a username field *and* a submit control *and* a login-intent marker, with no password field | Magic-link and passkey sign-in. See below — this is the one clause that is not a single fact |

Clauses 4–7 read a 200's body, which is the only condition under which a body was kept at
all, so `res.body` being present is itself the evidence that HTML answered.

**`LOGIN_PATHS` is the one rule that decides on a *name*.** Ten prefixes, and no
convention-guessing past them. Two signals consult it — `redirect-login` and
`meta-refresh-login` — and both only ever *add* a gate to a target that stayed on the origin; a
cross-origin target is already `redirect-origin` without asking. So a hand-rolled login path that
is missing costs a gate and never invents one. The risk runs the other way: a **wrong** entry
takes a service out of the exposed count on the strength of a word, and two entries carry odd
spelling for exactly that reason.

| Entries | Why these |
|---|---|
| `/login`, `/signin`, `/sso`, `/oauth2` | The four the OAuth and SSO ecosystem settled on |
| `/sign-in`, `/users/sign_in` | The same two words hyphenated and underscored. Not new conventions — the first is what a great many applications spell `/signin` as, and the second is Devise's own path, which every Rails application using it redirects to |
| `/auth/` | The fourth ecosystem convention, and the one that needs its trailing slash: bare `/auth` matches `/authors` and `/author/jane`, which is a blog routing to content. With the slash it still matches `/auth/login`, `/auth/realms/…` (Keycloak) and `/auth/authorize` |
| `/outpost.goauthentik.io`, `/if/flow/`, `/flows/-/` | Authentik's three published addresses: the outpost endpoint, the flow interface a browser is sent to, and the flow executor. `/flows/-/` keeps the `-` because that segment is Authentik's own placeholder for "no application context" — a bare `/flows` prefix would read a workflow tool routing to one of its own configured flows as a login page, which is what `fixtures/probe/authentik-flow/pipeline` exists to catch |

The Authentik entries are worth their own note, because they are what a real deployment needed.
An instance sends an anonymous visitor at `/` to `/flows/-/default/authentication/`, which
redirects again to `/if/flow/<slug>/`, whose sign-in form is drawn by JavaScript. Neither end of
that chain carries a signal in served markup, so no amount of following redirects arrives at one
— but the **first `Location` was always the evidence**, and it was simply a path the list did not
have. One list entry, one request, no chain walked. `LOGIN_PATHS` is exported for one reason: so
the smoke pass can assert every entry has a row of its own with a path it matches and a near miss
it does not.

Nothing else read off that one response is a gate. A bare 401 with no challenge header is an API
saying "not signed in" while its UI serves the whole application; a 403 refuses without asking for
anything; a same-origin redirect to `/dashboard` is routing, and so is a meta refresh to it; a
refresh with no `url=` is a live dashboard reloading itself on a timer; a homepage with the words
"Sign in" and no form to go with them is a homepage. All of them read as *answered, no gate
observed*, which leaves the exposure finding standing. The asymmetry is deliberate and it is
the whole reason the rule is strict: this function can only ever take a service **out** of the
exposed count, so a clause that is merely likely would manufacture the one thing this project
exists to remove. Half the `readGate` table in `scripts/smoke.ts` is near-misses for that
reason.

**`readLoginForm(body, requestUrl)`** is the third rule and the answer to the plainest question
about a 200: *is there a username field, a password field and a login button?* It reports
composition **per `<form>` element**, never page-wide — a footer search box and a nav "Sign in"
link are each real, and a page-wide scan would hold them up together as a login form that does
not exist. When several forms qualify the strongest wins, and the first of equals, so one page
yields one answer and yields it twice (I7).

| Field | Read from |
|---|---|
| `password` | `type="password"`, or `autocomplete="current-password"` — **not** `new-password`, which is a signup |
| `username` | `type="email"`, or a `text`/`tel` input whose `name`, `id` or `autocomplete` contains a word from a closed list (`user`, `login`, `email`, `identifier`, `account`, …). `q`, `search` and `query` are absent on purpose |
| `submit` | `<input type="submit">`, `type="image"`, or a `<button>` whose `type` is `submit` or absent — absent submits, by the HTML default |
| `otp` | `autocomplete="one-time-code"` — a 2FA-first page |
| `action` | the form's `action`, **only** when it stays on this origin and prefix-matches a login path |

Two of those deserve their reasons stated. The username match is loose, and that is affordable
only because it is never sufficient alone: `credential-form` also demands a submit control and
an intent marker, so a search box named `account_query` costs nothing. And a **cross-origin
action is rejected** rather than read as a hand-off, which is narrower than the redirect rules
deliberately: hosted newsletter signup is a form posting an email address to somebody else's
domain, the shape is identical to a hosted login and the meaning is the opposite, so reading it
as evidence would clear an exposure for every site with a Mailchimp box in its footer.

The shape is attached to `ServiceProbe.form` whenever a form was found — **including when
nothing was concluded from it**. A verdict a reader cannot inspect is one they have to take on
trust; a form of `username + submit` with no intent marker is exactly the case where they will
want to look, and the drawer shows the sentence beside the pill.

**`credential-form` is the one clause that holds several facts together, and that is a
deliberate exception.** Every other signal here is a single unambiguous marker; this one is a
conjunction, because passwordless sign-in has no single marker to find — there is no password
input, no `Location`, and often no distinguishing text. The class is large and growing, and
without this clause every magic-link and passkey login in a fleet reads as *reachable without
authentication*, which is a false finding in the noisy direction. The compensation is that all
three parts must be present on **one** form; the `news` service in `fixtures/probe/passwordless`
is the fixture that holds the line.

**Signals considered and rejected.** Each is tempting and each would buy false comfort, which
in this rule is the expensive kind of wrong:

| Rejected | Because |
|---|---|
| `<title>` or body text matching — "Sign in", "Log in" | `PROBE_APP_HTML` in the smoke pass exists to defeat exactly this: an open dashboard that says "Sign in" twice and links to an account page |
| Product-name markers — Keycloak, Authelia, oauth2-proxy | A *link* to one matches. A page mentioning an identity provider is not a page served by it |
| A `Set-Cookie` on a 200 | Every application sets a cookie |
| A cross-origin form `action` with no `SAMLRequest` | Indistinguishable from hosted newsletter signup, as above |
| A 401/403 that serves a login form | The body is read as evidence on a 200 only, so this is a known miss (§11) rather than a clause — loosening it would let any 401 rendering a form bypass the challenge clause's header requirement |

**The eighth signal: `state-challenge`, and the second request.** Every clause above reads a
response LabView already has. One shape of answer defeats all of them in principle rather than by
accident: **HTTP 200, `text/html`, and not a `<form>` anywhere in the body.** That is what a login
screen drawn in the browser looks like on the wire — the markup is a shell and the form is
assembled by a JavaScript bundle — and no reading of those bytes at any cap can tell it from a
public single-page application. It is also the single commonest miss in a real fleet.

So for that one shape, and only for it, the scan asks a second question: *does this page's own
client get served without a credential?* `wantsStateProbe` is the whole condition — no gate read,
status 200, HTML, no form — and `STATE_PATHS` is where it asks: `/api/`, `/api/me`, `/api/v1/me`,
`/api/v1/user`.

Four current-user addresses, in that order, walked until one **refuses** (401 or 407), which ends
it because a refusal is the answer. `stateTargets` resolves them against the *origin* that
answered, from a constant in `model/probe.ts` — nothing is parsed out of the page, so an
application LabView did not write can never name an address LabView then dials. `readState`
reduces the answers to `ProbeState`: how many were asked, which refused, with what status, and
whether that refusal named a scheme.

`readStateGate` gates on **that last fact alone**. A refusal carrying `WWW-Authenticate` is
`challenge` one address over: a server sending that header is asking a browser to prompt, which
nothing does by accident. A **bare** 401 is not a gate, and this is the most important line in the
subsection — an anonymous-enabled Grafana and a world-readable Gitea both answer exactly that way
while serving everybody, so reading it as a gate would take genuinely open applications *out* of
the exposed count, silently, in the one direction I1 does not permit. 403 is excluded for a
smaller reason with the same shape: nginx 403s a directory with no index file, so a static site
would read as gated.

A bare refusal is not thrown away, though — it is recorded on `ProbeState` and named in
`probeReasonText` as a place to look, in the same sentence that says the finding stands. That
compromise is the point: the reader is told what LabView found, and the count is not moved on a
maybe. `fixtures/probe/spa-shell` is the pair that pins both halves — `app` challenges at `/api/`
and leaves the count after one extra request, `anon` answers 200 twice and then a bare 401 and
stays exposed after three.

The price is honest and bounded: at most four extra requests per service, only for services
whose page could not be read, only at their own origin, and stated in the connection line (below)
rather than left to be inferred. A form-less shell that refuses nothing costs the full four and
buys a *reassurance* — "nothing behind the page contradicts what the page served" — which is worth
the traffic, because it turns "no signals found" from a limit of the rule into a finding about the
service.

**The facts a verdict rested on are recorded beside the verdict.** `readGate` decides on
things the response then goes away with — where a `Location` pointed, whether HTML came back
at all, where a `<meta refresh>` went — so a negative verdict used to be recorded as
`HTTP 302 — answered with no login page`: the conclusion, with the fact thrown away. A 302 to
`/dashboard` and a 302 to `/login` are the same sentence there, and the first is the one that
leaves a service in the exposed count. So the observation travels beside the verdict, one field
per fact a sentence has to be able to name:

| Field | Answers |
|---|---|
| `mediaType` | *a 200 that was not a page* — `application/json`, so nothing was read and nothing could be found |
| `redirect` | *a 3xx that stayed put* — `/dashboard`, same origin, off any login path: routing |
| `refresh` | *a `<meta refresh>` that was not a gate* — the `meta-refresh/home` fixture's own reason |
| `truncated` | *a form below the body cap* — §11's known miss, reported the one time it bites |
| `state` | *what the second request found* — which of the four addresses was asked, which refused, and whether it named a scheme. The only one of these fields that records a request rather than a reading, which is why `asked` is on it (**I8**: the payload states what went out) |
| `anon` | *what the page showed a caller who sent nothing* — characters of text, same-origin links, and a sign-in offer if the page made one (§3.6c). The only field here that is evidence **for** an open verdict rather than in explanation of one, and the only one no gate rule can see |

`readRedirect`, `readRefresh` and `readMediaType` are exported for this and consumed by
`readGate` itself, so there is exactly one rule for "where does this point" and the recorded
fact is the one the verdict was reached on rather than a second reading of the response. There
is deliberately **no** field for `WWW-Authenticate`: a 401 with no `challenge` gate already
*means* the header was absent, so a field would be a second copy of a fact already in the
payload.

All three readers reduce what they record, and the reductions are I6 rather than cosmetics. A
redirect to an identity provider carries `state`, `code` and `redirect_uri`; a redirect to a
login carries `?next=`. `ProbeRedirect.to` drops the query and the fragment, keeps the origin
only when the target *left* the origin — so a same-origin `Location` spelled absolutely cannot
be mistaken for a hand-off — and sets `crossOrigin` beside it. `mediaType` drops the
parameters, so a charset never reaches the payload either.

`probeReasonText(probe)` is then the sentence, and it is a pure rule for the same reason the
other three are: composed in `enrich/probe.ts` with the response in hand it could only be
tested by mocking the network, and what it says about the two trap fixtures is exactly what
the fixture-revert contract needs to pin (§8). It branches in `readGate`'s own precedence
order — one sentence per signal naming the fact that fired, and for a negative verdict the
clause that came *closest* and what it lacked: the header a bare 401 did not carry, the origin
a redirect did not leave, the page an `application/json` answer never was, the login intent a
newsletter box does not have. `GATE_REASON` is an exhaustive `Record<ProbeGate, …>`, so a new
signal is a compile error until it has been explained.

**Both findings are findings.** A login page answering means the service is not reachable
without authenticating: it leaves `exposedWithoutAuth`, is counted in `probeGated`, and
`noAuthReason` reports it as `probed-gate` with `auth.method` untouched at `none`. An answer
with *no* login page is the other half of the value — the exposure note gains a clause saying
LabView requested the address and was served the application, which turns a finding inferred
from configuration into one that was measured, and where the page it served carries readable
content the note says what a visitor was shown as well (§3.6c). A service that did not answer is neither: it is
counted in neither statistic, its note claims no measurement, and `probeOutcome` words it as
`No answer` rather than `No login page`, because letting a silence read as "no gate" would
reach this stage's one forbidden conclusion by accident.

**A probe never becomes a mechanism** (I3). A password field cannot say whether it is backed
by local accounts, OIDC or SAML, so `probed-gate` is reported as its own reason and counted in
its own statistic — exactly as an Authentik gate with no readable method is reported as
`unnamed-gate`. `svc.probe` sits beside `authentik` and `traefikLive`, never inside `auth`.

**Two things it does not override.** A detected gate answered with no login page keeps its
posture and gets a note saying the request came from LabView's own vantage point, which may
not be the path a visitor takes — the same reasoning `chainComplete` rests on (§3.6). And a
`.labview` declaration that supplies the only protection is not overridden by an open answer
either: a service can serve `/` to anyone and authenticate everything past it, and the probe
only ever asked for `/`. That second case is recorded as **unconfirmed**, not as drift — the
answer neither confirms the declaration nor contradicts it, and only a contradiction belongs
in the channel that raises warnings (§3.12).

**Containment** (I8). The addresses come from scanned documents, so the bounds are part of the
feature rather than a deployment concern: GET only, with no query; no credential, and
not by omission — no call path into `getResponse` has one in scope; no redirect followed,
because where a 3xx points is the evidence and following it would let a scanned label send
LabView somewhere of its choosing; a per-request timeout and a bounded number in flight; at
most `MAX_PROBE_TARGETS` addresses per service, so a compose file with thirty published ports
cannot turn one scan into thirty requests; the body read only when the content type is HTML
and then only to 64 KiB, with the stream cancelled at the cap. And, like every other client,
it cannot throw and cannot fail a scan (I4): disabled, nothing eligible, or nothing answering
each return a report that explains itself.

The `state-challenge` walk is the one thing here that sends more than one request per service, so
it is bounded the same way and the bounds are the same kind of fact. The paths are a constant in
`model/probe.ts`, not something read off a page; they are resolved against an origin LabView
*already reached*, so a scanned document can add at most four requests to its own origin and not
one to anybody else's; the walk stops on the first refusal; nothing is parsed from what comes
back — no body, no header value, only a status and whether a scheme was named. It is sequential
regardless of `probe.maxConcurrency`, because that budget is across *services* and a parallel walk
could not short-circuit. The addresses stay **out** of `ServiceProbe.attempts`, which is the
reachability record for the vantage walk, and the request count travels on `ProbeState.asked`
instead.

The report is the fourth `meta.connections` entry (§3.10), using existing phases only:
`disabled` when off, `not-found` when nothing was eligible, `partial` when part of the fleet
did not answer — which stays `ok`, because what was read is sound — and `connected` otherwise,
reading like `31 services probed — 12 gated, 17 open, 2 did not answer — 9 extra requests at
current-user addresses`. That last segment appears only when there were some, and it is summed
from `ServiceProbe.state.asked` rather than carried on `ProbeRun` — the difference from `skipped`
being that this number is derivable from the payload the UI already has, so duplicating it onto
the run would be two places to keep true instead of one. It is there because a stage reporting 18
services while sending 35 requests would be understating its own traffic by half, and an operator
deciding whether to switch this on is entitled to the real number.

#### Sharpening the rule: `tools/probe-lab`

Every signal in this rule was written against a hand-authored fixture, and the services that come
back **open** in a real fleet are exactly the ones the rule may be wrong about. An `open` verdict
has two completely different meanings — a genuinely unprotected application, or a login page this
rule cannot see — and they are the same row on the dashboard.

[tools/probe-lab](labview/tools/probe-lab/README.md) is how they are told apart. Point it at a
URL and it writes a Markdown report and a JSON record: the verdict, then **every one of the eight
signals and the fact that made each fire or not**, then **what a visitor was shown**, then all the
evidence no signal reads yet (every form and input unranked, every `<a href>` with the pipeline's
own reading of it, every form-less control, `<meta>`, mount points, inline scripts *described*,
`<noscript>`, the visible text, headers, `Set-Cookie` *names*), then one line per thing standing
between that page and a verdict. `--from-scan overview.json` reads a saved
payload and asks exactly the services this stage found neither authentication nor a login page
for, at the addresses `probeTargets` gives — the same selection the skip rule above makes, so the
tool's worklist and the scan's are one rule rather than two.

Three properties, and the first is the whole point:

- **The verdict is the pipeline's verdict.** `report.ts` imports `readGate`, `readLoginForm`,
  `readRedirect`, `readRefresh`, `readMediaType`, `probeGateText`, `probeOutcome`,
  `probeReasonText` and the clause predicates from `model/probe.ts` and reimplements none of
  them. A report describing a decision LabView would not make would be worse than no report — it
  would send somebody to change a rule that was never the problem — so the smoke pass drives
  every row of its own `readGate` table through `buildReport` and asserts the two agree (§8).
  The questions are shared; the *patterns* stay private to `model/probe.ts`.
- **The transport is the pipeline's transport.** `cli.ts` calls the same `getResponse`
  `enrich/probe.ts` calls, through a `FetchLike` wrapper whose only job is to keep the headers
  `getResponse` discards. So the timeout, `redirect: "manual"`, the HTML-only body read and the
  64 KiB cap are inherited rather than restated, and tightening a bound in the pipeline tightens
  the tool in the same commit. On top of that: `GET` only, no credential and no option that
  supplies one, one hop only under `--follow`, nothing a page *suggests* is ever fetched, and
  header values redacted by default because a report is a file somebody pastes into an issue —
  `Set-Cookie` values are not read at all, only names (I6).
- **It is not part of the product.** Nothing in `src/` imports it, no scan consults it, and the
  `Dockerfile` COPYs named paths, so `tools/` never enters the image. `reports/` is gitignored:
  it is the one place in this repository where a fleet's own hostnames would otherwise end up
  committed (I2).

The pure/I-O split is the same one `resolveBuildStamp`/`buildStamp` and `parsePasswd`/`readPasswd`
use, and for the same reason — `buildReport` is a function of an observation record, so the whole
report is assertable against canned bodies with no network and nobody's service involved. Which
is also what makes the JSON the real deliverable: it is a fixture a proposed eighth signal can be
replayed against offline.

**Section 3a answers the question an operator actually asked.** The signal table can only say which
of eight clauses failed; *this service has a sign-in page, why does the tool say it found nothing?*
needs a different kind of row. `evidence: EvidenceFinding[]` is that row — six detectors
(`login-link`, `login-control`, `login-route`, `login-heading`, `session-cookie`,
`content-served`), each carrying a `fact` quoted from the page and a `because`, all built on the
pipeline's own exported predicates. Two things keep it from being a second verdict:

- **`direction` has no `"gated"` member.** A finding can point at *open*, at *open with an optional
  account*, or at *worth another look*, and there is no member for the fourth possibility. So the
  worst a detector can be wrong about is a paragraph in a diagnostic file — never a service's place
  in the exposed count (I1). The `look-closer` grade is where a candidate ninth signal is
  *proposed*: `login-heading` — a `<title>` saying login with no form and a bundle — is the one
  finding here that would move a count, and it lands in section 4 as a proposal rather than being
  applied.
- **The smoke pass asserts the equality directly**, on every row of its own detector table:
  `buildReport(obs).verdict.gate === readGate(...)`. That is this section's version of the
  fixture-revert contract, and it fails the moment a detector leaks into a verdict (§8).

The dumps behind it are bounded, and every bound is reported as an `…Omitted` count rather than
applied in silence — a truncated anchor list that does not say it was truncated is how a reader
concludes a page had no sign-in link when what happened is that the report stopped before it.
Anchors inside a `<template>`, `<noscript>`, `<script>` or `<svg>` are kept but flagged `hidden`,
which is the one place the lab is deliberately wider than the rule: `readAnonAccess` cannot see
them at all (§3.6c), and a finding built on one is graded `weak` and points at `look-closer`.

**Two flags default to off, and both defaults are the same argument.** `--try-login-paths` GETs the
ten names in the pipeline's own `LOGIN_PATHS` on a form-less shell's origin — sequential, bounded,
`GET`, no credential. The chain and the auth-state sweep exist because a service *told* the tool
where to look; this one **guesses**, and a guess at ten addresses on somebody's service is a
different kind of act, so it happens only when somebody typed the flag. It is also the one section
that cannot move a verdict by plain statement rather than by construction — the scan asks none of
those addresses — so a login page found at one lands in section 4 sized as *one more entry in a
list*. `--save-body` writes a third file, the served HTML verbatim, and both the tool README and
the run's own closing lines say that it is the one artifact this tool writes that is **not** safe
to paste into an issue: an anonymous body carries no session, but it can carry whatever its
bootstrap script was handed (I6).

#### The switch beside Rescan

`probe.enabled` in the configuration is the **default**, not the authority. A `Login probe`
checkbox sits beside the Rescan button, and `POST /api/rescan` takes an optional body:

```json
{ "probe": true }
```

The value is fully authoritative for that build: `true` probes even where the configuration
says off, `false` skips it even where the configuration says on. That second direction is the
half a config default cannot express — an operator with probing on and no other way to ask for
one quiet rescan.

**It lasts for exactly one rescan.** A TTL rebuild, a timer, and a page load all carry no
request and fall back to the configured value. That has a consequence worth stating rather than
leaving to be discovered: probe results reappear or vanish on their own when the cache expires.
So the payload says what it did —

```ts
meta.probe: { enabled: boolean; source: "config" | "request" }
```

— always present, on the same reasoning §3.10 rests on: silence is indistinguishable from a
read that found nothing, and here it would be indistinguishable from a fleet with no login
pages in it. `source` is what keeps a reverted override from looking like a broken switch, and
the checkbox re-syncs from `meta.probe.enabled` on every overview it receives, so the revert
*moves the switch* instead of leaving it lying about what happened.

Three mechanics behind that, each chosen against a plausible alternative:

- **`withProbeEnabled(cfg, enabled)`** in [config.ts](labview/src/config.ts) returns a clone,
  never a mutation. The configuration object is captured by the cache's build closure, read
  again by the next timer rebuild, and still being read by a build already in flight when the
  click arrives — so `cfg.probe.enabled = true` would turn probing on *permanently* for every
  later scan with nobody having asked, and would break I7 besides.
- **`ScanCache<T, R>`** threads the value as a parameter of `build(req)` rather than through
  shared state, so the build that *starts* owns the override. A caller that coalesced onto an
  in-flight build has its own value discarded — deliberately, and visibly, which is again why
  `meta.probe` describes the build rather than the switch.
- **`readScanRequest`** validates rather than coerces: one known key, one known type. A missing
  body, an array, a JSON `null`, `{"probe":"yes"}` and `{"probe":1}` all mean *use
  configuration*. Ignoring an unknown field rather than rejecting it is the choice
  `parseSidecar` makes for the same reason (I4), and body-less POSTs — every client before this
  existed — keep working unchanged.

The security consequence is real and is in §7: when LabView is not enforcing a login, `POST
/api/rescan` is unauthenticated, so this switch lets any visitor start fleet-wide outbound
requests.

### 3.6c The other question: what the page showed (`readAnonAccess`)

Everything in §3.6b asks *is a gate in front of this?* and answers it from the shapes a gate
makes. This asks the opposite question, and it is the question a real fleet turned out to need.

Eight probe-lab reports against live services produced one sentence eight times: **no `<form>`
element in the served markup**. True, and useless. Three of those services had answered an
anonymous request with fifteen to twenty-four kilobytes of finished, readable page — an article
index, a landing page, a media library — and every one of them carried a plain `Sign in` link the
operator could see in a browser and LabView threw away unread, because the only things read out
of a body were forms, scripts and the `<title>`.

A page like that is not a rule failing to find a gate. It is **proof there is no gate**: an
anonymous request was answered with the application's own content, and the sign-in link beside it
is an optional account rather than a door. That is the first positive evidence LabView can report
about an open service. Until now `open` was only ever an absence — *none of the signals fired* —
and an absence is precisely what a reader discounts, rightly, because it is equally consistent
with a login this rule cannot see.

**One pure function, one body, no request.** `readAnonAccess(body, requestUrl)` in
[model/probe.ts](labview/src/model/probe.ts) returns a `ProbeAnon`: `textChars`, `links`, and
optionally `loginHref` and `loginLabel`. It reads the same body `readGate` was already handed
(**I8**), and keeps no header, no cookie and no attribute value except a resolved path and a
label shorter than `LOGIN_LABEL_MAX` (**I6**).

**It is structurally incapable of gating, which is the I1 argument and is not an argued one.**
`readGate` takes a `ProbeResponse`; this record is not on one, and `readGate` does not import the
function. There is no code path by which a sign-in link becomes a gate. So the worst a mistake
here can do is put a wrong *sentence* on a service that stays in the exposed count — it can never
take one out of it. Nothing else in this stage has that property, which is why this is the one new
kind of evidence that needed no new fixture-revert argument about counts.

**Both halves have to arrive together to mean anything**, which is why this is one function and
not two:

| What was read | On its own it means | So the rule |
|---|---|---|
| content served, no sign-in offer | an open application with no accounts at all | says the narrower sentence — *the application's own content and not a shell* |
| a sign-in offer, no content served | a login page whose form is drawn in the browser — the **opposite** conclusion | says nothing, and leaves the page to `stateShortfall` (§3.6b), which asks the addresses a shell's own client would ask |
| both | an application that serves everybody and offers an account | says so, and names the link or the control in the words the page used |

**A logout link is skipped before its path is read**, and that ordering is the one thing here that
would be a real bug the other way round. `isLoginPath` matches on prefix, so `/auth/logout`,
`/oauth2/sign_out` and `/sso/logout` are all login paths *by name*, and a page carrying one is a
page somebody is already signed in to. Reading it as a sign-in affordance would turn the strongest
available evidence of a **closed** session into evidence of an open one.

**Drawn markup, not served markup.** Every number comes off `drawnMarkup(body)`, which removes
comments, `<script>`, `<style>`, `<template>`, `<noscript>` and `<svg>` before anything is
counted. A `<template>` is where a client keeps the markup it has *not* rendered, and a framework
that routes in the browser routinely ships its whole sign-in screen inside one; a `<noscript>` is
the page for a visitor who is not the visitor being described. Counting either would produce
exactly the mistake this rule exists to avoid — a shell reading as a finished page because its
undrawn templates are full of links. `<svg/>` is dropped before either arm, because SVG is foreign
content and the only place in HTML where `/>` really does close an element; every other tag in the
list treats the slash as noise, so an unterminated-element arm that swallowed a self-closed `<svg/>`
would delete the rest of the page. Direction-safe either way — a page can only lose text, never
gain it — but losing it there means losing the sentence on exactly the services this rule is for.

**The vocabulary is shared as a question, never as a pattern.** `LOGIN_LABEL` and
`NOT_LOGIN_LABEL` are private, multi-language on purpose (a path stays `/login` in every locale;
the label is the part that gets translated), and `saysLogin` / `saysLogout` are exported for
`tools/probe-lab` — the discipline `isLoginPath` and `hasPasswordField` already follow. Three
details in them are load-bearing and pinned by fixtures: word boundaries, without which
`log[\s_-]?in` matches `Blog index` and a documentation site becomes a login page; `continue with`
deliberately **absent**, because it is a login label only when a provider name follows and naming
providers would make the list a vendor list; and sign-up deliberately absent from the veto, so
`Sign in / Sign up` — one control offering both — still reads as a login affordance.
`LOGIN_LABEL_MAX` (24) is exported rather than duplicated, because the lab grades a long hit as
weak and must grade it by the same number: it fits `Sign in with Google` and excludes *How to log
in to your router*.

**The thresholds are wording thresholds, not verdict thresholds.** `servedAnonContent` — exported,
so the lab can put the same answer in front of a reader without knowing the numbers — is
`textChars >= 200 && links >= 2`. Both must hold, because either alone has a cheap
counter-example: a login page can carry two hundred characters of legal boilerplate, and a page of
nothing but a navigation can carry ten links. The margin is wide rather than fine — the largest
client-rendered body in the reports that prompted this rule rendered under fifty characters and no
anchors at all. And since nothing downstream counts anything, a threshold set slightly wrong costs
one sentence on one service, so these can be tuned from real reports with no re-audit of what they
move.

**Where it surfaces.** `ServiceProbe` gains `anon?: ProbeAnon`, optional for the same reason
`state` is — present exactly when a body was read as HTML, and §3.7's rule that a field describing
the *run* is never optional does not apply to a field describing a *response*. `openReason`'s
HTML-200 branch gains `anonProof(anon)` after `stateShortfall`, built the same way and in the same
"and the finding stands" register. `probeOutcome` is untouched: the label stays `No login page`,
because it is still true. The UI needs no change for the same reason the eighth signal needed none
— the tile and the drawer both render `probeReasonText`.

Note what the record does **not** do on a gated page: `anon` is attached whenever an HTML 200 was
read, gate or no gate, because it describes a *response*. What never appears on a gated verdict is
the *sentence* — `anonProof` is reached only from `openReason` — and the fleet-wide smoke assertion
is worded that way rather than as "the record and a gate never coexist" (§8).

`fixtures/probe/public-portal/` is the rule and its trap in one stack: `app` serves content with
`<a href="/login">Sign in</a>` and must produce the sentence naming that link, while `blog` serves
content with an article headline reading *How to log in to your router* and a `/auth/logout`
anchor, and must produce the narrower sentence with no offer in it. Back out `anonProof` and `app`
fails; loosen `saysLogin` or drop `NOT_LOGIN_LABEL` and `blog` fails. Both have a search `<form>`,
so `wantsStateProbe` stays false and neither adds a second request.

### 3.7 The data contract

[model/types.ts](labview/src/model/types.ts) is the single contract between
backend and frontend, and `/api/overview` serves exactly an `Overview`. Rules:

- It must stay free of Node-only imports — the web build imports it directly.
- `web/model.ts` re-exports it so UI files have one import surface. Add new
  exported types there too.
- [model/access.ts](labview/src/model/access.ts) is under the same rule and for a
  sharper reason: the login screen imports it, `tsconfig.web.json` compiles `web/` with
  `types: []`, so a stray `node:crypto` there is a compile error rather than a bundle
  that breaks in a browser. Everything needing a hash, a file or a socket lives in
  `src/auth/`, and none of it is reachable from `web/`. `SessionInfo`, `LoginMethod`,
  `LoginFailureReason` and `AccessMode` are in `model/types.ts` with the rest of the
  contract; the *wording* for them is in `model/access.ts`.
- [model/auth.ts](labview/src/model/auth.ts) is web-safe under the same rule, and is
  there for the §8 reason rather than the bundling one: whether the absence of a
  mechanism may be reported at all is a statement about the fleet, and four call sites
  ask it. As a predicate in `src/` it is asserted once; as a condition repeated in the
  components it would be unfalsifiable and would drift. Not to be confused with
  `model/access.ts` beside it — that is LabView's own login, this is what was found in
  front of somebody else's service.
- [model/networks.ts](labview/src/model/networks.ts) is web-safe for the same reason and
  draws a line worth stating outright: **the analyzer emits the complete truth, the model
  decides what is drawn.** `buildGraph` puts every network, every spoke, every dependency
  and every network that dependency can travel over into the payload; which network nodes
  are worth drawing, how many spokes and peers fit, and how a relation is worded are pure
  functions here. Three consequences. A JSON consumer gets the whole membership relation
  and is not silently pre-pruned. The fleet graph and the fleet Networks section contain
  the same networks *by construction*, because both filter through `showsNetworkNode`.
  And every cap and every rule is asserted directly in smoke — including against
  synthetic nodes far larger than any fixture (§8) — rather than living in a `.tsx` where
  it could not be falsified.
- The sharpest rule in that module is a distinction rather than a cap: **a line between two
  services requires a dependency, never co-membership** — and the corollary, that **one
  service's view of a network names its dependencies and counts everything else.**
  `networkLinks` returns `dependencies`, each with a relation and a cap, beside
  `reachableCount`, a number with no names in it at all, because one mixed list is what let
  a renderer draw thirty members of a proxy network as thirty connections — and a second,
  truncated list of names beside the first is the same claim in quieter type. *Which*
  services are also attached is a fact about the network, not about this service, and it is
  answered where networks are described: `networkGroups` feeds the fleet Networks section,
  which names every member of every network under the network's own heading.
- **Resolution reads the declaration and never writes to it.** A `depends_on` reference is
  stored exactly as the sidecar wrote it; the service it resolved to lives on a graph edge,
  as `declaredBy`. That is not tidiness — the parsed declaration is what §3.11 compares
  across scans to report an edited file, so a resolved target inside it would make a rename
  in *another* stack read as this sidecar having changed. A reference that stops resolving
  becomes `drift`, which that comparison already excludes.
- **A field that describes the build is on `meta`, and is never optional.** `meta.probe`
  states whether the active probe ran and which of configuration or request decided it, in
  every payload — including the overwhelming majority where probing is off. An optional
  field would make a reader infer from silence, and the two things it could infer from an
  absent `probe` ("probing is off" and "this build predates the field") are not the same
  fact. `meta.dockerError` and `meta.connections` are the precedent; the difference is that
  those describe a failure and this describes a choice, which is exactly why it must appear
  when nothing went wrong. It also has a second job: the probe switch (§3.6b) lasts one
  rescan, and `meta.probe` is what lets the UI show a TTL rebuild reverting to config
  rather than leave the checkbox lying.
  **`skipped` is on the same rule and needs it more than the other two.** A service that was
  not asked carries no `ServiceProbe` at all, so its silence is indistinguishable from "no HTTP
  address was observed" unless the number is stated — and 0 is a real answer, and the commonest
  one: a fleet with probing on and no gate anywhere in front of anything reports it. Made
  optional, a probe count of 13 in a fleet of 14 HTTP services would have no explanation
  anywhere in the payload. `ProbeReport.notAsked` carries it to the tile for the same reason
  (§3.9).
- **`meta.build` is the second field under that rule, and it replaced one that was not.**
  `ScanMeta.version` used to carry a hardcoded copy of `package.json`'s version — read by no
  code, rendered nowhere and mentioned in no document, so it could not answer the question a
  version is asked ("is the fix in the thing I am running?"). `meta.build` is its
  *replacement* rather than a companion, because two versions of one fact is a duplicate
  somebody has to keep in step. It is a **breaking payload change** for an outside consumer
  and gets the treatment `unmatchedRouters` got: named in `labview/README.md` where the
  payload is described. `BuildStamp` carries `version`, an optional `commit`, and a required
  `source` — and which half is optional is the whole design. `commit` may be absent because a
  build genuinely may not know its revision: an image built with no `LABVIEW_BUILD_SHA`, or a
  copy of the tree with no git in it. `source` may **not** be absent, because the same seven
  characters mean different things depending on where they came from. `image` says these bytes
  were compiled from that commit. `checkout` says only that the working tree this process
  started in was at it, which is silent about uncommitted edits — no file read can see them.
  Reporting one as the other would be exactly the I1 failure the field exists to prevent, so
  each source has its own sentence in [model/build.ts](labview/src/model/build.ts) and §8
  asserts that no two are alike. `unknown` then *names* the absence rather than leaving it to
  a missing key, which is `ProbeRun`'s reasoning again.
- **A fact about one response is optional, and its absence is itself the fact.** The four
  fields `ServiceProbe` carries beside `gate` — `mediaType`, `redirect`, `refresh`,
  `truncated`, the last three typed as `ProbeRedirect | boolean` — are the observations
  `readGate` reached its verdict on, and each is absent exactly when the response had no such
  thing: no `redirect` because nothing was a 3xx, no `refresh` because the page had no
  `<meta>` tag, no `truncated` because the body fitted. That is the opposite case to
  `meta.probe` above and not an exception to it. `meta.probe` describes the *build*, where
  silence has two possible readings and neither is safe; these describe *one exchange*, where
  silence has one reading and `probeReasonText` is written to say it out loud ("it answered
  HTTP 200 with no page …"). Nothing infers from an absent field: the sentence names what was
  missing.
- **`ServiceProbe.state` is a fifth such field, and it is optional for a stronger reason than
  the other four.** They are absent when the response lacked something; this one is absent when
  **no second request was sent** — which is the ordinary case, since `wantsStateProbe` admits
  only a form-less HTML 200 that gated nothing (§3.6b). So its presence is the record that
  LabView asked again, and it is the only place in the payload from which the extra traffic is
  reconstructible. Inside it, `asked` is **not** optional on `ProbeRun`'s rule — a walk that
  sent one request and a walk that sent four are different facts about a fleet, and 0 is
  unreachable because the field only exists when a request went out — while `refusedAt`,
  `status` and `wwwAuthenticate` are absent exactly when nothing refused, which is what makes a
  list that simply ran out distinguishable from one that stopped. `challenge` is the single
  derived bit the verdict rests on, and it is `false`, not absent, when a bare refusal was
  found: that case is reported and deliberately not counted (§11), so it has to be sayable.
- **Both redirect fields are reduced, and the reduction is I6 rather than tidying.** A
  redirect to an identity provider carries `state`, `code` and `redirect_uri`; a redirect to a
  login carries `?next=`. `ProbeRedirect.to` drops the query and the fragment and keeps the
  origin only when the target *left* the origin — path alone otherwise, so a same-origin
  `Location` spelled absolutely cannot read as a hand-off — with `crossOrigin` beside it as
  the fact the verdict actually used. `mediaType` drops the parameters for the same reason a
  charset has no business in the payload. The reductions are asserted directly: a sweep over
  the `readRedirect` table checks that no recorded target contains `?` or `#` (§8).
- Adding or renaming a member of a union (`AuthMethod`, `IngressKind`) is a
  **breaking UI change**: the palette in `web/lib/palette.ts` maps every member to
  a colour and a label, and an unmapped member silently renders grey. For
  `IngressKind` two smoke assertions catch that (§8). For `AuthMethod` the palette's
  own row count is pinned, and `none` is asserted to be the only member `showsAuthMethod`
  suppresses — so a *removed* or renamed entry is caught, but a union member added with no
  palette entry still is not. See §10.

### 3.8 Serving

Fastify with a static mount and eight routes, three of them the data API and five the
gate's (§3.13):

| Route | Needs a session | Behaviour |
|---|---|---|
| `GET /api/overview` | yes | cached scan; rebuilds when older than `cacheTtlSeconds` |
| `POST /api/rescan` | yes | forces a rebuild that re-reads the apps root, and returns it (§3.11). Optional JSON body `{"probe": true \| false}` overrides `probe.enabled` for that one build (§3.6b); absent or non-boolean means "use the configuration" |
| `GET /api/healthz` | no | `{ok: true}`, no scan |
| `GET /api/session` | no | `SessionInfo`: the posture, the live methods, and the signed-in user if any |
| `POST /api/login` | no | username + password → a session cookie |
| `POST /api/logout` | no | revokes the token and clears the cookie |
| `GET /auth/oidc/start` | no | 302 to the provider's authorize URL |
| `GET /auth/oidc/callback` | no | code → a session cookie → 302 `/`, or 302 `/?login_error=<code>` |
| `GET /*` | no | the built UI from `web/dist`, SPA-style fallback to `index.html`; a 404 under `/api/` stays JSON |

"Needs a session" is conditional on enforcement being on; with none configured every
route answers as it did before R10 — which for `POST /api/rescan` now means any visitor
can turn the active probe on for a scan. §7 states what that costs and why the switch was
given full authority anyway.

`startServer` is split into **`buildApp(cfg, opts) → {app, scan}`** and a `startServer`
that calls it and listens. The split exists for the tests: the hooks in §3.13 are the one
part of that feature no unit test can reach, and `app.inject()` drives them without a
socket. Anything registered on the instance must therefore be registered inside
`buildApp`, not in `startServer`.

Concurrent requests during a rebuild share one in-flight promise, so a burst of
traffic cannot start N scans — **except** a forced one, which may only be answered
by a build that started after it arrived, or it would return a scan taken before the
edit that prompted it (§3.11). The cache is warmed in the background at startup so
the first page load is instant. If `web/dist` is absent the server still runs and
says how to build it — the API is the primary product, the UI is a view of it.

The probe override rides that same machinery as a **per-request value**, not as state on
the server: `ScanCache<T, R>` hands whatever the caller passed to the build it starts, and
a coalesced caller's value is discarded along with its build. That is why the reported
`meta.probe` is a statement about the build that ran rather than about the request that
was answered, and why a timer rebuild — which passes nothing — falls back to the
configuration. A mutable "probe next time" flag on the server would have been shorter and
would have let one caller's override be consumed by an unrelated passive build.

### 3.9 Frontend

Preact + Vite (`web/vite.config.ts`), built to `web/dist`: a single `app.js` with
mermaid and cytoscape inlined, one minified `styles.css`, and the `index.html`
shell. There is no CDN dependency and no network access beyond same-origin `api/*`
(relative, so it works under a path prefix).

Vite owns asset bundling, module resolution and stylesheet injection, which moves
three facts out of a build script and into the graph:

- **The stylesheet is an import, not a copied file.** `main.tsx` does
  `import "./styles.css"`, so Vite minifies it and writes the `<link>` into the
  built shell itself. `web/index.html` therefore carries no stylesheet tag and
  points at the *source* entry, `/main.tsx` — the one thing a hand-maintained tag
  could disagree with the build about.
- **The output names are pinned, not hashed.** `entryFileNames: "app.js"` and
  `assetFileNames: "styles.css"`, because the public artifact list is a documented
  security fact in §3.13, §7 and §12 rather than an implementation detail: exactly
  three files are served before sign-in, and they are named in prose.
- **`inlineDynamicImports` is load-bearing.** mermaid reaches for its diagram types
  through some 38 dynamic imports. Rollup's default is a chunk each, which would
  both break the three-file list above and make rendering a diagram a second
  request.

`base: "./"` for the same reason `api.ts` uses relative URLs: Vite's default emits
absolute `/app.js`, which is precisely the assumption that breaks a LabView served
under a path prefix. The shell and the API agree about this, and neither is absolute.

**View hierarchy.** The Stacks tab lists one card per stack — the unit a compose
fleet is organised in — which expands to its services, each opening the detail
drawer. Two rules hold it together:

- **Filtering stays service-level.** "Public" is a property of a service, not of a
  directory. The predicate runs over the flat service list; a stack renders when at
  least one of its services matches, and shows only the matching ones. A
  stack-level predicate would have to reduce a stack to one posture, which it does
  not have.
- **A collapsed stack rolls up, it does not summarise.** Every distinct ingress kind and
  every auth *mechanism* present is shown, plus a count of services reachable without
  auth. A stack with an internal database and a public UI is both at once; picking a "worst
  case" badge would misreport it. `none` is the absence of a mechanism rather than one of
  them, so it rolls up to nothing — the exposure count beside the badges is where a
  missing gate is reported, and only where one was expected (§5). The ingress union comes
  from `rollUpIngress` in
  `model/ingress.ts`, which must deliberately *not* withhold `internal` the way a
  service's own set does, or the UI's exposure would erase the database from the
  collapsed view (§12).

**The ingress filter is an expression, not a selection.** Because a service carries
several kinds, one chip per kind with one on/off state cannot express what an
operator actually wants to ask. So each legend chip is **tri-state** — clicking
cycles it off → include → exclude → off — and a two-button `Any / All` control
switches the
included set between OR and AND. Exclusion is always AND-NOT and always wins over
an include, which is the only ordering that makes `Public` + `¬ Internal` mean what
it reads as. Three consequences:

- **The expression is evaluated per service**, matching the rule above. `All of
  Public, LAN` selects services that are *themselves* both, not stacks that happen
  to contain one of each — the stack card then appears because one of its services
  matched, showing only that service.
- **The predicate is not in the component.** `matchesTagFilter` /
  `describeTagFilter` / `cycleTag` live in
  [model/filter.ts](labview/src/model/filter.ts), pure and generic over string
  tags, because the web bundle has no test harness and a truth table for AND / OR /
  NOT is exactly the thing that must be asserted (§8). Generic over tags rather
  than over `IngressKind` so the auth dimension gets the same include/exclude chips
  for free — `matchesTagFilter([svc.auth.method], authFilter)` — while only ingress
  shows the `Any / All` switch, auth being single-valued.
- **A three-part expression is read back, not inferred.** `describeTagFilter`
  renders one line — `ingress: all of Public, LAN; not Internal` — beside
  `Clear filters`, because which chips look bright is not a legible way to recover
  what is being asked.

**The ingress distribution is per-tag gauges, not a part-to-whole bar.** Once one
service can carry two kinds, a stacked bar's segments sum past the total and every
proportion in it is wrong; clicking a segment labelled `11` would return 26 rows.
So `TagBars` renders one row per kind — label, a bar of `count / services`, the
count — and the `OverviewStats` doc comment says outright that the three external
ingress counters **overlap** while `internalServices` and `noIngressServices` do not. The authentication bar stays `DistributionBar`, because
`svc.auth.method` is still one value per service. Both take the same tri-state
legend API, so the two dimensions filter identically even though they aggregate
differently.

`web/lib/palette.ts` is the single source of truth for categorical colour: every
`IngressKind` and `AuthMethod` maps to a CSS custom property from the validated
palette in `styles.css`. DOM nodes use `var(--…)` directly; canvas-based views
(cytoscape, mermaid) call `resolveVar()` so both follow the light/dark toggle from
one definition.

The `cssVar` strings are the one part of that mapping no compiler checks, and both
lookups fail soft — `ingressVar` returns `--muted` for an unmapped kind, and
`resolveVar` returns `#888888` for a property the stylesheet never defines. A
variable renamed in one file only therefore turns grey rather than erroring, so
smoke asserts the two files agree (§8).

**The relationship graph connects services *through* networks.** A network drawn hanging
off one service says nothing about what that service can reach, and a line drawn straight
between two services hides the thing that joins them. So there is one shape —
`service → network → service`, the network in the middle — and a dependency is expressed by
**where the arrowheads sit on the membership edges it uses**:

```
   web ──▶ (net: layered_inner) ──▶ api          web depends_on api, both on layered_inner
              4 services

   db-a ═┐
   db-b ═┼══▶ (net: backup) ══▶ backup-agent    databases + the service that backs them up:
   mon ──┘     4 services · 4 stacks             declared in each database's .labview, drawn
                                                 dashed; mon shares the network and nothing
                                                 else, so its leg carries no arrowhead
```

Following the arrows reads dependent → network → dependency, and a service in the middle of
a chain carries one leg with an arrowhead at each end. The direct service→service edge
survives only where the pair shares no network at all (`via` empty) — the one case where
there is no network to route through, and one worth seeing. Because `external:` networks
are keyed by their **real** docker name, a network shared by six stacks is genuinely one
node with six spokes, which is what makes the cross-stack case visible at all.

**A spoke with no arrowhead is membership, and membership is not a connection.** Compose
cannot declare a dependency across projects, so a cross-stack one exists only where the
`.labview` sidecar states it (§3.12) — and everything else on a shared network is reachable
and no more. The fleet graph draws membership spokes anyway, because that view *is* the
membership picture; a service's own diagram draws a leg only where a dependency crosses the
network, and names the rest in words. A declared dependency is dashed wherever it appears,
and a membership spoke whose arrowheads come only from declarations is dashed with it —
`flowSource` carries which, so the two are never presented as the same kind of fact.

Three views read the same graph through the same functions, so they cannot disagree:

- **The fleet graph** ([GraphView.tsx](labview/web/components/GraphView.tsx)) filters
  through `showsNetworkNode` and `visibleSpokes` and labels nodes with
  `networkNodeLabel`, so a network joining fifty services is one node stating its counts
  and how many spokes it did not draw rather than a hairball. Network nodes are tappable
  and reveal that network's row in the Networks section instead of opening a drawer.
  Stack-local nodes are dashed; `edge[flow]` carries the dependency colour and its
  arrowheads. No edge labels — cytoscape renders none, and direction plus node labels
  carry it.
- **The Networks section** ([NetworksSection.tsx](labview/web/components/NetworksSection.tsx))
  on the overview is the direct answer to "show me every service on this network": one
  collapsible row per network, sorted by stacks joined then services joined, its members as
  chips that open their drawers, and one line per dependency the network carries — which is
  what resolves the arrowhead ambiguity the picture has once a hub carries two dependencies
  (§11). It states how many single-service stack-local networks it is not listing.
- **The service drawer** reads `serviceConnections` off the **unpruned** graph, so it names
  every dependency a network carries even where the fleet view capped its spokes. Its
  mermaid diagram draws the same `svc → net → peer` shape but **only for dependencies**, and
  no leg touching a network node is labelled: any wording would make the network a party to
  the relation, so direction is the entire encoding. Beside it, one HTML row per network —
  real name, scope pill, counts, a chip per dependency carrying its relation and, where it
  was declared, a second pill naming the file it came from. That is the whole of the naming:
  `MEMBERSHIP_NOTE` says so once above the rows, and each row ends with
  `networkMembershipText`, which accounts for everyone else in a sentence with a count in
  it. Four cases — nothing else is on it and nothing else can be; nothing else *scanned* is
  on it but the far end is outside the scan; *n* others are on it and being on it is the
  whole of what is true; *n* others are on it beside the dependencies just named. The names
  behind the count are one click away rather than withheld: the network's own name in the row
  head is a link to its row in the fleet Networks section, which names every member.

**Integration panels.** The topbar states each API integration as a count —
`authentik: 13 apps · 9 matched` — which is an outcome with two questions behind it:
which application was tied to which service and on what evidence, and why the rest
were not. Both counts are buttons (`.linkbtn`) opening a side drawer
(`web/components/ApiDetail.tsx`) that answers both, and the tooltips stay as the
summary: hover for the gist, click for the case.

Three rules shape it:

- **The matched side is derived, not duplicated.** The rows are built with `useMemo`
  by walking `ov.stacks` for `svc.authentik` / `svc.traefikLive` — the same fields the
  service drawer reads. Copying the pairs into `ScanMeta` would put the same fact in
  two places, and the two would eventually disagree about the same match. A matched
  row's service key is a button that opens that service's own drawer, and opening it
  closes the panel so two drawers are never stacked.
- **The unmatched side leads with the reason, not the name.** Each entry shows its
  `UnmatchedReason` as a pill, the one-line `detail`, and the whole `considered` trace
  as an evidence list — one line per matching rule tried, in the order tried, so a
  reader can see which rule came closest instead of taking "unmatched" on trust.
- **`--critical` is not used here.** An unplaced entry is a gap in what LabView can
  say; the critical tint means one thing only — a service reachable from the internet
  with no gate (§12). `ambiguous`, an unauthenticated proxy API and a failed
  connection phase use `--warning`, the same register as `.note` and `.banner`.

When an integration is unreachable the pill shows a phase instead of a count, and it
is clickable in that state too: the same drawer becomes the failure body — the stage
that failed, the address and where it came from, the code, the detail, the fix, and
one row per candidate tried with its own phase — read from the `ConnectionReport` in
`meta.connections` (§3.10) rather than from a second source.

**The drift panel.** `Declaration drift 3` is the same shape of problem one tile
further down: an outcome with the case behind it withheld. The sentences are already
written — the analyzer puts one in `svc.declared.drift` per disagreement, in the
operator's own terms (§3.12) — and the only way to reach them was the `⚠ Declaration
drift` chip, which narrows the stack list and still leaves the reader opening service
drawers one at a time. So the tile is a control and the sentences are a panel
(`web/components/DriftDetail.tsx`): one `Section` per stack, and per drifting service a
`.linkbtn` reading `stack / service`, a pill naming the file it was declared in, and one
`.note crit` per entry — the same class and the same string `AppDetail` shows, so the
panel and the drawer cannot word one disagreement two ways.

Four rules shape it, three of them borrowed from the row above:

- **The grouping is a model function, not component code.** `collectDeclarationDrift`
  and `driftSummaryText` live in [model/declarations.ts](labview/src/model/declarations.ts)
  for the reason `matchesTagFilter` lives in `model/filter.ts`: a rule that only exists
  inside a `.tsx` file cannot be asserted, because smoke never mounts a DOM (§8). What
  is worth asserting here is specifically that the panel lists exactly the services the
  tile counted.
- **Two counts, because there are two questions.** `report.services` is by construction
  the figure `computeStats` puts in `stats.declarationDrift` — services that disagree
  with their sidecar — and `report.entries` is the larger one a stack card's badge
  already shows, since one service can drift several ways at once. Both are stated in a
  single `driftSummaryText`, shared by the tile's tooltip and the panel's subtitle, so a
  reader who sees `3` and then four warnings gets the sentence that says why those are
  the same fleet. Sorted by stack name then service name, matching the fleet list (I7).
- **The stack grouping is derived, not declared.** Drift is service-level only —
  `ServiceDeclaration` has `drift`, `Declaration` does not — so the stack is a heading
  the services imply. Same reasoning as the matched side of the integration panels being
  walked out of `ov.stacks` rather than rolled up into `ScanMeta`.
- **The tile becomes a control without becoming a `<button>`.** `StatTile` takes an
  optional `onClick` and, when it has one, carries `role="button"`, `tabIndex={0}` and
  the Enter/Space handler `.stack-head`, `.svc-row` and `.tagrow` already use; its
  content is block elements, which a real button may not contain. Only the tiles whose
  count stands for a set of sentences pass it — drift, `Not confirmed` below, and the login
  probe. A count a reader can take off the payload has nothing further to say, and a tile
  that looked clickable without being so would be worse than a plain one.

**`Not confirmed`, the same panel with the opposite meaning.** `stats.declaredAuthUnconfirmed`
gets its own tile and opens `DriftDetail` with `variant="unconfirmed"` — one component, one
layout, two intros, because the layout is the same question asked of two fields and a second
copy would be a second place for them to fall out of step. A `variant` union rather than a
handful of optional strings, so the wording of each is decided in one table and drift's
alarming intro cannot end up over a list of open questions. Three things differ deliberately:
the tile is **not** `alert` and the entries render as plain `.note` (the visual difference
between a disagreement and an open question is the whole point of the field existing); the
intro names the confounders, because a list that looks exactly like the drift list and means
the opposite has to say so; and the footnote pointing at the `⚠ Declaration drift` chip is
drift-only, since `ViewState.driftOnly` has no counterpart here and pointing a reader at a
control that is not there is worse than pointing at nothing. `StackCard` gains **no** badge
for the same reason — a second warning badge would re-create the noise this removed (§3.12).

**The probe panel.** `Login probe 5` is the third tile of that shape, and it is a **new**
tile rather than a line added to an existing one for a reason I3 states: `Exposed, no auth`
would drop every *gated* result, which is half of what the probe measured, and `Auth-protected`
or `Declared auth` would file a probe result where a mechanism belongs. So the probe gets the
tile whose number *is* its measurement, rendered when `report.probed > 0` **or**
`report.notAsked > 0`, and the panel (`web/components/ProbeDetail.tsx`) answers the three
questions the tile cannot: the address tried, what came back, and which fact the verdict rested
on. Four rules, two of them specific to this tile:

The `notAsked` half of that condition is not defensive. A well-run fleet where everything with
an HTTP address is already behind a detected gate probes *nothing* (§3.6b), and without it an
operator who had just turned the stage on would see no sign it had run at all — the one reading
worse than a wrong number. So the tile draws with a `0` and a subtitle of
`N already authenticated`, the panel's opening note says how many were withheld and why in the
same breath as what was asked, and its empty state distinguishes the two ways `probed === 0`
happens: everything eligible was already authenticated, or nothing was asked at all.

- **Nothing here is tinted by severity except the pill.** The tile is not `alert` and no row
  is `crit`, and that is `OverviewStats.probeOpen`'s own doing: it is documented as **not** a
  subset of `exposedWithoutAuth`, because a service behind a detected gate that answers
  LabView from inside the fleet is counted in it too — the request may simply have gone around
  the edge that gates real visitors. Tinting would claim a fleet finding that
  `Exposed, no auth` may correctly deny, and the critical tint means one thing only (§12).
  `probeOutcome` already decides which result pill is critical and it is the only thing in the
  panel entitled to.
- **What cleared nothing leads.** Sections run *answered with no login page*, *answered with a
  login page*, *did not answer* — first the half of the measurement that left every finding
  standing, then the half that withdrew one. The third is neither, and gets its own sentence
  saying so: nothing arrived, so those services are classified exactly as the configuration
  alone classified them. A blank third section would read as "no login page found", which is
  the §3.6b error in the other direction.
- **The grouping and the sentence are model functions.** `collectProbeReport`,
  `probeReportSummaryText` and `probeReasonText` are in `model/probe.ts` for the reason
  `collectDeclarationDrift` is in `model/declarations.ts`, and the claim worth asserting is the
  same one: the panel lists exactly the services the tile counted — `gated.length ===
  stats.probeGated`, `open.length === stats.probeOpen`, the three lists summing to `probed`
  (§8). Sorted by stack then service (I7), and derived from `ov.stacks` rather than carried in
  `ScanMeta`, so there is no second copy to keep in step.
- **One fact, one voice.** Every row renders through the same `probeOutcome`,
  `probeVantageText`, `probeFormText` and `probeReasonText` the service drawer renders
  through, and `AppDetail` shows the reason line too — so following a row into its drawer
  reads as the same result rather than a second account of it. The row is four lines in the
  same order in every section: who, where and from what vantage, the form if there was one,
  the reason. It does not restate the section it is filed under.

The drawer shell itself (`.drawer-scrim`, the sticky `.dhead`, the scrolling `.dbody`)
moved out of `ApiDetail.tsx` into `web/components/Panel.tsx`, on the `Section.tsx`
precedent, so the drift and probe panels inherit the scroll, close and Escape behaviour
rather than restating it. `main.tsx` holds one `panel` state for all five — `"authentik" |
"traefik" | "drift" | "unconfirmed" | "probe" | null` — which is what guarantees two are never stacked and
fixes the Escape order: the panel closes first, the service drawer second. A row handing over
to a service drawer clears the panel through the same `openService` the integration
panels use.

**The build stamp.** `● LabView d0e2030` — the commit on the wordmark's baseline, muted and
small, for the whole session. It is the one thing on the page that is about LabView rather
than about the fleet, which is why it is an identifier rather than a finding: nothing tinted,
nothing to click. The **commit** and not the version, because while this is pre-release every
build reports `0.1.0` and only the sha tells two of them apart; the version is the fallback
when there is no commit, so the stamp is never blank. What those seven characters are evidence
*of* is in the `title` rather than the label, and both come from
[model/build.ts](labview/src/model/build.ts) — `buildLabel` and `buildTitle` — so the sentence
that distinguishes "built from that commit" from "started in a tree at that commit" is a rule
§8 asserts, not a string in a `.tsx` (§3.7). `cursor: help` marks that there is a sentence
there at all.

**It stays behind the session.** `meta.build` arrives only on `/api/overview`, which requires
one, and the login screen has its own `.brand` that gets no stamp — §7 gives the reasoning.

### 3.10 Connection diagnostics

Every outbound read degrades softly (§4 I4), which leaves the operator with a
result that is quietly weaker than it looks. "Unreachable" is one word covering a
name that does not resolve, a refused connection, an untrusted certificate, a
rejected credential, a socket proxy with the endpoint switched off, and an SSO
login page answering HTTP 200 — six different fixes. So every target reports a
`ConnectionReport` (§5) naming the **phase** it got to, and the taxonomy is shared
rather than per-integration: a fourth outbound read is diagnosable without
inventing its own vocabulary.

**Classification happens where the error object is**, and there are two of those:

- [enrich/http.ts](labview/src/enrich/http.ts) is the chokepoint both API clients
  already share. `phaseForCode` maps a libuv/TLS code, `phaseForStatus` maps an
  HTTP status, and `getJson` returns the resulting `phase` and `code` beside the
  `error` string it always returned. `fetch` is why this is needed at all: it
  collapses DNS failure, refused connection and certificate rejection into one
  `"fetch failed"` message, with the actual reason only on `err.cause.code`.
- [enrich/docker.ts](labview/src/enrich/docker.ts) cannot use `getJson`, so
  `classifyDockerError` reads dockerode's different surface — the code on
  `err.code` rather than `err.cause`, the status on `err.statusCode` — and returns
  the same phases from the same two helpers.

Three rules in that mapping are load-bearing and each has an assertion that fails
if it is undone:

1. **`401` and `403` stay separate.** One says *bring a credential*, the other
   says *this credential is not allowed here*. On a socket proxy the second is the
   single most likely misconfiguration — an endpoint the proxy was never given
   (`CONTAINERS=1`) — and it is not a network problem at all.
2. **A unix socket is diagnosed before dockerode sees it.** `probeSocketPath` does
   the `stat`/`access` (the only I/O) and `phaseForSocket` is pure over its result,
   because the filesystem can tell apart four states that arrive as one opaque
   connect error otherwise: absent, present-but-not-a-socket (a bind mount of a
   missing host path creates an empty *directory* — the usual cause), present but
   not accessible to this uid (`authorize`, not `connect`: the fix is group
   membership or a socket proxy, not the network), and present and answering.
3. **A timeout is established by the clock, not by the code.** dockerode
   implements its `timeout` option by destroying the socket, so an endpoint that
   accepts the connection and then says nothing surfaces as an ordinary
   `ECONNRESET` / "socket hang up" — indistinguishable from a peer reset by the
   error alone. Each awaited call is therefore timed, and `classifyDockerError`
   returns `timeout` when the elapsed time reached `docker.timeoutMs` and there is
   no HTTP status and the code is absent or one of the teardown codes. Timing each
   call separately, rather than the phase, keeps a large fleet's cumulative scan
   time from being read as one slow request; a genuinely slow `403` keeps its
   status.

**Wording, hints and emission rules live in
[model/connections.ts](labview/src/model/connections.ts)** — pure, no I/O, so all
of it is assertable:

- `hintFor(target, phase)` — a table keyed by *both*, because the fix genuinely
  differs per target: `resolve` on docker asks whether LabView is on the socket
  proxy's network, on authentik it names `LABVIEW_AUTHENTIK_URL`.
- `formatConnection(report)` — the log and `--summary` lines, one implementation so
  [server.ts](labview/src/server/server.ts) and [cli.ts](labview/src/cli.ts) cannot
  drift, followed by one indented `·` line per rejected candidate. A report is
  kept with its attempts even when it succeeded: the list of candidates walked past
  on the way to a working endpoint is the same list printed when none of them
  answers, which is what makes that case diagnosable.
- `changedConnections(prev, next)` — the on-change filter. The signature compared
  is `target|ok|phase|endpoint` and deliberately **not** `read`, whose container
  count changes on almost every scan.
- `shouldBanner(report)` — the UI predicate: `partial`, or failed with a phase
  other than `disabled` / `not-configured`. An optional integration nobody switched
  on is not a fault and must not shout, in the log (`debug`) or on the page.

Reports travel through `meta.connections` rather than being logged where they are
produced, because `buildOverview` takes no logger and must not (§4 I7). The server
logs what `changedConnections` returns — `info` for a working target, `warn` for
`partial` and every failure — and the first scan logs all of them.

These are the rules that make the output trustworthy. A change that breaks one is
a bug even if every test passes.

### 3.11 Rescan and change detection

A scan holds nothing between runs: `scanStacks` re-walks the apps root and re-reads
every compose and `.env` file on every build, so a new stack directory, a new
service and an edited file are picked up by construction. Two things were missing
around that, and both made a working rescan look inert.

**A forced request may only be answered by a build that started after it arrived.**
A build reads the compose files once, at its start, so a build that began *before*
an edit cannot contain it. Sharing one in-flight build with every caller — the
right thing for a burst of page loads — therefore hands a rescan that arrived after
the edit a scan of the pre-edit fleet. On a fleet of 86 containers with two API
exchanges that window is seconds wide, and the UI opens one on mount. That rule
lives in [server/cache.ts](labview/src/server/cache.ts), separated from
`startServer` because the ordering *is* the behaviour and cannot be asserted
through a listening socket: `build` and `now` are injected, and the consequences
are each asserted —

- two passive callers share one build (unchanged);
- a forced caller behind a passive build waits for it and then builds fresh, rather
  than sweeping the Engine twice to answer one question;
- two simultaneous forced callers still coalesce into one build (the second's
  `startedAt >= requestedAt`);
- the value a forced caller passes reaches the build it starts, and a caller that
  coalesced onto that build has its own value **discarded** — the build owns the
  override, which is why `meta.probe` can only ever describe what ran (§3.6b) — while a
  timer rebuild, passing nothing, gets `undefined` and falls back to the configuration;
- a failed build rejects its caller and leaves the previous value readable.

**A rescan says what it found.** `onBuilt(next, prev, {forced})` fires once per
build — not once per waiting caller — which is what lets the server report a diff
without `buildOverview` keeping memory (§4 I7).
[model/changes.ts](labview/src/model/changes.ts) does the comparison and the
wording, pure and free of node imports so [web/model.ts](labview/web/model.ts) can
re-export it: the log line and the note beside `scanned <time>` cannot disagree
about the same rescan. Canonical JSON strings are compared directly rather than
hashed — both payloads are already in memory, and an exact comparison needs no
story about collisions.

What is compared is the **parsed configuration**, not file mtimes and not raw
bytes. That is the question an operator has (*did my edit take effect*), and it has
two visible consequences: a comment-only edit reports nothing, and a rotated value
that LabView masks is invisible, because masking happens before the payload exists
(§4 I6). Both are asserted so neither can be mistaken for a miss.

The canonical view omits the fields that move without anyone editing a file —
`docker`, `authentik`, `traefikLive`, `ingress`, `auth`, `notes`, `cloudflare` —
for the same reason `read` is kept out of `changedConnections`'s signature: a
container that restarted is not a configuration change, and a diff that says
otherwise reports everything on every rescan. `cloudflare` is in that list because
each route's `origin` resolves against the fleet index, whose container-address
table exists only when Docker is readable; the hostname edits it would have caught
are caught anyway, in `labels`.

It is a **deny-list, not an allow-list**, deliberately. Forgetting to exclude a new
derived field produces a spurious "changed" line — loud, and fixed the first time
anyone sees it. Forgetting to *include* a new field parsed out of the compose
document produces an edit that is silently never reported, which is the failure
this exists to prevent. See the §10 playbook line for adding a field.

Emission follows the same cadence rule as the connection lines. The first build
states the baseline (`LabView read 56 stacks, 86 services from /data/apps`); after
that a change always speaks, a forced rescan answers even when nothing moved, and
only a timer rebuild that found nothing stays quiet. The UI holds the outgoing
payload across the request and renders `scanned 12:04:11 · +1 stack, +2 services`
with the per-stack detail as the tooltip. No new API fields: both consumers already
hold the two payloads a diff needs.

#### A rescan re-reads the integrations, and reports what came back

A rescan re-runs both API exchanges — endpoint discovery and every request. Nothing is
memoized. It does **not** re-read the credentials: those come from the environment,
which is fixed for the life of the process, so a rotated token takes effect on the next
container restart and not before. (An earlier design read them from a path per build,
which did survive rotation; that is the one capability the move to env-only gives up,
and §12 records it as a documented consequence rather than a bug.) What changed in
those answers
is reported by `diffIntegrations(prev, next)`, and neither rule above would do it:
the configuration diff excludes live API answers on purpose, and `read` is excluded
from `changedConnections`'s signature for the same reason. Between them, an
application count going 18 → 40 would produce no line anywhere, which from the
operator's seat is indistinguishable from a rescan that never touched Authentik.

`diffIntegrations` is therefore a **second structure reported beside `ScanDiff`,
never folded into it**. Folding them would make "changed" mean two things at once
and would break the property the deny-list exists to protect — an API that answered
differently is not an edit. So the note and the log line carry two labelled clauses:
`no config changes; authentik +1 application, -3 withheld`.

**Reachability is decided before any count is compared, and that is what keeps the
numbers honest.** A failed read reports zeros, so comparing across it would announce
`-40 applications` — a statement about Authentik's contents from a scan that never
reached Authentik, and precisely the §4 I1 failure this codebase exists to prevent:

| prev → next | `state` | Reports |
|---|---|---|
| neither read | *no entry at all* | — the banner and connection line own a persistent failure; repeating it every rescan makes it look like news |
| both read | `unchanged` or `moved` | count deltas, and the records that appeared or disappeared, by name |
| not read → read | `started` | nothing numeric; the connection line already carries the counts |
| read → not read | `stopped` | nothing numeric; the banner carries why |

Counts come from a small table per target, each compared only when **both** sides
have a value — `applicationsConfigured` is optional, and an older payload without it
must degrade to saying nothing rather than to claiming the total fell to nothing
(§4 I4). True nouns go through `plural` (`+3 applications`); the modifiers of those
same nouns read identically in both directions (`-3 withheld`, `+1 matched`),
because `+3 withhelds` is not English and `-3 withheld applications` claims a loss
when the opposite happened. Traefik's `services` is rendered **`live service`**: a
proxy service is not a fleet service, and the two appear in the same line.

Named records are read back off the payload rather than tracked separately, so what
the diff names is exactly what the drawer shows — matched ones from the services
(`svc.authentik.applications[].slug`, `svc.traefikLive[].router`), unmatched ones
from the summary. Sorted, for determinism (§4 I7). Long lists are truncated **per
line** with the remainder stated: each target contributes at most three lines, so
the `MAX_DETAIL_LINES` ceiling could never be reached, while forty applications
would otherwise put forty names in one log line.

The cadence rule lives in `formatRescan` rather than in `logScan`, so it is
something a test can call, and "quiet" means *both* diffs. A rescan that found new
applications is not quiet just because no file was edited.

### 3.12 The declaration layer (`.labview`)

Some things are true about a service and written nowhere a scanner can read. An
application's own login is not a compose label. That a status page is *deliberately*
open to the LAN is a decision, not a config value. So an optional YAML sidecar beside
the `compose.yml` — `.labview`, or `.labview.yml` / `.labview.yaml`; the candidate
list is `cfg.sidecarFilenames` and the first that exists wins, so a directory holding
two can never half-apply one and then the other — carries what the operator knows:
description, owner, criticality, links, off-fleet dependencies, data, a dependency on
another *scanned* service, in-app authentication, and an accepted exposure.

This is the one place LabView accepts input that is *not* observable evidence, so the
whole design is about keeping it separable from what was proved. Read by
`scan/sidecar.ts`, attached as `stack.declared` / `svc.declared`, and governed by three
rules:

- **A declaration never changes a detection.** Declared auth is `svc.declared.auth`,
  not `svc.auth.method`, which stays `none`. `confidence`, `evidence`,
  `stats.authProtected` and `stats.byAuthMethod` are untouched, the declared mechanisms
  are counted only in `stats.declaredAuth`, and the UI badges them *declared*. A reader
  can always tell what LabView proved from what it was told — which is I1 (§4)
  surviving contact with an input that has no evidence behind it.
- **A declaration can change one verdict, in the open.** `exposedWithoutAuth` is not a
  measurement, it is a conclusion — *reachable, and nothing authenticates it* — and a
  declared in-app login answers its second clause. So `reachable && !hasEdgeAuth &&
  declaredAuth.length === 0`: a service whose sidecar says the app logs users in leaves
  the count. `hasEdgeAuth` itself is untouched, so evidence and declaration remain two
  terms of one expression rather than one merged source. The service does not go quiet —
  it gets `declared.authAgreement === "supplies"`, a *Protected — declared* badge, its
  own tile and CLI line (`stats.declaredAuthProtected`, counted off that same field so
  badge and number cannot diverge), and a note stating that the verdict rests on a
  declaration this scan cannot verify. **The one honest risk of the whole layer** is a
  stale declaration on a public service, and this is the mitigation: it is loud in place
  of an alarm rather than absent.
- **An accepted exposure is still an exposure.** A service reachable with no gate and no
  declared login stays in `exposedWithoutAuth` with `stats.exposureAccepted` counted
  beside it; the alarm is driven by the *remainder* and the KPI reads
  `formatExposureCount` → `23/28`, so a reviewed fleet stops shouting without ever
  understating what is reachable. `reason` is mandatory: an acceptance with no reason
  cannot be told apart from a stray key, so it is refused and warned about.

The last two are different statements and deliberately not interchangeable: `auth` says
there *is* a login, so the finding does not exist; `unauthenticated` says there is not
one and that is accepted here. Only the first leaves the count.

**Comparison: `compareDeclaredAuth`.** The declared and detected vocabularies describe
*different layers* of one request path, so a literal "declared ≠ detected → warn" rule
would fire on every layered setup there is. Three families are named by both sides —
`oidc` (`app-oidc` / `authentik-oauth`, `other-oauth`), `ldap` (`app-ldap` /
`authentik-ldap`, `ldap`), `proxy` (`external-proxy` / `authentik-forward-auth`,
`forward-auth`) — and both maps are **`Partial`** on purpose: absent means *not
comparable*, which is the common case and must stay the safe one. Each family sits in a
layer (`FAMILY_LAYER`: `oidc` and `ldap` are the app authenticating its own users,
`proxy` is a gate in front), and two statements are compared only *within* a layer.
Four outcomes, decided in this order:

| `DeclaredAuthAgreement` | when | effect |
|---|---|---|
| `supplies` | the caller's `wouldBeExposed` is true | rule 2 above |
| `redundant` | every declared mechanism's family equals the detected family | rendered **nowhere** — two sources that agree are one source to check twice |
| `conflicts` | the declaration names a mechanism in the detected family's layer, and none of them is that family | a `drift` entry naming both, and the declaration shown without any "not detected" claim |
| `supplements` | anything else | shown as declared, no warning — defence in depth, or a declaration on an unreachable service |

The third parameter is `wouldBeExposed`, not `reachable`: `hasEdgeAuth` includes
Cloudflare Access and enforced Authentik gates that carry no `AuthMethod`, so with plain
`reachable` an already-protected service would be labelled `supplies` and counted in
`declaredAuthProtected` without ever having been in the exposed count. It follows that
`supplies` implies `method === "none"`, which bounds the blast radius of the whole
feature to one case: **a declaration can only change a verdict where the scan found
nothing at all.**

**The vocabulary is mechanisms, not products.** `DECLARED_AUTH_MECHANISMS` is
`app-local-accounts`, `app-ldap`, `app-oidc`, `app-saml`, `app-token`, `mtls`,
`network-restricted`, `external-proxy`, `other` — the same I3 line the scan holds
itself to, applied to input. `authentik-proxy` is refused with the vocabulary quoted
back, because a mechanism is checkable and a vendor is an attribution. `other`
requires a `detail`, since alone it says nothing.

**`depends_on`: the one declared field that is resolved rather than shown.** Every other
field is prose or a fixed vocabulary; this one names a service LabView scanned, so it can be
looked up — and therefore must be. Two reasons it is a separate key from `dependencies:`
rather than a case of it: `dependencies:` is deliberately about things *outside* the fleet,
where nothing can be checked, and a list mixing prose with references cannot tell a typo
from a sentence. So `dependencies:` stays unchecked prose and `depends_on:` is checked
loudly.

It is **service level only**. A stack-level entry cannot say *which* of the stack's services
depends on the target, so it gets its own warning naming that reason instead of the generic
unknown-key line — a reader who mistyped the location learns what to do, rather than that a
key exists somewhere.

`resolveDeclaredDependencies` (step 6b) resolves each reference against the same fleet index
the origins pass built, preferring the declaring stack's own service for a bare name — which
is all compose's own `depends_on` can ever mean, so it is the reading least likely to
surprise. Four outcomes:

| the reference names | result |
|---|---|
| one service, qualified or bare | a `depends_on` edge with `declaredBy`, and `via` = the networks the pair shares |
| this stack's service **and** others, bare | resolved to the local one; the others are not candidates |
| two or more services in other stacks, bare | `drift` naming every candidate and asking for `stack/service`; **no edge** |
| nothing, or this service itself | `drift` quoting what was written; **no edge** |
| an already-resolved target, again | one edge, silently — a duplicate is idempotent, not a mistake worth a line |

**Declared once, shown from both ends.** The dependent's sidecar is the only file that says
anything; the target's drawer derives its `required-by` from the same edge. That asymmetry is
the point of the feature rather than an accident of it: a `required_by` key on a backup agent
would have to be edited every time anything new started depending on it, which is precisely
the maintenance an operator will not do — and a list nobody maintains is worse than no list.

Two things resolution is not. It is **not evidence** (I1): a declared dependency changes no
ingress kind, no exposed count, no auth posture, and it is dashed everywhere it is drawn with
the file it came from on its chip. And it is **not reachability**: a pair that shares no
docker network still gets the relation, plus a note saying that if those two communicate it
is over something this scan cannot see — the compose wording ("startup is ordered, yet
neither container can reach the other") is false for a declaration, because nothing orders
these two containers at all.

**Drift, because the real failure mode is not a typo.** A sidecar's actual risk is
going quietly out of date, so every checkable field is re-checked on every scan and
each disagreement is one entry in `svc.declared.drift`, counted in
`stats.declarationDrift`:

- an acceptance for a service the scan no longer finds reachable, or one that something
  now authenticates — including the mechanism declared in the same file, which is the
  `agreement === "supplies"` branch: an acceptance and a declared login on one service
  contradict each other, and saying so is better than honouring whichever ran first.
  Reachability is tested with `isExternallyReachable`, the same predicate
  `exposedWithoutAuth` uses, so the two cannot disagree about one service (§5);
- a declared mechanism that `compareDeclaredAuth` returned `conflicts` for, naming both
  sides and the layer they share, so the reader knows *which* of the two to go correct;
- a `depends_on` reference that no longer names exactly one scanned service — quoting it,
  and saying which of the three ways it failed. `drift` is the right channel rather than a
  warning: it is the existing home for *a sidecar statement the scan can no longer confirm*,
  it already has a counter and a UI row, and it sits outside the rescan comparison, so a
  reference that goes stale because another stack was renamed never reads as an edit to this
  file (§3.7);
- an `expected.ingress` that differs from the classification, reported through
  `diffIngress` in **both** directions — `missing: lan; unexpected: traefik` — because
  a set compared by eye is exactly what the operator should not have to do. Order is
  irrelevant on both sides: the declared list is normalized into `INGRESS_KINDS` order
  at parse time and then compared as a set, so `[public, lan, traefik]` in any order is
  one expectation. That same normalization is what drops a declared `internal` written
  beside an external kind, so an expectation can never drift on a kind the scan would
  never report (§5).

**Unconfirmed, because an absence of detection is not a disagreement.** There is a fifth
check, and it is deliberately *not* drift. Where a declaration `supplies` the only
protection and the login probe (§3.6) reached the address and found no gate, the result is
one entry in `svc.declared.unconfirmed`, counted in `stats.declaredAuthUnconfirmed` — a
subset of `declaredAuthProtected`, never an alarm of its own.

The probe asks one address, at `/`, once, without following redirects. A login one route
deeper, a sign-in screen the client draws after the page loads, a token guarding an API
rather than a landing page, and a network restriction this vantage point sits inside all
answer exactly like a service with no protection at all — which is why the entry names the
address and the status and then refuses the inference in words. This was reported as drift
until it was not: drift means *the file and the scan contradict each other*, and an alarm
that also fires on *the scan could not tell* is the kind that gets trained into noise,
which costs the genuine entries beside it their meaning. Nothing was lost in the move — the
same observation is already a row in the Login probe panel and a `probeReasonText` sentence
in the drawer; what went is the warning framing.

The two fields are collected by one walker with two wrappers
(`collectDeclarationDrift`, `collectUnconfirmedDeclarations`), rendered by one panel with
two intros, and shown in the drawer with two classes: `note crit` for a disagreement,
plain `note` for a question. The stale-acceptance check above stays drift under the same
rule, because its probe arm fires on a gate that *was* found.

**Agreement is silent, in both directions.** The `Expected ingress` row renders only
when `ingressMatchesExpectation` is false, and `DeclaredAuthBadge` and the declared
`Authentication` row render nothing for `redundant`. A sidecar that is right about
everything is invisible beyond the prose in it — which is what makes the rows that *do*
appear worth reading.

**An absence is silent too, unless it is a finding.** Nothing renders in place of a
mechanism the scan did not find. On a service whose sidecar declares an in-app login, a
badge reading "no auth" would argue with the declaration one slot to its left: this layer
exists to take the operator's word for what no scan can reach and to say plainly that it
is unverified — not to keep asking. And on the rest of the fleet it would be a warning
about correct topology, since most services in a compose file are internal and have no
gate because they need none. The one absence worth reporting is `exposedWithoutAuth`,
which already has a badge, a counter and a note of its own; `NoAuthReason` (§5) separates
it from the three that are not.

The classification always stands. Drift is a report, never an override.

**Everything about reading the file is defensive.** It is operator input from inside
the tree LabView already treats as untrusted (§7): resolved under the same containment
rule as `env_file` so a symlink cannot reach outside the apps root (I8), size-capped at
`MAX_SIDECAR_BYTES`, every text field length-capped, unknown keys **named** in a
warning rather than ignored (a mistyped `descripton` that silently does nothing is the
one failure mode an optional-everything format has), and every mistake a warning rather
than a failure (I4) — a malformed sidecar costs the fields it got wrong and nothing
else. Declared text is shown as written and no masking heuristic applies to prose, so
the documentation says plainly: never put a secret in one. Credentials in a declared
link URL are redacted as a backstop, which is also why the link label falls back to the
*redacted* URL and never the raw one.

`declared` is parsed from a file on disk, so it deliberately stays **off**
`VOLATILE_SERVICE_FIELDS` — the deny-list default (§3.11) then makes an edited sidecar
a reported change for free. Its two *analyzer-written* members are another matter:
`drift` and `authAgreement` are conclusions about the scan that happen to be stored on
the declaration, so `serviceConfig` compares `declarationConfig(svc.declared)` —
everything except `DERIVED_DECLARATION_FIELDS`. Without that, a scan in which the
*detected* posture moved (a Traefik read that worked this time, a container that came up
on another network) would be reported as an edit to a sidecar nobody touched, which is
the exact false positive the deny-list exists to prevent. The exclusion is narrow: an
edit to the prose in the same block is still a change.

### 3.13 Access control

LabView's own login (R10). Two methods — a password form over a passwd file, and OIDC —
and one posture rule that decides whether either applies.

**The naming hazard, first.** `AuthMethod` already contains **`basic-auth`**, meaning *a
scanned service* uses HTTP basic auth, and `--auth-basic` exists in the CLI palette. This
feature is a different thing entirely and shares no vocabulary with it: it is **access
control**, its methods are **`passwd`** and **`oidc`**, and no symbol in it contains the
word `basic`. A future reader merging the two would produce a dashboard that reports its
own login as a property of someone else's container.

#### Open unless configured

`resolveAccessMode(inputs)` in [auth/index.ts](labview/src/auth/index.ts) is pure and
returns `{enforced, methods, notes}`. Enforcement is on **iff at least one method is
live**:

| Method | Live when |
|---|---|
| `passwd` | `auth.passwd.enabled` **and** the file parsed to ≥ 1 usable entry |
| `oidc` | `auth.oidc.enabled` **and** `issuer` and `clientId` are both non-empty |

`enabled` means *allowed*, not *on*. A method switched on but unusable — an empty passwd
file, an issuer with no client id — produces a **note and a `warn`**, never an error and
never a lock-out (I4). This is the whole reason the default is what it is: a new image
pull must not be able to lock an operator out of a running deployment, and an operator
who has never heard of this feature must see exactly the behaviour they had before.

The posture is re-resolved on request, cached for `POSTURE_TTL_MS`, and the summary line
is re-logged only when it changes — the cadence `changedConnections` uses (§3.10), and
the reason an operator who creates the passwd file on a running LabView is told it was
picked up. `accessModeSummary()` lives in `model/access.ts` so the startup line and the
UI cannot drift, and it reports **counts, never names**: a user list in a log file is an
inventory of accounts to try.

#### The gate

One `onRequest` hook, one `onSend` hook, five routes, all in
[server/auth.ts](labview/src/server/auth.ts). Three rules the file holds to:

- **The gate never consults scanned data.** Whether a request is allowed depends on the
  config, the passwd file and the cookie — never on an overview, a container or anything
  an enrichment read returned. A Docker endpoint that goes away must not be able to
  change who may sign in. Concretely: no `getOverview()` call may appear in
  `server/auth.ts`.
- **A reply says less than the log.** The browser gets a code from `LoginFailureReason`;
  the reason, the path and the provider's complaint go to the log (I6).
- **A username is sanitised before it is logged.** It arrives in a request body or an ID
  token; `sanitizeUsername` returns `"?"` for anything outside `[A-Za-z0-9._@-]{1,64}`
  rather than a scrubbed copy, because a partially-sanitised name is a way to smuggle
  content into a log line.

`isPublicPath` is an **exact-match allowlist** over a normalised path — query and
fragment stripped, `//` collapsed, any `..` segment refused — holding `/api/healthz`,
`/api/session`, `/api/login` and `/api/logout`. Written as a rule because the obvious
`startsWith` version makes `/api/healthz/../overview` public and `/api/sessionx` a
bypass; both cases are asserted.

**Scope: gate the data, not the shell.** Everything under `/api/` needs a session;
`index.html`, `styles.css` and `app.js` stay public and render the login card. That is
sound only because of **I2** — shipped artifacts contain no fleet-specific identifiers by
construction — so serving the bundle before a login discloses nothing about the fleet. If
I2 is ever weakened, this decision has to be revisited with it.

`/auth/oidc/*` sits **off `/api`** deliberately: the redirect URI is typed into a
provider by a human and appears in browser history, and keeping it outside `/api` keeps
the allowlist to four exact paths instead of six. Registered routes take precedence over
`setNotFoundHandler`, so the SPA fallback is unaffected.

`onSend` adds `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and
`X-Frame-Options: DENY` unconditionally — they cost nothing, so they are never
conditional — and `Cache-Control: no-store` on `/api/*` while enforcing. **No CSP**:
mermaid and cytoscape both inject styles at runtime, and a policy that breaks the graph
tab is worse than none.

#### Passwd file

`user:hash`, one per line, `#` comments and blank lines ignored — `/etc/shadow`'s and
`htpasswd`'s format, with the algorithm named by the hash's own `$id$` prefix rather than
by a config key, which is what lets a file written by `htpasswd -nbB` work unchanged.
bcrypt (`$2a$`, `$2b$`, `$2y$`) is verified through `bcryptjs`; any other id is skipped
with a warning naming **the algorithm only**; a value with no `$` prefix is a plaintext
password and is never accepted.

Two rules shape [auth/passwd.ts](labview/src/auth/passwd.ts):

- **A warning never contains a hash.** It names the line, the user and the algorithm.
  Warnings reach logs, and logs reach issues and pastebins.
- **A bad line is skipped, never fatal.** A file with one mistyped entry still signs in
  every other user (I4). Only a file with *no* usable entry turns enforcement off, and
  that is reported as such.

Split into a pure `parsePasswd(text)` and an I/O `readPasswd(path)` for the reason
`scan/sidecar.ts` gives — every validation rule is then assertable without a fixture —
with caps `MAX_PASSWD_BYTES` (64 KiB), `MAX_PASSWD_ENTRIES` (1000) and
`MAX_PASSWORD_CHARS` (1024, so a large body cannot be turned into hashing work). Reads
are cached on size + mtime + inode, so adding a user needs no restart and an editor that
replaces the file is picked up as well as one that writes in place. `readPasswd`
distinguishes `ENOENT` (nothing configured — silent), a **directory** at the path (what
Docker creates at a bind-mount source it cannot find, and the single most common way this
goes wrong), over-size, and `EACCES` — which gets its own sentence naming the cause,
since the image runs unprivileged by design and a root-owned mode-600 file is unreadable
however correct its contents are.

Verification never discloses whether a username exists: an unknown name is verified
against a **decoy hash generated lazily from `randomBytes`** at the file's own prevailing
cost and the result thrown away, so the response time is not a list of valid accounts.
The decoy is generated rather than committed — a constant hash in the repository is a
credential-shaped artifact that secret scanners flag and that someone eventually tries to
"fix". Both outcomes return one message.

**The throttle is keyed on the sanitised username, not the address.** Behind a tunnel
plus a reverse proxy every request shares one source address, so address keying would let
one wrong password lock out the fleet. `maxFailedAttempts` within `lockoutSeconds` → `429`
with `retryAfterSeconds` **regardless of whether the password was right**, which is what
makes the lockout mean anything; the counter resets on success; the key is
case-folded, so `BOB` and `bob` share a bucket; the map is capped and evicts oldest.

#### Sessions

`v1.<b64url(payload)>.<b64url(hmac-sha256)>`, payload `{u, via, iat, exp, jti}`, verified
in the order the checks cost: shape → MAC → expiry → revocation. Expiry *after* the
signature on purpose — an unsigned token's claimed `exp` is not worth reading, and
reporting `expired` for one tells a forger their guess was parsed. The MAC is compared
through `safeEqual`, which hashes both sides so the comparison is fixed-width and
`timingSafeEqual` cannot throw on a length mismatch (the same helper guards the OIDC
`state`, where the length is not fixed).

No session store, deliberately: a dashboard that degrades to "sign in again" after a
restart is a better trade than a database, and two replicas behind one proxy work with no
shared state beyond `auth.session.secret`. The one piece of server state is the
revocation set, so signing out invalidates the token rather than merely dropping the
browser's copy; it is bounded twice (pruned by `exp`, capped with oldest-first eviction)
and a restart clears it along with every session it could apply to.

Cookie: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` from `ttlMinutes`. `Lax` rather
than `Strict` because `Strict` withholds the cookie on a cross-site *navigation*, which
is exactly what returning from an identity provider is — the callback would arrive with
no session and loop. `Secure` follows the **effective** scheme (`X-Forwarded-Proto`
first), because a `Secure` cookie over plain HTTP is never stored and the symptom is a
login form that takes the password and comes straight back with nothing in any log.

CSRF: `SameSite=Lax` plus an `Origin` check on every POST while enforcing, ordered
*before* the session check so a cross-site POST is refused whether or not it carried a
cookie, and returning no `Set-Cookie`. A **missing** `Origin` passes — browsers send it on
every cross-site POST, so its absence means the request did not come from a page and has
no ambient cookie to abuse.

Cookie handling is written out rather than delegated to `@fastify/cookie`, for the reason
`cookiePairs` in `enrich/http.ts` gives: this is `split(";")` and a header string, and a
dependency for it would have to be audited, updated and shipped.

#### OIDC

Authorization code with PKCE S256, in [auth/oidc.ts](labview/src/auth/oidc.ts). The HTTP
goes through `enrich/http.ts`, which already guarantees what a login flow needs: a
request never throws, a credential never reaches an error string, and a failure names its
stage — a token endpoint sitting behind an SSO gate answers with an HTML login page
exactly like every other gated endpoint, and `getJson` already has a word for that.
Everything that can be pure is pure and takes `now`: the PKCE derivation, the authorize
URL, the discovery validation, the ID-token check. `OidcClient` is only the part holding
a cache and a `fetch`.

Discovery is cached for `DISCOVERY_TTL_MS`, and the document's own `issuer` must equal
the configured one (trailing slashes forgiven, nothing else) — the standard mix-up
defence, without which a redirect to an attacker's authorization server would be followed
by a token exchange at their token endpoint against their keys. Every endpoint in the
document must be **https**, loopback excepted for a local stub issuer, so a downgraded
document cannot turn the exchange into a cleartext one.

`/auth/oidc/start` puts `{state, nonce, verifier, exp}` in a **signed transient cookie**
scoped to `Path=/auth/oidc` with a five-minute window — signed rather than stored, so
nothing is kept server-side and a restart mid-login fails cleanly. The window is
re-checked from the payload rather than trusted to `Max-Age`, because a browser that
keeps sending an old cookie is not a threat model to delegate to the client.

The ID-token check, in this order and non-negotiable: signature **before** any claim is
believed; then `iss` exactly, `aud` containing the client id, `azp` equal to it when
present, `exp`/`iat` within `CLOCK_SKEW_SECONDS`, and `nonce` equal to this attempt's.
**Asymmetric algorithms only** — `alg: none` is not a signature, and every HMAC alg is
refused because a symmetric alg beside a published JWKS is a known confusion vector: a
verifier accepting both can be handed a token signed with the public key as the HMAC
secret. There is no configuration to turn that back on. An unknown `kid` triggers
**exactly one** JWKS refetch (key rotation, without letting a crafted `kid` make LabView
hammer the provider). The username comes from `usernameClaim` → `preferred_username` →
`email` → `sub`, and must satisfy `isValidUsername`, because a claim from an identity
provider is still untrusted input.

Every failure redirects to `/?login_error=<code>` with a code from `LoginFailureReason`,
never a raw error string (I6), and the UI validates it against that closed set before
rendering — a crafted `?login_error=` cannot put text on the login screen.

#### Non-goals

No roles or per-user authorization: every signed-in user sees the same read-only
overview, so the provider's own group binding is the whole authorization story. No
trusted-header mode (§2.1). No persistence. No rate limiting beyond the login route. And
no change to any scanning, enrichment or rendering behaviour — this feature adds a gate in
front of the API and touches nothing behind it.

---

## 4. Invariants

Eight rules that outrank convenience. A change that breaks one is wrong even if it
passes every test.

### I1 — Documentation rests on observable evidence

Every statement in the output must trace to a value read from a compose file, an
`.env` file, or the Docker Engine. Not from a name, not from a convention, not
from what is statistically likely.

Where a conclusion cannot be established, the correct output is the weaker,
truthful one — plus a note saying what was missing. `AuthPosture.evidence` exists
so a reader can check the derivation, and `AuthPosture.confidence` exists so they
can tell a fact from a guess without re-deriving it.

The invariant governs **what was observed**, which is not the same as every field in
the output. A *measurement* — `auth.method`, `confidence`, `evidence`, the ingress
tags, `stats.authProtected`, `stats.byAuthMethod` — may never contain anything the scan
did not read. A *verdict* combines measurements with what the operator declared, and
`exposedWithoutAuth` is the one verdict that does: it asks whether anything
authenticates a reachable service, and a declared in-app login is an answer to that
question that no scanner can reach (§3.12). Two things keep this inside the invariant.
The declaration is a separate term of the expression rather than a value written into
`hasEdgeAuth`, so the measurement it stands beside is still exactly what was proved.
And a service that leaves the count on a declaration is *named* as such —
`declared.authAgreement`, its own badge, its own counter, and a note saying the verdict
rests on something unverified — so the weaker, truthful statement is still the one on
screen. What the invariant forbids is a declaration reaching a measurement, and nothing
here does.

**Why a probe may join `hasEdgeAuth` while a declaration may not.** The two look similar from
a distance — both take a service out of the exposed count without naming a mechanism — and the
difference is the whole of this invariant. A declaration is a *claim*: the file says a login
exists, and nothing in the scan can confirm or refute it, so it stays a separate term of the
expression. A probe result is an *observation*: LabView sent the request and read the answer,
which is the same kind of fact as a middleware definition or a router the proxy reports
serving. So it belongs inside the evidence term, and it is the only new term this invariant has
gained that does.

What keeps it inside I1 is the same discipline `unnamed-gate` already keeps. The probe is
counted in its own statistic (`probeGated`) and reported under its own reason
(`probed-gate`), it never touches `auth.method` or `confidence`, and the exposed count with
the probe term dropped is exactly the count a scan with probing off produces — asserted per
service, not only in aggregate, since two offsetting errors would satisfy a total. `probeGated`
is deliberately *not* the number to add back: it counts login pages, and one of them may belong
to a service that was already out of the count on a declaration. A counter of measurements and
a counter of findings removed are different things.

The identity provider's API is itself an observation, and the one place where a
*name* is allowed to establish anything: Authentik's records carry no compose
identifier, so for a service whose gate leaves no trace in any file — an OIDC
application is the standard case — a name is the only bridge that exists (§3.5,
rule 4). Two things keep this inside the invariant rather than outside it. An
ambiguous name resolves to nothing, so no service is ever *assigned* a gate on a
guess. And a tie made by name is reported at `observed` with the wording naming
the weakness, so the reader can tell it from an addressed match without re-deriving
it — which is exactly what `confidence` is for.

### I2 — No fleet-specific identifiers in shipped artifacts

Defaults, doc comments, example configs, UI copy and fixtures use
`example.com`-style placeholders and role words (`<reverse-proxy-host>`,
`<access-group>`). The operator's real fleet is input, never source.

This includes UI copy: a stat tile may say "tunnel route", not "Cloudflare" — the
routes' own labels say which tunnel, and a fleet using none should not be told
otherwise by a hard-coded caption.

It also bounds the one word list in the analyzer, `GENERIC_NAME_TOKENS` (§3.5): protocol
names and English connectives only. No application name, vendor or image belongs in it —
that would be recognising a fleet rather than reading it. `authentik` is absent for the
same reason in reverse: a stack named after the identity provider means that service.

**It bounds the build config too.** `web/vite.config.ts` names a host — the dev
proxy's loopback target — and that is the whole reason `server:` and `build:` are
separate concerns: dev-server configuration never reaches a built artifact. The web
sources read no `process.env` and no `import.meta.env`, so there is no path by which
an operator's environment could be inlined either. A change that reads a `VITE_`
variable in `web/` is a change to this invariant, because such a value *is* baked
into `app.js` at build time.

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

The provider's own API is the one source that settles both questions at once, which
is why an API-confirmed detection outranks every label-derived one. It does **not**
license a new attributed method for every provider type Authentik has: a gate the
model cannot name is reported as `none` *and* excluded from exposed-without-auth,
with the provider quoted as evidence (see the SAML row in §12).

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
- A single container `inspect` failing → that container is skipped, not the scan,
  and the number skipped is counted into the docker connection report as `partial`
  so a systematic failure is visible rather than merely quiet. An **aggregate count
  only** — never a container name (I2).
- Identity provider unreachable, token rejected, request timed out, response
  malformed → `snapshotAuthentik` returns `reachable: false` with the reason in
  `meta.authentik.error`; the scan proceeds on label-derived evidence. A *partial*
  read keeps what arrived and records the rest as an error, so one failing endpoint
  does not discard three good ones.
- Reverse proxy unreachable, no candidate answering, credential rejected, timed
  out, response shape unrecognised → `snapshotTraefik` returns `reachable: false`
  with the reason in `meta.traefik.error` and **no** credential in that text; every
  posture stays exactly as the labels described it. A partial read here is stricter
  than Authentik's: keeping what arrived is fine for reporting, but a chain that
  might be incomplete may not supersede a label, so `chainComplete` gates the
  downgrade (§3.6).

A soft failure is only worth anything if its reason names the fix, so `getJson` in
[enrich/http.ts](labview/src/enrich/http.ts) resolves two reasons that arrive
disguised:

- **A transport failure keeps the code `fetch` hid.** Every transport problem —
  a name that does not resolve, a port nothing listens on, a rejected certificate —
  surfaces from `fetch` as the same `fetch failed`, with the real reason on
  `error.cause`. Those call for opposite fixes, so the `cause.code` is appended:
  `fetch failed (ENOTFOUND)`. The code is a constant, never an address.
- **A 200 whose body is not JSON is an outcome, not a parser bug.** It is also the
  likeliest way an endpoint behind an SSO gate answers, because the login page is
  served with a success status. Reporting the `SyntaxError` verbatim reads as a fault
  in LabView; the message says the body was not JSON and that an HTML login page
  answers exactly like this. The endpoint is *not* treated as an API, so no credential
  follows it.

And a reason is only worth anything if it names the *stage* that failed, because
that is what selects the fix. So every soft failure above also carries a
`ConnectionPhase` and, where there is something useful to say, a hint — the
taxonomy and the three rules that hold it together are §3.10. The floor is that a
degraded scan says which of "the name is wrong", "nothing is listening", "the
certificate is not trusted", "the credential is missing", "the credential is not
allowed here" and "that is not this API" happened. An unrecognised code falls
through to `connect` carrying the raw message, which is still strictly more than
the word *unreachable*.

### I5 — Read-only, least privilege

LabView reads. It never writes to the fleet, never calls a mutating Docker
endpoint, and needs no privileged access:

- Apps root is mounted read-only.
- Docker access goes through a socket proxy with only read endpoints enabled
  (`CONTAINERS`, `NETWORKS`, `VOLUMES`, `IMAGES`, `INFO`, `PING`). Only `ping`,
  `listContainers` and `inspect` are ever called.
- The identity provider API is read with `GET` only, so the documented token is a
  groupless service account with `view_application`, `view_provider` and
  `view_outpost`. A change that needs a write scope, or a scope beyond those three,
  is a change to this invariant and needs the operator's consent, not a wider
  token. Least privilege has a stated cost here rather than a hidden one:
  `/core/applications/` filters its answer by what that account may launch, so the
  recommended token is served a subset. LabView reports the shortfall and rebuilds
  what the providers name (§3.5); it does not ask for superuser to avoid the
  problem, and it does not stay quiet about it either.
- The reverse proxy API is read with `GET` only, and only `/api/version`,
  `/api/rawdata` and `/api/entrypoints`. Traefik's API has no read-only credential
  to scope, which is another reason the recommended setup keeps it on an unpublished
  container-network entrypoint and involves no credential at all.
- **A credential is never sent to an unverified endpoint.** A discovered endpoint
  is probed on an unauthenticated route first and gets the token only if it
  answered as the expected API. For the proxy the bar is higher still: answering is
  enough to be *used*, but not to be *authenticated to* — that needs a hand-written
  URL or proven ownership of the hostname (§3.6). There is deliberately no
  TLS-verification bypass flag: `NODE_EXTRA_CA_CERTS` covers a private CA without
  teaching the tool to trust anything that answers. Both values come from the
  environment and nowhere else; the honest reading of that is in §6 — `docker inspect`
  does expose them, and it needs the Docker socket to do it, which is root-equivalent
  on that host anyway. The exposure worth engineering against is a compose file in a
  repository, which a gitignored `.env` beside it closes.
- **The active probe is `GET /`, and it is the one read that goes to a scanned service**
  rather than to an API LabView was given the address of (§3.6b). So it is the read with the
  least privilege of any of them: no credential is sent — not by omission, but because no call
  path into `getResponse` has one in scope — no redirect is followed, no path or method comes
  from a label, and only a service where HTTP was *observed* is asked anything at all, which is
  what keeps it off a database port. It is also the only integration that defaults to **off**:
  a scan must not start dozens of outbound requests unasked, and to a public hostname those
  requests leave the fleet. A change that gives the probe a credential, a second method, or a
  path from a scanned document is a change to this invariant.
- The image runs as `USER node`.
- **No build tooling in the runtime image.** Vite, the Preact preset and every
  bundled library are `devDependencies`, so `npm prune --omit=dev` in the build stage
  removes them and the runtime stage copies only `dist/`, `web/dist/` and production
  deps. There is no build server, no dev server and no compiler in the shipped
  container — `web/dist` is three static files behind `@fastify/static`.
- **The bundle ships without its sourcemap.** `build.sourcemap` is `false`: the map is
  ~13 MB, it would land in the image, and `@fastify/static` serves whatever is in
  `web/dist` to anyone who asks, pre-sign-in (§7). The dev server keeps its own maps,
  where the tradeoff runs the other way.
- Its own compose example publishes **no `ports:`** — see §7.
- **Its own login is read-only too.** LabView authenticates people; it authorizes
  nobody, because there is nothing to authorize — every signed-in user gets the same
  read-only overview. No route added by §3.13 writes anything outside memory, and the
  only file it reads is the passwd file, under the same containment thinking as the
  rest: a path from the config, size-capped, never followed anywhere. A change that
  adds a *write* to LabView's own state (a user-management route, a persisted session
  store) is a change to this invariant, not a feature.

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

**The probe's own fields are the "equivalent treatment" case, because they come from a
response rather than from the environment.** `maskEnv` cannot help: nothing here has a key
to match. So the reduction is in the reader. `ServiceProbe.endpoint` is an origin and a path
with no credential in it, and `ProbeRedirect.to` — for both the `Location` and the
`<meta refresh>` target — drops the query and the fragment before the value is ever recorded
(§3.6b). That is not neatness: an OAuth hand-off puts `state`, `code` and `redirect_uri` in
the query, a login redirect puts `?next=` there, and a service is free to put anything else
in it. `crossOrigin` beside it carries the only part of the dropped information the verdict
needed. A new field holding anything a scanned service *said* belongs under this rule, not
under `maskEnv`.

LabView's own credentials fall under this too, in three places (§3.13):

- `LABVIEW_OIDC_CLIENT_SECRET` and `LABVIEW_SESSION_SECRET` join
  `LABVIEW_AUTHENTIK_TOKEN` and `LABVIEW_TRAEFIK_PASSWORD` in **`keysAlways`**, for the
  reason already written above that list: a fleet that runs LabView from inside `appsRoot`
  scans its own stack, and editing `keyPatterns` must not be able to expose them. That
  list carries more weight since §6 made the environment the only place the four values
  live: every one of them is now guaranteed to be in a variable LabView may well read
  back out of its own container, and `keysAlways` is what makes that harmless.
- **No password hash, session token or client secret is ever an API field or a log
  value.** A passwd warning names the line, the user and the algorithm, never the hash;
  `/api/session` is unauthenticated and therefore carries no username, no user count, no
  file path and no reason — the detail is in the log, which only the operator reads.
- A login failure reaches the browser as a **code** from `LoginFailureReason`. The
  provider's own complaint, the endpoint it came from and the check that failed go to the
  log.

### I7 — Determinism

Same inputs, same output. `now` is injected into `buildOverview` rather than read
from the clock, stacks are sorted by id, routers are sorted by name, env is sorted
by key, and Docker keys are applied in list order so two containers colliding on a
key do not race. Keep it that way: the smoke test and any future golden-file test
depend on it.

**The web build holds the same line.** Two `npm run build:web` runs over an unchanged
tree produce byte-identical `app.js`, `styles.css` and `index.html` — pinned output
names mean no content hash moves, `sourcemap: false` means no absolute path is
embedded, and nothing in `web/` reads a clock or an environment variable. It is
checkable in one command, which is the only reason to claim it:

```
npm run build:web && shasum -a 256 web/dist/* > /tmp/a && \
npm run build:web && shasum -a 256 web/dist/* | diff /tmp/a -
```

This is also why `buildOverview` has **no logger**. Diagnostics are data: a
connection's outcome is returned on `meta.connections` and the *callers* print it,
exactly as `meta.dockerError` has always worked. A logger threaded into the
pipeline would make the same inputs produce different observable behaviour
depending on who called it, and would put an I/O dependency inside a function whose
value is that it has none.

It is also why the rescan diff (§3.11) lives **outside** the pipeline. Answering
"what changed" needs the previous scan, and a `buildOverview` that remembered its
last result would no longer give the same output for the same inputs. The memory
belongs to the caller: `createScanCache` holds it and hands it to `onBuilt`, and
`diffStacks(prev, next)` is a pure function of two payloads.

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

**And the same rule for an address.** A path out of a scanned document is contained by
`resolveContained`; an *address* out of one is contained by `probeTargets` (§3.6b), which is the
only place a scanned document can put a URL LabView will request. Everything downstream of it is
bounded before a request goes out: `GET` only, no credential on the call path, no redirect
followed, a per-service cap on addresses, a body read only when it is HTML and only to a cap.
The second request the probe may send is the one place this rule had to be restated rather than
inherited, and it is why `stateTargets` takes its paths from a constant list and its origin from
the address that already answered: nothing on the page decides where the next request goes. A
future signal that wanted to follow something *found* in a response would be asking for the
containment this invariant exists to refuse.

The passwd file is not contained the same way, and the difference is the point: it is a
path from LabView's *own* config, not from a scanned document, and it is meant to sit at
`/config/passwd` — outside the apps root by design. What replaces containment there is
that nothing scanned can influence it (see below), plus a size cap, an entry cap and a
refusal to follow anything but a regular file (§3.13).

**The gate never consults scanned data.** This is a new rule and belongs beside I8 rather
than inside §3.13, because it is a constraint on future changes anywhere in the codebase:
no decision in `src/auth/` or `src/server/auth.ts` may read an `Overview`, a compose
document, a container label or an API response about the fleet. The reason is direct — the
scan's whole input is untrusted (§7), so a gate that read it would let a compose file in
`appsRoot` participate in deciding who may see `appsRoot`. It also keeps the two halves
independently assertable: the gate is a function of config, the request and the clock, and
smoke drives it with no fleet at all. The one apparent exception is not one: `/api/overview`
is *behind* the gate, so the payload is produced only after the decision.

---

## 5. Definitions

**Stack** — one immediate subdirectory of `appsRoot` containing a compose file.
Its directory name is its id and its default compose project name.

**Service** — one entry under `services:` in a stack. Identified in the graph as
`svc:<stack>/<service>`; matched to a live container by
`com.docker.compose.project`+`service` labels first, then by container name.

**`ports:` vs `expose:`** — two different reachability claims, and both are read.
`ports:` publishes on the host, so it is `lan`; `expose:` does not publish
anything, it only records that the container listens, so it is `internal`. Any
entry under `ports:` counts, including the short form with no host side
(`ports: ["9100"]`), which still publishes — on an ephemeral host port. So for
both keys the *presence* of an entry is the signal, never a parsed port number.

**IngressKind** — the network situations a fleet distinguishes. Five values,
**independent**, ordered most → least exposed in
[model/ingress.ts](labview/src/model/ingress.ts):

| Kind | Evidence |
|---|---|
| `public` | a Cloudflare tunnel route with a hostname |
| `traefik` | a Traefik route with hosts or a rule |
| `lan` | `ports:` is non-empty — published on the host |
| `internal` | `expose:` is non-empty, **or** `realNetworks()` shares a name with another scanned service — **and** none of the three above holds |
| `none` | none of the above |

**A service carries a set, not a value.** `svc.ingress` is `IngressKind[]`, and a
container behind the tunnel, behind the proxy and with a published port is all three
things at once — each separately true, each its own tag. `internal` is the one
exception: `normalizeIngress` withholds it from any set that already carries `public`,
`traefik` or `lan`, so `svc.ingress` answers *is a neighbour the only way in* rather
than *can a neighbour get in* (§12). A stack carries the union of its services',
built by `rollUpIngress` — the one place that withholding must **not** apply, since a
stack is not a service and a public frontend beside an internal-only database is
genuinely both. Nothing combines two kinds into a third; the only function that picks
a winner is `primaryIngress`, and it exists solely because a graph node has one fill
colour.

**`realNetworks`** — the networks a service is demonstrably on, and what makes
`internal` positive evidence rather than a leftover bucket (§12). It materializes the
implicit `default` network, resolves `${project}_${key}`, and honours `external:`
under its verbatim name, so two services in one file are mutually reachable without
either declaring a network, and two *stacks* on one external network are too.
`depends_on` is deliberately **not** evidence — a dependency across two disjoint
networks is not reachability. With neither a shared real network nor an `expose:`, the
answer is `none`, which is a populated category rather than a curiosity.

Every question about a set goes through
[model/ingress.ts](labview/src/model/ingress.ts) rather than being asked inline,
so five callers cannot drift apart: `normalizeIngress` is the only constructor
(deduped, canonically ordered, never empty, `internal` only when alone),
`isExternallyReachable` is the single
definition of "someone outside the container network can answer" — used by both
`exposedWithoutAuth` and the stale-acceptance check — `externalIngress` narrows a
note to the kinds that make it reachable, and `diffIngress` reports a sidecar
disagreement in both directions.

**NetworkIndex / NetworkMembership** — the one fleet-wide membership index, built once
over `realNetworks` in [analyze/networks.ts](labview/src/analyze/networks.ts):
`byName` gives each real network its `members` (`stack/service`, scan order), the
distinct `stacks` among them and whether any stack declares it `external:`; `byService`
gives the reverse. The same relation used to be computed three times — `sharedNetworks`,
`FleetIndex.netsByKey` and the graph's own map — so all three now read this, which is
what makes the `internal` ingress rule and the connections the graph draws provably the
same relation. Passed as an optional trailing argument to `buildFleetIndex` and
`buildGraph`; both still build their own when called without one.

**NetworkScope** — `external | stack-local`, on a `network` graph node. Not a severity:
it says who *can* be on the network. A `stack-local` network is created by one compose
project, so only that project's services can ever join it; an `external:` one can carry
several stacks, and containers this scan never saw. It is the reason a single-member
network is sometimes worth drawing and sometimes not (§12), and both scopes' wording
lives in `NETWORK_SCOPES` in [model/networks.ts](labview/src/model/networks.ts).

**`memberCount` / `stackCount`** — on a `network` node: how many *scanned* services are
attached, and how many distinct stacks they come from. Counted on the node rather than
left to be inferred from the spokes beside it, because the spokes are capped — a reader
counting lines on a node that joins fifty services would be reading a number that is not
there. Neither counts what the scan cannot see, per I1.

**`flow`** — on a `network` edge, where the dependency arrowhead sits:
`to-network` when this service is the dependent, `to-service` when something else on that
network depends on it, `both` when both are true, absent for plain membership. This is
how a dependency is drawn *through* the network rather than beside it — following the
arrowheads reads dependent → network → dependency, and a service in the middle of a chain
carries one leg with an arrowhead at each end. **Absent is the common case and means
exactly one thing: this service is on the network and nothing crosses it.**

**`flowSource`** — on a `network` edge that carries `flow`: `observed | declared | both`,
where the arrowheads came from. It exists so a fleet graph cannot present a statement as a
measurement (I1): the arrowhead is the same shape either way, so the line is dashed when
every dependency crossing that leg was declared. `both` stays solid — something crossing it
*was* read from a compose file, and a solid line then understates nothing.

**`declaredBy`** — on a `depends_on` edge, the sidecar that stated it: the `file` and the
optional `detail` the operator wrote. Absent on an edge read from a compose file, which is
what every renderer tests to decide between dashed and solid. It is on the edge and not in
`svc.declared` on purpose (§3.7): the declaration holds the reference as written, the edge
holds what it resolved to.

**`via`** — on a `depends_on` edge, the real networks the pair shares, in the dependent's
compose order. Non-empty is the normal case and means the edge is **not** drawn directly
(`showsDirectDependency`); the relation is already visible as `flow` on the two membership
edges either side, and a direct line beside that would state it twice while hiding the
network that carries it. Empty means compose orders the two containers' startup yet
neither can address the other — the direct edge is then the only honest drawing, and the
analyzer also states it in words on the dependent's `notes`.

**NetworkRelation** — `depends-on | required-by | peer`, what one service is to another
*across a named shared network*. A dependency counts only over a network in its `via`, so
a service depending on a sibling over the stack's own network is not reported as depending
on it over an unrelated external network they also both join. The first two are relations
between two services; `peer` is not a third one but the **absence** of a relation — a
co-member, reachable and no more — which is why nothing is ever labelled with it: it is
vocabulary for the member wording, never for a chip or a diagram leg, and no function
returns it. The connection a `peer` would once have drawn now has to be stated: that is what
the sidecar's `depends_on` is for (§3.12).

**DeclaredServiceDependency / ResolvedDependency** — the two halves of one fact, kept apart.
`DeclaredServiceDependency` is what the sidecar wrote — a `ref` string exactly as typed,
plus an optional `detail` — and it is stored unresolved, because the parser cannot see the
other stacks and because this is the object a rescan compares (§3.11). `ResolvedDependency`
is what step 6b made of it: `from`, `to`, the `file` it came from, the `detail`, and `via`
from the same `sharedWith` helper the compose edges use. One is input, the other a
conclusion; nothing merges them.

**`NetworkLink.dependencies` / `.reachableCount`** — a service's view of one network, split
by whether anything actually crosses it: a list on one side, a number on the other.
`dependencies` carries a `DependencyRelation` and, when declared, the file that said so;
`reachableCount` is how many other scanned services are attached with no dependency either
way, and it holds **no names**, not even truncated ones. One mixed list is what let thirty
members of a proxy network render as thirty connections; a second list beside the first is
that claim in quieter type, because twelve arbitrary names out of fifty-three, in chips
identical to the dependency chips, are read as this service's connections and say nothing
about this service at all. A count cannot be misread that way and has nothing to truncate.
The names are answered by `networkGroups`, under the network's own heading, which is the
scope the question belongs to.

**MAX_GRAPH_SPOKES / MAX_DRAWER_PEERS / MAX_LIST_PEERS** — `12 / 8 / 12`. The fleet graph
caps spokes per network node; the drawer caps **dependencies** per network at
`MAX_DRAWER_PEERS`, which is the only list it has; `MAX_LIST_PEERS` caps the member chips
the fleet Networks section draws before a row is expanded, and reaches the drawer nowhere.
`visibleSpokes` keeps dependency-carrying spokes first, for the reason the drawer names only
dependencies at all: a leg in a diagram costs more than a co-member does, and anything that
lets merely-reachable services compete for the space crowds a real dependency out of the
picture. All of them report what was left out, and `networkNodeLabel` puts `+k not drawn` on
the node.

**`declaredDependencies`** — the `OverviewStats` counter beside the four other declaration
counters: `depends_on` references that resolved to an edge. Resolved, not written, so it
counts what is drawn; the references that failed are already in `declarationDrift` and need
no counter of their own.

**`networks` / `connectingNetworks` / `crossStackNetworks` / `soloLocalNetworks`** — the
four `OverviewStats` network counters: real networks, those with 2+ services, those
spanning 2+ stacks, and stack-local ones with a single service. The last is *exactly* what
the fleet graph omits, which is what lets smoke assert that drawn network nodes plus
`soloLocalNetworks` equals `networks` — an omission that is checkable rather than trusted.

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
origin resolved to, or on the service whose Traefik API answered. It stays an
ordinary service node (same kind, same drawer, same click target); the role only lets
the UI colour it as infrastructure. Nothing else reads it, and no service is ever
*declared* a proxy — the role is a consequence of having been resolved as a hop at
least once, or of having answered as the proxy's own API.

**AuthMethod / AuthConfidence** — see §4 I3. Three levels, strongest first:
`confirmed` means the identity provider's API reported the gate *and* named the service
it belongs to; `observed` means a value in the scanned config states it, or the API
reported the gate but could only tie it to the service by name
(`AuthentikMatchStrength`); `inferred` means the method rests on a middleware *name*
because no definition was found in any scanned stack, and it also produces a service
note saying so. When two accounts of one service disagree, the higher rank is reported
and the lower is kept in `evidence`.

**AuthentikMatch / AuthentikApplication / AuthentikProvider** — what the provider's
API said about a service, attached as `svc.authentik` (§3.5). Its three arrays are
parallel — index `i` of `applications`, `evidence` and `strength` describes the same
match. `evidence` records *why* the application was tied to this service, so a wrong
match is visible rather than silent. A provider carries `kind` (normalized), `rawKind`
(Authentik's own `verbose_name`, so an unmodelled provider type is still readable),
`backchannel`, and `outposts` — the names of the outposts serving it, empty when none
is.

**`discoveredVia`** — on `AuthentikApplication`: `"list"` when the applications
endpoint returned it, `"provider"` when that endpoint withheld it and LabView rebuilt it
from a provider naming it (§3.5). The value is what the `considered` trace, the drawer's
`rebuilt` tag and `applicationsRecovered` all rest on.

**applicationsConfigured / applicationsWithheld / applicationsRecovered** — on
`AuthentikSummary`, the arithmetic of what the applications endpoint did *not* return
(§3.5). `applicationsConfigured` is its own `pagination.count`, optional because an
endpoint may report no count at all; `withheld` is that minus what was listed,
`recovered` is how many of those a readable provider let LabView rebuild, and
`applications` is listed **plus** recovered. The remainder, `withheld - recovered`, is
derived where needed rather than stored, so the four numbers cannot disagree.

**AuthentikMatchStrength** — `"address" | "hostname" | "name"`: what kind of thing
established the tie, per match. An *address* is the provider pointing at the service; a
*hostname* is one name both sides declare independently; a *name* is only that the
operator chose similar words on each side. It sets the reported confidence (§3.5).
Absent is treated as `name`, the weakest reading, never the strongest.

**Enforcement vs existence** — a provider existing is not a gate existing.
`providerEnforces` decides: proxy/ldap/radius need at least one outpost, oauth2 and
saml are served by the Authentik server, scim gates nothing at all. An application
whose only provider enforces nothing leaves the service reported as unprotected,
with the reason on the service. `hasEnforcedAuthentikGate` is the separate question
of whether *any* enforced gate was confirmed, and it is what keeps a protected
service out of `exposedWithoutAuth` even when its provider type has no
`AuthMethod`.

**UnmatchedApplication** — an application the matcher could not tie to exactly one
service, in `meta.authentik.unmatchedApplications`. Carries the whole
`AuthentikApplication`, an `UnmatchedReason`, a one-line `detail`, and a `considered`
trace. Ambiguity is reported, never arbitrated (§12).

**UnmatchedRouter** — the same for a live router, in `meta.traefik.unmatchedRouters`,
carrying the whole `TraefikLiveRouter`. Because such a router demonstrably *exists*, it
must never produce a "declared but not live" note on anybody.

**UnmatchedReason** — `"ambiguous" | "no-candidate" | "internal"`. Not a severity but a
statement about who can act (§3.5): `ambiguous` means the evidence pointed at more than
one service and was discarded, which one distinct name fixes; `no-candidate` means
nothing pointed anywhere, usually LabView's gap to explain; `internal` is defensive
only — a matcher named a service key the scan does not hold.

**`considered`** — one line per matching rule tried and what it produced, in the order
tried: the same evidence discipline as `AuthPosture.evidence`, applied to the case that
failed. What each rule owes the trace is in §3.5; the constraint is that it carries only
what the payload already holds and never an env value (**I2**, **I6**), which smoke
asserts.

**TraefikRoute vs TraefikLiveRouter** — same subject, different source, and the
distinction the whole of §3.6 rests on. `TraefikRoute` is what the compose labels
asked the proxy for. `TraefikLiveRouter` is what the proxy built from them, plus
whatever it built from providers the scan cannot read: `status` and `errors` as
Traefik reports them, the `hosts` parsed out of its `rule`, its `entryPoints`, the
**fully resolved** `middlewares` chain, the Traefik service it targets with that
service's `servers`, and an `evidence` list saying how the router was tied to this
service. Attached as `svc.traefikLive`; absent when the API was not read or nothing
matched.

**TraefikLiveMiddleware** — one entry of a resolved chain. `type` is the middleware
type as Traefik keys it, taken from the definition Traefik *holds* — which is why a
file-provider middleware is knowable at all, and why a type LabView has never
modelled is still reported by name. `address` carries a forward-auth's delegate.
`viaChain` names the `chain` middleware this entry was reached through; `viaEntrypoint`
marks a middleware attached to the router's **entrypoint** rather than named by the
router. That flag exists because such a gate appears in no router's own list, so it
must be merged in before any conclusion about a *missing* gate can be drawn.

**TraefikLiveServer** — one backend URL plus the `serverStatus` Traefik last observed
for it, when it reported one. Absent status means "nothing known" and must not be
read as healthy.

**`chainComplete`** — `TraefikSummary.reachable && entrypointsRead`: the single gate on
the downgrade, and the reason a partial read changes no posture (§3.6).

**`credential: "none" | "basic"`** — which credential the successful read needed.
`none` means the API answered unauthenticated, which is direct evidence about how the
proxy's API is exposed on that network and is reported as a note on the proxy service
rather than inferred from config.

**`name@provider`** — how Traefik itself names a router, and how LabView reports one
(`qualifyRouter`). The provider half is not decoration: it says whether the route came
from a container label or from operator-written file configuration, which is what
decides whether the router-name matching rule may be applied to it at all (§3.6).

**`detail` vs `evidence` vs `notes`** — `detail` is the prose summary of the
primary detection plus any secondary ones; `evidence` is the flat list of raw
signals (`middleware x`, `env OIDC_ISSUER`, `forwardauth -> …`,
`provider not identified from the scanned config`); `notes` are per-service
warnings for a human (bypasses, refusals, unresolved references, inferences).

**`exposedWithoutAuth`** — `isExternallyReachable(svc.ingress)`, no auth detected
(proxy gate, OIDC/LDAP, basic-auth, a Cloudflare Access policy, or an API-confirmed
enforced gate), **and** nothing declared in the sidecar beside the compose file. Note
this counts a `lan`-only service as exposed, because it is — the LAN is outside the
container network, and nothing gates the published port.

A **verdict**, not a measurement, and the only field in the model where a declaration is
a term (§4 I1, §3.12). `hasEdgeAuth` stays evidence alone, and a service that leaves the
count on the strength of a declaration is counted in `stats.declaredAuthProtected` and
says so on its own face.

The test is `isExternallyReachable` and not "does the set contain `internal`", even
though the two agree on every service the classifier produces. Asking its own question
of its own three kinds means a change to the withholding rule cannot quietly redefine it,
and a sixth kind added later has to opt in rather than be counted safe by omission. It
lives in [model/ingress.ts](labview/src/model/ingress.ts) so this definition and the
stale-acceptance check (§3.12) cannot disagree about the same service.

**`NoAuthReason`** — which of four different things it means that `auth.method` is
`none`, and the only place the absence of a mechanism is put into words. Derived rather
than stored: `noAuthReason` in [model/auth.ts](labview/src/model/auth.ts) reads
`(method, exposedWithoutAuth, ingress, declared.auth)` and returns `undefined` the moment
a mechanism was detected, so nothing downstream has to re-derive the distinction.

| Reason | The service is | Wording |
|---|---|---|
| `gap` | `exposedWithoutAuth`: reachable from outside the container network, no gate of any kind detected, nothing declared | `No proxy auth`, styled as a finding |
| `not-reachable` | `internal` only, or has no ingress at all | `None expected` |
| `declared` | reachable, and its sidecar names a mechanism this scan cannot see | `Declared, not detected` |
| `unnamed-gate` | reachable, nothing declared, and yet not exposed — so a gate was confirmed that carries no `AuthMethod` (an API-confirmed enforced gate) | `None named — gate confirmed` |

A gate is only *expected* in front of something answerable from outside the container
network, so **only `gap` is a finding** — and `gap` is exactly `exposedWithoutAuth` above,
read through rather than re-decided, so the two can never disagree. The other three are
answers given only where the question was asked: the drawer's `Method` row, where a blank
beside the label would read as missing data. `showsAuthMethod` is the same rule for the
badge rows, which carry mechanisms only and render nothing at all where there is none
(§3.12, §12). The `none` bucket of `stats.byAuthMethod` is untouched by any of this — it
is a count of a categorical field, and its palette label says `None detected`, so the
finding's wording exists in exactly one place.

**Middleware registry** — every `traefik.http.middlewares.<name>.<type>` label
found in *any* stack, keyed by bare name (references carry a `@docker` /`@file`
provider suffix that is stripped). On a name collision an auth type wins over a
non-auth type, so a `headers` middleware cannot shadow a `forwardauth` one.

**Hint** — a string that identifies the SSO provider, either configured
(`labels.authentik.hostHints`) or discovered (§3.3). Matched at token boundaries
against forward-auth addresses, issuer URLs and LDAP hosts.

**ConnectionPhase** — how far an outbound read got, one vocabulary for every
target (§3.10). `disabled` and `not-configured` are outcomes, not faults: nothing
was attempted. `not-found` and `credential` are the two cases that stop before the
network: the read was asked for and discovery identified no candidate at all, and a
credential was asked for and arrived empty — its variable is set and carries nothing,
which since §6 made the environment the only source means an unresolved `${…}` in a
compose file far more often than
anything else. Both are faults — a half-finished configuration will never work — which
is what separates them from `not-configured`. The distinction is only observable in
`applyEnvOverrides`, which is why it is carried forward in `blankCredentialVars` rather
than recomputed: by the time a reader holds the config, an empty token and an unset one
are the same empty string. Then the transport stages `resolve`, `connect`,
`tls`, `timeout`; the answer stages `authenticate` (401), `authorize` (403), `path`
(404/405), `status` (any other non-2xx), `protocol` (answered, but not with this
API); and finally `partial` — connected, part of the read failed — and `connected`.
The set is closed, and adding a member is a UI change for the same reason
`AuthMethod` is (§3.7): `phaseText` in
[model/connections.ts](labview/src/model/connections.ts) maps each one to prose.

**ConnectionReport** — the per-target outcome carried on `meta.connections`:
`target`, `ok`, `phase`, the `endpoint` reached and whether that endpoint came from
`config`, was `discovered` or is the built-in `default`, a one-line `detail`, a
`hint` naming what to change, `read` describing what arrived when it worked
(`"86 containers"`, `"Traefik 3.1.2, 10 routers, 5 middlewares"`), and the
`attempts`. `source` is worth reporting on its own: "LabView is using the default
socket path and you meant to configure a proxy" is a real mistake, and only
`default` shows it.

**ConnectionAttempt** — one candidate that was tried: its credential-free
`endpoint` (`safeOrigin` output), the `why` discovery offered it, and the `phase`,
`code` and `detail` it failed with. Retained on successful reports too, so the
endpoints walked past are visible. `code` is a constant — a libuv code, a TLS code
or an HTTP status — never an address (I2), and no `detail` may carry a credential
(I6); both are asserted.

**ScanDiff** — what one rescan found, relative to the scan before it. Not part of
the API payload: it is derived locally by whoever holds both scans, in
[model/changes.ts](labview/src/model/changes.ts) (§3.11). `added` and `removed`
name each stack with how many services came or went with it, `changed` carries one
`StackChange` per stack that moved, `stacks` and `services` are the totals after
this scan — for the line that reports no change — and `unchanged` is the three
being empty.

**StackChange** — one stack that exists in both scans: `servicesAdded`,
`servicesRemoved`, `servicesChanged` by name, and `stackChanged` for an edit to the
stack itself (compose filename, project name, declared networks or volumes, parse
warnings). Service tallies count only stacks present in both scans; the services of
a stack that was just added are already accounted for by the stack.

**IntegrationDiff** — the other half of the same rescan: what the Authentik and
Traefik reads came back with. Also derived locally, also not in the payload. One
`IntegrationChange` per target read in either scan, in the order LabView reads them,
and `unchanged` when every entry is — including when there are none, because an
integration nobody switched on is not a status. Reported beside `ScanDiff` and never
folded into it (§3.11).

**IntegrationChange** — one target: `state` is `unchanged`, `moved`, `started` or
`stopped`, decided from `reachable` on both summaries *before* any count is
compared. `counts` holds the signed deltas and is empty for anything but `moved`
(§3.11). `appeared` and `disappeared` name the records that came and went —
application slugs, router names — sorted.

**Declaration / ServiceDeclaration** — what the operator wrote in a `.labview`,
attached as `stack.declared` (the shared fields) and `svc.declared` (those plus the
service-only ones) — see §3.12. Every field is optional and none of them is evidence,
which is why they live in their own object rather than in the fields the scan produced
(§12). `file` is the sidecar's name and never a full path, so a declared value is always
attributable to the file that claimed it without leaking the layout of the host — which is
also what lets a dependency chip in another stack's drawer name where the claim came from.
Every field is shown as written; `dependsOn` is the only one whose *contents* are looked up,
and even that resolves onto the graph rather than into this object (§3.7).

**DeclaredAuth** — `{ mechanism, detail? }`, where `mechanism` is one of
`DECLARED_AUTH_MECHANISMS`: authentication the operator states the app performs for
itself. Counted in `stats.declaredAuth` and badged *declared*; it never becomes
`svc.auth.method`, and `other` requires a `detail` (§3.12).

**AuthFamily** — `oidc | ldap | proxy`: the three mechanisms *both* vocabularies can
name, and therefore the only ground on which a declaration and a detection can be
compared at all. `DECLARED_FAMILY` and `DETECTED_FAMILY` are `Partial` — most members of
either vocabulary have no family, which means *not comparable* — and `FAMILY_LAYER` sorts
the three into the app's own login (`oidc`, `ldap`) and a gate in front of it (`proxy`),
so a comparison is only ever made within one layer (§3.12).

**DeclaredAuthAgreement** — `supplies | conflicts | redundant | supplements`, the
outcome of `compareDeclaredAuth`, stored on the declaration by the analyzer and
`undefined` when nothing was declared. One value rather than three booleans because it
decides three things at once: whether the service left the exposure count, whether a
drift entry was written, and whether the declaration is rendered at all. The four
outcomes and their effects are tabled in §3.12.

**`declaredAuthProtected`** — services with `authAgreement === "supplies"`: reachable,
nothing detected, and taken out of the exposure count by a declaration. Read off
`authAgreement` rather than recomputed, so the counter and the badge cannot disagree.
Never folded into `stats.authProtected`, which counts only what the scan could prove
(§12).

**`declaredAuthUnconfirmed`** — a **subset** of the above: those of them the login probe
reached and could not settle either way. Two questions, and one number cannot answer both —
*how much of my fleet's protection is unproven* is the counter above, *which of my sidecars
should I go and check by hand* is this one. Counted off `declared.unconfirmed.length` rather
than re-derived, and deliberately not an alarm: it is what the same observation used to be
reported as drift for, and why it no longer is, is in §3.12 and §12.

**`unauthenticatedAccepted`** — `{ reason }` on a service declaration, present only
when the sidecar said `intentional: true` **and** gave a reason; without the reason it is
refused with a warning (§3.12). It does not remove the service from `exposedWithoutAuth`;
it adds it to `stats.exposureAccepted` and puts the reason on the finding. Distinct from
a declared mechanism, which says a login *exists* and does remove the finding.

**`formatExposureCount`** — `23/28` when some exposures are accepted, plain `28` when
none are. Shared by the tile and the CLI, and the numerator is the *unaccepted
remainder* (§3.12).

**`expectedIngress`** — the sidecar's `expected.ingress`, normalized to
`IngressKind[]`. A list because the thing it is compared against is one: expecting
`[public, traefik]` and finding `[public, lan]` is a disagreement about the proxy, and
comparing only the first kind would report "expected public, got public". Normalized
through `normalizeIngress`, the same constructor the classifier uses, so a declared
`internal` written beside an external kind is dropped instead of drifting against a rule
the file cannot know about (§12).

**`drift`** — `svc.declared.drift[]`, one string per disagreement between the sidecar
and the scan, counted in `stats.declarationDrift`; the four checkable disagreements are
enumerated in §3.12. Filled by the analyzer, and a report rather than an override —
which is why it and `authAgreement` are excluded from the change comparison (§3.11).

**`unconfirmed`** — `svc.declared.unconfirmed[]`, the same shape and the opposite meaning:
one string per question the scan asked and could not settle, which today is exactly the
probed-and-no-gate case in §3.12. Kept as a sibling of `drift` rather than merged into it
because only one of the two is a warning, and as a sibling of `authAgreement` rather than a
fifth member of it because `compareDeclaredAuth` cannot see the probe by design. Also
analyzer-written, so also excluded from the change comparison — and the most volatile of the
three, since it turns on whether a probe ran at all: without the exclusion, a scan with the
toggle flipped would report every declared service in the fleet as an edited sidecar (§3.11).

**TagFilter / TagMode** — the dashboard's tri-state filter (§3.9):
`{ include, exclude, mode }` over string tags, with `exclude` always AND-NOT and
`mode` switching `include` between OR (`any`) and AND (`all`). Lives in
`model/filter.ts` rather than in the UI so its semantics are assertable (§8).

The rest of §5 is LabView's **own** access control (§3.13), which shares no vocabulary
with the `AuthMethod` union above: that one describes how a *scanned service*
authenticates its visitors, this one describes how *LabView* authenticates its own. The
overlap is a hazard, not a relationship — see the naming note opening §3.13.

**LoginMethod** — `passwd | oidc`. How a session was obtained, and equally which
mechanisms a visitor may choose from. Deliberately not `basic` in any spelling, so a
grep for LabView's own login can never land on a scanned service's `basic-auth`.

**AccessMode** — `{ enforced, methods, notes, summary }`, the answer to "is the surface
gated, and by what". Returned by `resolveAccessMode` from config plus the parsed passwd
state, and re-resolved on a short TTL rather than captured at startup so that adding the
first user to the passwd file switches enforcement on without a restart. `enforced` is
`methods.length > 0`: there is no separate switch, because a switch that could be on
with no usable method is a lock-out (§3.13).

**`enabled` (in `auth.*`)** — *allowed*, not *on*. `auth.passwd.enabled: true` with no
readable file leaves the method dead and writes a note; `false` means the file is never
read at all. The same distinction the `authentik` and `traefik` blocks use, kept because
an operator who has configured one integration should not have to learn a second rule.

**`notes` (on AccessMode)** — why a method that is switched on is not live: no passwd
file, no usable entry in it, an issuer with no client id. Counts and conditions only, and
the only shape in which they reach a browser is `/api/session` — which is readable
without a session, so a note may never name a path, a username or a reason for a specific
failure (I6, §3.13).

**SessionInfo** — the `GET /api/session` body: `{ enforced, methods, user?, oidcLabel? }`.
What a visitor needs to choose a method and what a signed-in browser needs to draw
"signed in as …", and nothing else — no counts, no notes about a *particular* user, no
paths. `user` is `{ name, via }`; its absence while `enforced` is what makes the SPA
render the login card instead of the overview.

**LoginFailureReason** — the eight codes `credentials`, `throttled`,
`method-unavailable`, `session-expired`, `oidc-state`, `oidc-provider`, `oidc-token`,
`oidc-identity`. A closed union rather than a message because a failure crosses two
boundaries: a JSON body from `POST /api/login`, and a `?login_error=` query parameter on
the OIDC redirect. The wording lives in `LOGIN_FAILURE_TEXT` in `model/access.ts`, so the
browser renders text the server never composed — which is how an upstream provider's
error string is kept out of the page (I6). `credentials` is one code for both an unknown
user and a wrong password, on purpose.

**`loginFailureText` / `parseLoginFailure`** — the two directions across that boundary.
`parseLoginFailure` accepts only a member of the union and returns `undefined` for
anything else, so `?login_error=<attacker's sentence>` cannot be reflected into the login
card.

**`isValidUsername` / `sanitizeUsername`** — `USERNAME_RE = /^[A-Za-z0-9._@-]{1,64}$/`,
and the fallback `"?"`. Every username is validated at each of the three places one can
enter — a passwd line, a login form, an OIDC claim — and sanitized before it reaches a
log line, so neither a crafted passwd file nor a provider claim can inject a newline into
the log or an identifier into an artifact (I2).

**`accessModeSummary`** — the one-line startup summary, in `model/access.ts` beside
`formatConnection` and `formatRescan` for the same reason: the log line and the UI must
not drift. Reports counts and the issuer host, never usernames (§3.13).

**Passwd entry** — `user:hash`, the hash self-identifying its algorithm through its
modular-crypt `$id$` prefix exactly as `/etc/shadow` and `htpasswd -nbB` do it. Only
`$2a$`/`$2b$`/`$2y$` are honoured; any other `$id$` is skipped with a warning naming the
**id alone**, and a line with no `$` is skipped rather than treated as a plaintext
password. Duplicates are first-wins (§3.13).

**`unreadable(path, code)`** — `readPasswd`'s four distinguishable read failures
(`ENOENT`, `EISDIR`, `EACCES`, over-size) as one shape, because the operator's next
action differs for each and "could not read the passwd file" would not tell them which.
`EISDIR` gets its own message: a `:ro` bind whose host file did not exist before `up`
makes Docker create a directory there, and that is the most likely first-run failure.

**Decoy hash** — the bcrypt hash an unknown username is compared against, so that a
missing user costs the same as a wrong password and enumeration learns nothing from
timing. Generated lazily from `randomBytes(32)` per cost and memoized, never a committed
constant: a constant in the repository is a published verifier that also tells anyone
reading the source which comparison path they are on.

**LoginThrottle** — failed sign-ins per **username**, case-folded, with `now` injected.
Keyed on the name rather than the address because behind a tunnel and a reverse proxy
every request shares one source address, so address keying would let one wrong password
lock out the fleet. Exceeding `maxFailedAttempts` within `lockoutSeconds` answers `429`
with `Retry-After` whether or not the password was right (§3.13).

**Session token** — `v1.<b64url(payload)>.<b64url(hmac-sha256)>` over
`{ u, via, iat, exp, jti }`. Signed, not encrypted, because nothing in it is a secret —
what must be impossible is *changing* it. Checked shape → MAC → expiry → revoked, in that
order, with the expiry deliberately after the signature (§3.13). There is no session
store; the only server state is the bounded revocation set, so signing out invalidates
the token rather than merely dropping the browser's copy.

**`safeEqual`** — a constant-time compare that hashes both sides first, so it tolerates a
length difference without leaking one. Used on the MAC, where the width is fixed anyway,
and on the OIDC `state`, where it is not.

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
| `LABVIEW_SIDECAR_FILENAMES` | `sidecarFilenames` | comma-separated; the declaration sidecar's candidate names in probe order, defaulting to `.labview`, `.labview.yml`, `.labview.yaml`. First that exists wins (§3.12) |
| `LABVIEW_DOCKER_HOST` / `DOCKER_HOST` | `docker.host` + `port` | `tcp://host:port`, `host:port`, `unix:///path` or `/path`. A socket form clears `host`. `LABVIEW_DOCKER_HOST` wins, being the more specific of the two |
| `LABVIEW_DOCKER_SOCKET` | `docker.socketPath` | always wins and disables the TCP host |
| `LABVIEW_DOCKER_ENABLED` | `docker.enabled` | `false` = config-only scan |
| `LABVIEW_DOCKER_MAX_CONCURRENCY` | `docker.maxConcurrency` | bounded `inspect` fan-out; raise for big fleets, lower if the proxy drops connections |
| `LABVIEW_DOCKER_TIMEOUT` | `docker.timeoutMs` | socket **inactivity** per request, not total time, so a large fleet's listing is unaffected. It exists so an endpoint that accepts and then says nothing becomes a reported `timeout` (§3.10) instead of a scan that never finishes |
| `LABVIEW_MASK_SECRETS` | `secrets.maskValues` | leave on |
| `LABVIEW_CACHE_TTL` | `cacheTtlSeconds` | |
| `LABVIEW_PORT` / `LABVIEW_HOST` | `server.port` / `host` | |
| `LABVIEW_BUILD_SHA` | — | which commit this build came from, baked in at image build time (`--build-arg`). A full object id is shortened to seven, anything else is used as given, and unset falls back to the checkout LabView is running from and then to reporting no revision at all (§3.7). **Env-only**, see below |
| `LABVIEW_AUTHENTIK_TOKEN` | `authentik.token` | unset = step 7 makes no request at all; set and empty = a `credential` fault (§3.10) |
| `LABVIEW_AUTHENTIK_URL` | `authentik.url` | skips discovery entirely; needed only when the provider is outside `appsRoot` |
| `LABVIEW_AUTHENTIK_ENABLED` | `authentik.enabled` | `false` = never contact the provider |
| `LABVIEW_AUTHENTIK_TIMEOUT` | `authentik.timeoutMs` | per request; `authentik.maxPages` bounds pagination and is file-only |
| `LABVIEW_TRAEFIK_URL` | `traefik.url` | skips discovery, and is one of the two things that make an endpoint eligible for a credential (§3.6) |
| `LABVIEW_TRAEFIK_USERNAME` | `traefik.username` | an Authentik user, or the reserved `goauthentik.io/token`. Only for an API behind a gate |
| `LABVIEW_TRAEFIK_PASSWORD` | `traefik.password` | an **app password**, not an API token. In `secrets.keysAlways`, so LabView scanning its own stack cannot print it. Set and empty = a `credential` fault |
| `LABVIEW_TRAEFIK_ENABLED` | `traefik.enabled` | `false` = never contact the proxy. Unlike Authentik this stage is on by default, because it needs no credential |
| `LABVIEW_TRAEFIK_TIMEOUT` | `traefik.timeoutMs` | per request; the whole exchange is three GETs and is not paginated |
| `LABVIEW_PROBE_ENABLED` | `probe.enabled` | the **default**, not the authority: it decides what a startup scan and every timer rebuild do, and `POST /api/rescan` can override it either way for one build (§3.6b). Any value other than `false` turns it on, because a variable someone set to `0` meaning "off" is the rarer mistake than one set to `yes` meaning "on" |
| `LABVIEW_PROBE_LAN_HOST` | `probe.lanHost` | the host LabView's own LAN vantage is at. Empty skips that vantage entirely — a guessed host produces connection failures that read as services being down (§3.6b) |
| `LABVIEW_PROBE_TIMEOUT` | `probe.timeoutMs` | per request. Short on purpose: a service that does not answer promptly is reported as not having answered, which is a third outcome and not an exposure |
| `LABVIEW_PROBE_MAX_CONCURRENCY` | `probe.maxConcurrency` | the fan-out over scanned services. How many addresses are tried *per* service is not configurable — `MAX_PROBE_TARGETS` is a constant in `model/probe.ts`, because the vantage list is derived from evidence and the cap is part of the rule, not a knob |
| `LABVIEW_AUTH_PASSWD_ENABLED` | `auth.passwd.enabled` | `false` = the password form is off and the file is not read at all. The explicit off switch for an operator who wants only OIDC, or only their edge |
| `LABVIEW_AUTH_PASSWD_FILE` | `auth.passwd.file` | `user:hash` lines. One usable entry is what turns enforcement on (§3.13) |
| `LABVIEW_AUTH_MAX_FAILED_ATTEMPTS` | `auth.maxFailedAttempts` | failed sign-ins per **username** before a `429`; keyed on the name, not the address |
| `LABVIEW_AUTH_LOCKOUT_SECONDS` | `auth.lockoutSeconds` | the window, and the `Retry-After` value |
| `LABVIEW_AUTH_COOKIE_SECURE` | `auth.session.secure` | `auto` (follow `X-Forwarded-Proto`), `true` or `false`. Override only if the proxy does not send that header |
| `LABVIEW_OIDC_ENABLED` | `auth.oidc.enabled` | `false` = never contact the provider, whatever else is set |
| `LABVIEW_OIDC_ISSUER` | `auth.oidc.issuer` | with a client id, this is what turns OIDC on. The discovery document's own `issuer` must equal it |
| `LABVIEW_OIDC_CLIENT_ID` | `auth.oidc.clientId` | |
| `LABVIEW_OIDC_CLIENT_SECRET` | `auth.oidc.clientSecret` | in `secrets.keysAlways` (I6). Set exactly the way `clientId` is — the provider issues the pair together. Unset = a public client; PKCE is used either way. Set and empty = a startup note plus a public client, never a refusal to start (I4) |
| `LABVIEW_OIDC_REDIRECT_URI` | `auth.oidc.redirectUri` | what the provider has registered. Empty derives it from the request, honouring `X-Forwarded-Proto`/`-Host` — right behind one proxy, wrong as soon as two hostnames reach the same LabView |
| `LABVIEW_OIDC_SCOPES` | `auth.oidc.scopes` | comma-separated; `openid` is sent whether or not it is listed |
| `LABVIEW_OIDC_USERNAME_CLAIM` | `auth.oidc.usernameClaim` | tried first, then `preferred_username`, `email`, `sub` |
| `LABVIEW_OIDC_LABEL` | `auth.oidc.label` | the button's text. Empty names the issuer host, which tells a visitor who has not signed in what your provider is |
| `LABVIEW_OIDC_TIMEOUT` | `auth.oidc.timeoutMs` | per request, for discovery, the token exchange and the JWKS |
| `LABVIEW_SESSION_SECRET` | `auth.session.secret` | in `secrets.keysAlways` (I6). Unset generates one per start, so restarts sign everyone out — said once in the log, and only when there are sessions to lose. Set and empty says both things |
| `LABVIEW_SESSION_TTL_MINUTES` | `auth.session.ttlMinutes` | also the cookie's `Max-Age` |
| `LABVIEW_SESSION_COOKIE_NAME` | `auth.session.cookieName` | the OIDC transient cookie is this plus `_oidc` |

The `auth` block follows the `authentik`/`traefik` shape on purpose — `enabled`, a value,
a `timeoutMs` — so an operator who has configured one integration already knows the
vocabulary. `enabled` means **allowed, not on**: what turns a method on is having
something usable (§3.13).

**`LABVIEW_BUILD_SHA` is the one row with no config-file key, and that is a rule rather than
an omission.** Everything else in the table is a decision about the operator's fleet; this is
a fact about the artifact, settled when the image was built. `config.yml` is editable while
LabView runs, so a key there would let a running instance be told it is a different build
than it is — the one claim a build stamp cannot survive making (I1). The image gets it from
the Dockerfile's `ARG`, the workflow passes `github.sha` (§9), and an operator who needs a
stamp on a hand-built image passes `--build-arg`. It is also why nothing writes it: LabView
reads this variable and never sets one.

### Credentials come from the environment

Four settings are credentials rather than knobs: `authentik.token`, `traefik.password`,
`auth.oidc.clientSecret` and `auth.session.secret`. Each has exactly one variable, and
that variable is the documented place for the value. There is deliberately **no path
form** — no `tokenFile`, no `LABVIEW_OIDC_CLIENT_SECRET_FILE` — because the alternative
was what LabView shipped before: the OIDC client id arriving as a variable and the
secret beside it as a bind-mounted file, two mechanisms for two halves of one credential
the provider issued together.

Two rules exist to keep that simplification from costing an operator anything:

**`blankCredentialVars: string[]`** — filled by `applyEnvOverrides`, holding the names of
credential variables that were **present and carried nothing**. That distinction exists
nowhere else: every other setting can fall back to its default silently, and by the time
a reader holds the config an empty token is indistinguishable from an unset one. It is
also the footgun the change introduces — `LABVIEW_OIDC_CLIENT_SECRET: ${OIDC_SECRET}`
with no matching `.env` entry expands to an empty value and compose passes it on without
complaint. Each reader translates the name into its own vocabulary: a `credential` fault
for a scan target (§3.10), a startup note for LabView's own login (§3.13). **Names only
— a value never lands in it** (I6).

**`retiredSettings(cfg, env)`** — the four retired variables and their four config-file
keys are still *recognised*, for the single purpose of saying they are gone. Ignoring one
silently would be a lock-out dressed as a simplification (I4): an operator whose client
secret was a mounted file becomes a public client on the next pull, the provider refuses
every sign-in, and nothing in any log explains it. The config-file keys are caught
because `merge()` preserves keys it does not recognise, so a `config.yml` written against
an older `config.example.yml` still parses and still contains `tokenFile:`. Each line
names the variable to move the value to, and neither the value nor the path is echoed.
Both entry points print it: `buildApp` through `app.log.warn`, `cli.ts` to stderr so JSON
on stdout stays parseable.

The consequence, stated rather than hidden: an environment variable is fixed for the life
of the process, so **rotating a credential needs a restart** (§3.11). `auth.passwd.file`
is untouched by all of this and is still re-read on change — a `user:hash` database is a
mechanism, not a single secret smuggled into a path.

**Docker endpoint resolution order:** explicit socket → configured/env TCP host →
default socket path. The default is the conventional local socket, the one
endpoint that requires no assumption about the operator's container names; a
socket proxy is opted into. Neither the Dockerfile nor `config.ts` may ship a
default TCP hostname (I2) — `compose.yml` sets it, as an example. Which of the
three was used is reported as the connection's `source`, because falling back to
the default when a proxy was intended is a silent failure otherwise.

**Authentik endpoint resolution order:** configured `url` → discovered internal
container addresses → discovered public hostnames. `authentik.url` ships empty for
the same reason: an address is a fact about the operator's fleet, so it is
discovered or supplied, never defaulted.

**Traefik endpoint resolution order:** the same shape — configured `url` →
discovered internal container addresses (declared target ports, plus `8080`) →
discovered public hostnames — and `traefik.url` ships empty for the same reason.
The one asymmetry is `enabled`: this stage defaults **on**, because the recommended
setup needs no credential at all and an unreachable endpoint costs one failed
connection and a reason string. `LABVIEW_TRAEFIK_ENABLED=false` opts out entirely.

**`probe.enabled` is the only setting a request can override**, and the exception is
narrow by construction. Every other value in the config is fixed for the life of the
process, which is what makes a scan reproducible from a config file and a fleet (I7);
`probe.enabled` decides whether traffic leaves for a scanned service at all, and that is a
question an operator wants to answer for *one* rescan without editing a file and
restarting. So the setting is the default that a startup scan and every timer rebuild use,
and `POST /api/rescan` may say otherwise for the single build it starts. Three things keep
that from eroding I7:

- the override is a **per-request value**, never state — it reaches the build the caller
  started and nothing else (§3.11);
- it is not sticky: the next timer rebuild is a config scan again, which is why the payload
  has to say what happened rather than leave it inferred (§3.7);
- `withProbeEnabled(cfg, enabled)` returns a **clone**, so a build already in flight
  holding the old config is unaffected. It is pure and asserted as such — that the copy
  carries the new value, that neither the config nor its `probe` block is the same object,
  and that the copy is otherwise byte-identical to the original. A mutating version passes
  every behavioural test in the suite and corrupts a concurrent scan, so the identity is
  asserted directly (§8).

Nothing else follows this pattern, and adding a second such setting is a decision about
I7, not a convenience: the reason this one is defensible is that it changes what LabView
*sends*, not how it reads what it got.

---

## 7. Security model

**Trust boundaries.** Compose files, `.env` files and container labels are
untrusted input parsed with no code execution. The Docker Engine is trusted but
reached read-only through a proxy. The HTTP surface has **two** possible guards, and
which of them applies is the operator's choice, not an assumption LabView makes: the
edge it is deployed behind — the same tunnel/proxy/SSO chain as the rest of the fleet,
which is exactly what it documents — and, since R10, a login of its own (§3.13).

**Why the login is off until configured, and why that is not "no authentication".** An
image that started refusing requests after a pull would lock an operator out of a running
deployment, and one whose only guard is an edge it cannot inspect is exactly the wrong
default for a page listing every hostname and unauthenticated service in the fleet. So
enforcement follows what is configured: one usable entry in `/config/passwd`, or an OIDC
issuer with a client id, and the surface is gated; neither, and it is open with one line
in the log saying so (§3.13). The unconfigured posture is what §7 previously described as
permanent — it is now the *floor*, and an operator who does nothing is no worse off than
before, while one who mounts a passwd file needs nothing from their proxy.

The distinction that matters is **authentication, not authorization**: LabView proves who
a visitor is and then shows every one of them the same read-only overview. There is no
role, no per-user scope and nothing to write (I5). Nor is there a trusted-header mode:
`X-Forwarded-User` and `X-authentik-username` are never read as identity, because
trusting a header is only safe when the edge is guaranteed to strip it and LabView cannot
verify that — the operator who has such an edge is already covered by leaving the login
unconfigured.

**Why the build stamp stays behind the session.** The commit in the topbar (§3.9) arrives on
`/api/overview`, which needs a session wherever one is configured, and the login screen gets
no stamp of its own. It is the smallest piece of this whole surface and still worth the rule:
a version an unauthenticated visitor can read is how a known advisory gets matched to a
running instance, which is work an attacker would otherwise have to do by probing behaviour.
Withholding it costs a signed-in operator nothing — they are one sign-in away from the same
seven characters, and the startup log has them without any HTTP at all. Not a claim that
LabView's version is a secret: an image tag on a registry says as much, and §11 lists what
this does and does not buy. Just the same rule the three pre-auth artifacts already follow —
nothing is served before a session that does not have to be (§3.13).

**Why LabView's own compose example publishes no `ports:`.** A published host port
answers directly at `<host-ip>:<port>`, bypassing the reverse proxy and therefore
any SSO middleware on it. For a dashboard that lists the whole topology — every
hostname, every exposed service, every env key — that is precisely the wrong
default. The same reasoning applies to its DockFlare example, which points the
tunnel origin at the reverse proxy rather than at the container, so the request
still traverses the auth middleware. LabView reports this class of mistake in
other people's stacks; it must not ship one.

That bypass is also the clearest case for the login of its own: a published port and a
tunnel pointed straight at the container are the two ways a request reaches LabView
without passing the middleware the operator believes protects it, and neither is visible
from inside the container. A configured passwd file holds in both.

**Handled:** path traversal and symlink escape via `env_file` (I8); secret
exposure via key patterns and URI credentials (I6); privileged Docker access
(socket proxy, read-only endpoints, `USER node`); denial by malformed input (I4);
scan stampede (in-flight coalescing); credential stuffing against the login (bcrypt,
a per-username throttle, one message for both halves of a wrong guess — §3.13); CSRF on
the two POST routes (`SameSite=Lax` plus an `Origin` check that runs *before* the session
check, so a rejection sets no cookie).

**The outbound calls, and their rules.** Three *scanning* stages initiate a connection
outside the Docker socket, and all three carry the same constraints (I5): `GET` only; no
TLS-verification bypass; the credential readable from a file so it need not sit in
the environment; and a discovered endpoint probed on an unauthenticated path
*before* any credential is sent, because a discovered address is a guess and a guess
must never be handed a credential.

- **The identity provider API** is entirely opt-in: with no token configured, no
  request is made. It needs a read-only groupless service account with three
  `view_*` permissions.
- **The reverse proxy API** is on by default, because in the intended setup it needs
  no credential: a `traefik` entrypoint on the container network, unpublished, with
  `api: {}`. It sends a credential only to an endpoint the operator configured by
  hand or to a hostname the scan proved belongs to the service whose own labels
  declare `api@internal`. When the read succeeds unauthenticated, that fact is
  reported as a note on the proxy service — LabView's own read is evidence about how
  the API is exposed, and saying so is more useful than staying quiet about it.
- **The active probe** is off unless switched on, and it is the one read whose address comes
  out of a scanned document rather than out of the configuration (§3.6b). It is therefore the
  most tightly bounded: `GET`, never a credential, never a redirect followed, a capped number
  of addresses per service, an HTML-only body read to a cap, and only for a service where HTTP
  was observed — so no request is ever sent at a database port. Where the address is a public
  hostname, that request leaves the fleet, which is the plainest reason this one defaults to
  off.
  **One service can cost more than one request, and the bound on that is stated.** The first
  is always `GET /`. A **second** goes out only for the one answer no body can settle — a 200
  of HTML with no `<form>` anywhere in it, having gated nothing — and only to the four constant
  current-user paths in `STATE_PATHS`, at the origin the first request already reached. Nothing
  is ever taken from the page: the addresses are a reviewed list, not something parsed out of
  markup, which is what keeps a scanned document from choosing where LabView sends its second
  request. The walk is sequential regardless of `probe.maxConcurrency` and stops at the first
  refusal, so the ordinary cost is one extra request and the ceiling is four. Every scan says
  the total it sent on its startup line, because a stage that can multiply its own traffic must
  not be able to do it quietly.
  **It also asks fewer services than it could.** A service this scan already found
  authentication for is not asked at all, because `hasEdgeAuth` is
  `configuredEdgeAuth || probeGate` and the answer could not have changed its verdict (§3.6b).
  The traffic that removes is the traffic aimed at exactly the wrong place: an SSO endpoint, a
  forward-auth-protected admin UI, a tunnel hostname behind a Cloudflare Access policy — the
  addresses in a fleet where an unexplained anonymous `GET` is most likely to be noticed, rate
  limited or logged as an intrusion attempt. What remains asked is the set of services nothing
  was found in front of, which is the set the stage exists to measure.

**Who can switch the probe on, stated plainly.** The switch beside Rescan sends
`{"probe": true}` to `POST /api/rescan`, and that route needs a session only when
enforcement is configured (§3.13). **With no passwd file and no OIDC issuer, anybody who
can reach the page can start a probing scan** — a `GET /` to every eligible service in the
fleet, at addresses out of the operator's own compose files, some of them public hostnames
that resolve outside it, plus up to four more at each service that answered with a form-less
HTML page. Two things are worth separating there:

- What it does *not* give away. A visitor who can reach `POST /api/rescan` can already
  reach `GET /api/overview`, which lists every hostname, every published port and every
  service with no gate in front of it. The inventory is not what probing adds; measurement
  is. The boundary that protects any of this is the login, not the switch — which is why
  the honest mitigation is §3.13 rather than a narrower switch.
- What it does add. Requests attributable to the operator's address reach third-party
  hostnames on an anonymous visitor's say-so, and each rescan can be repeated: LabView rate
  limits the login route and nothing else (a deliberate non-goal, below), and forced builds
  coalesce only while one is in flight, so sequential rescans mean sequential scans. That
  was already true of a probe-less rescan against the Docker socket; the change is that the
  traffic now leaves the host.

The switch was given full authority over `probe.enabled` in both directions anyway, and the
reason is that the alternative is worse in a way that is harder to see: a control the
configuration could veto is a control that shows a state it does not have. An operator who
wants probing to stay off for everyone has a sound answer — configure the login — and one
who has not configured it is already showing the whole inventory to the same visitor. The
default remains off, so this costs nothing until someone reaches for it.

A fourth stage reaches outward only when OIDC is configured, and it is not part of a
scan: discovery, the token exchange and the JWKS, to the one issuer the operator named
(§3.13). It shares the timeout and file-backed-credential rules, and adds two of its own —
the discovery document's `issuer` must equal the configured one, and every endpoint taken
from that document must be https or loopback, so a compromised or mistyped discovery
response cannot redirect the token exchange somewhere plaintext. It is also the only
outbound `POST` in the codebase; `GET`-only remains the rule everywhere a scan reads.

No credential can appear in output: `LABVIEW_AUTHENTIK_TOKEN`,
`LABVIEW_TRAEFIK_PASSWORD`, `LABVIEW_OIDC_CLIENT_SECRET` and `LABVIEW_SESSION_SECRET` are
all in `secrets.keysAlways`, so a fleet that includes LabView's own stack masks them like
any other secret, and no error string in any client interpolates a credential. Nothing
derived from one leaves either: no password hash, session token or signing secret reaches
an API field or a log value, and a login failure crosses to the browser as a code from a
closed union (I6).

**Deliberate non-goals:** no authorization — every signed-in visitor sees the same
read-only overview, and there is nothing to write; no trusted-header identity; no rate
limiting beyond the login route; no CSP, because mermaid and cytoscape both inject styles
at runtime and a policy that breaks the graph tab is worse than none; no TLS termination
(the proxy does it); no persistence, so nothing to leak at rest — which also means
sessions do not survive a restart (§11); no writes of any kind; and no outbound network
calls beyond the three scan reads above — the third only when it is switched on, by the
configuration or by a rescan that asked — and, when configured, the one issuer.

---

## 8. Testing contract

`npm run smoke` runs the entire pipeline against six fixture roots with Docker
disabled and asserts on the resulting `Overview`. It exits non-zero on any
failure and gates CI. `npm run typecheck` covers `scripts/` and `tools/` too
(`tsconfig.scripts.json`): `tsx` strips types without checking them, so an
assertion reading a renamed field would silently read `undefined` — and an
assertion on `undefined` can pass while proving nothing. `tools/probe-lab` is in that
project for the sharper version of the same reason: it exists to report what the
pipeline's own rules decided, so a drifted import there would describe a decision
LabView never made.

**`fixtures/apps`** — a representative happy-path fleet: a tunnel + proxy service,
a proxy-bypassing service, cross-stack middleware resolution, LDAP and OIDC
services, a stack with an `.env`, shared binds across stacks, and a `proxy` stack
that is the resolved hop for another stack's tunnel origin (§3.4). Asserts the
normal output is right — including that every `depends_on` in it names the network it
travels over and is drawn through it, which is the ordinary case `fixtures/nets` then
pins the edges of.

**`fixtures/edge`** — one stack per previously-fixed defect. The contract:

> **Each edge fixture must fail the smoke test if its fix is reverted.**

A test that passes either way documents nothing. When adding a fix, verify this
explicitly: back the fix out, confirm the new assertion fails, restore it. Current
stacks:

| Stack | Pins |
|---|---|
| `dbstack` | URI credential redaction; `env_file` containment |
| `cfdisabled` | `dockflare.enable=false` yields no route (and truthy variants still do). Also the sharpest pair for the withholding rule: two siblings on one implicit network, so the `internal` evidence is identical and the tag survives on exactly the one whose route is switched off |
| `ldapapp` | LDAP against a non-Authentik directory stays generic |
| `interp` | nested `${A:-${B:-lit}}` defaults, `$$`, unused-branch handling |
| `hostport` | published ports are reachability (`lan`) and `expose:` is not; the bypass note on a proxied service that also publishes |
| `sharednet` | `internal` from the network compose creates for free: two services, no `networks:` key anywhere, both on the implied `<project>_default` — so the rule must resolve networks the way docker does rather than read `networks:` off the service |
| `exposeonly` | `expose:` alone is `internal`. One service, so the shared-network arm cannot fire; the only stack that goes to `none` if that arm is dropped, since `hostport/worker` sits on a shared network too |
| `declared` | the declaration layer's happy path: every stack-level field, a bare-string dependency, and in-app auth (`app-local-accounts` + `app-ldap`) shown as *declared* without moving `svc.auth.method`. Also the only `supplies` case — it publishes a host port and the scan finds no gate, so it is the fixture that proves a declaration takes a service out of the exposure count *and* that the service still says so on its face |
| `accepted` | an exposure signed off with a reason: still counted in `exposedWithoutAuth`, badged accepted, reason shown |
| `staledecl` | both checkable fields going stale at once — an acceptance for a listener that no longer exists, and an `expected.ingress` the scan disagrees with |
| `partialdrift` | the same drift check against a set rather than a value: expected `[public, lan]`, scanned `[public, traefik]` — same *first* kind, wrong in both directions. `staledecl` cannot catch a primary-only comparison; this can. Both differences are *external* kinds deliberately: `internal` is withheld from a service with a route, so a disagreement phrased with it would collapse to a one-directional one and the fixture would pass while covering half of what it claims. Its `expose:` stays, which puts the withholding itself under test here too |
| `declcompare` | the declared-vs-detected comparison, isolated: four services, and the first three are configured *identically* (same LDAP env, nothing published, nothing in front) so the scan reaches the same conclusion about all three and the sidecar is the only variable — `conflicts`, `redundant` and `supplements` decided from the declaration alone. The fourth is the pair that pins the layer rule: `defence` declares the *same* mechanism as `conflict` and must not warn, because what the scan detected sits at a different tier. It also carries the only *agreeing* multi-kind `expected.ingress` in the fixtures — `[lan, traefik]`, written in the opposite order to the classification — so "order is not a disagreement" and "agreement is silent" are pinned by something other than a unit test. Two external kinds, for the same reason `partialdrift` uses them: an expectation containing `internal` would be collapsed to a single kind on both sides and stop being multi-kind at all. The published port that earns the `lan` also earns a bypass note, which is correct — the gate is on the route, not on the port |
| `badsidecar` | four mistakes in one file — a mistyped key, a product name where a mechanism belongs, a reasonless acceptance, a service the compose file does not define — each warned about, with two valid declarations in the same file that must survive them |
| `sidecaryml` | the `.labview.yml` filename variant, and the shorthand `auth: [app-token]` form |
| `escapedecl` | containment (I8): a symlink to a sidecar **outside** the apps root must be refused. The target is valid on purpose, so a regression shows up as leaked declarations rather than as different warning text |
| `tunnelorigin` | an origin that cannot be resolved stays unresolved: a port nothing publishes, and a tie between two reachable claimants. Neither may invent a hop |
| `otherprovider` | provider attribution needs proof, on both the env and the address path |
| `authentik` | upstream's generic service names (`server`, `worker`) must not become fleet-wide hints — `isSpecificHint`. Doubles as the definition site for the cross-stack `authentik@docker` references |

**Some rules are pinned across the existing stacks rather than by a new one.** The four
`NoAuthReason` branches (§5) are asserted on `cfdisabled` (`gap`), `exposeonly` and
`interp` (`not-reachable`), `declared` (`declared`), and — from the Authentik fleet below —
the application whose gate is API-confirmed but carries no `AuthMethod` (`unnamed-gate`),
plus a fleet-wide check that a reason exists for exactly the services whose method is
`none`. A purpose-built stack was considered and rejected: the obvious candidate, a
Cloudflare Access policy, already resolves to `other-oauth` and so cannot reach the branch
it was meant to cover, and a new stack would have moved the fleet counts several unrelated
assertions are written against. The contract holds per branch either way — dropping any one
of the three conditions in `noAuthReason` turns a check red.

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

**`fixtures/nets`** — eight small stacks whose only subject is what connects two services
and what merely lets them reach each other (§3.9). A separate root rather than stacks added
to `apps`, so no existing count or assertion shifts. Same revert-proof contract:

| Stacks | Pins |
|---|---|
| `shared-a`, `shared-b`, `shared-c` | the headline case, and the request this feature came from: three compose projects, one `external:` network, one node. Two databases are backed up by an agent in a third stack, which compose cannot say — so each database's `.labview` says it, one qualified and one bare, and `shared-c` has **no sidecar at all** while still reporting both as `required-by`. That last part is the check that fails if the reverse direction is ever taken from the target's own file instead of derived. Pins `scope: "external"`, `memberCount: 4`, `stackCount: 4`, `declaredBy.file`, the preserved `detail`, and that the two views agree about who is on it |
| `shared-d` | a fourth service on that same network declaring nothing, which is the trap for a revert to co-membership-as-connection: it must be *counted* in `reachableCount`, never named in `dependencies`, carry no `flow`, and stay out of the fleet list's pairs while staying in its members. Its name must not appear anywhere in the serialised link either — asserted against the whole payload rather than a field, so a list coming back under any key fails on the first name it prints. From its own side the network connects it to nothing and says so in words, with a count of the three it could reach |
| `badref` | every way a reference fails, in one stack: a name matching nothing, the declaring service itself, a bare name that resolves to the sibling ahead of two same-named services elsewhere, and a second reference to that same target. Two drift entries, one edge, nothing said about the duplicate — and the declaration still holding all four references exactly as written, which is what keeps a rescan from reading a rename elsewhere as an edit here |
| `layered` | a dependency drawn *through* the stack's own network: `web → api → cache` over `layered_inner`, so `via` names it, no direct line is drawn, and the three `flow` values are each pinned on the leg that must carry them — `to-network`, `both` (a service at both ends of a chain) and `to-service`. `extra` declares the cache in the sidecar, which is where `flowSource` is pinned in all four states: `observed`, `declared`, `both` on the cache's one leg, and absent on `probe`, the co-member with no dependency either way |
| `disjoint` | the exception, twice: a compose `depends_on` across two networks the pair does not share, and a declared one to another stack entirely. `via` empty and the direct edge **kept** in both, with the two different notes — docker orders startup yet neither container can address the other, against a declaration the scan can find no path for at all. Its sidecar also declares the bare `probe`, which two stacks now have, so the ambiguity names both candidates and draws nothing |
| `lonely` | both arms of the single-member rule at once: one service on an `external:` network (drawn, because something outside the scan may be on it) and one alone on a stack-local network (counted, not drawn). Also where two of the four membership wordings are pinned, which are opposite claims and would be a false statement if swapped |

**The caps are asserted against synthetic nodes, not a fixture.** `visibleSpokes` is driven
with 20 edges and `networkLinks` with a 26-member network, because the alternative is
committing a twenty-six-service fleet whose only purpose is to be large. The functions are
pure and live in `model/networks.ts` for exactly this reason, and the revert contract is
unaffected: returning every spoke, dropping the dependency-first ordering, or naming the
fifteen co-members the 26-member network's drawer only counts turns a check red. The
assertions that matter most are the ones about what is *kept* — the dependency-carrying
spokes are last in scan order in the synthetic input, and the ten dependencies are the last
ten members, so keeping them proves the sort rather than the slice, and proves a co-member
cannot displace a dependency. The same synthetic network is then read through
`networkGroups`, which must still name all 26: that is the check that the drawer's count and
the fleet list it points at are two views of one membership rather than a fact lost.

**`fixtures/authentik`** — a fleet with an identity provider in it, driven against
canned API responses in `fixtures/authentik-api.json` through `BuildDeps.fetchImpl`.
No network, no Authentik, and the same revert-proof contract as `edge`. Each stack
isolates one rule so an assertion cannot pass by accident through another path:

| Stack | Pins |
|---|---|
| `idp` | the provider itself: discovery must use the **target** port of `9443:9000`, not the published one, since the stub answers only on 9000 |
| `authentik-outpost` | a candidate that looks like Authentik by image but serves no API. Sorts before `idp`, so it is probed first and must be *skipped* — and must never receive the token |
| `wiki` | rule 1 (provider `internal_host`), a per-user `meta_launch_url` that must not be matched on, `confirmed` outranking the label-derived `observed`, and the tunnel-bypasses-the-outpost note |
| `docs` | rule 3 on a hostname declared in **both** DockFlare and Traefik labels (the dedupe); object-form `redirect_uris`; a backchannel SCIM provider listed but not treated as a gate |
| `metrics` | rule 3 via a redirect URI in the newline-delimited-string form, from page 2 of the paginated response |
| `notebook` | rule 2: no labels, no hostname, reachable **only** by a redirect URI naming the container (`http://notebook:8888/…`) — an OIDC gate that appears in no label and no env key |
| `vault` | rule 4 (slug), a backchannel LDAP provider found with its outpost, and the posture reported one step down (`observed`) for resting on a name |
| `home-assistant` | rule 4 by the *application name*, across differing separators: `Home Assistant` → the `home-assistant` stack |
| `ledger` | rule 4 by a *provider* name, once the mechanism words are dropped: `Provider for ledger` → `ledger`. Reported `observed` with `— tied to this service by name alone` |
| `db` | the `MIN_DERIVED_KEY` guard: a provider named `DB Provider` reduces to a two-character residue and must claim nothing, leaving the service `method: "none"` |
| `pair` | a slug **and** a provider name each naming a two-service stack: unmatched, not arbitrated. The provider is an OIDC one so an arbitrated match would visibly claim a gate on the winner |
| `orphan` | a proxy provider **no outpost serves** — matched, reported unprotected, reason on the service, and no bypass note for a gate that stands nowhere |
| `reports` | a SAML gate: `method: "none"` yet **not** exposed-without-auth, provider quoted verbatim |
| `archive` | an application the policy filter **withholds**: published with no gate in any label or env key, so it reads as exposed until the application is rebuilt from the provider whose redirect URI addresses the container. Its slug and name resemble nothing in the stack, so only the address can reach it |
| (api payload) | `broad-app`, whose only URL is a `forward_domain` `external_host` equal to the provider's own hostname — must stay unmatched rather than attach to `idp`. `ext-01`, whose redirect URI is an **IP literal** on a port `idp` publishes — must not be resolved through the published-port table (rule 2's guard). `wh-02`, withheld and rebuilt but addressing nothing in the fleet — the rebuilt-and-still-unmatched case, which is where the narrower basis has to be stated. `hidden-01`, withheld and assigned a SAML provider LabView never reads — permanently unaccounted for, so `partial` has a case recovery cannot close |

Six runs over that root assert the behaviours that are not about one stack:
discovery + token; a configured URL (nothing else is probed); a **superuser** token that
is served the whole list; a token whose withheld applications are *all* recoverable; no
token (zero requests, no error); and a throwing `fetchImpl`
(reported, not raised, fleet still analyzed). The exposed-without-auth count is asserted
**with and without** the API in the same run, so the integration's contribution is
measured rather than assumed — that pair is what fails if any match rule regresses. Three
of the gates in that gap are OIDC ones that appear in no label and no environment key,
and one of those three is an application the API withheld, so the difference is the whole
of what reading the provider buys.

The stub models the policy filter in both directions, because that is the only way the
recovery can be shown to be *faithful* rather than merely present. It serves the filtered
pages by default and appends the withheld page when `superuser_full_list=true` is sent to
a token it treats as a superuser — while reporting `pagination.count` as the full total in
**both** modes, which is the real upstream behaviour and the field the fix rests on. The
two runs are then compared: the default run's slug set must be a **subset** of the
superuser run's, short by exactly the SAML-only application, and the service the rebuilt
application gates must read with the identical method and confidence either way.

The third mode exists for the case in between, and it is the only thing holding one rule
in place. Given a narrowed withheld set — every one of them recoverable — the counts must
still state 14 of 16, and the connection must still be `connected` with no error, because
recovery closed the whole gap. Reporting `partial` on the difference rather than on what
is *still* missing passes every other assertion in the suite and fails only this one: a
banner an operator cannot clear is a banner that stops being read, and then the case above
stops working too.

**`fixtures/traefik`** — a fleet built so the labels and the live routing table
disagree in every way that matters, driven against `fixtures/traefik-api.json`
through the same `BuildDeps.fetchImpl`. That file carries the Authentik payload for
these runs too, so the three-way cross-check has all three sources. Same
revert-proof contract; one stack per rule:

| Stack | Pins |
|---|---|
| `edge` | the proxy itself: `service=api@internal` is the only thing in the fleet saying where the API is, so it pins both halves of the discovery rule. Also the `basicAuth` on its own dashboard router, and the "answered with no credential" note |
| `wiki` | the plain happy path (name-form backend, `forwardAuth` → `confirmed`) and the **container-IP trap**: its `3000:3000` is exactly what an IP-form backend on port 3000 would wrongly resolve to through the published-port index |
| `docs` | a gate reachable only by expanding a `chain`, a file-provider middleware whose name does *not* read as auth (so label-only it is `none`), and a backend Traefik reports `DOWN` |
| `dashboards` | **the downgrade** — label claims `authentik@file`, live chain empty, entrypoint carries nothing: method `none`, exposed, note names both sides |
| `metrics` | the false-positive **guard** — structurally identical to `dashboards`, except the gate is on its entrypoint. No downgrade, `confirmed`, evidence says which entrypoint |
| `legacy` | a router Traefik refused (`disabled` + `error[]`): its chain must count for nothing, and the errors are quoted |
| `blog` | a labelled router absent from the live table entirely — note, no protection claimed, no invented reason |
| `twin-a` / `twin-b` | one live `@file` router whose host rule matches two services: unmatched, not arbitrated. `twin-a` additionally pins that a router the proxy *is* serving never produces a "declared but not live" note, while `twin-b`'s genuinely absent router does |
| `crm` | the three-way **disagreement** — labels declare nothing, the live chain is empty, and Authentik has a `forward_single` proxy provider with an outpost: somebody built a gate the request never reaches |
| `shop` | the guard on that — identical but `mode: "proxy"`, where the outpost *is* the backend, so no forward-auth middleware should be expected and no finding is reported |
| `sso` | the far end of the forward-auth address, so resolving it back to a service is what makes the delegate nameable |
| (api payload) | PascalCase `/api/version`; a middleware type the model has never seen; `middlewares` and `serverStatus` *absent* rather than empty; a `mirroring` service with no backends; `api@internal` omitted from `services` entirely, as a real Traefik omits it |

Seven runs over that root cover what is not about one stack: discovery and what was
read; the leak check (a credential configured, the internal endpoint answering,
nothing sent anywhere); the gated host (Basic sent only there, probe first
unauthenticated, session cookie echoed on the rest); a configured URL (nothing else
probed); a partial read (`/api/entrypoints` failing → no downgrade, `confirmed`
falls back to `inferred`, no cross-check finding); a throwing `fetchImpl`
(reported, not raised, fleet still fully analyzed, credential absent from the error);
and the API switched off. That last run asserts the exposed-without-auth and
protected counts **both ways** — `6`/`5` from labels alone, `4`/`7` with the live
read — so the integration's contribution is measured in both directions rather than
assumed. The container-IP trap is asserted directly against `buildFleetIndex`, since
a container IP exists only in live Docker state and smoke runs without a socket.

**Why a match did not happen** (§3.5, §3.6) is asserted across both API fixture roots,
because a reason nothing checks decays back into a shrug. Three properties:

- **The five unplaced applications give five distinguishable answers.** `pair` is
  `ambiguous`, with both `pair/blue` and `pair/green` named in its trace; `broad-app`,
  `s01`, `ext-01` and `wh-02` are each `no-candidate` with their own cause quoted — the
  `forward_domain` mode, the three-character floor, an address literal, and a record the
  applications endpoint withheld and the provider rebuilt. Exactly one of
  the five is `ambiguous`, so a matcher that stopped telling contested from absent fails
  on the count as well as on the wording. Traefik pins the same pair: `twin-blue@file`
  contested between both twins, `standalone@file` belonging to nothing scanned.
- **Every unmatched entry carries its subject and a non-empty trace** — the application
  with its providers, or the router with its rule and entrypoints — plus one
  `considered` line per rule tried. A rule that stops appending leaves a *short* trace
  rather than a wrong one, so the assertion is on the length, not on the text.
  `standalone@file` additionally pins that a rule which was **skipped** says so, instead
  of reading like a rule that looked and found nothing.
- **No trace line carries a value out of the configuration.** Every `detail` and every
  `considered` string from both roots is checked against all three fixture `.env`
  secrets and the stub token — the same discipline as the connection diagnostics below,
  and for the same reason: these are new prose built from scanned input and served to a
  browser (**I2**, **I6**).

No posture number moves with them. `matchedServices` on both roots and the
exposed-without-auth pair asserted with and without the API are unchanged by the reason
model, which adds reporting and nothing else.

**`fixtures/probe`** — eighteen stacks, twenty-seven services, driven twice: once with probing off
and once on, against a URL-keyed `probeStub` in `scripts/smoke.ts` rather than a JSON payload,
because a probe reads status codes, three headers and a fragment of HTML, not a document. The
LAN host is `192.0.2.10` — documentation range, so a request that escaped the stub could not
arrive anywhere. Same revert-proof contract; one stack per rule:

| Stack | Pins |
|---|---|
| `tunnel-login` | the `password-form` signal end to end, and — with its sidecar — a **stale acceptance**: an exposure signed off as intentional that now answers with a login form is reported as drift naming the *measurement*, not "authenticated at the edge", because an application's own login page is not an edge |
| `proxy-challenge` | `challenge`, and that a router's own `tls` setting decides the scheme it is asked on |
| `sso-redirect` | `redirect-origin`, at the `http` address a router with no TLS implies |
| `own-login` | `redirect-login`, and — with its sidecar — the one service where `probed-gate` and `declared` are both true: the reader gets the measured one, and the same service falls back to `declared` with the probe off |
| `authentik-flow` | a **pair**, and the reason `LOGIN_PATHS` carries an odd-looking entry: `portal` 302s to `/flows/-/default/authentication/` — an Authentik flow executor, one `Location` and one request, no chain walked — and `dataflow` is the **trap**, a workflow tool 302ing to `/flows/123`, which the `-` in `/flows/-/` is the whole of what keeps out. Both halves are pinned on the payload: `portal`'s `redirect.to`, exactly one request to that origin, and `dataflow`'s reason naming the path it landed on |
| `spa-shell` | a **pair**, the eighth signal and the header it turns on. Both serve a 200 of form-less HTML — the one page no reading of a body can judge — so both cost a second request. `app` answers `401 WWW-Authenticate` at `/api/`, the *first* entry in `STATE_PATHS`, so it is `state-challenge` and `state.asked` is 1, which is what pins the short-circuit. `anon` is the **trap** and the more important half: a *bare* 401 at `/api/v1/me` after two 200s — an anonymous-enabled Grafana, a world-readable Gitea — which stays exposed, is reported rather than counted, and makes `state.asked` 3 |
| `meta-refresh` | a **pair**, differing in one URL, because that URL is the whole rule: `docs` refreshes to `/login` and is `meta-refresh-login`; `home` refreshes to `/dashboard` and is a **trap** — an application routing to its own landing page, which a rule reading "any meta refresh" would take out of the exposed count. Both halves of the trap are pinned, not just its verdict: `home`'s payload must carry `refresh.to === "/dashboard"` and its reason must name `/dashboard` and say it is neither off the origin nor a login path |
| `saml-post` | `sso-form` — the shape that defeats every simpler rule at once: no password field, no `Location`, and a cross-origin `action` the form rule refuses on purpose. The hidden `SAMLRequest` alone is the evidence. TLS on the router, so it is asked over `https` |
| `passwordless` | a **pair**, and the reason `credential-form` cannot degenerate into word-matching: `magic` serves an email field, a submit button and `action="/login"` with no password anywhere; `news` is the **trap** — the same three tags as a newsletter box, posting to a list service on another origin, which marks nothing and clears nothing, and whose reason must say so in those terms: the form shows no login intent and its action is not a login path |
| `open-app` | the **guard**, two services: `dash` answers 200 with a homepage and stays exposed with the finding now measured; `routing` redirects same-origin to `/dashboard`, which is application routing and clears nothing |
| `public-portal` | a **pair**, and the only stack here pinning a sentence that points at *open* (§3.6c). `app` serves a landing page and `<a href="/login">Sign in</a>`: `readGate` must stay `undefined`, the service must **stay** in the exposed count, and the reason must name the link, the label and the number of characters and links behind the claim — back out `anonProof` and it fails. `blog` is the **trap**, twice over: an article headline reading *How to log in to your router* (28 characters, so `LOGIN_LABEL_MAX` excludes it) and a `/auth/logout` anchor (a login path by prefix, which `NOT_LOGIN_LABEL` is checked before). It must produce the *narrower* sentence — content served, no offer — so a loosened label vocabulary or a dropped logout veto fails here rather than on a real fleet. Both carry a search `<form>`, so `wantsStateProbe` is false and neither adds a second request |
| `gated-open` | **a service whose gate was already detected is never asked.** An `authentik@docker` middleware whose definition is in no scanned stack, so the posture is `inferred` — the harder half of the eligibility rule, since a rule that only withheld `confirmed` postures would still send this request. Its entry in `PROBE_ANSWERS` stays, so the assertion fails on a *recorded request* rather than on a fixture with nothing to say |
| `access-gate` | the same withholding reached without a Traefik label at all: a tunnel hostname behind a Cloudflare Access policy, which is the second of `hasDetectedAuth`'s three terms. Its sibling `db` is a `tcp://` origin under the same policy — detected auth *and* no address, which is what pins the order of the two questions: counted as neither asked nor withheld |
| `silent` | eligible, nothing listening. "Did not answer" and "answered with no login page" are the same absence of a gate and completely different findings; it counts in neither statistic and drives the aggregate `partial` |
| `lan-fallback` | the vantage walk: a public hostname that does not resolve falls through to `http://<lanHost>:18099/`, with the failed attempt kept in the order it was tried |
| `declared-open` | a declaration that `supplies` the only protection, against an answer that settles nothing: the page is a shell — thirty-odd characters and one link, under both of `servedAnonContent`'s thresholds — so there is no evidence of an open service either. The verdict stands (the probe asked one address once) and the result is recorded as **unconfirmed**, not drift. `portal.declared.drift.length === 0` is the revert trap: restoring the inference this replaced fails there |
| `dbonly` | a Postgres and an Adminer publishing ports and nothing else: **no request at all**, which is the rule that keeps the probe off a database |
| `tcp-tunnel` | a `tcp://` and an `ssh://` tunnel origin: never resolved, let alone asked, and both stay honestly in the exposed count |

Seven groups of assertions carry what is not about one stack. The **rules**, driven pure: a
33-row `readGate` table where half the rows are near-misses, plus two meta-assertions — that
every signal in the union is reached, and that the near-misses outnumber the signals, which is
what "strict" means here. The union is reached across **two** tables now and the subtraction is
written out rather than the check loosened: `READ_GATES` is `PROBE_GATES` minus
`state-challenge`, because that clause is unreachable from `readGate` at any input, and a
7-row `stateCases` table covers it — `wantsStateProbe` (whether a request goes out at all,
the only rule here whose failure mode is *traffic* rather than a wrong answer), `readState`
(what the walk found, including that the count is truncated at the refusal), and
`readStateGate` (whether that is a gate), with the row where it says **no** the most important
one in the section. A 10-row `loginPathCases` table gives every entry of `LOGIN_PATHS` a path it
matches and a near miss it does not — which is the only reason that list is exported, since an
eleventh entry nobody pinned could take a service out of the exposed count for a reason nobody
wrote down; plus the coverage check both ways, so a row for a path that is no longer in the list
fails too. A 14-row `readLoginForm` table, which earns its own because a
composite rule's interesting cases are the ones where *some* parts are present, and a gate
assertion collapses all of those to `undefined`; three small tables for the readers `readGate`
now decides through — `readRedirect` (a relative `Location`, an absolute same-origin one
reduced to its path, a different port as cross-origin, an unparseable one as nothing at all),
`readRefresh` (including that the **first** parseable refresh in a document is the one recorded,
because that is the tag a browser honours) and `readMediaType` — with a sweep over the redirect
rows asserting the I6 reduction directly: no recorded target may contain a `?` or a `#`; a
23-row `probeReasonText` table asserting the sentence **names the deciding fact** rather than
merely coming back non-empty — `/dashboard` for the on-origin redirect, `application/json` for
the 200 that was not a page, the missing header for a bare 401 at `/`, and the address of the
one further out that refused without naming a scheme, whose row must still end "the finding
stands" — with `mustNot` clauses where a
wording could over-claim (a probe that never connected must not say "login page"), plus two
meta-assertions that every gate has a row and that no two gates are worded alike; a 13-row
`readAnonAccess` table reading the same bodies the other way round — the offer, the shell that must
stay silent, an icon-only anchor, an `aria-label`, the `/auth/logout` veto, the article headline, a
form-less control, an anchor beating a control for the same label, a cross-origin hand-off, a
duplicate path counted once, `href="#"`/`javascript:`/`mailto:`, a `<template>` and a `<noscript>`
— whose most important row is a property rather than a case: `readGate` returns `undefined` on
every body in the table, which is §3.6c's structural argument asserted rather than reasoned about.
Beside it, the two thresholds pinned at their boundary (200 characters and 2 links true; 199 and 2,
4000 and 1, and nothing at all false), four rows over the label vocabulary covering the positives,
the logout veto, the two *deliberate* absences (`continue with`, and sign-up — so `Sign in / Sign
up` still reads as an offer) and the word-boundary near misses that keep `Blog index` from being a
login, the `LOGIN_LABEL_MAX` pairing that separates a control's label from an article's headline,
and one row asserting `textChars` is `visibleText`'s own count on the same reduction rather than a
second reading of the page; four more `probeReasonText` rows for the sentence itself — the offer
branch, the no-offer branch, a shell that must produce neither, and a gated page that must produce
neither; and `probeTargets` over hand-built routes for
scheme, order, the per-service cap, dedupe, the bind-address guard, a port range, and each arm
of `isHttpObservable` separately. **Eligibility**, which decides whether a request is sent at
all: a table over `hasDetectedAuth` on hand-built services for all three of its terms —
including the enforced-Authentik one, which this root cannot produce because it has no Authentik
snapshot, and the two negatives that matter most, an *empty* Access block (a gate nothing stands
at) and a proxy provider with no outpost — plus the assertion that over the whole edge fleet the
predicate is exactly the negation of the exposure partition's own test, so eligibility and
posture cannot drift apart. Then, fleet-wide and revert-proof: **no service carries both
detected authentication and a probe result**; `anon` is present on exactly the services that
answered a 200 of HTML and on no others — gate or no gate, since the record describes a *response*
— while **no gated verdict in the fleet carries the sentence**, which is the I1 guarantee stated
the way it is actually true rather than as "the record and a gate never coexist"; the two withheld
services' `auth.method`,
`confidence` and `exposedWithoutAuth` are identical to the run where nothing was asked at all,
which is the safety argument for the whole rule asserted rather than reasoned about; and
`meta.probe.skipped` is exactly 2 with probing on and 0 with it off. The arithmetic is pinned
too — services with an address = asked + withheld — which is what fixes the *order* of the two
questions: `access-gate/db` has detected auth and no HTTP address, and counting it as withheld
would inflate the number. **Containment**, asserted on the recorded requests rather
than on the code: every request a GET with no query, at `/` or at one of the four constant
`STATE_PATHS` addresses and nothing else; every one of those second requests at an origin the
first request already reached; no credential on any of them; no address asked twice; nothing at
`:15432` or `:18081`; nothing named `pg.probe` or `ssh.probe`; neither withheld address anywhere
in the list; and the total exactly 37 — twenty-one first requests, one for each of the twenty
services asked plus the single fallthrough, and sixteen second ones. That last number is pinned
twice over, against the summed `state.asked` on the payload and against a per-service bound of
`STATE_PATHS.length`, which is what makes the short-circuit falsifiable: removing the `break`
changes no verdict anywhere in the root, only these counts. **Reconstruction** (I1): each service
exposed exactly when it was with probing off
minus the ones a login page answered for, asserted per service because two offsetting errors
would satisfy a total; the aggregate adding back up; `probeGated` being deliberately one *more*
than that, since it counts login pages and one belongs to a service already out of the count on
its declaration; and no `auth.method`, `confidence`, `authProtected` or `byAuthMethod`
differing between the two runs at all. **The switch**: that `withProbeEnabled` clones and
leaves its input alone; that a `ScanCache` hands each build the request that started it and
discards a coalescing caller's; that `meta.probe` states both what the build did and which of
configuration or request decided it; and, through `app.inject`, that `{"probe":true}`,
`{"probe":false}`, `{"probe":"yes"}`, an array, a JSON `null` and no body at all each land
where they should. Those route cases run against `fixtures/auth`, which carries no route on
anything — so `probe: true` is *observable* there while remaining incapable of sending a
request, because a body that turns the probe on must never be a body that makes the test suite
talk to the network. **The panel**, which is one claim in eight checks: it lists exactly the
services the tile counted. `collectProbeReport(probed.stacks, meta.probe.skipped)` must put
`stats.probeGated` services in `gated` and `stats.probeOpen` in `open`, `silent` must be the one
service nothing answered from, the three lists must sum to `probed` with no key appearing twice,
and every entry must be findable back in `probed.stacks` by object identity
(`s.probe === e.probe`) rather than by matching a copy. `notAsked` is the one field there that
*cannot* be derived from the stacks, so it is asserted both ways: 2 when the payload's count is
carried in, 0 when the argument is left off — a withheld service leaves no trace in `stacks` to
recover it from. Determinism is asserted the way the fleet's other groupings are — the same
input twice and the input reversed all produce identical JSON (I7) — the tile's tooltip and the
panel's subtitle are asserted to be one shared string, `probeReportSummaryText` is pinned on an
empty report, on a report that asked nothing *and* withheld some, and on the full one, and
`collectProbeReport(unasked.stacks, unasked.meta.probe.skipped)` must report `probed === 0` and
`notAsked === 0`, which is what keeps the tile off a scan that probed nothing.

**The diagnostic** is the seventh group, and it asserts one claim about `tools/probe-lab`: a
report says what the pipeline said (§3.6b). Every row of the 33-row `readGate` table above is
put through `buildReport` and the report's gate must equal the row's expected gate, so the tool
and the rule cannot drift by construction *and* cannot drift by accident — a clause added to
`readGate` and mirrored wrongly in the lab fails here. The labels are asserted to be
`probeOutcome`'s, the eight rows to be in `PROBE_GATES` order, and `withdrawsExposure` to be
true exactly when a gate fired. Beyond the equality, what a gate assertion cannot reach: that a
login page's *two* satisfied clauses both appear with the deciding one marked; that the
newsletter box is declined with a reason naming the part it lacks; that a non-HTML answer says
the body was never read rather than that a password field was missing from markup nobody
fetched; that a service which did not answer is never reported as having no login page; that a
same-origin redirect elsewhere names the path and asks for a fixture rather than a looser
clause; that a client-rendered shell is named as the known blind spot; and that a rendered
report carries no cookie value and no redacted header value (I6). All of it runs against the
canned bodies already in the file — no network, no temporary directory, nobody's service.

Section 3a is asserted the same way, and its load-bearing check is the same equality read as a
*non*-effect: an 11-row detector table, each row put through `buildReport`, and for every one of
them `verdict.gate` must equal `readGate`'s answer on the same body — so a detector that leaked
into a verdict fails here rather than on somebody's dashboard. Beside it, `direction !== "gated"`
restated as a runtime check rather than only as a type; that a page the rule *did* gate carries no
findings at all, since there is nothing left to argue about; and that a rendered report keeps the
whole of the I6 reduction across the new sections — the visible-text sample and the findings table
present, a session cookie's *name* present, its value absent, and a redacted header still reported
as a length. The three answer shapes of `--try-login-paths` get one row each — a login page found
at a guessed path, every path answering with the root's own bytes (a catch-all, and therefore proof
the login is drawn in the browser), and every path a 404 — with the same no-drift assertion over
all three, plus the ordinary run where the section is absent and the list is empty rather than
missing.

Two of those rows are what shipping the eighth signal changed, and they are worth naming because
they are the record of this tool having worked. The lab sweeps a **wider** list of current-user
addresses than the scan asks — `AUTH_STATE_PATHS` is `STATE_PATHS` plus four, and the superset
relation is itself asserted — so a refusal it finds at an address the scan does not ask is a
finding rather than the tool reporting its own sweep back. Section 4 has to state the **size** of
the change that finding implies, and that sentence used to have to say "a change to what the
probe requests", because the probe asked one address per service. It now asks four, so the same
observation has shrunk to *one entry missing from a list* — a commit with a fixture and no new
rule in it, which is what the row asserts in those words. The other is that a 401 the lab finds
at a current-user address is still not allowed to become the verdict, for the same reason
`readStateGate` requires the header: the tool reports what the pipeline would decide, so it
cannot be the place a looser rule gets tried out.

One assertion in that group is a rule about the whole vocabulary rather than about any stack:
between them the fixture services must answer with **every** member of `PROBE_GATES`. The
literal table proves each signal is reachable from some response; this proves the fleet
exercises it end to end, so a new signal cannot be added with only a literal behind it.

**The connection taxonomy** (§3.10) is asserted the same way, but without a fixture
root: the classifiers are pure, so each is driven directly. Every transport code,
every HTTP status and every socket-file state is mapped to its phase, the reports
are built through the real clients with a stubbed `fetchImpl`, and the formatter,
the hint table and `changedConnections` are asserted on their output. Four
properties are pinned deliberately, because each is a rule that could be quietly
merged away:

- **`401` and `403` do not collapse into each other**, and neither does *unreadable
  socket* into *refused connection*. Both pairs have an assertion that fails if the
  distinction is removed, since both would otherwise look like harmless
  simplifications.
- **A timeout is told from a peer reset by elapsed time**, asserted in both
  directions: a teardown code past the deadline is `timeout`, the same code well
  inside it is `connect`, and a slow `403` keeps its status.
- **The socket states are driven against real paths** made under `os.tmpdir()` — a
  name that does not exist, a regular file, and a listening `node:net` socket — so
  no docker daemon is needed and CI behaves as a laptop does. The
  not-readable-by-this-uid case is the exception: it goes through `phaseForSocket`
  on a literal probe, because a test process running as root can open a socket of
  any mode and the filesystem would refuse to reproduce the situation.
- **No diagnostic carries a credential.** Every formatted line from every run is
  checked against the stubs' token, password and session cookie, the same
  discipline as the leak check above.

**The scan cache and the rescan diff** (§3.11) are asserted the same way, and for
the same reason: the race *is* the behaviour, so it is driven through the injected
clock and a build only the assertion can settle — no server, no timers, no sleeping
on a real deadline. Seven properties are pinned (an eighth, on the palette, follows
them but needs no fixtures):

- **A forced request is never answered by a build that started before it.** Two
  concurrent passive gets coalesce into one build; a forced get arriving during a
  passive build makes a second one and receives *its* value; two simultaneous forced
  gets still coalesce into one. Backing the rule out makes the forced caller receive
  the stale value, and one assertion fails on exactly that.
- **Live state moving is not a configuration change.** Two builds over one unedited
  fixture root, through `BuildDeps.createDocker` (§3.11) with an Engine reporting
  different status, health, restart counts and addresses on the second pass, must
  diff to `unchanged`. This is what makes the deny-list load-bearing rather than
  decorative.
- **An edit to anything parsed out of the compose document is reported.** Eight
  fields are edited one at a time on a copied root, plus an `.env` value, plus a new
  stack directory — each must appear in the diff. A comment-only edit and a
  key-order change must not, and a rotated secret must not either, because masking
  runs before the payload exists (**I6**).
- **The wording says what moved, and says so when nothing did.** Singular and plural
  forms, the no-change line, and the announced truncation past twelve stacks. No
  formatted line may contain a fixture `.env` secret, or the API token the
  integration half of the line reports the results of reading with.
- **The integration reads are reported too, and only where there is evidence.** The
  same root read twice with the same stub must state `authentik unchanged` — the
  assertion the whole gap was about. The same root with two *different* API answers
  (the mode A and superuser Authentik stubs; for the proxy, a stub serving its
  runtime config minus one route) must leave the configuration diff `unchanged` while
  the integration diff moves, with every delta signed and the record that came or
  went named. Both diffs disagreeing there is the correct outcome.
- **Nothing is compared across a failed read.** A stub that throws, before and after
  a working one, must yield `stopped` and `started` with empty `counts` — and the
  `stopped` line must contain no negative anywhere, because a `-15 applications` from
  a scan that never reached Authentik is the failure that would make the whole line
  untrustworthy (**I1**). Two failed reads in a row, and an integration nobody
  configured, contribute no entry at all.
- **The cadence is asserted, now that it lives in `formatRescan`.** Quiet on both
  sides and unforced returns nothing; forced answers on both halves; an API that
  moved speaks even though no file was edited.

**The ingress palette agrees with the stylesheet.** Two assertions read
`web/lib/palette.ts` and `web/styles.css` as text: every `--ing-*` variable the
palette names must be defined in the stylesheet, and every `IngressKind` must have
a palette entry. This is the only check on that pair, because both lookups fail
soft to grey rather than erroring (§6). The first also pins the *count* of variables
found, so a regex that stopped matching fails instead of passing vacuously. The
second enumerates `INGRESS_KINDS` itself rather than a list written out in the test,
so adding a kind cannot be half-done: a new member with no palette entry fails
immediately, and renaming one breaks the build.

**The auth palette is read the same way, for a narrower rule.** `AUTH_META`'s block is
parsed out of the same text, and two things are asserted about it: `none` is the only
member `showsAuthMethod` suppresses — so the badge rows cannot start rendering an absence,
and cannot stop rendering a mechanism — and the block contains the finding's wording
nowhere, so the bucket in the distribution bar cannot re-acquire "no proxy auth" (§5, §12).
There is no `AUTH_METHODS` array to enumerate the way `INGRESS_KINDS` is enumerated above,
so the row count is pinned as a number; §3.7 says what that does and does not catch.

**The filter semantics are asserted as a truth table.** `matchesTagFilter`,
`cycleTag` and `describeTagFilter` are called directly — OR, AND, exclusion as
AND-NOT, exclusion beating an include, the empty filter matching everything, the
three-click cycle returning to off, and the four wordings of the readout. The web
bundle is never rendered by smoke, so this is the only coverage the filter can have,
and it is the reason the predicate lives in `model/filter.ts` rather than inside a
component (§3.9).

**The drift panel is asserted through its report, for the same reason.**
`collectDeclarationDrift` is called on both drifting roots and the clean one, and the
assertion that matters is `report.services === stats.declarationDrift` — the panel
cannot list a different set from the one the tile counted, in either root. Beside it:
the entry total against an independently summed one (the second, larger count), each
entry string identical to the service's own `declared.drift` so nothing is paraphrased
on the way to the screen, the stack/service grouping as a joined string, a clean fleet
producing an empty report rather than empty groups, and the three `driftSummaryText`
wordings including both singulars. Ordering is pinned against *reversed* clones of the
stacks and two renamed services, because fixture discovery is already alphabetical and
an assertion over the natural order would pass with no sort at all.

`collectUnconfirmedDeclarations` is asserted the same way over the probe root, and the pair
is what makes the distinction checkable rather than merely written down: over one fleet, one
stack lands in each report — `tunnel-login` in drift, because its acceptance was contradicted
by a login form the probe was actually served, and `declared-open` in unconfirmed, because
its answer contained nothing at all. `portal.declared.drift.length === 0` is the revert trap
for the whole change. Beside it: the entry's text against the clause that refuses the
inference, the verdict unmoved (`supplies`, still out of the exposed count, still counted in
`declaredAuthProtected`), the new counter a subset of that one, the probe-off run producing
neither field, and the write rule itself — every service carrying an unconfirmed entry has
`authAgreement === "supplies"` and a connected probe with no gate, while `own-login/wiki`,
whose probe *did* find a gate, carries none.

**The build stamp is asserted as a resolver table, because a `.git` directory is not a
fixture.** `resolveBuildStamp` takes its environment and its file reads as arguments
([build.ts](labview/src/build.ts)), so the whole precedence is driven from literals: a full
object id shortened to seven, a tag passed through whole, an unset/empty/whitespace variable
falling through to the checkout, the environment winning over a checkout that would also have
answered, a `HEAD` naming a branch followed to its loose ref and then to `packed-refs`, a
detached `HEAD` used directly, and five ways to end up at `unknown` — junk, a branch with no
ref, a ref outside `refs/`, a ref containing `..`, and nothing at all. Git will not let a
repository store a `.git` directory inside a fixture, so an fs-backed version of this test
could not exist. Four of the rows exist to fail if a rule is backed out: without the
shortening the topbar stops matching `git rev-parse --short HEAD`; with the precedence flipped
every container reports whatever tree it can see instead of the commit it was built from;
without the `..` guard a `HEAD` file chooses which path LabView opens (I8); and if `unknown`
is allowed a `commit` the stamp starts inventing provenance. Two more pin the walk itself — a
repository exactly four levels up is found and one five levels up is not, so a LabView
unpacked under an unrelated repository cannot borrow its commit, and a `.git` *file* ends the
walk rather than reporting the enclosing repository's.

The wording is a second table over `buildLabel` / `buildTitle` / `buildSummary`: the label is
the commit and falls back to the version, the `image` sentence is the only one entitled to
"built from", the `checkout` sentence must contain "uncommitted", the `unknown` sentence must
contain no object id and no "built from" at all, and no two of the three may be identical — a
copied sentence is exactly how a weak claim becomes a strong one (§3.7). In the payload,
`meta.build` is asserted present on a fixture run with the real version, with a `commit`
exactly when `source` is not `unknown`; and one run injects a stamp through `BuildDeps` and
checks it arrives verbatim. **No assertion names a commit value off the running machine** —
this suite runs from a checkout, in CI from a clone and inside `docker build` from neither,
so `LABVIEW_BUILD_SHA` is cleared with the other variables at the top of the file (I7).

**Ingress is asserted as a set, in canonical order, as a joined string.** `ing(svc)`
returns `svc.ingress.join(", ")` so a failing assertion prints both sets — `got
"public, lan"` against an expected `"public, traefik, lan"` names the kind that went
missing, which is the whole question when a classification rule regresses.
Element-by-element comparison would report only `false`. One fleet-wide assertion
complements the per-service ones: over every service in both roots, no set carries
`internal` beside an external kind, and `internalServices` equals the number of sets
that are `internal` alone — so a stack added later, or a fourth external kind, is
covered without anyone remembering to extend a list.

**Access control** (§3.13) is asserted at the end of the file and at length — 263 of the
1143 checks — because it is the only part of LabView where a silent regression is a security
hole rather than a wrong label. `fixtures/auth/` is not a fifth scan root: it holds three
passwd files, and nothing in the section reads a compose document. The modules are
imported locally at the bottom, for the reason `node:net` is, so the sections above do not
pay for minting keys and reading files.

`passwd.ok` carries a `$2b$`, a `$2a$` and a `$2y$` entry at cost 4, so the suite stays
fast while `hashpw` defaults to 12 — and one assertion pins that the fixtures' cost is
*not* the default, since a fixture quietly becoming the product's setting is how a cost
gets lowered for everyone. `passwd.messy` holds one line per way a line can be wrong
(duplicate, `$5$`, plaintext, over-long username, no colon, empty hash) and each must
produce its own warning; `passwd.empty` is comments only, which is what pins
open-unless-configured: it must leave enforcement **off**.

The groups, each pinning rules the revert contract can break: hash dispatch and
round-trip, including the decoy's cost and its memoization · `parsePasswd` order,
first-wins and every warning · `readPasswd` across `ENOENT`, `EISDIR`, `EACCES`
(`chmodSync` on a real temporary file) and the size cap, plus the stat-keyed re-read ·
session sign/verify with each segment tampered in turn, expiry, wrong secret, revoked
`jti` · the cookie attribute matrix, including that `Secure` follows the effective scheme ·
the throttle, with an injected clock, keyed case-folded on the username · `resolveAccessMode`
over every configuration and the exact wording of its summary · `isPublicPath` including
`/api/healthz/../overview` and `/api/sessionx` · OIDC authorize-URL parameters and the S256
derivation, issuer mismatch, non-https endpoints, the stubbed token exchange, and ID-token
accept/reject for tampered, expired, wrong `aud`, wrong `iss`, wrong `nonce`, `alg: none`,
an HMAC alg and an unknown `kid`. The ID tokens are signed with an RSA keypair
**generated at test time**, so no private key is committed and no secret scanner has
anything to find.

Three properties are pinned deliberately, because each is the kind of rule that reads like
a simplification:

- **Both postures run end to end.** The gate is driven through `app.inject()` — real
  hooks, real routes, real headers, no socket — first with a passwd file and then with
  none. Everything a unit test cannot see is here: a hook that decides correctly and
  forgets to reply, an allowlist consulted after routing instead of before it, a `401`
  that arrives with the body still attached. The open pass lets a real `/api/overview`
  through, so it runs against a fixture root with Docker and both integrations off — an
  operator's exported Authentik URL must not turn a test into a request to their own lab.
- **A refusal says less than the log does.** `/api/session` without a cookie is checked
  for the *absence* of a username, of the file's path and of the user count; the `401`
  body is asserted to be exactly `{"error":"unauthorized"}`; a wrong password and an
  unknown user get one indistinguishable answer; and a rejected `Origin` is asserted to
  carry no `Set-Cookie`, because the check runs before the session check.
- **The environment cannot reach it.** Every `LABVIEW_AUTH_*`, `LABVIEW_OIDC_*` and
  `LABVIEW_SESSION_*` variable is deleted at startup alongside the integration ones: an
  operator with a real `LABVIEW_SESSION_SECRET` exported would otherwise have the suite
  assert against their own credential, and a real `LABVIEW_AUTH_PASSWD_FILE` would put
  their users' hashes in front of assertions that print what they compared.

`fixtures/outside-root.env` and `fixtures/outside-root.labview` sit outside every scan
root on purpose: they are the targets of the two escape attempts that must be refused —
an `env_file` reaching out of the stack (`fixtures/edge/dbstack`) and a `.labview`
symlinked out of it (`fixtures/edge/escapedecl`). Both are deliberately *valid* files
carrying a `LEAKED_FROM_OUTSIDE_ROOT` marker, and both are asserted by that marker's
absence from the output rather than by a warning's wording: a containment regression
then surfaces as fixture data appearing where a reader would see it, which no rephrasing
of a message can hide (I8).
`fixtures/authentik-api.json` and `fixtures/traefik-api.json` sit beside the roots
rather than inside one so the scanned trees stay purely compose stacks.

Fixtures are also subject to I2 — they use `example.com` and RFC-1918 addresses,
never anything from a real fleet. The stubs' token and password are arbitrary strings
they demand verbatim, and smoke deletes every `LABVIEW_AUTHENTIK_*` and
`LABVIEW_TRAEFIK_*` variable at startup (and forces `LABVIEW_TRAEFIK_ENABLED=false`
for the other three roots) so an operator's real credentials can neither reach the
network nor change a result.

---

## 9. Build, CI, release

```
npm run typecheck   # tsc --noEmit for server, web and scripts (three tsconfigs)
npm run smoke       # pipeline assertions over the fixtures
npm run build       # vite build -> web/dist, then tsc server -> dist/
npm run build:web   # just the UI: vite build --config web/vite.config.ts
npm run build:server # just the server: tsc -p tsconfig.json -> dist/
npm run dev         # build web once, then tsx watch on the server
npm run dev:web     # Vite dev server with HMR, proxying /api and /auth
npm run start       # node dist/index.js — what the image runs, after a build
npm run scan        # one-shot JSON to stdout; --summary for the digest
npm run hashpw -- <user>   # prompt for a password, print one `user:hash` line
npm run probe-lab -- <url> # diagnostic: what the login rule reads at a URL (§3.6b)
```

**The two dev commands are a pair, not alternatives.** `npm run dev` is the whole
product: it builds `web/dist` once and reloads the server on a source change, which
is what you want when the change is in `src/`. `npm run dev:web` adds HMR for the
half where a full rebuild is the slow part — Vite serves `main.tsx` and its imports
as modules, patches a component or a rule in `styles.css` into the running page
without a reload, and proxies `/api` and `/auth` to the server started by
`npm run dev`. So the UI loop is both, in two terminals, with the browser pointed at
Vite's port rather than LabView's.

`/auth` is in that proxy alongside `/api` because the OIDC round-trip is registered
outside `/api` on purpose (§3.13) and the login flow cannot complete without it. The
proxy target is loopback on `LABVIEW_PORT` (default 8080) and lives under `server:`
in the Vite config, which is dev-only configuration and is never inlined into a
bundle — see **I2**. Vite binds `localhost`, so on a host that resolves that to IPv6
the dev server answers on `::1` and not on `127.0.0.1`.

`hashpw` is the second entry point in `dist/`, so the same tool exists in the image as
`node dist/hashpw.js <user>` — which is how an operator hashes a password without
installing Node on the host. The password is prompted with echo off or read from stdin and
**never taken from argv**, because `ps` shows argv to every user on the box.

`tsc` runs with `strict` and `noUncheckedIndexedAccess`; the web tsconfig uses
`moduleResolution: Bundler` since Vite resolves. **All three** projects must
typecheck — the web build imports backend types directly, so a model change can
break the UI without touching a `.tsx` file, and the same is true of the assertions
(§8).

Two details about which project owns what, both of which exist because `tsc` never
sees Vite's own resolution:

- **`tsconfig.web.json` sets `types: ["vite/client"]`**, replacing the previous
  `types: []`. That declaration is what makes `import "./styles.css"` a typed import
  rather than an unresolved module, and it brings `import.meta.env` with it. Node's
  types stay out on purpose: this is the browser half, and a `process` or `Buffer`
  that typechecks here would be a runtime error in the bundle.
- **`web/vite.config.ts` is typechecked by `tsconfig.scripts.json`, not by
  `tsconfig.web.json`**, which excludes it explicitly. It reads `process.env` and
  resolves its own directory from `import.meta.url`, so it needs exactly the node
  types the web project refuses — and the alternative, leaving it out of every
  project, is how a build config quietly stops being checked at all.

The gate before any commit:

```
npm run typecheck && npm run smoke && npm audit --omit=dev --audit-level=high && npm run build
```

CI lives in `.github/workflows/`:

- **docker-image.yml** — runs on every push to `main`. The `test` job runs
  typecheck + smoke and the build `needs:` it, so a broken build or a reverted
  fixture fix cannot reach Docker Hub. The build context is `./labview`, not the
  repo root: the Dockerfile and every path it copies are context-relative, so a
  root context finds none of them. It also passes
  `build-args: LABVIEW_BUILD_SHA=${{ github.sha }}`, which is the only way the image can
  learn its own commit — `.git` is at the repo root, outside that context, and
  `.dockerignore` excludes it in any case. The full sha goes in and LabView shortens it, so
  the stamp in the topbar is the first seven characters of the `:${{ github.sha }}` tag the
  same step pushes (§3.7). A local `docker build` with no `--build-arg` is a supported
  state, not a failure: the image then reports that it does not know its revision, which is
  the path `security.yml`'s bare build exercises.
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
2. For an ingress kind, add it to `INGRESS_KINDS` in `model/ingress.ts` **in its
   place in the most→least-exposed order**, which is load-bearing three times over
   (canonical order of a normalized set, `primaryIngress`'s priority, the dashboard
   row order). Then decide the one question that module exists to force: is it
   exposure? If yes it goes in `EXTERNAL_KINDS` too, and `exposedWithoutAuth`
   changes with it. The list is written positively so a kind that is *not* added
   there is not silently counted as safe.
3. Emit it — `classifyIngress` / `deriveAuth`. An ingress kind is one more
   independent `if` pushing onto the set; nothing needs to be made mutually
   exclusive with it, and nothing may be combined with it into a compound value.
   For an auth method, place it in the precedence `order` array in `deriveAuth`
   instead: a proxy-level gate ranks first because it is what actually stops a
   request at the edge.
4. `computeStats` if it needs a counter (add the field to `OverviewStats`). For an
   ingress kind that is an `includes()` counter, and it overlaps the others.
5. `analyze/graph.ts` if it changes which hub a service hangs off (I3).
6. `web/lib/palette.ts` — add a `RoleMeta` entry, keeping the ordering meaning
   (ingress: most→least exposed; auth: identified providers before generic ones). The
   stack roll-up does not need touching: `rollUpIngress` enumerates `INGRESS_KINDS`,
   so a new kind appears on the stack row from step 2 alone. A new `AuthMethod` also
   raises the literal row count asserted in §8, and is a badge unless `showsAuthMethod`
   is changed to say otherwise — `none` is the only member that is not one, and any
   second exception has to be argued for in `model/auth.ts` rather than added at a call
   site.
7. `web/styles.css` — define the CSS custom property in both themes, from the
   validated palette; do not invent a colour. For an ingress kind, check the new
   entry against its **neighbours in the bar order** in both themes: adjacent rows
   must differ in hue *and* lightness (§3.9).
8. `web/components/badges.tsx` if the new member changes which icon reads right.
9. `web/lib/mermaidDef.ts` if the static diagram labels it.
10. A fixture and an assertion (§8). The palette assertions enumerate
    `INGRESS_KINDS` directly, so step 6 is enforced by construction — but the
    expected variable count is a literal and has to be raised, which is what turns
    step 7 from "remembered" into "enforced". An ingress kind also needs a fixture
    where it is the *only* evidence present, or a revert of step 3 will be covered
    by whichever other kind the fixture also has (this is exactly why `exposeonly`
    exists next to `hostport`).

**Add a field to `Service` or `AppStack`.** The rescan diff (§3.11) compares
whatever it finds, so ask one question about the new field: *does it come out of the
compose document, or out of a live read?*

- **Parsed out of the document** — nothing to do. It is compared by default, so an
  edit to it is reported the day it is added. That default is the point.
- **Derived from a live read** — put it on `VOLATILE_SERVICE_FIELDS` in
  `model/changes.ts`, with a comment saying which read it depends on. Otherwise every
  rescan reports that stack as changed whenever the read's answer moves, which is
  noise the operator will learn to ignore — and an ignored diff is the same as no
  diff.

The failure modes are asymmetric on purpose: the first mistake is loud and gets
fixed, the second is silent. When it is genuinely unclear, leave it compared.

**Add a count to `AuthentikSummary` or `TraefikSummary`.** Add it to the target's
metric table in `model/changes.ts` at the same time, or a rescan will re-read it and
never say it moved — the gap this pair of tables exists to close. Pick `noun` if it
counts things (`+3 applications`) and `label` if it modifies a count of the same
things (`-3 withheld`); if the noun collides with a word already in the line, qualify
it, as Traefik's `services` is qualified to `live service`. Make it optional only if
a read can genuinely produce it sometimes, since an absent value is skipped, not
compared as zero (**I4**). Then extend the `moved` assertion in §8 — the smoke run
compares two API answers over one root, and a metric missing from the table fails
nothing on its own.

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

**Read another endpoint from the identity provider API.** Add the fetch in
`enrich/authentik.ts` — inside the existing `Promise.all`, and returning a soft
error rather than throwing (I4). Extend the model in `enrich/authentik.ts`'s
`buildApplications`, not at the call site, so `analyze/authentik.ts` stays free of
API shapes. Add a page to `fixtures/authentik-api.json` and assert on it; if the new
data can change whether a service counts as protected, assert the exposure count
both with and without the API. Anything requiring a permission beyond
`view_application` / `view_provider` / `view_outpost` is a change to I5 — say so
explicitly and update the token guidance in `config.example.yml` and both READMEs.

Two things a new list read must not drop. **Keep `pagination.count`** — `getList`
returns it, and it is the only way to tell a complete answer from a filtered one; the
applications endpoint has always reported the full total while returning a subset, and
throwing that field away is what made the under-count invisible for as long as it was.
And **ask what filters the endpoint applies to its own answer.** RBAC is not the only
one: `/core/applications/` runs the policy engine as the token's user, and any endpoint
that does something similar cannot be read as an inventory without saying so (§3.5).

**Add a matching rule for applications.** Put it in `matchOne` in
`analyze/authentik.ts`, in descending order of strength, and require **exactly one**
candidate. Before adding one, ask what it would do to a fleet where two services
plausibly satisfy it — if the answer is "pick one", the rule does not belong. Give
it a fixture whose other rules cannot fire, so the assertion tests the new rule
rather than an existing one. Four further obligations:

- **Append to `considered`, on every path.** A rule that finds nothing, finds too many,
  or declines to run must still say so in one line, because that trace is the whole
  answer an operator gets for an unmatched application (§3.5) and a silent rule leaves a
  hole in it that reads as if the rule never existed. Set `contested` when the rule
  produced more than one candidate and `blocked` when it declined on evidence it could
  see — those are what promote the entry to `ambiguous` and what headline the `detail`.
  The line may name only what the payload already carries: service keys, slugs,
  hostnames, provider names, never an env value (**I2**, **I6**).
- **Return a `strength`.** Ask what the rule actually proves: that the provider points
  at this service (`address`), that both sides name one hostname (`hostname`), or that
  the words resemble each other (`name`). Getting this wrong misreports confidence,
  which is the one thing a reader uses to tell a fact from a guess.
- **Resolve addresses in the right space.** Host addresses go through `lookupAddress`,
  container addresses through `lookupContainerAddress`, and the two must not be crossed
  (§3.4). A rule reading a URL must decide which space the host is in *before*
  resolving; on a host running a reverse proxy, port 443 belongs to the proxy.
- **Widen the name forms, not the token list.** If a naming convention is unmatched,
  prefer another *normalization* (a form comparable on both sides) over another word in
  `GENERIC_NAME_TOKENS`, which is bounded by I2. And add a fixture for the guard, not
  just the rule: a fixture proving the rule fires is half the contract, one proving it
  *declines* on an ambiguous or degenerate name is the other half.

**Read another endpoint from the reverse proxy API.** Add it to `snapshotTraefik`'s
sequence in `enrich/traefik.ts`, tolerant of every field being absent, returning a
soft error rather than throwing (I4), and record in `TraefikSummary` whether it was
read — the way `entrypointsRead` does. If a *conclusion* depends on it having been
read, gate that conclusion on the flag rather than on `reachable`: `chainComplete` is
the precedent, and the reason it exists is that a missing read is not the same as a
missing gate. Never send the credential on a probe, and never put it in an error
string. Add the shape to `fixtures/traefik-api.json`, with its assumption written into
that file's `_comment` — the fixture is the only documentation of Traefik's runtime
shapes we have.

**Add a matching rule for live routers.** Same discipline as applications: put it in
`analyze/traefik.ts` in descending order of strength, require exactly one candidate,
and be explicit about which *provider* the rule is valid for — the `@docker`-only
restriction on the router-name rule is not an optimisation, it is the difference
between evidence and coincidence. Ask what an address-shaped rule reads the port as
before reusing an existing lookup (see the container-IP row in §12). The `considered`
obligation above applies here too, with one difference: this matcher tracks `contested`
but deliberately not `blocked` (§3.6), so a rule that is inapplicable for a provider
records the skip in the trace without promoting the router to `ambiguous`.

**Add a new outbound connection.** The diagnostics are shared, so most of this is
already done for you — the work is to route through them rather than invent a
parallel vocabulary.

1. Read through `getJson` in `enrich/http.ts` if it is HTTP. That is where the
   phase and code come from, and it is the whole reason a new integration is
   diagnosable for free. If the client is a library with its own error surface
   (dockerode is the precedent), classify with `phaseForCode` / `phaseForStatus`
   from wherever *that* library puts the code and the status — write a
   `classify<X>Error` beside it rather than teaching `http.ts` about it.
2. Return a `ConnectionReport` from **every** exit of the snapshot function,
   including the ones that are not faults: `disabled` when switched off,
   `not-configured` when nothing was asked for, `not-found` when it was asked for
   and no candidate could be located. A missing report is worse than a failed one —
   the target silently vanishes from the log and the banner.
3. Fill `read` on success with what arrived, as aggregate counts (I2). This is what
   makes the success line worth printing: `connected` alone does not tell an
   operator the credential has the rights the read needs.
4. Add a `hintFor` row per phase that has a distinct fix for this target. Skip the
   ones where the generic wording is already right; an unhelpful hint is worse than
   none, and hints are worded as the likely fix ("check that…", "set…"), never as a
   diagnosis of the operator's network.
5. Push the report into `meta.connections` in `analyze/index.ts`. Nothing in
   `server.ts`, `cli.ts` or the UI needs touching — they loop over that array, and
   the log cadence, banner predicate and formatting all follow.
6. Assert it: the phases the new client can produce, and a formatted line from a run
   that was handed a credential not containing it (§8). If it has a timeout, assert
   both directions of the deadline the way the docker one does — a classifier that
   only ever returns the interesting phase proves nothing.

---

## 11. Known limitations

Not bugs — bounded scope, stated so nobody assumes otherwise:

- **Traefik dynamic-file config is invisible to the scan.** Only label-defined
  middlewares are in the registry. A middleware from a file provider resolves to
  nothing, which is why the name-based fallback and `confidence: "inferred"` exist.
  Reading the proxy's API (§3.6) is the only way out of this, and it removes the gap
  rather than narrowing it — the proxy holds the definition. Without that read the
  limitation stands unchanged, and the static config file is never parsed either:
  nothing guarantees it lives under `appsRoot`, and the API supersedes it.
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
  that config is outside what a *file* scan can know. Both APIs narrow this — an
  outpost assignment is enforcement rather than intent, and a middleware in the
  proxy's runtime chain is the config it is demonstrably running — but it is still
  configuration. LabView never sends a request through a gate to see what happens.
- **A login page the probe cannot recognise reads as an exposure — and that is the
  direction the error has to run in.** Every gate rule fires on something present in the
  response, so a page that gates by means no rule names is reported as exposed without
  authentication. That is a false finding in the noisy direction, and it is the tolerable
  one: a gate can only ever take a service *out* of the exposed count, so a rule loose
  enough to catch the remaining cases would clear real exposures instead. Four known
  misses, each left open deliberately — the first narrowed twice since, once by an extra
  request and once by reading the same response the other way round, and neither closed it:
  - **A login shell rendered by script — narrowed twice, not closed.** A single-page
    app that ships an empty `<div id="root">` and builds its form in the browser has no form
    in the HTML, and nothing in *that* response distinguishes it from an open dashboard. There
    is no headless browser and there will not be one — that is a different program. What there
    is instead is `state-challenge` (§3.6b): the one shape no body can judge gets a second
    request, at the current-user addresses in `STATE_PATHS`, and a refusal carrying
    `WWW-Authenticate` settles it. That closes the subset whose API asks properly and leaves
    the rest open, deliberately — an API that refuses with a *bare* 401 is what an
    anonymous-enabled Grafana and a world-readable Gitea both answer, and reading that as a
    gate would clear genuinely open services. Those are reported (`ProbeState.refusedAt`, in
    the drawer's own words) and not counted.

    The second narrowing is not another gate rule; it is the **population** this miss draws
    from getting smaller. "No `<form>` in the markup" used to cover two quite different pages —
    an empty shell, and a fully prerendered application whose sign-in is one anchor — and both
    came back as *no signals fired*. `readAnonAccess` (§3.6c) reads the second one positively:
    content served to an anonymous caller, beside an offer to sign in, is an application with an
    optional account rather than a gate in front of one, and the reason says so in the page's own
    words. So a prerendered page is no longer a blind spot at all; what remains one is a body
    that rendered *nothing*, which is a much narrower and much more recognisable thing. Note
    which way that runs: it adds a sentence to an `open` verdict and can only ever leave a
    service **in** the exposed count, so it narrows the doubt rather than the count — the one
    new reading in this stage with no I1 exposure of any kind.

    **Where this stops, and what would reopen it.** Two further extensions were weighed at this
    point and both declined, which is worth writing down because the second one is cheap enough
    to look obvious. Rendering is out for the reasons above, and one more: a rendered DOM needs a
    *settle* decision — network-idle, or a fixed wait — so the observation becomes
    time-dependent, and a slow bundle would let a service leave the exposed count on one scan and
    return on the next, which is I7 broken in the one direction a count must not move.
    **Fetching what the page merely named** — the bundle, the stylesheets, the chunk graph — needs
    no browser and no execution, and is still out, for a reason that is a property of the artifact
    rather than of the effort: a bundle is *deployment-invariant*. An anonymous-enabled Grafana
    ships the same JavaScript as a gated one, so a login route literal or a `"Sign in"` string in
    it proves the application **has** a login screen, not that this deployment put one in front of
    anything. That is exactly the reading `login-route` already carries in the lab at `weak`, and
    it can never be promoted past it, because clearing an exposure on it would clear the open
    services with the same bytes. The general rule both refusals follow: **evidence of a gate has
    to come from what happened to *this* request at *this* address** — the answer at `/`, where it
    redirected, or the application's own refusal of an anonymous caller. Everything else
    establishes that accounts exist, which is a different proposition;
    `fixtures/probe/public-portal/app` is that distinction as a fixture, and it is why the lab's
    `--try-login-paths` guesses land in section 4 as a proposal rather than becoming a ninth
    signal — a login form at `/login` is what an open application with an optional account serves
    too.

    So the residue is priced, not ignored. On the fleet this was built against it is two services,
    both shells whose API refuses an anonymous caller with a bare 401, and both already carry a
    declared `app-local-accounts` login in a sidecar — which takes them out of the exposed count,
    says the word *declared* while doing it, and leaves what the scan detected untouched (§3.9).
    The miss therefore costs one line per service, once, rather than a wrong count. What would
    reopen it is a **cheap disambiguator for the bare 401**, and the most promising shape is
    `readAnonAccess`'s question asked one layer down: whether the API *serves* anything to a
    caller with no credential as well as refusing its current-user address. An application that
    refuses everything anonymously is not the anonymous-enabled Grafana the bare 401 has to stay
    safe for. That fact is deployment-specific, so unlike anything in a bundle it could reach gate
    strength — and it would arrive the way `state-challenge` did: measured in `tools/probe-lab`
    against real bodies first, then a rule, a fixture, and a revert trap.
  - **A form past the body cap.** `MAX_BODY_BYTES` is 64 KiB and the read stops there, so
    a login form below an inlined stylesheet or a base64 hero image is never seen. The cut
    may also land inside a tag, in which case that element is simply not counted: a
    partial read yields a partial shape, never an exception (I4), and both halves of that
    are asserted (§8). The miss is now **reported** where it can be: the response carries
    `truncated` when the read stopped at the cap, and `probeReasonText` appends the caveat
    that the page continued past what was read. That narrows the entry rather than closing
    it — the reader is told the answer may be incomplete, which is all an unread byte can
    support, and a page exactly 64 KiB long does not raise it because the stream reported
    itself done.
  - **A login action nothing recognises as one.** `credential-form` needs a login-intent
    marker, and one of the two is the form's action resolving onto a `LOGIN_PATHS` path.
    NextAuth-style endpoints — `/api/auth/callback/email` and its neighbours — are outside
    that list, so a magic-link form posting there, with no `one-time-code` field either,
    looks exactly like a newsletter box. Adding an `/api/auth/` prefix would recognise it
    and would also accept whatever else an app happens to serve under that path, which is
    the trade the asymmetry above forbids on a likelihood.
  - **The shape of a challenge page is never read.** `readGate` reads a body only on a
    200. No exposure is missed by that — a 401 or 403 is already `challenge`, for a
    stronger reason than any body could give — but `svc.probe.form` is absent for those
    services even though a login form was served, so the drawer cannot say what the form
    was made of.

  `tools/probe-lab` exists to work these misses down one at a time (§3.6b): pointed at a URL
  it reports why each of the eight signals did not fire and dumps the evidence none of them
  reads, which is the material a ninth signal would be designed from. `state-challenge` is what
  came out of it: five reports against real services, four of them form-less shells, and the
  fifth a redirect chain whose first `Location` was a path `LOGIN_PATHS` simply did not have. It
  changes nothing about a scan — it is a diagnostic, not in the image, and imports the rules
  rather than restating them.

  `readAnonAccess` came out of the same loop, and out of the tool's own gap rather than the
  rule's: eight reports later, three of them described twenty-four kilobytes of prerendered page
  as "no `<form>` element in the served markup", because the only things `readUnread` captured
  were forms, scripts and the `<title>` — no `<a href>`, no anchor text, no form-less control, no
  visible text at all. The proof the operator could see in a browser was a plain
  `<a href="/login">Sign in</a>` that nothing in the tool had ever read. So the extraction grew
  to cover the whole of what a page shows, section 3a says what those facts *prove* about a
  visitor's view, and one of the six detectors was worth promoting into the pipeline — the only
  one pointing at *open*, and therefore the only one that could be promoted without a rule getting
  looser. The candidate ninth signal the tool now proposes (`login-heading`: a title saying login,
  no form, one bundle) is deliberately still a proposal.
- **A service behind a detected gate is no longer measured at all.** Since the probe skips
  every service this scan found authentication for (§3.6b), a configured gate that has
  quietly stopped working — a forward-auth middleware pointing at a dead outpost that now
  fails open — no longer shows up as an open answer behind a declared mechanism. That was
  never *reported* as a finding, because the configured posture won either way; it was
  visible only in the drawer's probe block, to a reader who went looking. The direction of
  the loss is the important part and it is the safe one: skipping can only ever leave a
  service **in** the exposed count, never take one out. What was bought is not sending an
  unauthenticated `GET` at somebody's SSO endpoint on every scan. A reader who wants that
  measurement can take it with `tools/probe-lab`, at one address, deliberately.
- **The proxy integration is Traefik-specific.** Another reverse proxy is still
  classified from its labels and simply not verified; there is no second client.
  Only `/api/rawdata` is used, with no fallback to the paginated granular endpoints,
  and no write call of any kind exists. The response shapes come from Traefik v3's
  runtime model rather than a published schema, so the parser is deliberately
  tolerant and a mismatch degrades to `reachable: false` with a reason (I4).
- **A live router is only as attributable as the fleet makes it.** With no Docker
  state the backend-address rule is skipped entirely, and a `@file` router with a
  host rule matching two services stays unmatched by design. Expect entries in
  `unmatchedRouters` on a fleet whose routing lives mostly in file providers; the fix
  is a label, not a looser rule.
- **Only applications, providers and outposts are read from the identity
  provider.** Policy bindings are not, so an application whose access policy denies
  everyone reads as protected (it is), and a flow customization that weakens a gate
  is invisible. Provider types beyond proxy/oauth2 are read from the application's
  embedded `provider_obj` only, so their type-specific fields (a SAML ACS URL, for
  instance) are not available for matching.
- **A recovered application is a thinner record than a returned one, and some cannot
  be recovered at all.** Rebuilding from a provider yields no launch URL and no group,
  and only the providers this token may read, so such an application can be tied by
  address or by name but never by a launch URL (§3.5). An application whose only
  provider is a kind LabView does not fetch — SAML, or LDAP without a proxy alongside
  — is named by nothing readable and stays a count. That is why a least-privilege token
  can produce a `partial` banner no scan will clear: the honest alternative to the
  silent under-count, not nagging. Superuser on the token's account removes the filter
  entirely; widening the account's policies removes it case by case.
- **An unmatchable application is reported, not resolved.** Four rules (§3.5) are not
  every naming convention an operator might use, and an application whose slug, name,
  provider names and URLs all resemble two services equally is discarded on purpose. So
  expect some unmatched, and read `meta.authentik.unmatchedApplications` — behind the
  `authentik` count in the topbar — as the list of gates LabView can see but cannot
  place, each with the rule-by-rule trace of what it tried. The fix is a name or a
  redirect URI that agrees with the compose file, not a looser rule: every loosening
  trades a visible gap for an invisible wrong answer.
- **A name match cannot be verified, only reported.** Rule 4 rests on the operator
  having named things consistently. Two independently-named services could satisfy it
  the same way and only one be right — the matcher can tell that *two* candidates exist
  and decline, but not that a single candidate is the wrong one. That is what the
  `observed` confidence and the "by name alone" wording are for; a fleet where it
  matters should give the application a redirect URI naming the container, which moves
  the same match up to rule 2.
- **A connection phase describes the answer, not the network.** It is derived from
  one error object or one response, so it can name the stage that failed and the
  likely fix, but it cannot tell a firewall from a stopped container, and dockerode's
  error surface is not a documented contract — an unrecognised code falls through to
  `connect` carrying the raw message. A wrong phase yields a wrong *hint*, never a
  wrong posture: diagnostics feed no conclusion about the fleet. There are also no
  retries, no backoff and no on-demand probe endpoint; a phase is what one attempt
  during one scan produced.
- **A network's members are the ones this scan can see.** An `external:` network can carry
  containers from outside `appsRoot` entirely, and nothing in a compose file names them.
  So a network node states its scope and its *scanned* member count, and a network with
  one visible member says so in words rather than being reported as empty — but the far
  end of an external network is genuinely not knowable from the files (I1). Membership is
  also reachability in principle, never a claim that anything is listening; that is what
  `ports:`/`expose:` answer.
- **A cross-stack dependency exists only if somebody writes it down.** Compose cannot
  express one, and nothing in the files distinguishes two services that share a network
  because one backs the other up from two that merely both sit behind the same proxy. So
  LabView draws neither and asks for the sidecar's `depends_on` (§3.12) — which means a
  fleet that declares nothing shows every cross-stack relation as bare co-membership. That
  is the honest reading of what the files contain, and the alternative was inferring
  connections from co-membership, which on one proxy network is hundreds of false lines.
- **A declared dependency is unverifiable by construction.** It resolves to a real scanned
  service and it may still be wrong: the operator can declare a dependency that no longer
  exists, and no scan can contradict it — the same shape of risk the rest of the
  declaration layer carries, and the reason it is dashed and attributed rather than
  presented as a finding. What LabView *can* check is that the reference still names one
  scanned service, which is what `drift` reports.
- **An unqualified reference is resolved by a rule, not by understanding.** `depends_on:
  [postgres]` in a fleet where three stacks each run a `postgres` resolves to the
  declaring stack's own — which is what compose's key would mean, and is usually right,
  but *usually* is the whole caveat. With no local candidate and two elsewhere LabView
  declines and reports both; with one elsewhere it resolves, and a fleet that later adds a
  second same-named service turns that reference into drift rather than silently
  re-pointing it. Qualifying as `stack/service` avoids the question entirely.
- **A hub with two dependencies across it does not say which pairs with which.** The
  arrowheads on a membership edge belong to the service, not to a pair: a network with
  `a → b` and `c → d` over it draws four arrowheads and cannot show the pairing. The
  Networks section names every pair in words for that reason, and the drawer separates
  `depends on` from `required by` per dependency. The picture is the index; the pairs are
  in the text.
- **A large network is summarised, not drawn whole.** The fleet graph draws at most 12
  spokes per network node; the drawer names at most 8 dependencies and no co-members at all,
  and the Networks section 12 member chips before a row is expanded. Each states how many it
  left out, and the service drawer reads the unpruned graph so nothing is unreachable. But a
  monitoring network with forty members is a count on a node plus a list under the network's
  own heading, not forty lines — deliberately, since forty lines is what makes the small
  informative networks impossible to find.
- **A service's own view of a network is deliberately incomplete about its membership.** It
  says how many others are on it and not who, and the only route to the names is the link to
  the fleet Networks section. That is a real limit: a reader who wants both at once has two
  places to look. It is the intended trade, because the alternative measured worse — a
  truncated list of a proxy network's members, in the same chips as the dependencies, is read
  as this service's connections while saying nothing about this service at all.
- **No history.** Every scan is a snapshot; nothing is persisted, so there is no
  drift detection or change log.
- **The probe switch lasts one rescan, so probe results appear and then leave on their
  own.** A timer rebuild passes no override and falls back to `probe.enabled`, which means
  a fleet scanned with the switch on shows gates until the TTL expires and then shows the
  configuration's answer again. This is mitigated rather than fixed: `meta.probe` states
  what *this* build did and which of configuration or request decided it, and the checkbox
  re-syncs from it on every overview, so the revert moves the switch instead of leaving it
  claiming something untrue. The two ways to actually fix it are both worse — persisting a
  runtime setting, when nothing else here is persisted (above), or letting one visitor's
  click change what every later scan does, including scans nobody asked for. An operator
  who wants probing on for good sets `probe.enabled` and gets it on every build.
- **The Docker snapshot lists all containers**, including ones with no compose
  file under `appsRoot`; those simply do not match a service and are not reported.
- **A `checkout` build stamp cannot see uncommitted work.** The commit comes from reading
  `.git/HEAD`, which is the last thing committed — so a tree with edited, staged or stashed
  files reports the commit it diverged from, and two developers with different working trees
  can show the same seven characters. There is no fix that stays inside a file read: knowing
  the tree is clean means running `git status`, and shelling out to git from a scan is a
  bigger change than the stamp is worth. So it is *said* instead — the tooltip on a
  `checkout` stamp states that uncommitted changes are not reflected (§3.9), and an `image`
  stamp, which is baked in at build time from a committed sha, carries no such caveat. What
  the stamp is good for is the case it was added for: identifying which *built* artifact is
  running.
- **A linked worktree or a submodule reports no revision.** `.git` in those is a file
  pointing at a real git directory elsewhere; following it leads into another repository's
  layout, and walking further up the tree would report the *enclosing* repository's commit,
  which is a different build. Both are wrong answers, so LabView gives none and says
  `unknown`. `LABVIEW_BUILD_SHA` is the way to stamp such a tree, and it is what the image
  uses anyway.
- **Sessions do not survive a restart.** There is no session store, and the revocation
  set is in memory beside it — so a restart, a redeploy or an image pull signs everyone
  out. With `auth.session.secret` unset it is stricter still: the secret is minted per
  start, so every existing cookie is invalid rather than merely forgotten. Setting the
  secret makes cookies survive a restart, and makes two replicas behind one proxy
  interchangeable, but the revocations do not: a token signed out just before a restart
  becomes valid again for the remainder of its TTL. The bound on that is
  `auth.session.ttlMinutes`, which is the knob to lower if it matters.
- **Everyone who signs in sees everything.** Authentication without authorization
  (§7): there are no roles, no per-stack scoping and no read-only-vs-detail distinction,
  because there is nothing to write and the whole page is one inventory. A fleet that
  needs some people to see only some stacks needs a second LabView with a narrower
  `appsRoot`, not a permission model.
- **The login is a gate in front of the API, not a filter inside it.** `index.html`,
  `styles.css` and `app.js` are served to anyone who asks, which is safe only because
  I2 holds — the bundle carries no fleet-specific identifier by construction. If a
  future change puts anything fleet-derived into a shipped artifact, the gate's scope
  becomes wrong, and that is a change to I2 before it is a change to §3.13.
- **The passwd file is read, never written.** There is no password change, no reset and
  no user management in the UI; `hashpw` plus an editor is the whole administrative
  interface, and it is deliberate (I5). Nor is there any lockout state on disk: the
  throttle is in memory, so a restart clears it along with the sessions.
- **OIDC is one provider, and group membership is the provider's business.** A single
  issuer is supported, LabView reads no groups or roles from the ID token, and every
  successful sign-in is equal — so *who may sign in* is decided entirely by the policy
  or group binding on the provider's side (§3.13). ID tokens must be signed with an
  asymmetric algorithm; a provider that only offers HMAC cannot be used.

---

## 12. Decision log

Why the non-obvious choices are what they are. Read before reversing one.

| Decision | Rationale |
|---|---|
| Published ports are reachability, not metadata | `ports:` makes a service answerable at `hostIP:port` with no proxy and no SSO. Treating it as decoration under-reported exposure on real fleets. |
| The ingress kinds are named `public` / `traefik` / `lan` / `internal` / `none` | These are the situations an operator distinguishes, and the previous `local` (meaning *proxy route*) collided with the separate LAN concept — the tile said "Local" for something that was not the LAN. `traefik` names a product against I3, admitted because the kind is derived from Traefik-format labels, so the name follows its evidence. |
| `svc.ingress` is a **set** of independent kinds, and nothing is ever combined | A single-valued field forced the vocabulary to grow combinatorially, and it still could not express the fleet: a service that was tunnelled *and* proxied *and* published a port had no value at all, so the classifier silently dropped the LAN half. Compound values (`public+lan`) made the counters need folding to stay disjoint, which made "Traefik 2" true and useless in a fleet with 26 proxied services. Independent tags say each true thing once; the cost is that the counters overlap, which is stated rather than hidden. |
| `internal` is positive evidence, not the leftover bucket | As a fallback it meant "nothing else applied", which is not a fact about the fleet — it conflated a database two containers talk to with a service nothing can reach at all. Now it requires proof another container can reach it (`expose:`, or a shared real network) and `none` is a populated category. It buys a `noIngressServices` that answers the question the old value only appeared to. |
| `internal` is **reported only when it is the only way in** | The other four kinds are independent of each other; this one is not independent of them. Nearly every service in a real fleet shares a network with a neighbour — 82 of 86 on the fleet this was measured against — so reporting it everywhere puts the same tag on almost everything, and a tag that is true of nearly everything says nothing about any of it. The service a reader is looking for is the one reachable *only* over the container network (the database behind a frontend), so that is the only place it is shown; the frontend shows `public`/`traefik`/`lan` alone. It is a withholding, not an inference: the evidence is unchanged, `internal` is still positive evidence, and I1 holds because nothing was added. It costs the ability to tell from an externally-reachable service's tags whether a sibling also reaches it — which the drawer's Networks section and the graph's network edges still say — and it moved `internalServices` from 82 to 25 on that fleet, which is breaking for a JSON consumer and worth it: that counter now answers a question. |
| The **stack roll-up** is exempt from the withholding | A stack is not a service. Its badges are a union — the whole reason a collapsed row is not reduced to a "worst case" — so a public frontend beside a database only its neighbour can reach is a stack that is legitimately both, and the row saying `Public` `Internal` is what tells a reader there is something inside worth expanding for. Renormalizing the union would let the frontend's exposure delete the database from the collapsed view, which inverts the request that prompted the rule. So the union is built by `rollUpIngress` and not by `normalizeIngress`, the two are documented against each other, and the exemption is asserted over every mixed fixture stack rather than trusted: the roll-up is now the only stack-level place `internal` appears, and it previously lived as an inline expression in a `.tsx` file where nothing could test it. |
| A connection between two services is drawn `service → network → service` | The two obvious drawings each hide the thing the reader came for. A network hanging off one service says nothing about what that service reaches — the far end is missing. A line straight between two services hides *what joins them*, which is the answer to "can I move this container" and "what else is on that network". Putting the network in the middle makes one shape answer both, and makes the cross-stack case *drawable* at all: two compose projects cannot declare anything about each other, so the network they share is the only place a relationship between them can be shown. Being shown there is not the same as existing — that is what the sidecar's `depends_on` is for, and the next row. |
| A dependency is drawn as arrowheads on the membership edges, not as its own edge | With the network in the middle, a separate `depends_on` edge beside it states the same relation twice and invites the reader to believe the two are different facts. So `flow` puts the arrowhead at the network end for the dependent and at the service end for the dependency, and following the arrows reads dependent → network → dependency. It costs the pairing on a hub carrying two dependencies (§11), which the Networks section and the drawer state in words; a labelled edge would not have recovered it either, since cytoscape renders no edge labels. |
| ...and the direct edge survives only where no network carries it | An empty `via` is not a missing value, it is a finding: compose orders the two containers' startup and neither can address the other. That is the one case where a line straight between two services is the honest drawing, so it is kept and the dependent also gets a note — a picture of an oddity that reads like a normal edge is worse than no picture. A *declared* dependency with an empty `via` gets the same drawing and a different note, because nothing orders those two containers at all. |
| **Co-membership of a network is not a connection between two services** | The first version of the network feature treated every service on a shared network as a peer of every other and drew them that way. On a real fleet's proxy network that is every published service joined to every other published service — 30 members become 435 lines — and it is false: they share a path, nothing more. So a leg in a service's diagram now requires a dependency, and "who else is on it" is answered by a separate list under its own heading. The fleet relationship graph is the one exception, and deliberately: that view *is* the membership picture, so its spokes stay, and an arrowhead is what marks the ones a dependency crosses. |
| A cross-stack dependency is **declared in the sidecar**, under a new `depends_on` key | Compose cannot express one, and nothing observable distinguishes "backs this database up" from "also behind the same proxy" — so the operator is the only source, and refusing to have a source at all was what forced the co-membership drawing above. A new key rather than the existing `dependencies:` because that one is prose about things *outside* the fleet: a key whose entries must resolve can report a typo loudly, while a mixed list cannot tell a typo from a sentence. |
| Declared **once, on the dependent**; the other direction is always derived | The target's drawer needs to list its dependents — that is most of the value, since a backup agent's own file says nothing about what it backs up — but a `required_by` key would have to be edited every time anything new depended on it. Nobody maintains that, and a list nobody maintains is worse than no list. So the declaration is one-sided in authoring and two-way in display, read off the same edge from both ends. |
| `depends_on` is **service level only**, with its own warning at stack level | A stack-level entry cannot say which of the stack's services depends on the target, so it would have to be applied to all of them or to none. Both are wrong, so it is refused — and refused with a warning that names *that* reason rather than the generic unknown-key line, because a reader who put it in the wrong place needs to know where it goes, not that it does not exist. |
| An unqualified reference prefers the declaring stack, and an ambiguous one is drift | `depends_on: [postgres]` almost always means the sibling, which is also all compose's own key can mean, so resolving locally first is the least surprising rule. Two candidates in other stacks and no local one is not guessable: both are named, no edge is drawn, and the operator qualifies it. Guessing there would produce a line between two services with no relationship, which is the failure this whole change removed. |
| Resolution lands on the graph, never on the declaration | The parsed declaration is what a rescan compares to report an edited sidecar (§3.11), so a resolved target stored inside it would make a rename in *another* stack read as this file changing. The reference is kept exactly as written; the edge carries `declaredBy`. A reference that stops resolving becomes `drift`, which that comparison already excludes. |
| A declared dependency is **dashed** everywhere, and changes no verdict | I1 with an input that has no evidence behind it: the relation is drawn because the operator stated it, so it is drawn differently from one that was read out of a compose file, and its chip names the file that claimed it. It alters no ingress kind, no exposed count and no auth posture — it draws a relation and nothing else. |
| The drawer has one cap, because it has one list | Dependencies are capped at 8; co-members are a count with nothing to cap. An earlier version gave them their own, larger cap and their own list, on the reasoning that a name in a sentence costs less than a leg in a diagram — which was true about cost and wrong about meaning. With one list left, no number of merely-reachable services can push a real dependency out of the picture, which is what the two-cap split existed to prevent. |
| **A service's network row names its dependencies and counts everyone else** | The drawer used to name co-members too, in a second list under *also on it*. On a shared transport network — the proxy network half a fleet sits on to be reached by Traefik — that list is the case it cannot serve: it is arbitrary (scan order), truncated, and in chips identical to the dependency chips beside it, so it reads as *what this service is connected to*, which is the claim this whole module exists to deny. It is also not about this service: membership is a property of the network, and the same list appears in the drawer of every member. Rewording it does not fix either problem, and a size threshold only moves the line. So the names left, the count stayed, and the network's name in the row head became a link to the fleet Networks section — the network-scoped view, under the network's own heading, where every member is named and the question actually belongs. Nothing about dependencies, edges, `via` or `flow` changed: this removed names from one list and added a number and a link. |
| A single-member **external** network is drawn; a single-member **stack-local** one is not | Both look identical as a count, and they say opposite things. Nothing else *can* join a stack-local network that one service created, so it connects nothing and never will. An external network with one scanned member means something outside the scan may be on the other end — a real statement about reachability, and the only place the scan's own boundary is visible. Dropping either arm loses a different truth, which is why the rule is two-armed and each arm has its own fixture and its own revert check. |
| Large networks are capped at 12 spokes rather than expanded on demand | A monitoring network with forty members renders forty lines through the middle of the graph, and the small networks that carry an actual dependency become unfindable. Interactive expand/collapse was the alternative and was rejected: it re-runs the layout, moves every other node, and answers "who else is on this" worse than a list does. So the cap is fixed, dependency-carrying spokes survive it first, the node states `+k not drawn`, and the drawer reads the unpruned graph — the information is never gone, only not in the picture. |
| A fleet-level Networks section, beside the graph rather than inside it | "Show me every service on this network" is a list question, and a layout engine is a poor way to answer it — the answer moves every time it is asked. One collapsible row per network, members as chips, dependency pairs in words, needs no layout and is the only place the hub pairing can be stated exactly. It filters through the same `showsNetworkNode` the graph draws with, so the picture and the list cannot come to disagree about which networks exist. |
| One membership index, replacing three independent computations | The same relation — who shares a real network with whom — was being computed in `sharedNetworks`, in the fleet index and again in the graph. This feature needed a fourth view of it, and four implementations of one relation is four chances for the `internal` ingress tag to mean something different from the line drawn on screen. `buildNetworkIndex` is built once, after the pass that attaches live network names, and the other three read it. |
| The withholding lives in `normalizeIngress`, not in `classifyIngress` | A kind set has exactly two sources — the classifier, and a `.labview` `expected: ingress:` list — and `normalizeIngress` is the only constructor for both. Putting the rule there means a sidecar written as `[public, lan, internal]` is read as `[public, lan]` and agrees with the scan, instead of drifting against a rule the file cannot know about. Collapsed silently rather than warned about: writing down everything that is true of a service is not a mistake, and a warning would train operators to omit true things. The alternative — hiding the tag in the badges only — would have left `stats.internalServices`, the filter chip and the gauge all answering the old, useless question. |
| `depends_on` is not evidence of reachability | It expresses start order, not a network path: two services in disjoint networks can depend on each other and never connect. Counting it would make `internal` true for pairs that cannot reach each other, which is the exact failure the change above was made to fix. |
| `lan` is tagged whether or not a proxy is in front, and the bypass note stays | As a fallback kind, `lan` answered "publishes a port with nothing in front of it", so the count could not answer "how many publish a port" — the more useful question, since a published port is answerable with no proxy and no SSO in the path. Both are now available: the tag counts the port, and `noteHostPortBypass` still says the proxied service can be reached around its gate. That note is not cosmetic; it is the difference between "protected by SSO" and "protected by SSO unless you use the port". |
| The ingress distribution is per-tag gauges, not a stacked bar | A part-to-whole bar whose segments sum past the total misstates every proportion in it, and clicking a segment labelled `11` would return 26 rows. The auth bar stays part-to-whole because `auth.method` is still single-valued. |
| Filter chips are tri-state with an `Any`/`All` switch, exclusion always AND-NOT | Multi-valued tags make "which of these" ambiguous — a set, a mode and an exclusion are three different questions, and a single on/off chip can express none of them. The cycle puts NOT on the chip the operator already knows instead of a second control elsewhere. Exclusion wins over an include because it is the more specific statement, and because a filter that quietly ignored one of its own chips would be worse than one that returns nothing. |
| The filter expression is evaluated **per service** | Same reason filtering is service-level at all (§3.9): `All of Public, LAN` has to mean one service that is both, not a stack containing one of each. A stack-level reading would answer a question nobody asked and would hide which service actually matched. |
| The filter predicate lives in `model/filter.ts`, generic over string tags | The web bundle has no test harness, and AND/OR/NOT precedence is precisely the logic that must be asserted rather than eyeballed (§8). Generic rather than typed to `IngressKind` so the auth dimension reuses it unchanged. |
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
| The identity provider API is opt-in and read-only | It answers the one question compose files cannot: whether a configured gate is actually being enforced. But it needs a credential, so it stays off until the operator supplies one, and it never needs more than three `view_*` permissions because it only ever issues `GET`s. |
| A discovered endpoint is probed unauthenticated before the token is sent | A discovered address is a guess. `/api/v3/root/config/` is `AllowAny` upstream, so identity can be established without spending the credential — and a wrong guess (or a host that has taken over the name) never receives one. |
| Internal container addresses are tried before public hostnames | The public hostname routes back out through the tunnel and the proxy, so it works but traverses the whole edge — and on a fleet where the provider fronts itself, that means authenticating to read the API. The container address is the same instance, one hop away. |
| No flag to skip TLS verification | A bearer token sent to an unverified endpoint is a token given away, and such flags are set once "to get it working" and never unset. `NODE_EXTRA_CA_CERTS` covers a private CA; plain HTTP over the container network avoids the question. |
| Provider→application is joined via the application's embedded `provider_obj` | The application embeds its provider *and* its group and launch URL, so joining from that side yields the complete record in one read. The provider endpoints do name their application — `ProviderSerializer.Meta.fields` carries `assigned_application_slug` and `_name` — but that direction gives a strictly thinner record, so it is the fallback for applications the list withheld, not the primary. |
| Applications the policy filter withholds are rebuilt from the providers already read, not from a new endpoint | `/api/v3/providers/all/` would reach provider kinds LabView cannot match on anyway, and it is a further permission to ask for. `providers/proxy/` and `providers/oauth2/` are already read, are RBAC-only rather than policy-filtered, and carry both the application assignment and the fields rules 1–2 match on. So the recommended token stays the same three `view_*` permissions. |
| `superuser_full_list=true` is sent unconditionally, with no config knob | It is ignored for a non-superuser token, so it can only widen the answer — there is no case where an operator would want it off. A knob would add a way to be under-read silently, which is the defect it fixes. |
| `partial` is reported on `withheld - recovered`, not on `withheld` | A banner nobody can clear becomes furniture and stops being read. Recovery that closes the whole gap has nothing left to warn about; a gap recovery *cannot* close is a real limit on what LabView can conclude, and the hint names both ways to close it. |
| An application matching two services matches neither | Arbitrating by iteration order would move a service between "protected" and "exposed" on a coin toss, and the result would look identical to a real finding. An unmatched application is a visible gap the operator can close with a label. |
| A provider with no outpost protects nothing | Proxy, LDAP and RADIUS providers are enforced by an outpost in the request path. With none assigned, nothing is in any path. This is the integration's most valuable output precisely because the admin UI shows such an application as complete. |
| SAML gets no `AuthMethod`, but is excluded from exposed-without-auth | Every `AuthMethod` has a palette colour and the only one left is the red reserved for the exposure warning — colouring a protected service in the warning colour is worse than having no badge. Reporting it as reachable without auth, though, would be plainly false, so the count excludes it and the drawer names the provider. It is also the one case behind `NoAuthReason`'s `unnamed-gate` (§5): the `Method` row reads `None named — gate confirmed` rather than leaving the reader to infer a missing gate from a blank. Revisit if the palette gains a colour. |
| `forward_domain` external hosts are not matched on | In that mode `external_host` is the authentication domain shared by every application in it, usually the provider's own hostname. Matching it attaches unrelated gates to whichever service serves the SSO domain — which is the identity provider itself, so the error inflates the protected count. |
| The hostname index dedupes by service key | A service fronted by both a tunnel and a reverse proxy declares the same hostname in both label sets. Those are two statements about one service; counting them as rival candidates makes the commonest configuration in a fleet unmatchable. |
| A redirect URI's bare-name host is resolved as an address; an IP literal is not | `http://app:3000/oauth/callback` is the provider pointing at a container, and compose publishes that name as the container's network alias — a pointer, not a resemblance. An IP literal in the same field addresses the *host*, where port 443 belongs to the reverse proxy, so resolving it through the published-port table would attach the application to whatever answers there. Confidently wrong beats unmatched here, which is why the guard is not an optimisation. |
| A name may establish a match, but the posture is reported one step down | On a fleet where no service declares an OIDC environment key, a name is the only bridge between an OAuth2 application and the service it gates — refusing names means never reporting OIDC at all. But a name is the operator having chosen similar words twice, not an address, and the reader needs to see which of the two they are looking at. `observed` plus "tied to this service by name alone" says it without weakening the finding into uselessness, and no roll-up reads confidence, so nothing moves between "protected" and "exposed". |
| Mechanism words are stripped from the Authentik side only | Authentik's wizard names providers `Provider for X`, so those words have to be removable for a name to be comparable at all. On the fleet side they are meaningful: a service named `authentik-proxy` *is* that, and stripping `proxy` would invent a collision with the identity provider's own stack. The list is protocol and English words only (I2). |
| Two name indexes — as declared, and with separators removed | One merged map makes a stack `foo-bar` and a service `foobar` collide into a contested key, so both are discarded and the *exact* match is lost to the existence of the looser one. Kept apart, adding a looser form can only ever add reach. The first form with any entry decides, and a contested one decides against a match: falling through would be arbitrating, and cannot help anyway, since every looser form pools at least the same services. |
| A three-character floor on a derived name | `DB Provider` reduces to `db`, which would pin an application to whichever service happens to be short. A two-character residue is not a name, it is a coincidence with a small search space. |
| An OAuth2 provider Authentik records is taken as being in use | No outpost is involved, and the client configuration lives in the application rather than in any compose file, so there is nothing in the scan to corroborate it with — the identity provider's own record is the whole of the available evidence, and it is authoritative about its own configuration. Requiring a second source would mean an OIDC gate is never reportable, which is the gap this integration exists to close. |
| The reverse proxy API is on by default, unlike the identity provider's | The Authentik read cannot happen without a credential the operator must create, so it stays off until they do. The Traefik read needs none in the intended setup — an unpublished container-network entrypoint — so requiring opt-in would mean most fleets never get the one check that catches a label claiming a gate the proxy is not applying. The cost of it being on and finding nothing is one failed connection and a reason string. |
| An Authentik API token is not accepted as a proxy credential | It cannot work. A proxy provider validates HTTP Basic by driving the OAuth2 machine-to-machine flow with those credentials, which needs an **app password**; an API token authenticates to Authentik's own REST API and nothing else. The reserved username `goauthentik.io/token` (2023.2+) is the supported way to use a token, and it is a username choice, not a second mechanism. Accepting a token silently would produce a 401 the operator could only debug by reading this table. |
| The credential is never sent to a discovered endpoint on the strength of its looking like a proxy | A discovered address is a guess (§3.5's rule, applied again). Two things earn a credential: the operator typing the URL, or the scan proving the hostname belongs to the service whose own labels declare `api@internal`. Everything else gets the unauthenticated probe and nothing more. |
| The downgrade requires `/api/entrypoints`, not just `/api/rawdata` | A middleware attached to an entrypoint gates every router arriving on it and appears in no router's own list. Reading only `rawdata` therefore cannot distinguish "no gate" from "gate one level up", and the downgrade would invert the finding — reporting a protected service as reachable without auth, which is the single worst error this codebase can make. So the two reads together are the precondition, and a partial read notes the gap and changes nothing. |
| A live chain supersedes the labels rather than merging with them | They are two accounts of one thing, and only one of them is what requests actually traverse. Merging would let a label add a gate the proxy is not applying, which is exactly the class of error the integration exists to find. The label list is kept as evidence and named in the note, so nothing is hidden. |
| Backend container IPs need their own index | A docker-provider backend is `http://<container-ip>:<port>`, and `lookupAddress` reads an IP literal's port as a *published host port* — correct for a tunnel origin, wrong table entirely here. Reusing it would match whichever unrelated service publishes that number, and confidently: an IP-form URL looks like the strongest evidence available. `byContainerIp` keeps the two address spaces apart, and with no Docker state the rule is skipped rather than approximated. |
| The router-name rule applies to `@docker` routers only | Traefik derives a docker router's name from the labels of the container it found it on, so an exact match against that service's own `router` value is the label round-tripping — evidence, not coincidence. A `@file` router's name was typed by hand in a file this scan cannot read, so the same match there is a coincidence with no evidentiary weight. `fixtures/traefik/twin-a` exists to pin that distinction. |
| The declared-but-absent check runs over every router in the snapshot | Checking only the routers matched to a service would report a route the proxy is demonstrably serving as missing, whenever LabView could not attribute it. The absent-router note has to be about the whole live table or it is about nothing. |
| A `proxy`-mode provider is exempt from the forward-auth cross-check | In `proxy` mode the outpost *is* the backend: the request goes to it and it forwards on. No forward-auth middleware exists anywhere in that topology, so "Authentik has a gate but the proxy forwards no auth" is not a finding, it is the mode working as designed. Only `forward_single` / `forward_domain` providers can disagree with the proxy this way. |
| The unauthenticated-API outcome is reported, not silently used | An operator who does not know whether `api.insecure` is on gets a definite answer from the only party in a position to test it. It is a fact about their fleet that LabView established by observation, which is exactly what it exists to report — and it is not framed as a verdict, since an API on a container network with no host port is a reasonable configuration. |
| A 200 with a non-JSON body is reported as that, not as a JSON parse error | It is the likeliest way a gated endpoint answers: an SSO login page is served with a success status, so the body is the only tell. Surfacing the `SyntaxError` blames LabView for the operator's missing credential and buries the one actionable fact. The endpoint is also not counted as an API, so nothing further — least of all a credential — follows it. |
| `fetch`'s `cause.code` is kept in the failure reason | `fetch` collapses a name that does not resolve, a port nothing listens on and a rejected certificate into one `fetch failed`. Those have nothing in common as fixes, and the distinction is already in `error.cause` — discarding it makes the reason string worthless for exactly the setup step where it is read. The code is a constant like `ENOTFOUND`, so keeping it leaks no address and no credential. |
| `scripts/` is typechecked by its own tsconfig | `tsx` strips types without checking them, so a stale field name in an assertion becomes `undefined` at runtime instead of a build error — and an assertion on `undefined` can pass while proving nothing. `rootDir: src` in the emit config is why it needs a second file rather than a wider `include`. |
| One connection taxonomy for every target, not a message per integration | The three reads fail in the same six or seven ways, and the operator's next action is chosen by *which* way. A per-integration string means the fourth integration invents its own vocabulary and its own gaps — and it is the gaps that cost: "unreachable" covered a wrong hostname, a refused connection, an untrusted certificate, a rejected credential and an HTML login page, which have nothing in common as fixes. |
| `401` and `403` are separate phases | They call for opposite actions: supply a credential, versus stop trying that credential and grant the access. On a socket proxy the second is the most likely misconfiguration of all — an endpoint the proxy was never given, `CONTAINERS=1` — and it is not a network fault, so folding it into `authenticate` would send the operator hunting for a credential that is already correct. |
| The unix socket is probed before dockerode is handed it | Four states arrive as one opaque connect error otherwise, and they have four different fixes: the path is absent (mount it), it exists but is a directory (a bind mount of a missing host path creates one — the usual cause), it exists but this uid cannot open it (group membership, or better a socket proxy — `authorize`, not `connect`), or it is there and the daemon is not. `stat` distinguishes all four for the cost of one syscall, before any of it is guessed at. |
| A docker timeout is established by the clock, not by the error code | dockerode implements its own `timeout` by destroying the socket, so a black-holed endpoint surfaces as `ECONNRESET` / "socket hang up" — the deadline appears nowhere in the error. Classifying that as `connect` prints "nothing accepted the connection" about an endpoint that demonstrably did. Each awaited call is timed instead; a `Promise.race` on the same deadline would tie nondeterministically, and racing on a *different* one would leave the request running. |
| `read` is excluded from the change signature | The container count moves on almost every scan, so including it would log all three connection lines every 60 seconds and turn the on-change rule into no rule at all. The signature is `target`, `ok`, `phase` and `endpoint` — the part whose change an operator needs to see. |
| `disabled` and `not-configured` log at `debug` and never banner | An optional integration nobody switched on is not a fault. Warning about it trains the operator to ignore the banner, which is the one place the real failures are stated. `not-found` and `credential` *are* faults for the same reason: the operator asked for the read and it cannot ever happen. |
| Diagnostics are returned on `meta`, not logged where they happen | `buildOverview` has no logger and must not gain one (I4, I7): the same inputs would stop producing the same observable behaviour, and an I/O dependency would land inside the one function whose value is having none. `meta.dockerError` was already the precedent; `meta.connections` generalises it. |
| Rejected candidates are kept on a *successful* report too | It is the same list that gets printed when none of them answers, which is what makes that case diagnosable at all — and on success it answers the question the log otherwise raises, namely why the endpoint in use is not the one the operator expected. |
| A forced rescan may only be answered by a build that *started after it* | Joining any in-flight build is the one code path that can genuinely lose an edit: a scan takes seconds on a real fleet, and one that began before the operator saved the file read the old file. The operator sees a fresh `scanned` time and a payload that predates their edit — a wrong answer indistinguishable from a right one. Waiting for the in-flight build and then building again costs one extra sweep and cannot lose anything. |
| Changes are compared over the parsed configuration, not file mtimes | The question is "did my edit take effect", not "did a file get written". An mtime moves for a `touch`, a `git checkout` that restores identical bytes, or a comment; it does not move for an `.env` edit that changes what a compose file interpolates to. Comparing what LabView actually parsed answers the operator's question and needs no filesystem access, which is what lets the same function run in the browser. |
| The excluded fields are a deny-list, not an allow-list | The two mistakes are not equal. Forgetting to exclude a newly *derived* field produces a spurious "changed" line — loud, and fixed the first time anyone sees it. Forgetting to *include* a field parsed from the compose document produces an edit that is silently never reported, which is the failure the whole feature exists to prevent. So anything new is compared by default. |
| Declared facts go in a parallel `declared` block, never into the detected fields | The sidecar is the one input with no evidence behind it, so the whole value of accepting it depends on it staying distinguishable from what was proved (I1). Merging declared auth into `svc.auth.method` would be one line and would make every auth number in the product unfalsifiable: a reader could no longer tell a middleware LabView resolved from a sentence somebody typed. Kept parallel, the operator gets credit for what they know and the scan keeps its own account intact. |
| An accepted exposure stays counted, and the alarm watches the remainder | Subtracting it is the obvious design and it is wrong twice: a reviewed exposure is still reachable, and a decision that disappears from the UI is a decision nobody revisits when the reason expires. Counting it and marking it accepted keeps the fact and records the review. Driving the red off the *unaccepted* remainder is what stops a fully-reviewed fleet from shouting, so there is no incentive to clear the finding by deleting it. |
| An acceptance without a `reason` is refused, not honoured | `intentional: true` alone is indistinguishable from a stray key or a half-finished edit, and it is the one declaration that changes how a security finding reads. Requiring the reason means the field cannot be set by accident, and it puts the justification where the next reader will be — on the finding, not in a commit message. |
| Both checkable declarations are re-checked every scan, and drift is a report | A sidecar's real failure mode is not a typo, it is going quietly out of date — the port is withdrawn, the route is removed, and the file still asserts the old shape. So the two fields that *can* be checked are, on every scan. Drift never overrides the classification, because the operator's expectation being wrong is the finding; silently adopting it would delete the finding. |
| A declared login takes a service out of the exposure count — and gives it a badge, a counter and a note | `exposedWithoutAuth` is a conclusion, not a measurement: *reachable, and nothing authenticates it*. An in-app login is an answer to the second clause that no scanner can reach, so leaving the finding up asks the operator to keep dismissing a question they already answered in writing — which is how a real alarm gets trained into noise. The cost is real and is the honest risk of the whole layer: a stale declaration on a public service stops being flagged. So it is loud *in place of* the alarm rather than absent — `Protected — declared`, `stats.declaredAuthProtected`, and a note saying the verdict rests on something this scan cannot verify. The alternative considered and rejected was leaving the count untouched and only annotating it, which is what the acceptance field already does; two fields that behave identically would have made the distinction between "there is a login" and "there is none and that is fine" unrecoverable from the output. |
| A missing mechanism is reported only where a gate was expected | "No auth detected" is true of most services in a compose fleet and worth saying about almost none of them: a database on an internal network has no gate because it needs none, so a badge saying so on every card teaches the reader to skip the words that matter — and on a service whose sidecar declares its own login it contradicts the declaration one slot to its left, which is the opposite of taking the operator at their word. The condition that *is* worth stating was already computed and already loud: `exposedWithoutAuth`. So the badge rows carry mechanisms only and `AuthBadge` renders nothing for `none`, and the drawer's single `Method` row — the one place the question has been asked outright, where a blank would read as missing data — answers it through `noAuthReason`, which separates the one absence that is a finding from the three that are not (§5). This reverses the earlier decision to render `No proxy auth` beside a declaration so the two could be read together. The rule lives in `model/auth.ts` rather than in the four call sites, because a rule that only exists inside a `.tsx` cannot be asserted (§3.7). The `none` bucket keeps its row in the distribution bar and its filter chip, relabelled `None detected`: there it is a bucket of a measurement, not a verdict, and moving the finding's wording out of the palette leaves it in exactly one place — which smoke pins, so the bucket cannot re-acquire it. |
| Only a **same-layer** disagreement warns | The literal reading of "declared ≠ detected → warn" fires on every layered setup there is: an app that logs users in *and* sits behind a proxy gate is defence in depth, and warning about it teaches the operator that drift means nothing. The two vocabularies describe different tiers of one request path, so they are compared only where both can name the same thing — three families, sorted into the app's own login and the gate in front of it. `declared app-oidc + detected ldap` is two answers to one question and warns; `declared app-oidc + detected forward-auth` is two true statements and does not. `declcompare` pins it with a *pair*: two services declaring the same mechanism, opposite outcomes, decided only by what the scan found. |
| `declaredAuthProtected` is its own counter, never folded into `authProtected` | `authProtected` means *the scan proved a gate*, and that is the number a reader checks a fleet against. Adding unverifiable protection to it would make it unfalsifiable in exactly the way I1 exists to prevent, and would do it silently — the total would look better with no way to see why. A separate tile, badge and CLI line costs a few lines of UI and keeps both numbers meaning one thing each. |
| The comparison takes `wouldBeExposed`, not `reachable` | `hasEdgeAuth` includes Cloudflare Access policies and API-confirmed enforced gates, neither of which carries an `AuthMethod`. With plain `reachable`, an already-protected service would be labelled `supplies` and counted in `declaredAuthProtected` — a service credited to a declaration that never left the exposed count, because it was never in it. Passing the caller's own verdict term also makes `supplies` imply `method === "none"`, which is what bounds the feature: a declaration can only change a verdict where the scan found nothing at all. |
| An absence of detection is not a disagreement, and the alarm channel is the wrong place to say so | A probe that reaches a declared-protected service and finds no login page used to write a `drift` entry. That treats the one inference this stage may never draw as a fact: the probe asks one address, at `/`, once, and a login a route deeper, a client-drawn sign-in screen, a token guarding an API, or a network restriction it sits inside all answer identically. `drift` is the channel for *the file and the scan contradict each other*, and it has a warning tile, a `⚠` CLI line and a filter chip behind it; an alarm that also fires on *we could not tell* is trained into noise, which costs the genuine entries their meaning too. So the observation moved to `declared.unconfirmed` with its own non-alarming tile and counter. **Nothing was lost:** the same fact was already a row in the Login probe panel and a `probeReasonText` sentence in the drawer — only the warning framing went. Not gated on evidence strength either, `servedAnonContent` included: a rule that promoted *strong* silence back to drift would put the reader back to arguing with a measurement about a mechanism it cannot see. A sibling field rather than a fifth `DeclaredAuthAgreement`, because `compareDeclaredAuth` takes `(declared, detected, wouldBeExposed)` and cannot see the probe by design — the alternative was pushing the probe into a pure function or overwriting `authAgreement` after the fact. The stale-acceptance check keeps its drift entry, because its probe arm fires on a gate that *was* found. |
| A declaration that agrees with the scan is rendered nowhere | The point of the sidecar is to say what the scan cannot see. Repeating what it already found sends the reader to check two sources that agree, and makes the rows that do matter harder to spot — the same reason the expected-ingress row lost its `matches the scan` pill. `redundant` is the outcome that renders nothing, and the fixture that pins it asserts on *silence*: no note, no badge, no drift. |
| The sidecar is parsed defensively and every mistake is a warning | It is operator input from inside a tree already treated as untrusted (§7), so it is contained like `env_file`, size-capped, length-capped per field, and its unknown keys are *named* — a mistyped `descripton` that silently does nothing is the one failure mode an optional-everything format has. Nothing in it can fail a scan (I4): a malformed sidecar costs the fields it got wrong. And because declared text is prose shown as written, with no key-name heuristic that could apply, the documentation says plainly never to put a secret in one; URL credentials are redacted as a backstop only, which is why a link's label falls back to the redacted URL. |
| The diff is derived by the caller, not carried in the payload | It needs memory of the previous scan, and `buildOverview` is required to have none (I7). Both consumers already hold two payloads, so `diffStacks(prev, next)` as a pure function of them adds no API surface, no server state, and nothing to keep consistent between the log line and the topbar. |
| "No config changes" is stated rather than left implied | A rescan that reports nothing is indistinguishable from a rescan that never ran, and `scanned <time>` moves either way. The commonest true answer to pressing the button is "I re-read everything and nothing in it differs" — which is only reassuring if it is said out loud. |
| An unmatched entry carries the reason, not just the name | Both matchers already knew the difference between "nothing named this" and "two services named it" and threw it away at the `return`. Those are not one problem: the second is the operator's to settle with a label and the first is usually LabView's to explain, and a bare `string[]` reported them identically. The lists became objects rather than gaining a parallel array so the same fact cannot exist twice and drift — accepted as a **breaking change** to `/api/overview`, documented in both READMEs. |
| The trace is a line per rule, including the rules that found nothing | A reason alone says what the verdict was, not what was examined to reach it, and an operator who disagrees with the verdict has nothing to check. Recording every rule also makes an omission visible: a new rule that forgets its line leaves a *short* trace, which an assertion can catch, where a silent rule reads exactly as if it never existed. |
| `--critical` is not used in the integration panels | It is the exposure warning's colour (see the SAML row above), and the panel's worst news is an ambiguity or a failed connection — neither is a service reachable without authentication. Reusing red there would make the two indistinguishable at a glance, which costs more than the panel gains. `--warning` carries `ambiguous`, an unauthenticated proxy API and the failed phase. |
| Integration movement is a second diff, not a field on `ScanDiff` | Folding it in would make `unchanged` mean two different things and would destroy the property the deny-list protects: a container that restarted, or an API that answered this time, is not an edit to a file. Two labelled structures reported side by side keep both answers available — `no config changes; authentik +1 application` says exactly what happened, where one merged "changed" would say neither. |
| Reachability is decided before any count is compared | An unreachable read reports zeros, so a count comparison across it announces `-40 applications`: a claim about Authentik's *contents* from a scan that never reached Authentik, and the clearest possible I1 violation. `started` and `stopped` therefore carry no numbers at all, and two failed reads in a row produce no entry — the banner and the connection line already state a standing failure, and repeating it as a change every rescan would make it read as news. |
| The counts are compared, but the diff is still not the connection line | `read` stays out of `changedConnections`'s signature: a count that moves on every scan must not log three connection lines a minute, and that trade is still right. The difference is that a *rescan* is an event somebody asked about, so stating what the read returned there costs one line per press instead of one line per minute. |
| The matched side is derived in the browser, not duplicated into `ScanMeta` | Every matched pair is already on `svc.authentik` / `svc.traefikLive`, so adding a roll-up to the payload would mean two representations of one join, kept in step by nothing. A `useMemo` over `ov.stacks` reads the same source the service drawer reads, which is also what makes a row in the panel able to open that drawer. The unmatched side has no such home — it is by definition attached to no service — so that half genuinely lives on `meta`. |
| The drift count opens a panel, rather than only driving the filter chip | The `⚠ Declaration drift` chip already existed and is not the same answer: it narrows the stack list to the stacks involved and leaves the reader opening service drawers one at a time to find sentences the analyzer had already written. What a count owes its reader is the case behind it — the same argument that made the integration counts buttons — and here the case is one string per disagreement, addressed to the operator, with a file to go and edit. So the tile opens the list and the chip keeps the filtered-in-place view; each row in the panel is a link into the service's own drawer, where the declaration sits beside the evidence, so the panel adds a route rather than a second version of the fact. The counts are the reason this needed a model function: the tile shows *services* and a stack badge shows *disagreements*, and one shared wording naming both figures is what stops the pair looking like a contradiction. |
| LabView gets a login of its own, reversing the §7 non-goal | The original posture assumed the deployment LabView documents: always behind a tunnel, a proxy and an SSO gate. It is a fair assumption about *this* fleet and a bad default for the product, because the two ways a request reaches LabView without traversing that gate — a published host port, and a tunnel origin pointed at the container — are invisible from inside the container, and what is served past them is the fleet's whole inventory. The non-goal is therefore replaced rather than narrowed, and §7 says so instead of accumulating a caveat. What is *not* reversed is authorization: there are still no roles and nothing to write. |
| Enforcement follows what is configured, rather than a switch | An `auth.enabled` an operator could set with no usable method is a lock-out, and a default-on gate would lock people out of a running deployment on an image pull. So `enforced` is `methods.length > 0` and each method is live only when it is usable — one entry in the passwd file, or an issuer with a client id. `enabled: false` remains as the explicit *off* switch the feature was asked for, and the unconfigured posture is exactly today's behaviour plus one line in the log saying the surface is open (I4). |
| The posture is re-resolved on a TTL, not captured at startup | Adding the first user to `/config/passwd` is the moment an operator expects the gate to close, and a startup-only read makes that require a restart of the thing they are trying to protect. The file is stat-keyed and cached, so the steady state costs one `stat` per window, and `POSTURE_TTL_MS` bounds how stale the answer can be. It also makes the failure recoverable in the direction that matters: a passwd file fixed after a bad edit takes effect on its own. |
| `bcryptjs` rather than `argon2` or `node:crypto`'s `scrypt` | The hash format has to be the one operators already have: `htpasswd -nbB` emits `$2y$`, Traefik's own basicauth takes it, and every homelab has one lying around. Of the bcrypt implementations, `bcryptjs` is pure JavaScript with no transitive dependencies and its own types — so the alpine multi-arch image needs no build toolchain and `npm audit --omit=dev` is unaffected. `scrypt` would have meant inventing a serialization nobody's tooling writes; a native argon2 binding would have meant a compiler in the image for a dashboard's login. The modular-crypt prefix is what makes the choice survivable: adding an algorithm later is a new `$id$` branch, not a migration. |
| The gate covers the data, not the shell | `index.html`, `styles.css` and `app.js` are public and render a login card; `/api/*` needs a session. Gating the bundle too would mean serving a `401` to a browser that has no way to display it, or a second login page in server-rendered HTML — a whole second UI for the case the SPA already handles. It is safe *only* because I2 holds: the shipped artifacts carry no fleet-specific identifier by construction, so a pre-login visitor gets the same bytes as any other install. That coupling is stated in §11, because a future change that bakes anything fleet-derived into a bundle invalidates this row. |
| `isPublicPath` is an exact-match allowlist over a normalized path | The obvious `startsWith("/api/healthz")` makes `/api/healthz/../overview` public and `/api/sessionx` a bypass, and both read as harmless while doing the opposite of what the list is for. Four exact paths over a path with the query stripped, `//` collapsed and any `..` segment refused is a rule that can be enumerated in a test — and it is, including both traps. |
| `/auth/oidc/*` sits off `/api` | The redirect URI is typed into the provider by a human and appears in browser history and in the provider's logs, so it wants to read like a page, not an API call. Keeping it out of `/api` also keeps the allowlist at four entries instead of six, which matters because every entry is a path the gate is asked to let through. |
| Cookies are handled by hand, not by `@fastify/cookie` | It is `split("; ")` on the way in and a header string on the way out, which `cookiePairs` in `enrich/http.ts` already established as not worth a dependency: one more package to audit, update and ship, in the request path of the one feature where a supply-chain problem is a security problem. Both directions are asserted, including the full attribute matrix. |
| ID tokens must be signed asymmetrically; `alg: none` and every HMAC are refused | A symmetric algorithm beside a JWKS is a known confusion vector — the verifier can be talked into using a public key as an HMAC secret — and there is no benefit to accepting one, since every provider worth using offers RSA or EC. The practical cost is worth naming: Authentik signs with HS256 using the client secret when no signing key is selected on the provider, so the walkthrough in the README leads with choosing an RSA key. A refusal with a clear code is much better than a verifier that can be argued out of verifying. |
| The throttle is keyed on the username, case-folded, not on the address | Behind a tunnel and a reverse proxy every request arrives from one address, so address keying means one attacker locks out the fleet, and `X-Forwarded-For` is a header LabView has already decided not to trust for identity. A username key bounds the damage to the account being guessed, and folding case stops `BOB` and `bob` from being two budgets. It answers `429` whether or not the password was right, because branching on correctness at the throttle would turn the lockout into an oracle. |
| An unknown user is compared against a decoy hash, minted per cost at runtime | Returning early on an unknown username makes the response time an existence oracle, which is the whole enumeration attack against a small fleet's user list. The decoy is generated from `randomBytes` and memoized per cost rather than committed: a constant in the repository is a published verifier, and it also tells anyone reading the source which comparison path a given timing belongs to. |
| No CSP | Mermaid and cytoscape both inject styles at runtime, so any policy tight enough to be worth setting breaks the graph tab, and one loose enough to work (`style-src 'unsafe-inline'`) buys nothing. The three headers that cost nothing — `nosniff`, `Referrer-Policy: same-origin`, `X-Frame-Options: DENY` — are set unconditionally instead. Revisit if the graph libraries gain a nonce-friendly mode. |
| The `Origin` check runs before the session check | Both orders refuse the request; only this one refuses it without having looked at the cookie, so a cross-site POST cannot learn from the difference between `403` and `401` whether the visitor has a session — and a rejection carries no `Set-Cookie`. A missing `Origin` passes, because browsers always send it on a cross-site POST: its absence means the request did not come from a page, and `curl` has no ambient cookie to abuse. |
| A login failure crosses the boundary as a code, never a message | The failure has to survive two trips — a JSON body, and a `?login_error=` query parameter on a redirect from the provider — and text in a query parameter is text an attacker can put on the login page. So the union is closed, `parseLoginFailure` refuses anything outside it, and the wording lives in `model/access.ts` where the browser composes it and smoke asserts it (I6). It is also what keeps a provider's raw error string off the page. |
| Every credential comes from an environment variable, and the `*File` forms are gone | The precedence rule was documented eleven times and the wording nagged in all eleven — *works, but is visible in `docker inspect` — prefer the file form* — which produced the state this row reverses: the OIDC client id arriving as a variable while the client secret beside it needed a bind mount and a `/run/secrets` path. Two mechanisms for two halves of one credential the provider issues together, and no reader can tell which half is misconfigured. One mechanism means no precedence to explain and nothing that can silently override what was set. The exposure argument is real and is now stated once, honestly, in §6: `docker inspect` needs the Docker socket, which is root-equivalent on that host and can read a mounted file just as easily; what a gitignored `.env` beside the compose file actually closes is a credential committed to a repository. `auth.passwd.file` is untouched — a `user:hash` database is a mechanism, not a single secret in a path. |
| A retired variable is warned about, not ignored | Ignoring `LABVIEW_OIDC_CLIENT_SECRET_FILE` on the next image pull turns a confidential client into a public one, the provider refuses every sign-in, and nothing in any log connects the two — a lock-out dressed up as a simplification, against I4. So `retiredSettings` keeps all four variable names and all four `config.yml` keys recognised for the single purpose of naming what replaced them. The config-file half is checkable because `merge()` preserves unknown keys, so a `config.yml` written against the previous `config.example.yml` still contains `tokenFile:` and still gets told. Neither the value nor the path is echoed: the variable to move it to is the whole actionable part. |
| "Set but empty" is carried forward in `blankCredentialVars` rather than recomputed | `applyEnvOverrides` is the only place the difference between unset and empty survives — every reader downstream sees one empty string — and that difference is now the likeliest way a credential fails to arrive: `${OIDC_SECRET}` with no matching `.env` entry expands to nothing and compose passes it on without complaint. Carrying the *names* keeps the readers pure and assertable, keeps `credential` (§3.10) a producible phase after its file-read producer was deleted, and holds to I6 by construction, since a value never lands in the list. The compose examples use `${VAR:-}` and not `${VAR:?}` for the same reason: an unresolved credential should reach LabView and be reported, not stop the container from starting. |
| Rotation now needs a restart, and the docs say so | `tokenFile` and `passwordFile` were read per build, so a rotated secret took effect on the next rescan; an environment variable is fixed for the life of the process. This is the one capability the row above gives up, and it is written into §3.11 and the README rather than quietly dropped — a documented `docker compose up -d` beats an undocumented rotation that silently stopped working. The passwd file keeps its per-change re-read, which is where the property was actually earning its cost. |
| The scan **asks** a service, instead of only reading its configuration | An application with its own login page — the largest class of real protection there is — carries no label, no env key and no entry in anybody's API, so no amount of reading configuration can see it. The only previous way to keep such a service out of the exposed count was a `.labview` declaration, which is unverifiable by construction: the count was either wrong or resting on a claim. A GET and the answer to it is observable evidence in the sense I1 means, and the codebase already knew the phenomenon from the other side — `discoverTraefikEndpoints` prefers an internal address precisely because a public hostname is fronted by an edge whose access policy would answer with a login page. |
| The probe is **opt-in, default off** — the only integration that is | Every other read goes to an address the operator configured; this one goes to services out of their own compose files, and where that address is a public hostname the request leaves the fleet. A scan that started dozens of outbound requests unasked would be doing something the operator did not ask for, however benign each request is. The Authentik read set the precedent for opt-in; this is the stronger case for it. |
| Eligibility is **observable HTTP only**, never a port number or an image name | The request said "http/https services, not databases", and the only way to honour that without a heuristic is to require evidence: a tunnel route whose own `service:` origin is http/https, or a `traefik.http.routers.*` label. A service with `ports:` and no route yields no address at all — so nothing is ever sent at a database port, and the rule needs no list of ports or images to keep out of I2's way. The cost is real and stated: a LAN-only web UI stays inferred rather than measured. Guessing from `5432` would be a fleet-recognising heuristic that is wrong on the first service that moves its port. |
| The LAN address is **configured**, not discovered | LabView runs in a container and cannot observe its host's LAN address. `probe.lanHost` is the operator's answer; empty means the LAN vantage is skipped, because a guessed host would produce connection failures that read as services being down. |
| Every signal that counts as a login page is a fact, and everything else leaves the finding standing | `readGate` can only ever take a service **out** of the exposed count, so a clause that is merely likely manufactures false comfort — the one thing this project exists to remove. Hence a challenge header is required for a 401 (a bare 401 is an API saying "not signed in" while its UI serves the whole app), a same-origin redirect must land on a login path (`/dashboard` is routing), a `<meta http-equiv="refresh">` is resolved through the same rule rather than trusted for existing, a `SAMLRequest` input counts because nothing but the SAML POST binding emits one, and a password field must arrive on a 200 whose body was HTML. A finding a reader dismisses costs them a look; the reverse error costs them the exposure. The signals grew from four to eight; the bar did not move — the eighth needed a second request precisely because no reading of the first response could clear it honestly, and it still requires the refusal to carry a challenge header. |
| The eighth signal is allowed a **second request**, and only for one shape of answer | Seven signals read one response, which is the cheapest thing a rule can cost and was the whole budget until a form-less HTML shell turned out to be the single most common thing a real fleet's `open` list is made of — a login screen drawn in the browser, indistinguishable in its markup from an open dashboard at any body size. That is not a rule that needs loosening; it is a question asked at the wrong address. So `wantsStateProbe` names the one answer a second request can settle — 200, HTML, no `<form>` anywhere, and nothing already gated — and everything else is decided on the response in hand. The cost is bounded before it is spent: four constant paths, the origin already reached, the walk stops at the first refusal, nothing parsed from the page, sequential regardless of `probe.maxConcurrency`. The ordinary case is one extra request and the worst case is four, and the startup line says the total out loud (§3.6b) so a fleet of shells cannot quietly cost several times what "13 services probed" implies. |
| A **bare** 401 at a current-user address is reported and not counted | It is the strongest evidence in this whole area and it still is not enough. An API answering 401 with no scheme named is exactly what an anonymous-enabled Grafana and a world-readable Gitea answer — pages that serve everybody, whose current-user endpoint truthfully says nobody is signed in. Counting it would take genuinely open services *out* of the exposed count, the one direction I1 forbids. So `readStateGate` requires `WWW-Authenticate` on the refusal, exactly as `challenge` does one address over: a server sending that header is asking a browser to prompt, which nothing does by accident. 403 is excluded for a different reason — nginx answers it for a directory with no index. What the walk found is still on the payload (`ProbeState.refusedAt`) and still in the drawer's words, as a place to look rather than a verdict, and `fixtures/probe/spa-shell` carries the trap beside the real thing so a rule that dropped the header requirement fails instead of quietly clearing an open service. |
| Proof that a service is **open** is worth as much as proof that it is gated — and it is the only new evidence here with no I1 exposure at all | Every other rule in this stage answers *is there a gate?*, and an `open` verdict was therefore an absence: none of the eight signals fired. An absence is what a reader discounts, correctly, because it is equally consistent with a login the rule cannot see — which is exactly what eight probe-lab reports said in the same words eight times while three of the services behind them were serving twenty-four kilobytes of public page with a `Sign in` link on it. `readAnonAccess` (§3.6c) says the positive thing instead: an anonymous request was answered with the application's own content, and the offer beside it is an optional account rather than a door. Every constraint that makes the other seven signals expensive to get right is absent here, because the direction is reversed — this can only add a sentence to a service that stays in the exposed count, never remove one from it. That is why its thresholds can be two numbers picked from real reports rather than a fine line somebody has to defend, and why it needed no new `ProbeGate`, no `PROBE_GATES` entry, no second request, and no UI change: the tile and the drawer already render `probeReasonText`. |
| A login **link** is not a gate, and the type system is where that is enforced rather than the review | The two halves of this change are one fact read twice — a page with a sign-in affordance on it — and they point in opposite directions depending on whether content came with it. That makes "a sign-in link must never clear a service" the single thing most likely to be got wrong later, by somebody adding a detector in a hurry. So it is arranged to be impossible rather than forbidden: `readGate` takes a `ProbeResponse` and the `ProbeAnon` record is not on one, so there is no code path from a link to a gate in the product; and in the lab, `EvidenceFinding.direction` has no `"gated"` member, so the six detectors *cannot* express the conclusion they must not reach — the strongest a finding gets is `look-closer`, which lands in section 4 as a proposal (`login-heading` is the one that would move a count, and it stays a proposal). Two runtime assertions back the types where a type alone would be a promise about source rather than behaviour: every detector row must leave `buildReport(obs).verdict.gate` equal to `readGate`'s own answer, and no gated verdict anywhere in `fixtures/probe` may carry the open-access sentence (§8). |
| The rule set stops at **one response per address**, and the two obvious ways past that are declined on their properties rather than their cost | Both extensions were asked for and both were weighed at the point where the eight signals had just been measured against real bodies. **Rendering** the page — the only thing that catches a login a bundle draws — would execute third-party JavaScript in the process holding the Docker socket, the API tokens and the session secret, would fetch subresources from wherever the page names including off the fleet in an offline-first program, and needs a *settle* decision, network-idle or a fixed wait, which makes the observation time-dependent: a slow bundle would let a service leave the exposed count on one scan and come back on the next, which is I7 broken in the one direction a count must not move. **Fetching what the page merely named** — the bundle, the stylesheets, the chunk graph — needs no browser and no execution, and is declined for a property of the artifact instead: a bundle is *deployment-invariant*. An anonymous-enabled Grafana ships the same JavaScript as a gated one, so a login route literal or a `Sign in` string inside it proves the application **has** a login screen and not that this deployment put one in front of anything — which is exactly the reading `login-route` already carries in the lab at `weak`, and it can never be promoted past it, because clearing an exposure on it would clear the open services with the same bytes. So the general rule both refusals follow: **evidence of a gate has to come from what happened to *this* request at *this* address** — the answer at `/`, where it redirected, or the application's own refusal of an anonymous caller. `fixtures/probe/public-portal/app` is that distinction as a fixture, and it is why the lab's `--try-login-paths` guesses land in section 4 as a proposal: a login form at `/login` is what an open application with an optional account serves too. The residue is priced rather than ignored — on the fleet this was built against it is two services, both shells whose API refuses an anonymous caller with a *bare* 401, and both already carry a declared `app-local-accounts` login (§3.9), so the miss costs one sidecar line per service, once, and not a wrong count. What would reopen it is a cheap disambiguator for that bare 401, and the shape is `readAnonAccess`'s question one layer down: whether the API *serves* anything to a caller with no credential as well as refusing its current-user address. That fact is deployment-specific, so unlike anything in a bundle it could reach gate strength — and it would arrive the way `state-challenge` did, measured in `tools/probe-lab` against real bodies first, then a rule, a fixture, and a revert trap. |
| `credential-form` reads **several** facts at once, and it is the only gate that does | Passwordless sign-in — magic links, passkey-first pages — has no password field, no redirect and no hidden binding parameter. One-fact rules cannot see it at all, so a growing class of services that serve nothing but a login form was being counted as exposed. No single fact on such a page is sufficient either: a username field and a submit button are also a newsletter box, which is the default footer on a static site. So this one clause requires a username field, a submit button, and a login-intent marker — an action resolving onto a login path, or a `one-time-code` field — and `fixtures/probe/passwordless` carries the near-miss beside the real thing so the composite cannot drift into word-matching. `types.ts` used to say a fifth member would be an inference; that prose was rewritten to say which fact combination is admitted and why, rather than left to contradict the code. |
| The switch overrides `probe.enabled` in **both** directions, not just off | A control the configuration can veto is a control that displays a state it does not have — the operator turns it on, nothing probes, and nothing on the page explains it. Full authority also makes the useful case work: trying probing once, on a fleet where it is off by default, without editing a file and restarting. The cost is stated rather than hidden (§7): when no login is configured, `POST /api/rescan` is unauthenticated, so any visitor can start a probing scan. The mitigation is the login, because the same visitor can already read the entire inventory — a narrower switch would protect nothing that `GET /api/overview` does not already give away. |
| The override lasts one build, and the payload says what that build did | Sticky would mean either persisting a runtime setting, in a program that persists nothing, or letting one click decide what every later scan does — including timer scans nobody asked for, which is precisely the "outbound requests unasked" the default-off row exists to prevent. Per-build keeps the blast radius at one rescan and costs one visible oddity: the TTL expires and probe results leave on their own. `meta.probe` is what pays for it — it records whether *this* build probed and which of configuration or request decided it, and the checkbox re-syncs from it on every overview, so the revert moves the switch rather than leaving it lying (§11). |
| A probe result joins `hasEdgeAuth`, where a declaration may not | They look alike — both remove a service from the count without naming a mechanism — and the difference is I1 exactly. A declaration is a claim nothing in the scan can check, so it stays a separate term. A probe result is something LabView observed, the same kind of fact as a middleware definition, so it belongs in the evidence term. What keeps it honest is the `unnamed-gate` discipline it borrows: its own counter, its own reason, `auth.method` untouched, and the count reconstructible with the term dropped. |
| The walk **stops at the first address that answers** | An answer is an answer, whatever the status — a 401 is the best outcome available here — so continuing to a weaker vantage would spend requests to learn something less. Only a transport failure falls through, which is what makes the LAN vantage useful at all: a public hostname routinely does not resolve from inside the container. Vantage order is `INGRESS_KINDS` order, most-exposed first, so the answer a reader is shown is the one an outsider would get. |
| "Did not answer" is a **third** outcome, never folded into "no login page" | They are the same absence of a gate and completely different findings: one measured an exposure, the other measured nothing. Folding them would let a firewalled service read as "answered, open" — or, worse in the other direction, a timeout read as protection. So it counts in neither statistic, `probeOutcome` words it as `No answer`, and its note claims no measurement. |
| The payload carries the facts a verdict rested on, so the reason can be a rule rather than a sentence | `readGate` decides on things the response then goes away with, so a negative verdict was recorded as `HTTP 302 — answered with no login page`: the conclusion, with the fact discarded, and a 302 to `/dashboard` spelled identically to a 302 to `/login`. Composing the fuller sentence in `enrich/probe.ts`, where the response is still in hand, was the smaller change and the wrong one — a string built at probe time can only be tested by mocking the network, and what these sentences say about the two trap fixtures is exactly what the revert contract has to pin. So four observations go into `ServiceProbe` (`mediaType`, `redirect`, `refresh`, `truncated`), read by the same exported readers `readGate` decides through, and `probeReasonText` is a pure rule in `model/probe.ts` with 20 rows behind it (§8). The cost is four more fields in the contract and one more thing to reduce for I6; the gain is that "why" is falsifiable. |
| The probe gets its own tile, and the tile is not tinted | An existing tile could not hold it. `Exposed, no auth` drops every gated result, which is half the measurement; `Auth-protected` and `Declared auth` name mechanisms, and I3 forbids a probe result becoming one. So the count that *is* the measurement gets the tile. It is deliberately not `alert` and its rows are not `crit`, on `probeOpen`'s own documented terms: a service behind a detected gate that answers LabView from inside the fleet is counted in `probeOpen` too, because the request may have gone around the edge that gates real visitors. Tinting it would assert a fleet finding that `Exposed, no auth` may correctly deny, and the critical tint means one thing only (above). Severity stays with the per-result pill, which `probeOutcome` decides. |
| Only services with **no detected authentication** are asked, unconditionally and with no config knob | `hasEdgeAuth` is `configuredEdgeAuth \|\| probeGate`, so where a Traefik auth middleware, an OIDC issuer, a Cloudflare Access policy or an enforced Authentik provider was already found, the answer could not have moved the verdict in either direction. What the request could still do is arrive at an SSO endpoint, unauthenticated and unexplained, on every scan. A switch was considered and rejected: its non-default value would send extra traffic to services already known to be authenticated in exchange for a result incapable of changing anything, which is a control with no use case. The direction is what makes it safe — withholding can only ever leave a service **in** the exposed count — and it is asserted rather than argued, on two fixtures whose canned answers stay in the stub so the check fails on a *recorded request*. The price is paid in two places and stated in both: pass 2 splits so the probe no longer overlaps the two API reads (§3.2), and a gate that has silently stopped working is no longer measured (§11). |
| An **`inferred`** posture counts as detected | A router naming `authentik@docker` whose definition is in no scanned stack is still authentication detected through Traefik — the request asked for it in those words — and `svc.auth.method` is not `none`, so `configuredEdgeAuth` is already true and the probe could not have changed that service's verdict either. Restricting the skip to `confirmed` postures would have sent exactly the requests this change exists to stop, at the services where a name was all LabView could read. `fixtures/probe/gated-open` is that case and asserts the confidence explicitly, so a rule narrowed to `confirmed` fails rather than quietly resuming the traffic. |
| "Not asked" is a **counted** outcome, not a silence | A withheld service carries no `ServiceProbe` at all, so its absence is indistinguishable from "no HTTP address was observed" — and the tile would read 13 in a fleet of 14 HTTP services with nothing anywhere to explain the fourteenth. So `ProbeRun.skipped` is non-optional (§3.7), the connection line gains a third segment, `ProbeReport.notAsked` carries it to the panel, and a run whose candidates were *all* withheld is `ok: true` rather than the `not-found` failure it would otherwise be mistaken for. `probeTargets` is asked first, so a service with no address is never counted as withheld: two different facts, two different numbers. |
| The fine-tuning tool **imports** the rule instead of reimplementing it | `tools/probe-lab` exists because an `open` verdict has two meanings — genuinely unprotected, or a login page the rule cannot see — and only a look at the page tells them apart (§3.6b). A standalone script with its own parsing would have been quicker and would have been worthless: a report describing a decision LabView would not make sends somebody to change a rule that was never the problem. So `report.ts` imports `readGate` and every reader and wording rule from `model/probe.ts`, `cli.ts` inherits its transport from the same `getResponse` the pipeline calls, and the smoke pass drives the pipeline's own `readGate` table through `buildReport` to assert the two agree (§8). The patterns stay private: the tool can ask what the rule asks and can never ask it differently. It ships nowhere — no `src/` import, not in the image, `reports/` gitignored because it is the one place a fleet's own hostnames would otherwise be committed (I2). |
| The build stamp on the page is the **short commit**, not the version | A version answers "is the fix in the thing I am running?", and `0.1.0` cannot: it is the same string across every pre-release build, so a page showing it says only that this is LabView. The short commit is the smallest thing that answers the question, and it is the identifier the project already uses everywhere else — the image tag, the workflow's `github.sha`, `git rev-parse --short HEAD` in a terminal — so the stamp reads as the same name a reader already has, rather than a new one to correlate. The version is not discarded; it moves into the tooltip and the log line, where it costs nothing and is there when the pre-release ends. This replaced `meta.version`, a hardcoded copy of `package.json` that no code read and no document mentioned — so the change is a duplicate removed, and a breaking payload change on the `unmatchedRouters` precedent. |
| `source` sits beside the commit and is never optional | `image` and `checkout` are different claims about the same seven characters, and only one of them is about the bytes that are running. An image was compiled from that commit; a checkout merely *started* in a tree that was at it, and no file read can see the uncommitted edits on top — so a stamp that reported the sha alone would let a developer's half-finished tree spell exactly like a released build, which is the I1 error in the one place a reader trusts most. Recording which source answered makes each claim wordable on its own terms: `buildTitle` is a `Record` over the three, exhaustive, so a fourth way to learn a commit is a compile error until somebody decides what it entitles LabView to say. `commit` is optional for the opposite reason — a build genuinely may not know its revision, and `unknown` is a real outcome with a sentence of its own rather than a blank field to be misread as a bug. |
