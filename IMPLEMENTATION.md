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
| **R4b** | Optionally verify that ingress against the reverse proxy's own runtime API, discovering the endpoint from the fleet | [enrich/traefik.ts](labview/src/enrich/traefik.ts) + [analyze/traefik.ts](labview/src/analyze/traefik.ts); §3.6 |
| **R5** | Report SSO posture, whether wired as a reverse-proxy gate or as OAuth/OIDC/LDAP | [auth.ts](labview/src/labels/auth.ts) |
| **R5b** | Optionally confirm that posture against the identity provider's own API, using a read-only credential the operator supplies | [enrich/authentik.ts](labview/src/enrich/authentik.ts) + [analyze/authentik.ts](labview/src/analyze/authentik.ts); §3.5 |
| **R6** | Build the documentation dynamically, and use the Docker socket proxy for live state when available | [enrich/docker.ts](labview/src/enrich/docker.ts); every scan is fresh, nothing is persisted |
| **R7** | Serve the documentation from a built-in webserver, itself exposable through the same tunnel/proxy/SSO chain | [server/server.ts](labview/src/server/server.ts), labelled example in `labview/compose.yml` |
| **R8** | Be generic: the above is an *example* of a fleet, never a description of one | §4 I1–I3, enforced by the fixtures in §8 |
| **R9** | When one of those optional reads does not work, say which stage failed and what to change — for every target, present and future | [model/connections.ts](labview/src/model/connections.ts); §3.10, surfaced in the startup log, `--summary`, `meta.connections` and a banner |

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
    model/connections.ts  connection-report wording, hints, log/banner rules (pure)
    model/changes.ts  what changed between two scans, and its wording (pure)
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
      authentik.ts    cross-stack matching of identity-provider applications to services
      traefik.ts      cross-stack matching of live proxy routers to services + its notes
      networks.ts     real docker network names for a service (shared by graph + origins)
      index.ts        the pipeline; ingress classification; stats
      graph.ts        nodes/edges for the relationship graph
    enrich/
      http.ts         fetch wrapper: timeouts, JSON, injectable fetchImpl (no I/O policy)
      docker.ts       Docker Engine snapshot (never throws)
      authentik.ts    Authentik REST API snapshot (never throws; all network I/O)
      traefik.ts      Traefik runtime-API snapshot (never throws; all network I/O)
    server/cache.ts   scan cache: TTL, coalescing, force semantics (§3.11)
    server/server.ts  Fastify: /api/* + static UI, with a TTL cache
  web/                Preact UI (see §3.9)
  scripts/
    build-web.mjs     esbuild bundle
    smoke.ts          pipeline assertions over the fixtures
  fixtures/
    apps/             a representative happy-path fleet
    edge/             one stack per previously-fixed defect
    authentik/        a fleet with an identity provider in it
    authentik-api.json  canned API responses driven through an injected fetch
    traefik/          a fleet whose labels and live proxy config disagree
    traefik-api.json    canned proxy + identity responses, same injected fetch
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
| 5. Pass 1 — routes | `labels/dockflare.ts`, `labels/traefik.ts` | `svc.cloudflare`, `svc.traefik`, `svc.docker`, `svc.ingress` |
| 6. Fleet index + origin resolution | `analyze/origins.ts` | `FleetIndex` (host ports, DNS names, container IPs, hostnames); `route.origin` — what each tunnel origin points at, and notes where it could not be told |
| 7. Identity provider API | `enrich/authentik.ts` | `AuthentikSnapshot` — applications with their providers and outposts, or a reason it is absent. Skipped entirely without a token |
| 8. Reverse proxy API | `enrich/traefik.ts` | `TraefikSnapshot` — the routers the proxy is serving with their resolved middleware chains and backends, or a reason it is absent. Runs concurrently with step 7 |
| 9. Provider discovery | `discoverAuthentikHints` | hint strings that identify the SSO provider *in this fleet* |
| 10. Application matching | `analyze/authentik.ts` | `svc.authentik` — which applications belong to which service, and which matched nothing |
| 11. Live router matching | `analyze/traefik.ts` | `svc.traefikLive` — which live routers belong to which service, and which matched nothing |
| 12. Pass 2 — auth | `labels/auth.ts` | `svc.auth`, `exposedWithoutAuth`, notes; then secrets masked |
| 13. Graph | `analyze/graph.ts` | `Graph` of services, networks, shared volumes, resolved ingress paths, auth hubs |
| 14. Stats | `computeStats` | `OverviewStats` for the dashboard header |

**Why two passes.** Steps 6–11 cannot run per-service inside step 5. Four
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

A change that needs fleet-wide knowledge belongs in a new pass or in step 4/9,
not in a per-service function reaching for global state.

**Where the two API reads sit, and why.** A *configured* endpoint depends on
nothing in the scan, so that request is started before the docker snapshot and
awaited after, overlapping the two. A *discovered* endpoint cannot be found until
pass 1 has parsed the routes, so it runs after. Either way the result is one value
with the same shape.

Origin resolution moved **ahead** of the discovered reads for two reasons. A
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
   any scanned stack and is therefore only ever `inferred` (§11's first limitation —
   this stage is what retires it).

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
from it, which is what retires the old "the responsible proxy is unknown" edge.

### 3.7 The data contract

[model/types.ts](labview/src/model/types.ts) is the single contract between
backend and frontend, and `/api/overview` serves exactly an `Overview`. Rules:

- It must stay free of Node-only imports — the web build imports it directly.
- `web/model.ts` re-exports it so UI files have one import surface. Add new
  exported types there too.
- Adding a member to a union (`AuthMethod`, `IngressKind`) is a **breaking UI
  change**: the palette in `web/lib/palette.ts` maps every member to a colour and
  a label, and an unmapped member silently renders grey. See §10.

### 3.8 Serving

Fastify with three routes and a static mount:

| Route | Behaviour |
|---|---|
| `GET /api/overview` | cached scan; rebuilds when older than `cacheTtlSeconds` |
| `POST /api/rescan` | forces a rebuild that re-reads the apps root, and returns it (§3.11) |
| `GET /api/healthz` | `{ok: true}`, no scan |
| `GET /*` | the built UI from `web/dist`, SPA-style fallback to `index.html`; a 404 under `/api/` stays JSON |

Concurrent requests during a rebuild share one in-flight promise, so a burst of
traffic cannot start N scans — **except** a forced one, which may only be answered
by a build that started after it arrived, or it would return a scan taken before the
edit that prompted it (§3.11). The cache is warmed in the background at startup so
the first page load is instant. If `web/dist` is absent the server still runs and
says how to build it — the API is the primary product, the UI is a view of it.

### 3.9 Frontend

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

#### A rescan re-reads the integrations, and now says so

A rescan already re-ran both API exchanges — endpoint discovery, every request, and
the credential files with them, since `tokenFile` and `passwordFile` are read per
build, so a rotated secret is picked up. Nothing was memoized. But **nothing
reported it**, and the two rules above are why: the configuration diff excludes live
API answers on purpose, and `read` is excluded from `changedConnections`'s
signature for the same reason. Between them, an application count going 18 → 40
produced no line anywhere, which from the operator's seat is indistinguishable from
a rescan that never touched Authentik.

`diffIntegrations(prev, next)` closes that, as a **second structure reported beside
`ScanDiff`, never folded into it**. Folding them would make "changed" mean two
things at once and would break the property the deny-list exists to protect — an
API that answered differently is not an edit. So the note and the log line carry two
labelled clauses: `no config changes; authentik +1 application, -3 withheld`.

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

The cadence rule itself moved into `formatRescan`, out of `logScan`, so it can be
asserted for the first time — and "quiet" now means *both* diffs. A rescan that
found new applications is not quiet just because no file was edited.

### I1 — Documentation rests on observable evidence

Every statement in the output must trace to a value read from a compose file, an
`.env` file, or the Docker Engine. Not from a name, not from a convention, not
from what is statistically likely.

Where a conclusion cannot be established, the correct output is the weaker,
truthful one — plus a note saying what was missing. `AuthPosture.evidence` exists
so a reader can check the derivation, and `AuthPosture.confidence` exists so they
can tell a fact from a guess without re-deriving it.

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
  teaching the tool to trust anything that answers. `tokenFile` and `passwordFile`
  exist so neither value need sit in the environment where `docker inspect` reveals
  it.
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
from a provider naming it (§3.5). A `provider` record is the narrower thing it looks
like: no launch URL, no group, and only the providers this token may read. Reported
rather than smoothed over — a match made on less evidence should look like one — and the
value is what the `considered` trace, the drawer's `rebuilt` tag and
`applicationsRecovered` all rest on.

**applicationsConfigured / applicationsWithheld / applicationsRecovered** — on
`AuthentikSummary`, the arithmetic of what the applications endpoint did *not* return.
`applicationsConfigured` is its own `pagination.count`, which counts records before its
policy filter runs and is therefore the total Authentik holds; it is optional because an
endpoint may report no count at all. `withheld` is that minus what was listed,
`recovered` is how many of those a readable provider let LabView rebuild, and
`applications` is listed **plus** recovered. The remainder, `withheld - recovered`, is
derived where needed rather than stored, so the four numbers cannot disagree — and it,
not `withheld`, is what makes the connection `partial`.

**AuthentikMatchStrength** — `"address" | "hostname" | "name"`: what kind of thing
established the tie, per match. An *address* is the provider pointing at the service; a
*hostname* is one name both sides declare independently; a *name* is only that the
operator chose similar words on each side. Load-bearing rather than cosmetic — it sets
the reported confidence (§3.5), because a posture resting on a name should not read the
same as one resting on a resolved address. Absent is treated as `name`, the weakest
reading, never the strongest.

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
trace. Ambiguity is reported, never arbitrated: picking a candidate by iteration order
would move a service between "protected" and "exposed" on a coin toss.

**UnmatchedRouter** — the same for a live router, in `meta.traefik.unmatchedRouters`,
carrying the whole `TraefikLiveRouter`. Because such a router demonstrably *exists*, it
must never produce a "declared but not live" note on anybody.

**UnmatchedReason** — `"ambiguous" | "no-candidate" | "internal"`. Not a severity but a
statement about who can act: `ambiguous` means the evidence pointed at more than one
service and was discarded, which one distinct name fixes; `no-candidate` means nothing
pointed anywhere, usually LabView's gap to explain; `internal` is defensive only — a
matcher named a service key the scan does not hold. Reporting all three as "unmatched"
hides the actionable one, which is the whole reason the field exists.

**`considered`** — one line per matching rule tried and what it produced, in the order
tried: the same evidence discipline as `AuthPosture.evidence`, applied to the case that
failed. A rule that could not run says why rather than being omitted. Constrained to
what the payload already carries — slugs, provider and service names, hostnames — and
never an env value, which smoke asserts.

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

**`chainComplete`** — `TraefikSummary.reachable && entrypointsRead`. The single gate
on the downgrade (§3.6): only a read that got **both** `/api/rawdata` and
`/api/entrypoints` may let a live chain supersede a label list. Anything less notes
the gap and changes no posture.

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

**`exposedWithoutAuth`** — `ingress !== "internal"` and no auth detected (proxy
gate, OIDC/LDAP, basic-auth, a Cloudflare Access policy, or an API-confirmed
enforced gate). Note this counts a `host-port`-only service as exposed, because it
is.

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
configured credential could not be read (a missing or empty `tokenFile`). Both are
faults — a half-finished configuration will never work — which is what separates
them from `not-configured`. Then the transport stages `resolve`, `connect`,
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
integration nobody switched on is not a status. Deliberately separate from
`ScanDiff`: an API that answered differently is not an edit (§3.11).

**IntegrationChange** — one target: `state` is `unchanged`, `moved`, `started` or
`stopped`, decided from `reachable` on both summaries *before* any count is
compared. `counts` holds the signed deltas and is empty for anything but `moved`,
because nothing may be compared across a failed read. `appeared` and `disappeared`
name the records that came and went — application slugs, router names — sorted.

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
| `LABVIEW_DOCKER_TIMEOUT` | `docker.timeoutMs` | socket **inactivity** per request, not total time, so a large fleet's listing is unaffected. It exists so an endpoint that accepts and then says nothing becomes a reported `timeout` (§3.10) instead of a scan that never finishes |
| `LABVIEW_MASK_SECRETS` | `secrets.maskValues` | leave on |
| `LABVIEW_CACHE_TTL` | `cacheTtlSeconds` | |
| `LABVIEW_PORT` / `LABVIEW_HOST` | `server.port` / `host` | |
| `LABVIEW_AUTHENTIK_TOKEN_FILE` | `authentik.tokenFile` | preferred over the token env var, which `docker inspect` exposes. Wins over `authentik.token` |
| `LABVIEW_AUTHENTIK_TOKEN` | `authentik.token` | with neither set, step 7 makes no request at all |
| `LABVIEW_AUTHENTIK_URL` | `authentik.url` | skips discovery entirely; needed only when the provider is outside `appsRoot` |
| `LABVIEW_AUTHENTIK_ENABLED` | `authentik.enabled` | `false` = never contact the provider |
| `LABVIEW_AUTHENTIK_TIMEOUT` | `authentik.timeoutMs` | per request; `authentik.maxPages` bounds pagination and is file-only |
| `LABVIEW_TRAEFIK_URL` | `traefik.url` | skips discovery, and is one of the two things that make an endpoint eligible for a credential (§3.6) |
| `LABVIEW_TRAEFIK_USERNAME` | `traefik.username` | an Authentik user, or the reserved `goauthentik.io/token`. Only for an API behind a gate |
| `LABVIEW_TRAEFIK_PASSWORD_FILE` | `traefik.passwordFile` | preferred over the password env var, which `docker inspect` exposes. Wins over `traefik.password` |
| `LABVIEW_TRAEFIK_PASSWORD` | `traefik.password` | an **app password**, not an API token. In `secrets.keysAlways`, so LabView scanning its own stack cannot print it |
| `LABVIEW_TRAEFIK_ENABLED` | `traefik.enabled` | `false` = never contact the proxy. Unlike Authentik this stage is on by default, because it needs no credential |
| `LABVIEW_TRAEFIK_TIMEOUT` | `traefik.timeoutMs` | per request; the whole exchange is three GETs and is not paginated |

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

**The outbound calls, and their rules.** Two stages initiate a connection outside
the Docker socket, and both carry the same constraints (I5): `GET` only; no
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

Neither credential can appear in output: `LABVIEW_AUTHENTIK_TOKEN` and
`LABVIEW_TRAEFIK_PASSWORD` are both in `secrets.keysAlways`, so a fleet that includes
LabView's own stack masks them like any other secret, and no error string in either
client interpolates a credential.

**Deliberate non-goals:** no authentication, authorization or rate limiting in
LabView itself; no TLS termination (the proxy does it); no persistence, so
nothing to leak at rest; no writes of any kind; no outbound network calls beyond
the two reads above.

---

## 8. Testing contract

`npm run smoke` runs the entire pipeline against four fixture roots with Docker
disabled and asserts on the resulting `Overview`. It exits non-zero on any
failure and gates CI. `npm run typecheck` covers `scripts/` too
(`tsconfig.scripts.json`): `tsx` strips types without checking them, so an
assertion reading a renamed field would silently read `undefined` — and an
assertion on `undefined` can pass while proving nothing.

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

- **The four unplaced applications give four distinguishable answers.** `pair` is
  `ambiguous`, with both `pair/blue` and `pair/green` named in its trace; `broad-app`,
  `s01` and `ext-01` are each `no-candidate` with their own cause quoted — the
  `forward_domain` mode, the three-character floor, an address literal. Exactly one of
  the four is `ambiguous`, so a matcher that stopped telling contested from absent fails
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
on a real deadline. Seven properties are pinned:

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

`fixtures/outside-root.env` sits outside all four roots on purpose: it is the
target of the `env_file` escape attempt that must be refused.
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
| SAML gets no `AuthMethod`, but is excluded from exposed-without-auth | Every `AuthMethod` has a palette colour and the only one left is the red reserved for the exposure warning — colouring a protected service in the warning colour is worse than having no badge. Reporting it as reachable without auth, though, would be plainly false, so the count excludes it and the drawer names the provider. Revisit if the palette gains a colour. |
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
| The diff is derived by the caller, not carried in the payload | It needs memory of the previous scan, and `buildOverview` is required to have none (I7). Both consumers already hold two payloads, so `diffStacks(prev, next)` as a pure function of them adds no API surface, no server state, and nothing to keep consistent between the log line and the topbar. |
| "No config changes" is stated rather than left implied | A rescan that reports nothing is indistinguishable from a rescan that never ran, and `scanned <time>` moves either way. The commonest true answer to pressing the button is "I re-read everything and nothing in it differs" — which is only reassuring if it is said out loud. |
| An unmatched entry carries the reason, not just the name | Both matchers already knew the difference between "nothing named this" and "two services named it" and threw it away at the `return`. Those are not one problem: the second is the operator's to settle with a label and the first is usually LabView's to explain, and a bare `string[]` reported them identically. The lists became objects rather than gaining a parallel array so the same fact cannot exist twice and drift — accepted as a **breaking change** to `/api/overview`, documented in both READMEs. |
| The trace is a line per rule, including the rules that found nothing | A reason alone says what the verdict was, not what was examined to reach it, and an operator who disagrees with the verdict has nothing to check. Recording every rule also makes an omission visible: a new rule that forgets its line leaves a *short* trace, which an assertion can catch, where a silent rule reads exactly as if it never existed. |
| `--critical` is not used in the integration panels | It is the exposure warning's colour (see the SAML row above), and the panel's worst news is an ambiguity or a failed connection — neither is a service reachable without authentication. Reusing red there would make the two indistinguishable at a glance, which costs more than the panel gains. `--warning` carries `ambiguous`, an unauthenticated proxy API and the failed phase. |
| Integration movement is a second diff, not a field on `ScanDiff` | Folding it in would make `unchanged` mean two different things and would destroy the property the deny-list protects: a container that restarted, or an API that answered this time, is not an edit to a file. Two labelled structures reported side by side keep both answers available — `no config changes; authentik +1 application` says exactly what happened, where one merged "changed" would say neither. |
| Reachability is decided before any count is compared | An unreachable read reports zeros, so a count comparison across it announces `-40 applications`: a claim about Authentik's *contents* from a scan that never reached Authentik, and the clearest possible I1 violation. `started` and `stopped` therefore carry no numbers at all, and two failed reads in a row produce no entry — the banner and the connection line already state a standing failure, and repeating it as a change every rescan would make it read as news. |
| The counts are compared, but the diff is still not the connection line | `read` stays out of `changedConnections`'s signature: a count that moves on every scan must not log three connection lines a minute, and that trade is still right. The difference is that a *rescan* is an event somebody asked about, so stating what the read returned there costs one line per press instead of one line per minute. |
| The matched side is derived in the browser, not duplicated into `ScanMeta` | Every matched pair is already on `svc.authentik` / `svc.traefikLive`, so adding a roll-up to the payload would mean two representations of one join, kept in step by nothing. A `useMemo` over `ov.stacks` reads the same source the service drawer reads, which is also what makes a row in the panel able to open that drawer. The unmatched side has no such home — it is by definition attached to no service — so that half genuinely lives on `meta`. |
