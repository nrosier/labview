# LabView — Implementation Guide

The build spec. Every statement here is normative: a reimplementation that satisfies
this document is a drop-in replacement — same files at the same paths, same
environment, same endpoints, same authentication, same conclusions. `README.md`
explains how to run it.

Rules are grouped by module. §20 lists the eight invariants that outrank every other
rule in this document.

---

## 1. What it is

A read-only documentation generator for a Docker Compose homelab: it reads a tree of
compose files, optionally enriches them with live state from the Docker Engine,
Authentik, Traefik and an active HTTP probe, derives how each service is reached and
what authenticates it, and serves the result as a JSON API plus a self-contained
Preact UI. It never writes to the fleet.

- Backend: Node ≥ 20, TypeScript (ESM, `NodeNext`), Fastify 5, `dockerode`, `yaml`, `bcryptjs`, `@fastify/static`.
- Frontend: Preact bundled by Vite into `web/dist` — one self-contained `app.js`.
- Distribution: two-stage Alpine image (`node:26-alpine`), `USER node`, `EXPOSE 8080`.

Nothing about a particular fleet may be hard-coded: no hostnames, domains, container
names, network names or IPs, no assumption that a proxy/tunnel/SSO exists, no naming
convention read as a role (`auth.*` is not Authentik, `db` is not a database), no
assumption the Docker Engine is reachable, no assumption the edge in front of LabView
authenticates anything. The only names shipped as defaults are ones upstream projects
publish: label prefixes `dockflare` and `traefik`, the string `authentik`, the domain
`goauthentik.io`, and `/var/run/docker.sock`.

---

## 2. Layout

```text
labview/
  Dockerfile  compose.yml  config.example.yml  passwd.example  .labview.example
  package.json  tsconfig.json  tsconfig.web.json  tsconfig.scripts.json  .dockerignore
  src/
    index.ts          entrypoint: loadConfig() -> startServer()
    cli.ts            one-shot scan to stdout (`npm run scan [-- --summary]`)
    config.ts         defaults, config.yml merge, env overrides, withProbeEnabled, retiredSettings
    secrets.ts        env masking + URI credential redaction
    build.ts          which build is running (resolveBuildStamp pure; fs read separate)
    hashpw.ts         CLI: password -> a `user:hash` line
    model/types.ts    THE contract between backend and frontend (appendix A)
    model/access.ts   access-control vocabulary: posture line, failure text, username rule
    model/auth.ts     when a missing gate may be reported, and its wording
    model/build.ts    what the topbar and startup line say about the build
    model/changes.ts  what changed between two scans, and its wording
    model/connections.ts  connection-report wording, hints, log/banner rules
    model/declarations.ts the values a `.labview` may use, how each is worded, drift roll-up
    model/filter.ts   the dashboard's tri-state tag filter
    model/ingress.ts  the ingress vocabulary and every pure operation on it
    model/networks.ts which network nodes are drawn, dependency vs membership, caps, wording
    model/ports.ts    reading a compose port mapping for the published host port
    model/probe.ts    which addresses may be asked, what counts as a login page, form shape,
                      per-verdict reason text, the Login probe roll-up
    model/viewstate.ts the dashboard's view as a query string
    scan/discover.ts  appsRoot -> stack directories
    scan/compose.ts   compose YAML -> normalized AppStack/Service
    scan/env.ts       dotenv parsing + Compose-compatible interpolation
    scan/paths.ts     path containment for every file read out of a stack dir (I8)
    scan/sidecar.ts   the `.labview` file: parse, clamp, refuse anything outside the root
    scan/index.ts     scanStacks(): discover + parse, collecting warnings
    labels/dockflare.ts labels -> CloudflareRoute[]
    labels/traefik.ts   labels -> TraefikRoute[]
    labels/auth.ts      routes + env + registry -> AuthPosture
    analyze/middlewares.ts cross-stack Traefik middleware registry
    analyze/origins.ts     cross-stack tunnel-origin resolution + FleetIndex/lookupAddress
    analyze/authentik.ts   applications -> services
    analyze/traefik.ts     live routers -> services, and its notes
    analyze/networks.ts    real network names + the fleet membership index
    analyze/dependencies.ts sidecar-declared dependencies -> resolved pairs + drift
    analyze/index.ts       the pipeline; ingress classification; stats
    analyze/graph.ts       nodes/edges for the relationship graph
    enrich/http.ts     fetch wrapper: timeouts, JSON, injectable fetchImpl (no I/O policy)
    enrich/pool.ts     bounded concurrency (no I/O policy)
    enrich/docker.ts   Docker Engine snapshot (never throws)
    enrich/authentik.ts Authentik REST snapshot (never throws)
    enrich/traefik.ts  Traefik runtime-API snapshot (never throws)
    enrich/probe.ts    asks each scanned HTTP service what it answers (never throws)
    auth/hash.ts       modular-crypt dispatch over bcryptjs (`$2a$`/`$2b$`/`$2y$`)
    auth/passwd.ts     parsePasswd (pure) + readPasswd (fs, re-read on stat change)
    auth/session.ts    signed session cookie, revocations, Origin/scheme rules (now injected)
    auth/oidc.ts       discovery, PKCE, token exchange, ID-token verification (now+fetch injected)
    auth/throttle.ts   failed sign-ins per username (now injected)
    auth/index.ts      resolveAccessMode, isPublicPath, requiresSession, config resolution
    server/cache.ts    scan cache: TTL, coalescing, force semantics, per-request value
    server/auth.ts     the gate: one onRequest hook, one onSend hook, five routes
    server/server.ts   Fastify: buildApp() -> /api/* + static UI
  web/
    index.html  main.tsx  model.ts  api.ts  styles.css  vite.config.ts
    lib/{palette,mermaidDef,format,modal}.ts
    components/{ApiDetail,AppDetail,DriftDetail,ProbeDetail,Panel,Section,StackCard,
                GraphView,Mermaid,NetworksSection,Login,badges,icons,stats}.tsx
  scripts/smoke.ts   pipeline assertions over the fixtures
  tools/probe-lab/{report,cli}.ts + README.md   diagnostic, not in the image
  fixtures/
    apps/        a representative happy-path fleet
    edge/        one stack per previously-fixed defect
    nets/        shared networks, declared dependencies, bad references
    authentik/   a fleet with an identity provider in it       + authentik-api.json
    traefik/     labels and live proxy config that disagree    + traefik-api.json
    probe/       what a service answers when asked, one address per stack
    auth/        passwd files: passwd.ok, passwd.messy, passwd.empty
    outside-root.env       the `env_file` escape target, outside every scan root
    outside-root.labview   the sidecar-symlink escape target (I8)
```

Repo root holds README, LICENSE, `IMPLEMENTATION.md` and `.github/`. All code is under
`labview/`, which is why every workflow scopes its paths there and why the Docker build
context is `./labview`.

`model/*` is pure and web-safe: no Node-only imports, no I/O, no clock. `web/model.ts`
re-exports `model/types.ts`. Anything that decides what a reader sees lives in `model/`
so `scripts/smoke.ts` can call it without a DOM.

---

## 3. Configuration

Precedence, lowest to highest: **defaults in `config.ts`** → **`config.yml`** (path from
`LABVIEW_CONFIG`, default `./config.yml`) → **environment**. Arrays replace, never merge.
A malformed config file logs `[config] failed to parse <path>: <message>; using defaults`
and falls back to defaults rather than exiting. `merge()` deep-copies (never spreads):
`applyEnvOverrides` mutates nested objects in place, so a shallow merge would leak one
`loadConfig()` call's overrides into the next. `merge()` preserves unknown keys — which
is what lets `retiredSettings` still see a `tokenFile:` in an old config file.

### 3.1 Defaults

```yaml
appsRoot:          "/data/apps"
composeFilenames:  ["compose.yml","compose.yaml","docker-compose.yml","docker-compose.yaml"]
sidecarFilenames:  [".labview",".labview.yml",".labview.yaml"]
docker:   { enabled: true, host: "", port: 2375, socketPath: "/var/run/docker.sock",
            maxConcurrency: 8, timeoutMs: 5000 }
secrets:  { maskValues: true,
            keyPatterns: ["PASS","SECRET","TOKEN","KEY","APIKEY","CREDENTIAL","PRIVATE",
                          "SALT","PEPPER","DSN"],
            keysAlways: ["LABVIEW_AUTHENTIK_TOKEN","LABVIEW_TRAEFIK_PASSWORD",
                         "LABVIEW_OIDC_CLIENT_SECRET","LABVIEW_SESSION_SECRET"],
            keysNever: ["PUBLIC_KEY_URL","KEYCLOAK_REALM"],
            redactUriCredentials: true }
labels:   { dockflare: { prefix: "dockflare" }, traefik: { prefix: "traefik" },
            authentik: { hostHints: ["authentik","goauthentik.io"],
                         ldapEnvHints: ["LDAP_HOST","LDAP_URI","LDAP_SERVER","LDAP_URL"],
                         oauthEnvHints: ["OIDC","OAUTH","OPENID","ISSUER","CLIENT_ID",
                                         "CLIENT_SECRET","SSO"] } }
authentik: { enabled: true, url: "", token: "", timeoutMs: 5000, maxPages: 20 }
traefik:   { enabled: true, url: "", username: "", password: "", timeoutMs: 5000 }
probe:     { enabled: false, lanHost: "", timeoutMs: 5000, maxConcurrency: 4 }
auth:      { passwd: { enabled: true, file: "/config/passwd" },
             oidc: { enabled: true, issuer: "", clientId: "", clientSecret: "",
                     redirectUri: "", scopes: ["openid","profile","email"],
                     usernameClaim: "preferred_username", label: "", timeoutMs: 5000 },
             session: { secret: "", ttlMinutes: 720, cookieName: "labview_session",
                        secure: "auto" },
             maxFailedAttempts: 5, lockoutSeconds: 60 }
cacheTtlSeconds: 60
server: { host: "0.0.0.0", port: 8080 }
blankCredentialVars: []          # filled by applyEnvOverrides only
```

`DEFAULT_DOCKER_SOCKET = "/var/run/docker.sock"` is exported: the enrichment layer must
tell "the built-in default nobody chose" from "the operator named this path".

`enabled` everywhere means **allowed, not on**: a method or integration is live only
when it is also usable. No default TCP Docker host, no `authentik.url`, no
`traefik.url`, no host-naming convention (`auth.`, `sso.`) may ever ship (I2).

### 3.2 Environment

Booleans are `value !== "false"` — the variable being present at all means the operator
meant something. Numbers are `Number()`, `Number.isFinite`, floored, and rejected
(default kept) when out of range; `maxConcurrency` requires `>= 1`, timeouts `> 0`,
`ttlMinutes`/`maxFailedAttempts`/`lockoutSeconds` `>= 1`.

| Env | Config | Rule |
|---|---|---|
| `LABVIEW_CONFIG` | — | config file path, default `./config.yml` |
| `LABVIEW_APPS_ROOT` | `appsRoot` | scan root and containment boundary (I8) |
| `LABVIEW_SIDECAR_FILENAMES` | `sidecarFilenames` | comma-separated, trimmed, empties dropped; ignored when the result is empty |
| `LABVIEW_DOCKER_HOST` / `DOCKER_HOST` | `docker.host`+`port` | `tcp://h:p`, `http(s)://h:p`, `h:p`, bare `h` (port defaults 2375), `unix:///p`, `/p`. A socket form sets `socketPath` and clears `host`. `LABVIEW_DOCKER_HOST` wins |
| `LABVIEW_DOCKER_PORT` | `docker.port` | `Number()`, unvalidated |
| `LABVIEW_DOCKER_SOCKET` | `docker.socketPath` | always wins; clears `host` |
| `LABVIEW_DOCKER_ENABLED` | `docker.enabled` | `false` = config-only scan |
| `LABVIEW_DOCKER_MAX_CONCURRENCY` | `docker.maxConcurrency` | bounded `inspect` fan-out |
| `LABVIEW_DOCKER_TIMEOUT` | `docker.timeoutMs` | socket **inactivity** per request, not total time |
| `LABVIEW_MASK_SECRETS` | `secrets.maskValues` | |
| `LABVIEW_CACHE_TTL` | `cacheTtlSeconds` | `Number()`, unvalidated |
| `LABVIEW_PORT` / `LABVIEW_HOST` | `server.port` / `host` | |
| `LABVIEW_LOG_LEVEL` | — | Fastify logger level, default `info` |
| `LABVIEW_BUILD_SHA` | — | **env-only, no config key** (§3.4) |
| `LABVIEW_AUTHENTIK_TOKEN` | `authentik.token` | credential. Unset = step 7 makes no request; set-and-empty = `credential` fault |
| `LABVIEW_AUTHENTIK_URL` | `authentik.url` | skips discovery |
| `LABVIEW_AUTHENTIK_ENABLED` | `authentik.enabled` | |
| `LABVIEW_AUTHENTIK_TIMEOUT` | `authentik.timeoutMs` | per request; `authentik.maxPages` is file-only |
| `LABVIEW_TRAEFIK_URL` | `traefik.url` | skips discovery; one of the two things that make an endpoint eligible for a credential (§11) |
| `LABVIEW_TRAEFIK_USERNAME` | `traefik.username` | an Authentik user, or the reserved `goauthentik.io/token` |
| `LABVIEW_TRAEFIK_PASSWORD` | `traefik.password` | credential; an app password, not an API token |
| `LABVIEW_TRAEFIK_ENABLED` | `traefik.enabled` | on by default — needs no credential |
| `LABVIEW_TRAEFIK_TIMEOUT` | `traefik.timeoutMs` | per request |
| `LABVIEW_PROBE_ENABLED` | `probe.enabled` | the **default**, not the authority (§12.7). Any value but `false` turns it on |
| `LABVIEW_PROBE_LAN_HOST` | `probe.lanHost` | empty skips the LAN vantage entirely; never guessed |
| `LABVIEW_PROBE_TIMEOUT` | `probe.timeoutMs` | per request |
| `LABVIEW_PROBE_MAX_CONCURRENCY` | `probe.maxConcurrency` | services at once. Addresses *per* service is not configurable (`MAX_PROBE_TARGETS`) |
| `LABVIEW_AUTH_PASSWD_ENABLED` | `auth.passwd.enabled` | `false` = form off, file never read |
| `LABVIEW_AUTH_PASSWD_FILE` | `auth.passwd.file` | `user:hash` lines |
| `LABVIEW_AUTH_MAX_FAILED_ATTEMPTS` | `auth.maxFailedAttempts` | per **username** |
| `LABVIEW_AUTH_LOCKOUT_SECONDS` | `auth.lockoutSeconds` | window and `Retry-After` |
| `LABVIEW_AUTH_COOKIE_SECURE` | `auth.session.secure` | only `auto`\|`true`\|`false` accepted; anything else keeps the default |
| `LABVIEW_OIDC_ENABLED` | `auth.oidc.enabled` | |
| `LABVIEW_OIDC_ISSUER` | `auth.oidc.issuer` | with a client id, this turns OIDC on |
| `LABVIEW_OIDC_CLIENT_ID` | `auth.oidc.clientId` | |
| `LABVIEW_OIDC_CLIENT_SECRET` | `auth.oidc.clientSecret` | credential. Unset = public client (PKCE either way); set-and-empty = startup note + public client, never a refusal to start |
| `LABVIEW_OIDC_REDIRECT_URI` | `auth.oidc.redirectUri` | empty derives it from the request, honouring `X-Forwarded-Proto`/`-Host` |
| `LABVIEW_OIDC_SCOPES` | `auth.oidc.scopes` | split on `[,\s]+`; `openid` is sent whether listed or not |
| `LABVIEW_OIDC_USERNAME_CLAIM` | `auth.oidc.usernameClaim` | |
| `LABVIEW_OIDC_LABEL` | `auth.oidc.label` | empty = "Sign in with \<issuer host>" |
| `LABVIEW_OIDC_TIMEOUT` | `auth.oidc.timeoutMs` | discovery, token exchange, JWKS |
| `LABVIEW_SESSION_SECRET` | `auth.session.secret` | credential. Unset = a random one per start (restarts sign everyone out) |
| `LABVIEW_SESSION_TTL_MINUTES` | `auth.session.ttlMinutes` | also the cookie `Max-Age` |
| `LABVIEW_SESSION_COOKIE_NAME` | `auth.session.cookieName` | the OIDC transient cookie is this + `_oidc` |

### 3.3 Credentials come from the environment

Exactly four settings are credentials: `authentik.token`, `traefik.password`,
`auth.oidc.clientSecret`, `auth.session.secret`. Each has exactly one variable and
**there is deliberately no path form** — no `tokenFile`, no `*_FILE`. All four are in
`secrets.keysAlways`. Rotation therefore requires a process restart; `auth.passwd.file`
is exempt and is still re-read on change.

- **`blankCredentialVars: string[]`** — filled by `applyEnvOverrides` with the names of
  credential variables that were **present and carried nothing** (`raw !== undefined`,
  `raw.trim() === ""`). That distinction survives nowhere else. Assigned, never appended:
  a config file setting the key has no standing. **Names only, never values** (I6).
  Readers translate it: a `credential` fault for a scan target (§14), a startup note for
  LabView's own login (§18).
- **`retiredSettings(cfg, env)`** — recognises four retired variables and four config
  keys for the single purpose of saying they are gone. Neither value nor path is echoed.
  Both entry points print it: `buildApp` via `app.log.warn`, `cli.ts` to stderr so JSON
  on stdout stays parseable.

| Retired variable | Retired config key | Message |
|---|---|---|
| `LABVIEW_AUTHENTIK_TOKEN_FILE` | `authentik.tokenFile` | `<was> is no longer read — put the value in <now> instead` |
| `LABVIEW_TRAEFIK_PASSWORD_FILE` | `traefik.passwordFile` | same |
| `LABVIEW_OIDC_CLIENT_SECRET_FILE` | `auth.oidc.clientSecretFile` | same |
| `LABVIEW_SESSION_SECRET_FILE` | `auth.session.secretFile` | same |

A config key produces `<block>.<field> in the config file is no longer read — put the
value in <now> instead`, and is reported when the held value is a non-blank string.

**`LABVIEW_BUILD_SHA` has no config-file key, as a rule rather than an omission.**
`config.yml` is editable while LabView runs, so a key there would let a running instance
claim it is a different build than it is (I1). Nothing ever writes the variable.

### 3.4 The build stamp

`resolveBuildStamp(sources)` is pure (`{env, readText, from?}`) and `buildStamp()`
memoizes it over `process.env` + a sync reader. `VERSION = "0.1.0"`,
`SHORT_SHA_CHARS = 7`, `MAX_SHA_CHARS = 40`, `MAX_WALK_LEVELS = 4`,
`MAX_GIT_FILE_BYTES = 256 * 1024`.

1. **Environment first.** `LABVIEW_BUILD_SHA`, trimmed, must match
   `/^[A-Za-z0-9._-]+$/` — anything else is treated as absent, not trimmed into a
   different string. Capped at 40 chars; a full object id (`/^[0-9a-f]{40}$/i`) is cut to
   7, anything else used as given (a tag is a deliberate answer). ⇒
   `{version, commit, source: "image"}`.
2. **Else the checkout.** Walk up from this module's directory at most
   `MAX_WALK_LEVELS` levels looking for `.git/HEAD`. A `.git` that reads as a *file*
   (worktree/submodule pointer) **ends the walk with no answer** rather than following
   `gitdir:`. `HEAD` is either a full sha (shortened to 7) or `ref: <name>` where the
   name must match `/^refs\/[A-Za-z0-9._\-\/]+$/` and contain no `..` (I8 in the small);
   then the loose ref file, then `packed-refs` (ignoring `^`-peeled and comment lines).
   ⇒ `source: "checkout"`.
3. **Else** `{version, source: "unknown"}` — no `commit` key at all, never an empty
   string.

`model/build.ts` turns a `BuildStamp` into `buildLabel` (`● LabView d0e2030`, falling
back to the version when there is no commit) and `buildTitle` — one sentence per
`source`, so "built from that commit" and "started in a tree at that commit" are
distinguished in one place.

### 3.5 Endpoint resolution orders

- **Docker:** explicit socket → configured/env TCP host → default socket path. Which of
  the three was used is the connection's `source` (`config` | `discovered` | `default`).
- **Authentik:** configured `url` → discovered internal container addresses → discovered
  public hostnames.
- **Traefik:** configured `url` → discovered internal container addresses (each declared
  `ports[].target`, plus `8080`) → discovered public hostnames.

Internal addresses always before public ones, deduped and capped. An address is a fact
about the operator's fleet: discovered or supplied, never defaulted (I2).

### 3.6 The one request-scoped setting

`probe.enabled` is the only setting a request may override, and only for the single
build that request starts (§12.7). `withProbeEnabled(cfg, enabled)` returns a
**clone** — `{...cfg, probe: {...cfg.probe, enabled}}` — because the cache may have
another build in flight holding the old config. Asserted directly: the copy carries the
new value, neither the config nor its `probe` block is the same object, and the copy is
otherwise identical. Everything else is fixed for the life of the process (I7).

---

## 4. The pipeline

`buildOverview(cfg, now)` in `analyze/index.ts` is the whole program: a pure function
of `(config, filesystem, docker, now)` with **no logger** — diagnostics are data on
`meta.connections`, printed by callers (I7).

| Stage | Owner | Produces |
|---|---|---|
| 1. Discover | `scan/discover.ts` | one `DiscoveredStack` per immediate subdirectory holding a compose file, sorted by id |
| 2. Parse | `scan/compose.ts` + `scan/env.ts` + `scan/sidecar.ts` | `AppStack[]` — services, ports, mounts, interpolated env, labels, declarations |
| 3. Docker snapshot | `enrich/docker.ts` | `DockerSnapshot` keyed by `"project service"`, container name and short id |
| — | each `enrich/*` client | one `ConnectionReport` per target → `meta.connections` (§14) |
| 4. Middleware registry | `analyze/middlewares.ts` | every Traefik middleware *defined* anywhere, by bare name |
| 5. Pass 1 — routes | `labels/dockflare.ts`, `labels/traefik.ts` | `svc.cloudflare`, `svc.traefik`, `svc.docker` |
| 5b. Ingress classification | `sharedNetworks` + `classifyIngress` | `svc.ingress`, over the whole fleet at once; builds the `NetworkIndex` |
| 6. Fleet index + origins | `analyze/origins.ts` | `FleetIndex` (host ports, DNS names, container IPs, hostnames); `route.origin` |
| 6b. Declared dependencies | `analyze/dependencies.ts` | resolved sidecar `depends_on` pairs with their shared network; `declared.drift` for the rest |
| 7. Identity provider API | `enrich/authentik.ts` | `AuthentikSnapshot`, or a reason it is absent. Skipped entirely with no token |
| 8. Reverse proxy API | `enrich/traefik.ts` | `TraefikSnapshot`, or a reason. Concurrent with step 7 |
| 8b. Active probe | `enrich/probe.ts` | `svc.probe` for eligible services. Off unless switched on; runs between the halves of step 12 |
| 9. Provider discovery | `discoverAuthentikHints` | hint strings identifying the SSO provider *in this fleet* |
| 10. Application matching | `analyze/authentik.ts` | `svc.authentik` + `unmatchedApplications` |
| 11. Live router matching | `analyze/traefik.ts` | `svc.traefikLive` + `unmatchedRouters` |
| 12. Pass 2 — auth | `labels/auth.ts` | **2a**: every `svc.auth`, and the set of keys with detected auth (the probe's eligibility). **2b** after the probe: `exposedWithoutAuth`, notes; then secrets masked |
| 13. Graph | `analyze/graph.ts` | services, networks, shared volumes, resolved ingress paths, auth hubs |
| 14. Stats | `computeStats` | `OverviewStats` |

**Two passes, because six conclusions need the whole fleet:** a middleware reference
like `authentik@docker` is usually defined in another stack (step 4); which hostnames
represent the SSO provider is learned from the stack that *runs* it (step 9 after 5); a
tunnel origin routinely names a proxy in another stack (step 6); an application is
matched against the fleet as a whole (step 10, reusing step 6's index); a live router
names its backend by container address and its hosts by rule (step 11); and `internal`
ingress is a claim about *other* containers, so every service's networks must be counted
before any service is classified (step 5b). Step 6b needs both step 6's index (to
resolve a name in any stack) and step 5b's `NetworkIndex` (to know which network the
pair shares), and runs before the graph because that is where a resolved pair lands.

A change that needs fleet-wide knowledge belongs in a new pass or in step 4/9, never in
a per-service function reaching for global state.

**Scheduling.** A *configured* endpoint depends on nothing in the scan, so its request
starts before the docker snapshot and is awaited after, overlapping the two. A
*discovered* endpoint cannot be found until pass 1 parsed the routes, so it runs after —
and both discovered exchanges go out under one `Promise.all`. Origin resolution runs
**ahead** of the discovered reads: a resolved origin structurally identifies the service
acting as reverse proxy, which is one of Traefik discovery's three signals. An endpoint
that answered the Authentik API becomes an input to step 9 — having answered as an
Authentik API is stronger evidence of identity than any name match, and it is what
attributes an OIDC issuer correctly when the provider runs outside the scanned root.

**The probe does not join the concurrent reads.** Whether this scan found any
authentication is unknown until both API reads land and `deriveAuth` has run, so pass 2
splits: 2a derives auth and collects the keys with detected authentication, the probe
runs, 2b attaches results and settles exposure. An enabled probe therefore adds its own
wall-clock; what it buys is not asking an SSO endpoint a question whose answer could not
have changed anything.

---

## 5. Scanning

**Stack** — one immediate subdirectory of `appsRoot` containing a compose file
(`composeFilenames`, in order). Its directory name is its id and its default compose
project name. **Service** — one entry under `services:`, keyed in the graph as
`svc:<stack>/<service>`; matched to a live container by
`com.docker.compose.project` + `com.docker.compose.service` labels first, then by
container name.

- `scan/env.ts` — dotenv parsing plus Compose-compatible interpolation:
  `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `${VAR:?err}`, `${VAR?err}`, escaped
  `$$`. Recursion is bounded (`MAX_DEPTH = 32`), names match `/^([A-Za-z_][A-Za-z0-9_]*)/`.
  Each `EnvVar` records its `source`: `env_file` | `environment` | `shell-default`.
  An unresolved `${VAR}` is a `service.notes` entry, never a failure (I4).
- `scan/paths.ts` — `resolveContained(dir, appsRoot, name)` returns `null` for anything
  that escapes the apps root lexically (`../../etc/shadow`) **or** through a symlink.
  Both the literal and the fully-resolved apps root are accepted, because an apps root is
  often reached through a symlink or bind mount. Every file read out of a stack directory
  goes through it: `env_file` and the sidecar today, anything added later by rule (I8).
  A refusal is a service note or a sidecar warning, never silence.
- `scan/index.ts` — `scanStacks()` collects: YAML parse error → `stack.warnings` with the
  stack still listed; unreadable stack → `meta.warnings`.

**The sidecar** (`scan/sidecar.ts`). Candidate names come from `cfg.sidecarFilenames`;
the first that exists wins, so two sidecars in one directory can never half-apply.
Untrusted input, served verbatim on `/api/overview`, so: `MAX_SIDECAR_BYTES = 64 * 1024`
(over-size ⇒ ignored with a warning naming the size and the limit), `MAX_TEXT_CHARS =
2000` per string, `MAX_LIST_ENTRIES = 32` for `links`/`dependencies`/`depends_on` each,
`MAX_AUTH_ENTRIES = 8` per service. Deliberately **not** interpolated with the stack's
`.env`: declarations are prose, so `${VAR}` stays exactly as written.

Accepted keys — anything else is named in a warning:

| Level | Keys |
|---|---|
| top | `description`, `owner`, `criticality`, `notes`, `data`, `links`, `dependencies`, `services` |
| `services.<name>` | those minus `services`, plus `depends_on`, `auth`, `unauthenticated`, `expected` |

A declaration for a service the compose file does not define is reported rather than
silently doing nothing. `Declaration.file` is the sidecar's **basename**, never a full
path (I2).

Every rejection is a warning and every warning is formulaic — `${where}: <what was wrong>;
ignored`, where `where` is `${file}`, `${file} services.<name>`, or that plus the field and
index (`… .links[2].url`). Smoke asserts the strings verbatim, so a reimplementation must
keep the shapes:

- a wrong type — `expected a mapping`, `expected text`, `expected a list`,
  `expected {label, url}`, `expected a name or {name, detail}`,
  `expected "stack/service" or {service, detail}`,
  `expected a mechanism name or {mechanism, detail}`, `expected {intentional, reason}`,
  `expected {ingress}`
- a missing required half — `needs a "url"`, `needs a "name"`, `needs a "service"`,
  `needs a "mechanism"`, `needs "intentional: true" to apply`
- a value outside a closed set — `"${x}" is not a known mechanism (<the list>)`,
  `"${kind}" is not one of <INGRESS_KINDS>`,
  `"${ref}" is not a service reference — write "stack/service", or the service name on its own`
- a cap — `truncated to 2000 characters` (and `…` appended to the value),
  `.links: more than 32 entries; the rest ignored`, `.auth: more than 8 entries; …`
- a typo — `unknown key(s) "a", "b"; ignored`
- the two that explain rather than name a type: `"depends_on" is a service-level key — at
  stack level it cannot say which service depends on the target`, and `"intentional: true"
  needs a "reason" — an acceptance with no reason cannot be told from a mistake`

Three details a reimplementation gets wrong by default: a link is passed through
`redactUriCredentials` **before** the label falls back to the URL, or a password lands in the
visible link text; `readExpected` tries the **list** branch first, because `readText` refuses a
non-scalar and a list reaching it would be reported as the wrong type; and `hasContent` /
`hasServiceContent` decide whether a declaration is stored at all, so an all-empty block
produces no `Declaration` rather than an empty one.

---

## 6. Label readers

`labels/dockflare.ts` → `CloudflareRoute[]`: both the flat and the indexed multi-route
label forms, `enable` honoured, `access` (group/policy/emails), `noTlsVerify`, and the
raw label map retained.

`labels/traefik.ts` → `TraefikRoute[]`: router name, `rule`, hosts parsed out of the
rule, path prefixes, entrypoints, `tls`, `certResolver`, middleware references,
`servicePort`, service name.

**Middleware registry** (`analyze/middlewares.ts`) — every
`traefik.http.middlewares.<name>.<type>` label found in *any* stack, keyed by **bare
name** (a reference's `@docker`/`@file` provider suffix is stripped). On a name collision
an auth type wins over a non-auth type, so a `headers` middleware cannot shadow a
`forwardauth` one.

**`labels/auth.ts`** → `AuthPosture` from routes + env + registry.

- `classifyMiddleware` reads the **registry definition first** and only falls back to the
  middleware *name* when no definition was found anywhere — and then marks the result
  `inferred` and writes a service note saying so. A middleware called `authentik` that
  points elsewhere is not Authentik (I3).
- `identifies()` matches hints at **token boundaries, never as bare substrings**: `auth`
  must not match `oauth.bigcorp.example.com`.
- `CONFIDENCE_RANK = {confirmed: 0, observed: 1, inferred: 2}`. When two accounts of one
  service disagree, the higher rank is reported and the lower is kept in `evidence`.
- `NO_PROVIDER = "provider not identified from the scanned config"` is the evidence line
  for a mechanism whose provider could not be named.
- `providerEnforces` and `routerIsServing` live here and are reused by the analyzers.

**Hints** — a string identifying the SSO provider, configured
(`labels.authentik.hostHints`) or discovered. Matched at token boundaries against
forward-auth addresses, issuer URLs and LDAP hosts.

**`discoverAuthentikHints` (step 9)** walks the parsed fleet for a service that is
identifiably Authentik — its image mentions `authentik`, or one of its labels defines a
forward-auth address containing `goauthentik.io` — and adopts that service's container
name and every Traefik/DockFlare hostname it answers on as hints. Two properties:

- **It cannot invent a provider.** No such service ⇒ nothing learned, every issuer stays
  generic. This is what makes a non-Authentik fleet report honestly.
- **A hint must be specific.** `isSpecificHint` rejects short or bare words, because
  upstream Authentik names its own services `server` and `worker` and learning `server`
  verbatim would make every `OIDC_ISSUER=https://server.example.com` look like Authentik.

---

## 7. Ingress and networks

**`IngressKind`** — five independent values, ordered most → least exposed in
`INGRESS_KINDS` (`model/ingress.ts`); `EXTERNAL_KINDS = ["public","traefik","lan"]`:

| Kind | Evidence |
|---|---|
| `public` | a Cloudflare tunnel route with a hostname |
| `traefik` | a Traefik route with hosts or a rule |
| `lan` | `ports:` is non-empty — published on the host |
| `internal` | `expose:` is non-empty, **or** `realNetworks()` shares a name with another scanned service — **and** none of the three above holds |
| `none` | none of the above |

`ports:` vs `expose:` are two different reachability claims and both are read: `ports:`
publishes on the host so it is `lan`; `expose:` only records that the container listens
so it is `internal`. Any entry counts, including the short form with no host side
(`ports: ["9100"]`) — for both keys the *presence* of an entry is the signal, never a
parsed port number.

A service carries a **set**: `svc.ingress` is `IngressKind[]`. `normalizeIngress` is the
only constructor — deduped, canonically ordered, never empty, and it **withholds
`internal`** from any set already carrying `public`, `traefik` or `lan`, so `svc.ingress`
answers *is a neighbour the only way in*. A stack carries the union of its services',
built by `rollUpIngress`, which is the one place the withholding must **not** apply.
Nothing combines two kinds into a third; the only function that picks a winner is
`primaryIngress`, and it exists solely because a graph node has one fill colour.

Every question about a set goes through `model/ingress.ts`: `isExternallyReachable` is
the single definition of "someone outside the container network can answer" — used by
both `exposedWithoutAuth` and the stale-acceptance check, and it asks its own question of
its own three kinds rather than testing for `internal`; `externalIngress` narrows a note
to the kinds that make a service reachable; `diffIngress` reports a sidecar disagreement
in both directions.

**`realNetworks`** — the networks a service is demonstrably on. It materializes the
implicit `default` network, resolves `${project}_${key}`, and honours `external:` under
its verbatim name, so two services in one file are mutually reachable without either
declaring a network, and two *stacks* on one external network are too. `depends_on` is
deliberately **not** evidence: a dependency across two disjoint networks is not
reachability.

**`NetworkIndex` / `NetworkMembership`** (`analyze/networks.ts`) — the one fleet-wide
membership index, built once over `realNetworks`. `byName` gives each real network its
`members` (`stack/service`, scan order), the distinct `stacks` among them, and whether
any stack declares it `external:`; `byService` gives the reverse. Passed as an optional
trailing argument to `buildFleetIndex` and `buildGraph`, both of which still build their
own when called without one. This is what makes the `internal` ingress rule, the graph's
network nodes and the stats provably one relation.

**`NetworkScope`** — `external | stack-local` on a `network` node; not a severity, it
says who *can* be on the network. A `stack-local` network is created by one compose
project so only that project's services can ever join it; an `external:` one can carry
several stacks and containers this scan never saw. Wording lives in `NETWORK_SCOPES`.

**`memberCount` / `stackCount`** — how many *scanned* services are attached and from how
many distinct stacks, counted on the node because the spokes beside it are capped.
Neither counts what the scan cannot see (I1).

**Edges.** `flow` on a `network` edge is where the dependency arrowhead sits:
`to-network` (this service is the dependent), `to-service` (something else on that
network depends on it), `both`, or **absent** — the common case, meaning this service is
on the network and nothing crosses it. `flowSource` is `observed | declared | both`: the
line is dashed when every dependency crossing that leg was declared, and `both` stays
solid. `declaredBy` on a `depends_on` edge carries the sidecar `file` and optional
`detail`; absent means read from a compose file, which is what renderers test for dashed
vs solid. `via` on a `depends_on` edge is the real networks the pair shares in the
dependent's compose order: non-empty is normal and means the direct edge is **not** drawn
(`showsDirectDependency`), because `flow` on the two membership edges already shows it;
empty means compose orders the two containers' startup yet neither can address the other,
so the direct edge is the only honest drawing and the analyzer also states it in words on
the dependent's `notes`.

**`NetworkRelation`** — `depends-on | required-by | peer`, what one service is to another
*across a named shared network*. A dependency counts only over a network in its `via`.
`peer` is the **absence** of a relation — a co-member, reachable and no more — so nothing
is ever labelled with it and no function returns it.

**`DeclaredServiceDependency` / `ResolvedDependency`** — two halves of one fact, kept
apart. The first is what the sidecar wrote (`ref` exactly as typed, optional `detail`),
stored unresolved because the parser cannot see other stacks and because this is the
object a rescan compares. The second is what step 6b made of it: `from`, `to`, `file`,
`detail`, and `via` from the same `sharedWith` helper the compose edges use.

**`NetworkLink.dependencies` / `.reachableCount`** — a service's view of one network split
by whether anything crosses it: a list on one side, a number on the other.
`reachableCount` holds **no names**, not even truncated ones; the names are answered by
`networkGroups` under the network's own heading.

**Caps** — `MAX_GRAPH_SPOKES = 12`, `MAX_DRAWER_PEERS = 8`, `MAX_LIST_PEERS = 12`. The
fleet graph caps spokes per network node; the drawer caps **dependencies** per network at
`MAX_DRAWER_PEERS` (its only list); `MAX_LIST_PEERS` caps the member chips the fleet
Networks section draws before a row is expanded and reaches the drawer nowhere.
`visibleSpokes` keeps dependency-carrying spokes first. All of them report what was left
out, and `networkNodeLabel` puts `+k not drawn` on the node.

**Network counters** — `networks`, `connectingNetworks` (2+ services),
`crossStackNetworks` (2+ stacks), `soloLocalNetworks` (stack-local, single service). The
last is *exactly* what the fleet graph omits, so drawn network nodes +
`soloLocalNetworks` = `networks` is checkable. `declaredDependencies` counts references
that **resolved** to an edge; the ones that failed are in `declarationDrift`.

---

## 8. Tunnel origin resolution (step 6)

A tunnel rarely terminates at the container whose labels declare it: the origin
(`dockflare.service`) normally names a reverse proxy that forwards over a shared network.
`analyze/origins.ts` resolves it from evidence and records the conclusion on
`route.origin` for every route whose `service` is non-empty.

- **An IP literal addresses the host**, so its port is a *published host port*, and a
  host port can only be held by one service — a match identifies rather than suggests.
- **A bare name addresses a container**, so the port says nothing about ownership and the
  *name* is the evidence: compose publishes a service's name and `container_name` as DNS
  aliases on its networks.
- **Network membership breaks a port tie.** A fleet may declare one host port on several
  services; a candidate sharing no network with the service it supposedly fronts cannot
  forward to it.
- **Repeated declarations by one service are not rivals.** `443:443/tcp` beside
  `443:443/udp`, or a name equal to the service's own `container_name`, reach the index
  twice; `distinct()` collapses them by service key.
- **A genuine tie stays unresolved** — never a winner picked by order. So do a FQDN and a
  port nobody publishes.

| `OriginKind` | Meaning | Graph |
|---|---|---|
| `self-network` | the origin host is this service's own name or `container_name` | direct `tunnel → service` |
| `self-host-port` | the origin port is a host port *this* service publishes | direct `tunnel → service` |
| `fleet-service` | resolves to another scanned service sharing a network with this one — `hopKey` names it | chained `tunnel → hop → service` |
| `unresolved` | no match, a FQDN, or a tie between reachable candidates | direct `tunnel → service` + a service note stating which reason applied |

`unresolved` keeps the direct edge deliberately: an invented hop would be a claim about
the path, and dropping the edge would hide a route that exists. Every `OriginTarget`
carries `address`, `host`, `port`, `kind`, optional `hopKey` and an `evidence` string.

No image, vendor or naming convention is consulted anywhere in the module — the proxy is
identified structurally, by what it publishes and what it can reach.

The module also exports the **`FleetIndex`** the later passes share: published host ports,
container DNS names, container IPs (`byContainerIp`) and declared hostnames, plus
`lookupAddress` (name or URL → candidate `ServiceRef[]`), `lookupContainerAddress`,
`normalizeHost` and `serviceRefKey`.

**Proxy role** — `GraphNode.role: "proxy"` is set on a service another service's origin
resolved to, or on the service whose Traefik API answered. It stays an ordinary service
node (same kind, same drawer, same click target); the role only lets the UI colour it as
infrastructure. No service is ever *declared* a proxy.

---

## 9. Docker enrichment (step 3)

`snapshotDocker(cfg, deps)` in `enrich/docker.ts`. Never throws.

- Endpoint: `unix://<socketPath>` when `docker.host` is empty, else
  `tcp://<host>:<port>`. `ConnectionReport.source` is `default` when the socket path is
  still `DEFAULT_DOCKER_SOCKET`, else `config`.
- **Three Engine calls and no others** (I5, and the whole of `DockerLike`): `ping()`,
  `listContainers({all: true})`, and `getContainer(id).inspect()` per container. No
  `exec`, no logs, no writes.
- A unix socket is diagnosed **before** dockerode sees it: `probeSocketPath` does the
  `stat`/`access` (its only I/O), `phaseForSocket` is pure over the result and separates
  absent, present-but-not-a-socket (a bind mount of a missing host path creates an empty
  *directory* — the usual cause), present but not accessible to this uid (`authorize`, not
  `connect`), and present and answering.
- Inspects run through `mapWithConcurrency` (`docker.maxConcurrency`). A refused inspect
  is skipped, counted, and turns the read `partial` with
  `read: "<n> containers, <k> could not be inspected"` — the containers' ports, networks
  and health are missing, so they are left out of every conclusion rather than guessed.
- The index is written in **list order** so a duplicate key's winner does not depend on
  which inspect finished first. `byKey` holds three keys per container:
  `composeKey(project, service)` = `` `${project}\0${service}` `` from the
  `com.docker.compose.project`/`.service` labels, the container name, and the 12-character
  short id.
- `DockerState` from one inspect: `id` (12 chars), `name` (leading `/` stripped), `image`,
  `imageDigest` (`i.Image` when it starts `sha256:`, sliced to 19 chars), `state`
  (`State.Status`), `status` (the summary string from `listContainers`), `health`
  (`State.Health.Status`, else `"none"`), `running`, `restartCount`, `createdAt`,
  `startedAt`, `networks` (keys of `NetworkSettings.Networks`), `ipAddresses` (per network,
  only where non-empty — this is what `FleetIndex.byContainerIp` is built from), and
  `publishedPorts` from `NetworkSettings.Ports`: one `PortMapping` per binding
  (`published`, `target`, `protocol`, `raw` = `` `${HostIp?HostIp+":":""}${HostPort}->${key}` ``),
  or one entry with no `published` where a port is exposed and unbound.
- **A timeout is established by the clock, not by the code.** dockerode implements its
  `timeout` by destroying the socket, so a silent endpoint surfaces as `ECONNRESET` /
  "socket hang up". Each awaited call is timed and `classifyDockerError` returns `timeout`
  when elapsed ≥ `docker.timeoutMs`, there is no HTTP status, and the code is absent or a
  teardown code. A genuinely slow `403` keeps its status.

## 10. Identity provider API (steps 7 and 10)

Two modules split on the I/O boundary: `enrich/authentik.ts` (all network, no fleet
knowledge, never throws — a failure becomes a reason string) and `analyze/authentik.ts`
(no network; matches applications onto services with step 6's index).

**Endpoints read:** `core/applications/`, `providers/proxy/`, `providers/oauth2/`,
`outposts/instances/`, all under `API = "/api/v3"`. Paged through `getList` with
`PAGE_SIZE = 100`, up to `authentik.maxPages`.

`isAuthentikService(svc)` — the one definition of "this is Authentik", shared with hint
discovery (§6) — is true when the image matches `/goauthentik|authentik/i` or a label whose
key matches `/forwardauth\.address$/i` has a value containing `goauthentik.io`. Both are
things Authentik publishes about itself, never an assumption about how the operator named
anything (I2).

**Endpoint selection.** A configured `authentik.url` is used verbatim. Otherwise
candidates come from services whose image identifies Authentik, ordered **internal
addresses before public hostnames** and capped. Each is probed on
`/api/v3/root/config/` (upstream `AllowAny`); **only a candidate that answers with a JSON
object receives the token.** A discovered endpoint is a guess and a guess must never be
handed a credential. On a candidate that *did* answer, a 401/403 is conclusive: later
candidates are not tried and nothing further is sent.

**Enumerating applications is not a plain list read.** Upstream
`ApplicationViewSet.list()` drops `meta_hide = True`, paginates, and *then* runs the
policy engine over the page as the token's own user — skipped only when
`superuser_full_list=true` is sent **and** the token is a superuser. So the default answer
to a least-privilege token is "what may this user launch", and a service protected by an
application the token cannot launch would read as having no gate (I1). Two properties make
it recoverable:

- Pagination runs before the filter, so `pagination.count` is the **unfiltered** total.
  `ListResult.count` keeps it for every read, and it stays optional — the DRF-shaped
  `outposts/instances/` envelope carries no `pagination` block, and a non-numeric or
  negative count is treated as no count at all.
- Both provider lists name their application (`assigned_application_slug` / `_name`, plus
  the backchannel pair) and neither viewset applies a policy filter.

`buildApplications` is therefore two passes: pass one is the listed applications, tagged
`discoveredVia: "list"`; pass two walks both provider lists, skips any slug pass one
produced (the list response wins — it alone carries `launch_url` and `group`) and rebuilds
the rest as `discoveredVia: "provider"`, **in slug order** (I7). A rebuilt record is
thinner — no launch URL, no group, only the providers this token may read — so it can be
tied by address or name but never by a launch URL; `matchOne` states that as the first line
of its `considered` trace and the UI tags the row `rebuilt`.

`superuser_full_list=true` is sent unconditionally on that one request; it is ignored for a
non-superuser so it can only widen the answer. No config knob.

| Count | Meaning |
|---|---|
| `applications` | listed **plus** recovered |
| `applicationsConfigured` | `pagination.count` — what Authentik says exists (optional) |
| `applicationsWithheld` | configured − listed |
| `applicationsRecovered` | of those, how many a readable provider let LabView rebuild |

`withheld − recovered` is derived where needed, never stored. **The connection is
`partial` only when that difference is non-zero**; the hint names both fixes (superuser for
the exact list, or check the token's permissions).

**Matching (step 10)** — four rules, descending strength, each requiring **exactly one**
candidate; an ambiguous match is discarded and the application reported unmatched:

1. A proxy provider's `internal_host`, through `lookupAddress` — the provider naming its
   own target. → `strength: "address"`
2. A **bare-name** host inside a URL the provider hands out (launch URL, `external_host`,
   OAuth2 redirect URI), through the fleet index. → `"address"`
3. A **hostname** named by one of those URLs and declared by the service in a DockFlare or
   Traefik label. → `"hostname"`
4. A **name** — application slug, application name, or any of its providers' names — when
   it identifies exactly one service's stack, compose or container name. → `"name"`

Rule 2 resolves **only** a name host: an IP literal in a redirect URI addresses the host,
where the standard ports belong to the proxy, so reading it through the published-port
table would attach the application to whatever answers on 443.

Rule 4 compares three forms, narrowing only when the wider one found nobody: the name as
written, the name with separators removed, and the name with mechanism words removed
(`GENERIC_NAME_TOKENS` — protocol and English words only, nothing fleet-specific,
`authentik` deliberately absent). Three constraints: **separate raw and tight indexes**
(merged, a stack `foo-bar` and a service `foobar` would collide into a contested key and
both be discarded); **the first form with any entry decides**, and a contested entry
decides *against* a match; **`MIN_DERIVED_KEY = 3`**, so a one- or two-character residue
cannot pin an application to whichever service happens to be short. Generic-token
stripping applies to the **Authentik side only**.

Three details with fixtures: `meta_launch_url` may contain `%(username)s`-style
placeholders and a per-user template is not matched on; `external_host` is matched
**except** in `forward_domain` mode, where it is the shared authentication domain; one
service naming one hostname in both DockFlare *and* Traefik labels is one candidate — the
hostname index dedupes by service key.

**Why it was not matched is part of the answer.** `matchOne` returns `Hit | Unplaced`, and
every unplaced application carries an `UnmatchedReason` (`ambiguous` | `no-candidate` |
`internal`), a one-line `detail`, and a `considered` trace with one line per rule tried in
the order tried. A rule that found more than one service sets `contested`; a rule that
found usable evidence and deliberately declined to resolve it (an IP literal, a
`forward_domain` external host) sets `blocked`. `detail` is the first of `contested`,
`blocked`, then the generic fallback; `reason` is `ambiguous` **exactly when** something was
contested. A rule that could not run says so ("No proxy provider, so there is no forwarded
address to resolve") rather than being omitted. The trace carries only what the payload
already holds — slugs, provider names, service keys, hostnames — never an env value (I2,
I6).

**What a provider means** — `providerEnforces`:

| Provider | Enforced by | Gate exists when |
|---|---|---|
| proxy, ldap, radius | an **outpost** in the request path | ≥ 1 outpost lists it |
| oauth2, saml | the Authentik server itself | always |
| scim | nothing — outbound provisioning | never |

A proxy provider assigned to no outpost is reported as protecting nothing, with that as
the stated reason. LDAP and SCIM are **backchannel** providers, so
`backchannel_providers_obj` must be read as well as `provider_obj` — reading only the
latter misses every LDAP gate. A provider Authentik records is taken as being in use by
the service it matched; for OAuth2 that is the whole of the available evidence.
`hasEnforcedAuthentikGate` is the separate question of whether *any* enforced gate was
confirmed, and it is what keeps a protected service out of `exposedWithoutAuth` when its
provider type has no `AuthMethod`.

**Confidence follows the match, not the provider:** `address` → `confirmed`, `hostname` →
`confirmed`, `name` → `observed` with `— tied to this service by name alone` in the detail.
Absent strength is read as `name`, never the strongest. This changes **no** posture roll-up:
`AuthMethod` precedence sorts by mechanism before confidence, and
`hasEdgeAuth`/`exposedWithoutAuth` do not read confidence at all.

`svc.authentik` carries the matched applications (three **parallel** arrays —
`applications`, `evidence`, `strength`, index `i` describing one match). `labels/auth.ts`
merges the API's account with the label-derived one by confidence rank, keeping the loser
as evidence. `meta.authentik` reports endpoint, `config`-vs-discovery, the four counts,
matched services, unmatched applications with reason and trace, and any error.

## 11. Reverse proxy API (steps 8 and 11)

Same split: `enrich/traefik.ts` reads `/api/version`, `/api/rawdata` and
`/api/entrypoints` and returns a `TraefikSnapshot`, never throwing;
`analyze/traefik.ts` matches live routers onto services with step 6's index. It resolves
three things a file scan cannot see: a router the labels declare that Traefik is not
serving, a middleware named in a label that is not in the chain the proxy built, and a
middleware defined in a Traefik **file provider** (which has no definition in any scanned
stack and is otherwise only ever `inferred`).

**Endpoint selection.** A configured `traefik.url` is used verbatim. Otherwise a scanned
service becomes a candidate on one of three signals, each recorded as the candidate's
`why`:

| Signal | Why it is evidence |
|---|---|
| a router of its own whose service is `api@internal` | the operator's own label saying this container serves the proxy API — and it yields the exact public hostname |
| another service's tunnel origin resolved to it (§8) | an observed reverse proxy, established without consulting any image or name |
| it runs the Traefik image | last resort, same precedent as `isAuthentikService` |

Per candidate the URLs are `http://<name|container_name>:<port>` for each declared
`ports[].target` plus `8080` (the port the dedicated `traefik` entrypoint conventionally
serves), followed by its Traefik/DockFlare hostnames. Internal before public, deduped,
capped — exactly as `discoverAuthentikEndpoints`.

**The credential rule.** Every candidate is probed on `/api/version`, which needs no
authentication; a candidate that answers is used **with no credential at all, and none is
sent**. A credential is sent only to a candidate that is either configured by hand
(`mayAuthenticate` set at construction) or a hostname the scan proved belongs to the
service whose own labels declare `api@internal` — that is ownership evidence; a hostname
that merely looks like a proxy never receives one. A 401/403 or a redirect on such a host
triggers the authenticated retry, and cookies set during that exchange are replayed on its
remaining requests (the Authentik outpost expects its session cookie echoed). **An
Authentik API token is not a valid credential here.** `credential: "none" | "basic"`
records which was needed; `none` is evidence about how the proxy's API is exposed on that
network and is reported as a note on the proxy service.

**Matching (step 11)** — exactly one candidate or no match:

1. **The backend address** — `loadBalancer.servers[].url`, the proxy naming its own
   target. An IP-form URL resolves **only** through `FleetIndex.byContainerIp`; a name-form
   URL through the name branch of `lookupAddress`. (`lookupAddress` reads an IP literal's
   port as a *published host port*, which is right for a tunnel origin and wrong for a
   container IP. With no Docker state the rule is skipped rather than guessed.)
2. **The router name**, `@docker` routers only — Traefik derives those names from the
   labels of the container it found them on, so an exact match against `svc.traefik[].router`
   is that label round-tripping. A `@file` router's name was typed by hand in a file this
   scan cannot read, so this rule does not apply to it.
3. **The host rule**, through the same hostname index the Authentik matcher uses.

Unmatched routers go to `meta.traefik.unmatchedRouters`, the mirror of
`unmatchedApplications` including the reason model — each entry carries the whole
`TraefikLiveRouter` plus `reason`, `detail` and `considered`. One deliberate asymmetry:
this matcher tracks `contested` but **not** `blocked`, because rule 2's skip applies to
every non-docker router and promoting it would displace the answer a reader needs. Because
such a router demonstrably **exists**, it must never produce a "declared but not live" note
on anybody.

**What the live read may conclude** is decided once per scan in `TraefikLiveContext`:
`reachable` (the API answered) and `chainComplete` = `reachable && entrypointsRead`. Only a
complete read lets a live chain supersede a label list, because a gate attached at an
*entrypoint* appears in no router's own middleware list; a partial read notes the gap and
changes no posture.

Where a router matched and `chainComplete` holds, **the live chain is the chain**: a
resolved `forwardAuth` whose address resolves to a provider identity yields
`authentik-forward-auth` at `confirmed`; `basicAuth`/`digestAuth` yields `basic-auth`; a
`chain` middleware is resolved recursively to `MAX_CHAIN_DEPTH = 5`, each entry recording
`viaChain`;
a middleware attached to the router's entrypoint is merged in marked `viaEntrypoint`; and a
label declaring an auth middleware the live chain does **not** contain is **downgraded** —
detection suppressed, the service free to land in `exposedWithoutAuth`, and a note naming
the discrepancy. A router the proxy reports as `disabled`, or carrying `error[]`, counts as
neither protection nor working ingress, with its errors quoted verbatim.
`TraefikLiveMiddleware.type` is taken from the definition Traefik *holds*, so a
file-provider middleware is knowable and an unmodelled type is still reported by name.
`TraefikLiveServer` carries one backend URL plus the `serverStatus` Traefik last observed;
absent status means nothing known and must not read as healthy. Routers are reported as
`name@provider` (`qualifyRouter`) — the provider half decides whether rule 2 may apply.

The declared-but-absent check runs against **every router in the snapshot**, not only the
matched ones.

**Three-way cross-check.** When the live `forwardAuth` address resolves to the service the
Authentik API answered on, and Authentik reports an outpost serving a provider for an
application matched to *this* service, the note records labels, proxy and identity provider
agreeing. Disagreement is the finding: a forward-auth address pointing at an instance with
no matching application, or a matched provider whose `mode` means the request never reaches
the outpost. A provider in `proxy` mode is exempt — there the outpost *is* the backend.

`svc.traefikLive` carries the matched routers; `meta.traefik` reports endpoint, source,
whether a credential was used, whether the API answered unauthenticated, version, counts,
matched services, unmatched routers and any error. The proxy service gets `role: "proxy"`
and every matched router is drawn from it.

## 12. The active probe (step 8b)

Every other source says what a service is *configured* to do; this says what it
**answers**, for one blind spot: an application with its own login page carries no label,
no env key and no entry in anybody's API. One GET to the service's own address, and a login
page answering is evidence in the sense I1 means it.

It is the only integration that **defaults to off**, the only one that sends a request to
something the fleet's own documents named, and the only one a reader can turn on from the
UI for a single rescan.

**Every rule is pure, in `model/probe.ts`** — none in the client that fetches. Five jobs:
what may be asked (`probeTargets`), what an answer means (`readGate`, `readLoginForm`,
`isLoginPath`), whether a second question is worth asking (`wantsStateProbe`,
`stateTargets`, `readState`, `readStateGate`), what the page showed a caller who sent
nothing (`readAnonAccess`, `saysLogin`, `servedAnonContent`), and which fact a decision
rested on (`probeReasonText`).

### 12.1 Eligibility

Two separate questions: `probeTargets` says whether there is an HTTP address, and
`hasDetectedAuth(svc)` says whether asking could tell anyone anything.

`hasDetectedAuth` (in `labels/auth.ts`) is true when authentication was **detected** —
`svc.auth.method !== "none"` from labels or the live Traefik chain, a Cloudflare Access
policy on the tunnel route, or an Authentik provider the API reports as enforced. It is not
merely a term of `finalizeAuth`'s `configuredEdgeAuth`; it **is** that term, called from
there, so eligibility and the notes explaining the outcome cannot come apart. An
`inferred` posture counts as detected. Neither a probe result nor a `.labview` declaration
counts.

`finalizeAuth` computes `hasEdgeAuth = configuredEdgeAuth || probeGate`, so withholding a
request can only ever leave a service *in* the exposed count, never take one out. The two
terms stay written as two even though they are provably disjoint, because that keeps
`probeGated` a subtractable statistic; the disjointness is asserted in smoke.

**Not asked and no address are different facts.** `probeTargets` runs first, so a service
with no HTTP address is not counted as skipped — it was never a candidate. `ProbeRun.skipped`
counts withheld candidates, and a run whose candidates were *all* skipped is `ok: true`,
not `not-found`. No new `NoAuthReason`: a skipped service has detected authentication, so
`noAuthReason` is never asked about it.

### 12.2 Addresses

`probeTargets(svc, lanHost)` — from evidence already on the service, never from a port
number and never from an image name:

| Vantage | Eligible on | Asked at |
|---|---|---|
| `public` | a tunnel route with a resolved hostname whose `service:` origin is `http`, `https` or absent | `https://<hostname>/` |
| `traefik` | a `traefik.http.routers.*` route's own host (`parseTraefik` reads only HTTP routers, so a non-empty route list *is* the evidence this is HTTP) | `https://<host>/` when the router declares TLS, else `http://<host>/` |
| `lan` | a service one of the two above already found HTTP, **and** `probe.lanHost` set, **and** a published port whose bind address answers there | `http://<lanHost>:<published port>/` |

`PROBE_VANTAGES = ["public","traefik","lan"]` — most- to least-exposed, the `INGRESS_KINDS`
order — and the walk stops at the first address that **answers**, meaning an HTTP response
arrived whatever its status (a 401 is the best outcome available here). Only a transport
failure falls through. **A service with `ports:` and no route of either kind yields no
address at all**, which is what keeps the probe off a database without consulting a port
number or an image name. `lanHost` empty means no LAN vantage, not a guessed one.

### 12.3 `readGate` — seven signals from one response, strongest first

| Signal | Fires on |
|---|---|
| `challenge` | 401 or 407 **with** a `WWW-Authenticate` header |
| `redirect-origin` | a 3xx whose `Location` resolves to a different origin |
| `redirect-login` | a 3xx that stayed on the origin and landed on a `LOGIN_PATHS` entry (prefix match) |
| `meta-refresh-login` | a 200 whose HTML carries `<meta http-equiv="refresh">` whose `url=` resolves cross-origin or onto one of those paths (`readRefresh` resolves through the same `readRedirect`) |
| `sso-form` | a 200 carrying a hidden `SAMLRequest` or `SAMLResponse` input |
| `password-form` | a 200 whose HTML carries `<input type="password">` or `autocomplete="current-password"`, anywhere on the page |
| `credential-form` | a 200 where **one** form has a username field *and* a submit control *and* a login-intent marker, with no password field |

Clauses 4–7 read a 200's body, which is the only condition under which a body was kept, so
`res.body` being present is itself the evidence that HTML answered.

`LOGIN_PATHS` — the one rule that decides on a *name*, ten prefixes, in source order:
`/login`, `/signin`, `/sign-in`, `/users/sign_in`, `/sso`, `/oauth2`, `/auth/`,
`/outpost.goauthentik.io`, `/if/flow/`, `/flows/-/`. Only `redirect-login` and
`meta-refresh-login` consult it and both only ever *add* a gate to a target that stayed on
the origin, so a missing hand-rolled login path costs a gate and never invents one. Three
spellings are load-bearing: `/auth/` keeps its trailing slash (bare `/auth` matches
`/authors`); `/flows/-/` keeps the `-` (Authentik's own placeholder for no application
context — a bare `/flows` would read a workflow tool as a login page); `/users/sign_in` is
Devise's own path.

Nothing else read off that one response is a gate: a bare 401 with no challenge header, a
403, a same-origin redirect to `/dashboard`, a meta refresh with no `url=`, a homepage with
the words "Sign in" and no form. All read as *answered, no gate observed*, which leaves the
exposure finding standing. The asymmetry is the point — this function can only ever take a
service **out** of the exposed count.

Rejected signals, each of which would buy false comfort: `<title>` or body text matching;
product-name markers (a *link* to one matches); a `Set-Cookie` on a 200; a cross-origin form
`action` with no `SAMLRequest`; a 401/403 that serves a login form (the body is read as
evidence on a 200 only).

`readLoginForm(body, requestUrl)` reports composition **per `<form>` element**, never
page-wide; when several qualify the strongest wins and the first of equals, so one page
yields one answer and yields it twice (I7):

| Field | Read from |
|---|---|
| `password` | `type="password"`, or `autocomplete="current-password"` — **not** `new-password` |
| `username` | `type="email"`, or a `text`/`tel` input whose `name`, `id` or `autocomplete` contains a word from `USERNAME_WORDS` = username, user, uname, userid, uid, login, email, e-mail, identifier, account. `q`, `search`, `query` absent on purpose |
| `submit` | `<input type="submit">`, `type="image"`, or a `<button>` whose `type` is `submit` or absent |
| `otp` | `autocomplete="one-time-code"` |
| `action` | the form's `action`, **only** when it stays on this origin and prefix-matches a login path |

The loose username match is affordable only because it is never sufficient alone. A
**cross-origin action is rejected** rather than read as a hand-off: hosted newsletter signup
has the identical shape and the opposite meaning. The shape is attached to
`ServiceProbe.form` whenever a form was found — **including when nothing was concluded from
it**.

`credential-form` is the one clause holding several facts together, deliberately:
passwordless sign-in has no single marker, and without it every magic-link and passkey login
reads as reachable without authentication. All three parts must be present on **one** form.

Patterns, verbatim and load-bearing:

```js
META_TAG        = /<meta\b[^>]*>/gi
SAML_FIELD      = /<input\b[^>]*\bname\s*=\s*["']?saml(?:request|response)\b/i
PASSWORD_INPUT  = /<input\b[^>]*(?:\btype\s*=\s*["']?password\b|\bautocomplete\s*=\s*["']?current-password\b)/i
```

### 12.4 The eighth signal: `state-challenge`

One shape defeats every clause above in principle: **HTTP 200, `text/html`, and no `<form>`
anywhere in the body** — a login screen assembled by a JavaScript bundle, indistinguishable
from a public single-page application at any body cap, and the commonest miss in a real
fleet. For that one shape only, the scan asks a second question: *does this page's own
client get served without a credential?*

`wantsStateProbe` is the whole condition — no gate read, status 200, HTML, no form.
`STATE_PATHS = ["/api/", "/api/me", "/api/v1/me", "/api/v1/user"]`, walked in that order
against the **origin that answered**, until one **refuses** (401 or 407). `stateTargets`
resolves them from that constant; nothing is parsed out of the page. `readState` reduces the
answers to `ProbeState`: how many were asked, which refused, with what status, and whether
that refusal named a scheme.

`readStateGate` gates on **that last fact alone**. A refusal carrying `WWW-Authenticate` is
`challenge` one address over. A **bare** 401 is *not* a gate — an anonymous-enabled Grafana
and a world-readable Gitea both answer that way while serving everybody, so reading it as a
gate would take genuinely open applications out of the exposed count. 403 is excluded too
(nginx 403s a directory with no index). A bare refusal is still recorded on `ProbeState` and
named in `probeReasonText` as a place to look, in the same sentence that says the finding
stands.

Bounded the same way as everything else: the walk is sequential regardless of
`probe.maxConcurrency` (that budget is across *services*), stops on the first refusal, parses
nothing from what comes back — only a status and whether a scheme was named — and its
addresses stay **out** of `ServiceProbe.attempts`, the request count travelling on
`ProbeState.asked` instead.

### 12.5 `readAnonAccess` — the opposite question

`readAnonAccess(body, requestUrl)` returns a `ProbeAnon`: `textChars`, `links`, and
optionally `loginHref` and `loginLabel`. One pure function, one body, no request — it reads
the same body `readGate` was already handed (I8) and keeps no header, no cookie and no
attribute value except a resolved path and a label shorter than `LOGIN_LABEL_MAX = 24` (I6).

**It is structurally incapable of gating:** `readGate` takes a `ProbeResponse`, this record
is not on one, and `readGate` does not import the function. The worst a mistake here can do
is put a wrong sentence on a service that stays in the exposed count.

| What was read | The rule says |
|---|---|
| content served, no sign-in offer | the narrower sentence — the application's own content and not a shell |
| a sign-in offer, no content served | nothing; the page is left to `stateShortfall` (§12.4) |
| both | says so, and names the link or the control in the words the page used |

**A logout link is skipped before its path is read**: `isLoginPath` matches on prefix, so
`/auth/logout`, `/oauth2/sign_out` and `/sso/logout` are login paths *by name*, and a page
carrying one is a page somebody is already signed in to.

**Drawn markup, not served markup.** Every number comes off `drawnMarkup(body)`, which
removes comments, `<script>`, `<style>`, `<template>`, `<noscript>` and `<svg>` before
anything is counted. `<svg/>` is dropped before either arm, because SVG is the one place in
HTML where `/>` really closes an element.

`LOGIN_LABEL` and `NOT_LOGIN_LABEL` are **private**, multi-language (a path stays `/login`
in every locale; the label is what gets translated); `saysLogin` / `saysLogout` are exported
for `tools/probe-lab`. Three details are pinned by fixtures: **word boundaries**, without
which `log[\s_-]?in` matches `Blog index`; `continue with` deliberately **absent**, because
it is a login label only when a provider name follows; and sign-up deliberately absent from
the veto, so `Sign in / Sign up` still reads as a login affordance.

`servedAnonContent` — exported — is `textChars >= ANON_TEXT_MIN (200) && links >= ANON_LINK_MIN (2)`.
Both must hold: a login page can carry 200 characters of boilerplate, and a page of nothing
but navigation can carry ten links. These are **wording thresholds, not verdict thresholds**.

`ServiceProbe.anon` is attached whenever an HTML 200 was read, gate or no gate, because it
describes a *response*; the *sentence* (`anonProof`) is reached only from `openReason`, after
`stateShortfall`. `probeOutcome` is untouched — the label stays `No login page`.

### 12.6 Recorded facts, verdicts, bounds

The facts a verdict rested on travel beside the verdict, one field per fact a sentence has to
name: `mediaType` (a 200 that was not a page), `redirect` (a 3xx that stayed put),
`refresh` (a `<meta refresh>` that was not a gate), `truncated` (a form below the body cap),
`state` (§12.4 — the only one recording a request rather than a reading, which is why `asked`
is on it), `anon` (§12.5). There is deliberately **no** field for `WWW-Authenticate`: a 401
with no `challenge` gate already means the header was absent.

`readRedirect`, `readRefresh` and `readMediaType` are exported and consumed by `readGate`
itself, so there is exactly one rule for "where does this point". All three reduce what they
record (I6): `ProbeRedirect.to` drops query and fragment and keeps the origin **only** when
the target left the origin, with `crossOrigin` beside it; `mediaType` drops the parameters.

`probeReasonText(probe)` is the sentence, pure, branching in `readGate`'s own precedence
order — one sentence per signal naming the fact that fired, and for a negative verdict the
clause that came *closest* and what it lacked. `GATE_REASON` is an exhaustive
`Record<ProbeGate, …>`, so a new signal is a compile error until it has been explained.

**Both findings are findings.** A login page answering: the service leaves
`exposedWithoutAuth`, is counted in `probeGated`, and `noAuthReason` reports `probed-gate`
with `auth.method` untouched at `none`. An answer with no login page: the exposure note gains
a clause saying LabView requested the address and was served the application. A service that
did not answer is neither — counted in neither statistic, claiming no measurement, and worded
`No answer` rather than `No login page`.

**A probe never becomes a mechanism** (I3): `probed-gate` is its own reason with its own
statistic, and `svc.probe` sits beside `authentik` and `traefikLive`, never inside `auth`.

**Two things it does not override.** A detected gate that answered with no login page keeps
its posture and gets a note saying the request came from LabView's own vantage point. A
`.labview` declaration supplying the only protection is not overridden by an open answer
either — recorded as **unconfirmed**, not drift.

**Containment** (I8): GET only, no query; **no credential, and not by omission** — no call
path into `getResponse` has one in scope; **no redirect followed**, because where a 3xx
points is the evidence; a per-request timeout and a bounded number in flight
(`probe.maxConcurrency`); at most `MAX_PROBE_TARGETS = 4` addresses per service; the body read
only when the content type is HTML and then only to 64 KiB, with the stream cancelled at the
cap (`MAX_BODY_BYTES` in `enrich/http.ts`, shared with every other read). Disabled, nothing
eligible, or nothing answering each return a report that explains itself (I4).
`ServiceProbe.attempts` is truncated to `MAX_REPORTED_ATTEMPTS = 8`.

The report is the fourth `meta.connections` entry: `disabled` when off, `not-found` when
nothing was eligible, `partial` when part of the fleet did not answer (still `ok`), and
`connected` otherwise — `31 services probed — 12 gated, 17 open, 2 did not answer — 9 extra
requests at current-user addresses`, the last segment summed from `ServiceProbe.state.asked`
and present only when there were some, plus `— 1 service not asked (authentication already
detected)` from `ProbeRun.skipped`.

### 12.7 The switch beside Rescan

`probe.enabled` is the **default**, not the authority. `POST /api/rescan` takes an optional
body `{"probe": true}` and the value is fully authoritative for that build: `true` probes
where config says off, `false` skips where config says on. **It lasts exactly one rescan** —
a TTL rebuild, a timer and a page load all carry no request and fall back to the configured
value. So the payload always states what it did:

```ts
meta.probe: { enabled: boolean; source: "config" | "request" }
```

Three mechanics: `withProbeEnabled(cfg, enabled)` returns a **clone**, never a mutation (the
config object is captured by the cache's build closure and read again by the next timer
rebuild); `ScanCache<T, R>` threads the value as a parameter of `build(req)` so the build that
*starts* owns the override and a coalesced caller's value is discarded; `readScanRequest`
**validates rather than coerces** — one known key, one known type, and a missing body, an
array, a JSON `null`, `{"probe":"yes"}` and `{"probe":1}` all mean *use configuration*, while
unknown fields are ignored rather than rejected (I4). The UI checkbox re-syncs from
`meta.probe.enabled` on every overview received.

Security consequence, stated: when LabView is not enforcing a login, `POST /api/rescan` is
unauthenticated, so this switch lets any visitor start fleet-wide outbound requests.

### 12.8 `tools/probe-lab`

A diagnostic CLI, **not part of the product**: nothing in `src/` imports it, no scan consults
it, the `Dockerfile` COPYs named paths so `tools/` never enters the image, and `reports/` is
gitignored (I2). Point it at a URL and it writes Markdown + JSON: the verdict, every one of
the eight signals and the fact that made each fire or not, what a visitor was shown, then all
the evidence no signal reads yet (forms and inputs unranked, every `<a href>` with the
pipeline's own reading, form-less controls, `<meta>`, mount points, inline scripts
*described*, `<noscript>`, visible text, headers, `Set-Cookie` **names** only), then one line
per thing standing between that page and a verdict. `--from-scan overview.json` asks exactly
the services the stage found neither authentication nor a login page for, at the addresses
`probeTargets` gives.

- **The verdict is the pipeline's verdict.** `report.ts` imports `readGate`, `readLoginForm`,
  `readRedirect`, `readRefresh`, `readMediaType`, `probeGateText`, `probeOutcome`,
  `probeReasonText` and the clause predicates from `model/probe.ts` and reimplements none of
  them; smoke drives every row of its own `readGate` table through `buildReport` and asserts
  `buildReport(obs).verdict.gate === readGate(...)`.
- **The transport is the pipeline's transport.** `cli.ts` calls the same `getResponse`, through
  a `FetchLike` wrapper whose only job is to keep the headers `getResponse` discards — so the
  timeout, `redirect: "manual"`, HTML-only body read and 64 KiB cap are inherited. GET only,
  no credential and no option that supplies one, one hop only under `--follow`, nothing a page
  *suggests* is ever fetched, header values redacted by default.
- `evidence: EvidenceFinding[]` — six detectors (`login-link`, `login-control`, `login-route`,
  `login-heading`, `session-cookie`, `content-served`), each with a `fact` quoted from the page
  and a `because`. **`direction` has no `"gated"` member**, so the worst a detector can be
  wrong about is a paragraph in a diagnostic file. Anchors inside a `<template>`, `<noscript>`,
  `<script>` or `<svg>` are kept but flagged `hidden` and graded `weak`.
- Every bound is reported as an `…Omitted` count. `--try-login-paths` (off by default) GETs the
  ten `LOGIN_PATHS` names on a form-less shell's origin — it **guesses**, so it needs a typed
  flag. `--save-body` writes the served HTML verbatim and is the one artifact this tool writes
  that is **not** safe to paste into an issue.

---

## 13. Declarations

`.labview` is operator input and is **explicitly not evidence**. Three rules govern
everything the analyzer does with it:

**1. A declaration never changes a detection.** `noteDeclarations` writes notes, drift and
agreement; it never touches `svc.auth`, `svc.ingress`, `svc.authentik`, `svc.traefikLive` or
`svc.probe`. Declared LDAP does not become an `AuthMethod`; a declared `expected.ingress`
does not become an ingress kind. The words on the page change; the conclusion does not.

**2. A declaration can change exactly one verdict, in the open.** Declared authentication
clears the *finding*, because a service authenticating its own users is not an exposure —
that is a true statement about the world and refusing to make it is what turns a real finding
into noise. It is confined to one boolean:

```ts
exposedWithoutAuth = reachable && !hasEdgeAuth && declaredAuth.length === 0
```

with `declared.authAgreement === "supplies"`, a *Protected — declared* badge, a
`stats.declaredAuthProtected` count, and a note saying which mechanism and which file said
so. `svc.auth.method` stays `none`, `NoAuthReason` reports `declared`
(*Declared, not detected*), and the KPI states the split. Nothing anyone typed makes an
undetected gate detected.

**3. An accepted exposure is still an exposure.** `unauthenticated: {intentional: true,
reason}` is counted in `stats.exposureAccepted`, **not** subtracted from
`stats.exposedWithoutAuth`; the KPI renders `formatExposureCount` → `23/28`, "28 exposed, 23
accepted". `reason` is mandatory (§5's sidecar rules) — an acceptance with no reason cannot
be told from a stray key.

**`compareDeclaredAuth(declared, detected, wouldBeExposed)`** — three families, compared
only within a **layer**:

| Family | Detected members | Declared members |
|---|---|---|
| `oidc` | `authentik-oauth`, `other-oauth` | `app-oidc` |
| `ldap` | `authentik-ldap`, `ldap` | `app-ldap` |
| `proxy` | `authentik-forward-auth`, `forward-auth` | `external-proxy` |

Both maps are `Partial`, so an unmapped mechanism has no family and cannot conflict.
`FAMILY_LAYER` puts `oidc` and `ldap` at *the app authenticating its own users* and `proxy`
at *a gate in front of it*; a forward-auth gate and an app's own OIDC are both true at once,
so they are never compared. Four outcomes, in order:

1. `supplies` — the caller's `wouldBeExposed` is true and a declaration is the only
   protection. This is rule 2.
2. `redundant` — declared and detected in the same family. Rendered **nowhere**; agreement is
   silent.
3. `conflicts` — same layer, different family (declared `app-oidc`, detected
   `authentik-ldap`). A drift entry.
4. `supplements` — declared in a layer with nothing detected in it, while the other layer has
   a gate. Noted, not drift.

The third parameter is `wouldBeExposed`, not `reachable`, so `supplies` implies
`method === "none"` and can never be reported on a service that has a detected gate.

`DECLARED_AUTH_MECHANISMS` (closed, in order): `app-local-accounts`, `app-ldap`, `app-oidc`,
`app-saml`, `app-token`, `mtls`, `network-restricted`, `external-proxy`, `other`. `other`
requires a `detail`.

**`depends_on`** is service-level only — one entry at stack level cannot say which service
depends on the target, so it is named in its own warning rather than lumped in with unknown
keys. `resolveDeclaredDependencies` (step 6b) prefers **the declaring stack's own service**
for a bare name, then the fleet:

| Resolution | Result |
|---|---|
| exactly one service | an edge with `declaredBy` (file + detail) and `via` |
| a local service **and** others, written bare | the local one wins, silently |
| two or more in other stacks, written bare | drift, no edge — write `stack/service` |
| nothing, or itself | drift, no edge |
| a pair compose already resolved | one edge, silently — the declaration adds a `detail` |

Declared once, shown from both ends: the target's drawer lists it as `required-by` without
its sidecar mentioning it. It is **not** evidence and **not** reachability — `via` may be
empty, and an empty `via` is itself the finding (§7).

**Four drift checks** (`model/declarations.ts`):

1. A stale acceptance — `unauthenticated` on a service no longer externally reachable
   (tested with `isExternallyReachable`, so `lan`-only still counts as reachable).
2. A `conflicts` mechanism.
3. A `depends_on` reference that no longer names exactly one service.
4. An `expected.ingress` mismatch, reported through `diffIngress` **in both directions**:
   `missing: lan; unexpected: traefik`.

The **fifth** check is not drift: `unconfirmed` collects a declaration that nothing
contradicts and nothing corroborates — a declared mechanism in a layer where the scan
detected nothing, and a probe that answered with no login page on a service whose only
protection is declared. Both fields are collected by **one walker with two wrappers**
(`collectDeclarationDrift`, `collectUnconfirmedDeclarations`) so a service can never be in
one list and not the other by accident, and rendered by one panel component with two intros:
drift reads as `note crit`, unconfirmed as a plain `note`.

`declared` stays **off** `VOLATILE_SERVICE_FIELDS` (§16), and `serviceConfig` compares
`declarationConfig(svc.declared)` — everything except `DERIVED_DECLARATION_FIELDS`
(`drift`, `authAgreement`), which are conclusions about this scan and not the file.

---

## 14. Connections: one taxonomy for every outbound target

Every target LabView talks to reports through one shape, and the taxonomy is closed.
`ConnectionPhase`, in order:

| Phase | Meaning |
|---|---|
| `disabled` | switched off in configuration — an outcome, not a fault |
| `not-configured` | nothing to talk to (no token, no URL, nothing discovered) — likewise |
| `not-found` | the thing to talk to does not exist (a missing socket path) — stops before the network |
| `credential` | a credential was needed and was absent or blank — likewise |
| `resolve` | DNS said no |
| `connect` | refused, unreachable, no route |
| `tls` | handshake failed |
| `timeout` | no answer inside the budget, **established by the clock** |
| `authenticate` | answered 401 |
| `authorize` | answered 403 |
| `path` | answered 404 or 405 — right host, wrong route |
| `status` | answered with any other non-2xx |
| `protocol` | answered, but not as this API (HTML where JSON was due) |
| `partial` | read enough to be useful, not all of it — `ok` stays **true** |
| `connected` | full read |

`401` and `403` stay separate everywhere: a wrong token and a token without permission need
different fixes. `phaseText` in `model/connections.ts` maps each to prose; `hintFor(target,
phase)` gives the one action to take.

`ConnectionReport`: `target`, `ok`, `phase`, `endpoint` (credential-free — `safeOrigin`),
`source` (`config` | `discovered` | `default`), `detail`, `hint`, `read` (what came back:
`"86 containers"`, `"Traefik 3.1.2, 10 routers, 5 middlewares"`), and `attempts`. Each
`ConnectionAttempt` is one rejected candidate: credential-free `endpoint`, the `why` that
made it a candidate, `phase`, `code`, `detail`.

`enrich/http.ts` is the shared chokepoint — `phaseForCode` (a Node/undici error code → a
phase), `phaseForStatus` (an HTTP status → a phase), and `getJson`, which returns `phase` and
`code` beside `error` so no caller re-derives them from a message string.
`enrich/docker.ts` adds `classifyDockerError` for the Engine's own failures, and
`probeSocketPath`/`phaseForSocket` for a unix socket (§9).

`model/connections.ts` also owns: `formatConnection(report)` — one line, plus one indented
`·` line per rejected candidate; `changedConnections(prev, next)`, comparing
`target|ok|phase|endpoint` and **not** `read`, so a container count ticking does not
re-announce a working target; and `shouldBanner(report)` — true for `partial`, or a failure
whose phase is neither `disabled` nor `not-configured`. The server logs `info` for a working
target and `warn` for `partial` and failures; the first scan logs all of them.

---

## 15. The model layer contract

- `model/types.ts` carries **no Node-only imports** — it is the shared vocabulary and the web
  bundle imports it. `web/model.ts` re-exports it; `model/access.ts`, `model/auth.ts`,
  `model/ingress.ts`, `model/networks.ts`, `model/filter.ts`, `model/probe.ts`,
  `model/declarations.ts`, `model/viewstate.ts` are web-safe under the same rule.
- **The analyzer emits the complete truth; the model decides what is drawn.** Caps, roll-ups
  and label text live in `model/*`, never in `analyze/*`.
- A line between two services requires a **dependency**, never co-membership.
- Resolution reads a declaration and never writes to it.
- **A field describing the build is on `meta` and is never optional** — `meta.probe`,
  `meta.build`, `ProbeRun.skipped`, `ProbeReport.notAsked`. `BuildStamp` is
  `{version, commit?, source}` with `source` required (`image` | `checkout` | `unknown`), so
  an unknown build says *unknown* rather than being absent.
- **A fact about one response is optional and its absence is the fact** — `mediaType`,
  `redirect`, `refresh`, `truncated`, `state`, `anon`. Inside `state`, `asked` is not
  optional (a request was made) while `refusedAt`/`status`/`wwwAuthenticate` are, and
  `challenge` is `false` rather than absent for a bare refusal.
- **Adding or renaming a union member is a breaking UI change**: `web/lib/palette.ts` keys
  colour and label off the member name.

Vocabulary that must be reproduced exactly:

**`AuthConfidence`** — `confirmed` (an API reported the gate *and* named the service),
`observed` (a scanned config value states it, or an API tied it by name alone), `inferred`
(rests on a middleware name, with a service note saying so). Never a severity.

**`AuthentikMatch`** — three **parallel** arrays, `applications`, `evidence` and `strength`,
where index `i` describes one match. `AuthentikMatchStrength` absent reads as `name`, never
the strongest.

**`NoAuthReason`** — four members, derived by
`noAuthReason(method, exposedWithoutAuth, ingress, declared.auth)`:

| Member | Renders as |
|---|---|
| `gap` | **No proxy auth** — styled as a finding; the only finding here |
| `not-reachable` | None expected |
| `declared` | Declared, not detected |
| `unnamed-gate` | None named — gate confirmed |

`showsAuthMethod` is the same rule for badge rows. The `none` bucket of `stats.byAuthMethod`
has the palette label **None detected**. `probed-gate` (§12) is the fifth reason and belongs
to the probe.

**`exposedWithoutAuth`** = `isExternallyReachable(svc.ingress)` and no auth detected and
nothing declared — so a `lan`-only service counts as exposed.

**Traefik live records** — `TraefikLiveMiddleware.viaChain` / `viaEntrypoint`;
`TraefikLiveServer` with an absent status meaning *nothing known*, never healthy;
`credential: "none" | "basic"`; routers named `name@provider` via `qualifyRouter`.

**`detail` vs `evidence` vs `notes`** — `detail` is one line about one record, `evidence` is
the string a conclusion rests on, `notes` are service-level sentences a reader needs.

Other closed sets: `ScanDiff` / `StackChange` / `IntegrationDiff` / `IntegrationChange`;
`TagFilter` / `TagMode`; `LoginMethod` = `passwd | oidc`; `AccessMode` =
`{enforced, methods, notes, summary}` with `enforced = methods.length > 0`; `SessionInfo` =
`{enforced, methods, user?, oidcLabel?}` where `user` is `{name, via}`;
`USERNAME_RE = /^[A-Za-z0-9._@-]{1,64}$/` with fallback `"?"`; and **`LoginFailureReason`**,
eight codes — `credentials`, `throttled`, `method-unavailable`, `session-expired`,
`oidc-state`, `oidc-provider`, `oidc-token`, `oidc-identity` — worded in
`LOGIN_FAILURE_TEXT` in `model/access.ts`, with `parseLoginFailure` accepting only a union
member.

---

## 16. Rescan and the change note

**A forced request may only be answered by a build that started after it arrived.** That is
the whole of `server/cache.ts`, with `build` and `now` injected. Five consequences are
asserted: a forced request never receives an in-flight build's result; two forced requests
arriving together share one build; a forced build resets the TTL; a non-forced request during
a forced build joins it; `onBuilt(next, prev, {forced})` fires exactly **once per build**, not
once per waiter.

`model/changes.ts` compares the **parsed configuration**, not the enriched payload, via
canonical JSON strings. `VOLATILE_SERVICE_FIELDS` omits `docker`, `authentik`, `traefikLive`,
`ingress`, `auth`, `notes` and `cloudflare` — it is a **deny-list**, so a newly added field
is compared by default and a genuinely volatile one has to be named.

Cadence, in `formatRescan`: the first build states the baseline
(`LabView read 56 stacks, 86 services from /data/apps`); a change always speaks; a **forced**
rescan answers even when nothing moved (somebody asked); only a quiet **timer** rebuild stays
silent. "Quiet" means **both** diffs. The UI renders `scanned 12:04:11 · +1 stack, +2
services`. `formatStackChanges` writes one line per stack that moved, capped at
`MAX_DETAIL_LINES = 12` with the remainder stated rather than silently dropped.

A rescan re-runs both API exchanges but does **not** re-read credentials — they are env-only
(§3.3), so rotating one needs a restart.

**`diffIntegrations(prev, next)`** is a second structure beside `ScanDiff` and is never folded
into it; the note reads `no config changes; authentik +1 application, -3 withheld`.

- **Reachability is decided before any count.** Neither side read → no entry. Both read →
  `unchanged` or `moved`, with deltas and named records. Not-read → read = `started`; read →
  not-read = `stopped`. The two are not numeric comparisons and are not phrased as ones.
- Counts are compared only where **both** sides have a value, so an optional count appearing
  or vanishing is not a delta.
- True nouns via `plural`; modifiers are identical in both directions (`+1 application`,
  `-3 withheld`). Traefik's `services` renders as **`live service`**, because "service" in this
  payload already means a compose service.
- Named records are read back off the payload — `svc.authentik.applications[].slug`,
  `svc.traefikLive[].router` — and sorted (I7). `nameList` truncates at `MAX_NAMES = 12`
  **names per line**, not lines, with the remainder stated: each target contributes at most
  three lines, so a fleet with forty applications still puts forty names into one of them.

---

## 17. Serving

`startServer` splits into `buildApp(cfg, opts) → {app, scan}` plus a listener, and
**everything registered on the instance lives inside `buildApp`** — a route registered in the
listener half is invisible to any caller that only builds the app.

| Route | Session | Behaviour |
|---|---|---|
| `GET /api/overview` | yes | cached `Overview`; rebuilds past `cacheTtlSeconds` |
| `POST /api/rescan` | yes | forced rebuild, optional `{"probe": true\|false}` (§12.7) |
| `GET /api/healthz` | **no** | `{ok: true}`; runs no scan |
| `GET /api/session` | **no** | `SessionInfo` |
| `POST /api/login` | **no** | passwd login |
| `POST /api/logout` | **no** | clears the cookie |
| `GET /auth/oidc/start` | **no** | 302 to the provider's authorize URL |
| `GET /auth/oidc/callback` | **no** | code → session cookie → 302 `/`, or 302 `/?login_error=<code>` |
| `GET /*` | **no** | the built UI from `web/dist`; SPA fallback to `index.html`. A 404 under `/api/` stays JSON |

"Needs a session" is conditional on enforcement (§18): with no method configured, everything
is open.

Concurrent requests share one in-flight build unless one is forced; the cache is warmed in
the background at startup so the first reader does not wait; a missing `web/dist` still
serves the API and says how to build the UI.

---

## 18. Access control

**Open unless configured.** With no method enabled the dashboard is reachable as before —
LabView is a read-only viewer and a lock nobody asked for is a regression.

**Naming hazard, stated once:** the methods are **`passwd`** and **`oidc`**. The passwd file
holds bcrypt hashes and has nothing to do with HTTP Basic; no symbol in the codebase contains
`basic`.

`resolveAccessMode(inputs)` in `auth/index.ts` is pure and returns `{enforced, methods,
notes}`. `passwd` is live when `auth.passwd.enabled` **and** the file parsed to at least one
usable entry; `oidc` is live when `auth.oidc.enabled` **and** `issuer` and `clientId` are both
non-empty. `enabled` means *allowed*, not *on*. An enabled-but-unusable method produces a note
and a `warn` and **never** a lock-out — a typo in a path must not make the dashboard
unopenable. Posture is re-resolved per request and cached for `POSTURE_TTL_MS = 5000`, so
dropping a passwd file in takes effect without a restart; the summary is re-logged only when it
changes.
`accessModeSummary()` in `model/access.ts` reports counts, never names.

**The gate**: one `onRequest` hook, one `onSend` hook and five routes, all in
`server/auth.ts`. Three rules:

- **The gate never consults scanned data.** No `getOverview()` may appear in that file: a
  login screen that waits on a fleet scan is a login screen that times out.
- **A reply says less than the log.** `401 {"error":"authentication required"}` to the client;
  the reason to the log. `sanitizeUsername` returns `"?"` for anything outside
  `[A-Za-z0-9._@-]{1,64}` so a hostile username cannot forge a log line.
- **`isPublicPath` is an exact-match allowlist** over a normalised path — query and fragment
  stripped, `//` collapsed, any `..` refused — holding exactly `/api/healthz`, `/api/session`,
  `/api/login`, `/api/logout`. A prefix test would open `/api/healthz/../overview`.

**Scope: gate the data, not the shell.** `index.html`, `styles.css` and `app.js` stay public,
because the bundle contains no fleet data and gating it means the reader gets a JSON 401
instead of a login form. `/auth/oidc/*` sits off `/api` so the allowlist stays about the API.

`onSend` adds `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and
`X-Frame-Options: DENY` unconditionally, plus `Cache-Control: no-store` on `/api/*` while
enforcing. **No CSP** — the bundle is a single self-contained file behind a header that already
forbids framing, and a CSP would be one more thing to get subtly wrong.

**Passwd file.** `user:hash`, one per line, `#` comments and blank lines ignored. The
algorithm is read from the `$id$` prefix and only `$2a$`, `$2b$` and `$2y$` are honoured, via
`bcryptjs`; any other id is skipped with a warning naming **the algorithm only**. A value with
no `$` is never accepted (it would be a plaintext password). Duplicate usernames: first wins.
**A warning never contains a hash.** A malformed line is skipped, not fatal. Caps:
`MAX_PASSWD_BYTES` 64 KiB, `MAX_PASSWD_ENTRIES` 1000, `MAX_PASSWORD_CHARS` 1024 (bcrypt
truncates at 72 bytes; the cap is about the work of hashing a megabyte). Reads are cached on
size + mtime + inode. `readPasswd` distinguishes `ENOENT`, `EISDIR`, over-size and `EACCES`
through `unreadable(path, code)`.

**An unknown username is verified against a decoy hash**, so the answer takes the same time as
a known one. The decoy is generated lazily from `randomBytes(32)` per cost factor and
memoized — never a committed constant.

**Throttle** keyed on the case-folded sanitised username: `maxFailedAttempts` inside
`lockoutSeconds` → `429` with `retryAfterSeconds`, **regardless of whether the password was
right**, because the lock is on the name. The counter resets on success. The map tracks at most
4096 distinct usernames, oldest evicted. `npm run hashpw` mints entries at
`DEFAULT_COST = 12`.

**Sessions** are signed, not stored: `v1.<b64url(payload)>.<b64url(hmac-sha256)>` over
`{u, via, iat, exp, jti}`, checked in that order — shape, then MAC, then expiry, then
revocation — `SessionRejection` is `malformed | signature | expired | revoked`. `safeEqual`
hashes both sides before comparing so a length difference leaks nothing. There is no session
store; logout adds the `jti` to one `SessionRevocations` set, pruned by `exp` on every write and
capped at 10 000 entries with the **earliest expiry** evicted first. The cookie is `HttpOnly`,
`SameSite=Lax`, `Path=/`, with
`Max-Age` from `ttlMinutes` and `Secure` following the **effective** scheme
(`X-Forwarded-Proto` first, since LabView normally sits behind the very proxy it documents).
CSRF is `SameSite=Lax` plus an `Origin` check on every POST while enforcing, ordered **before**
the session check and returning no `Set-Cookie`; a **missing** `Origin` passes, because
non-browser clients omit it. Cookie parsing and serialisation are written out rather than
adding `@fastify/cookie`.

**OIDC** — authorization code with **PKCE S256**, in `auth/oidc.ts` over `enrich/http.ts`, so
a provider that will not resolve reports the same phases as any other target. Everything pure
takes `now`. Discovery is cached for `DISCOVERY_TTL_MS = 10 * 60 * 1000`, the document's own
`issuer` must equal the configured one (trailing slashes forgiven), and every endpoint must be
`https` (loopback excepted). `/auth/oidc/start` puts `{state, nonce, verifier, exp}` in a signed
transient cookie scoped to `Path=/auth/oidc`, with a `LOGIN_WINDOW_SECONDS = 300` window
re-checked from the payload.

ID-token checks, in order: signature → `iss` exactly → `aud` contains the client id → `azp`
equal when present → `exp` and `iat` within `CLOCK_SKEW_SECONDS = 60` → `nonce`. **Asymmetric
algorithms only**: no `alg: none`, every HMAC alg refused, and no configuration to re-enable
them — with a client secret in the environment, an `HS256` token forged with that secret would
verify. An unknown `kid` triggers exactly **one** JWKS refetch. The username comes from
`usernameClaim` → `preferred_username` → `email` → `sub` and must satisfy `isValidUsername`.
Every failure redirects to `/?login_error=<code>` with one of the eight
`LoginFailureReason` codes.

Non-goals, deliberate: no roles or per-service permissions, no trusted-header mode, no session
persistence across restarts, no rate limiting beyond the login route.

---

## 19. Secrets

`secrets.ts` masks before serialisation, never at render time (I6). Any env key matching the
sensitive-name patterns is replaced with a mask that preserves shape and not content; URI
credentials are redacted by `redactUriCredentials`, which sidecar link parsing calls **before**
the label falls back to the URL. A configured token or client secret never appears in a
`ConnectionReport`, an attempt, a note, a warning or a log line — `safeOrigin` is what
produces every `endpoint` field. Masking runs at the end of pass 2b, so no later stage can
read an unmasked value.

---

## 20. Invariants

Eight rules. A change that breaks one is wrong regardless of what it adds.

- **I1 — Evidence only.** Every conclusion names what it rests on. No heuristic that guesses a
  gate from a port number, an image name or a naming convention. Where evidence is missing the
  answer is *not identified*, with the reason.
- **I2 — No fleet identifiers in artifacts.** No hostname, domain, container name, IP or token
  from a real fleet in source, fixtures, docs or a committed report. Fixtures use
  `example.com`, `192.0.2.0/24` and invented names.
- **I3 — Mechanism is not provider.** A middleware named `authentik` that forwards elsewhere is
  not Authentik. A probe result is never an `AuthMethod`.
- **I4 — Degrade, never fail.** Any enrichment may be absent, unreachable, partial or hostile;
  the scan still produces an `Overview` and says what it could not do. No enrichment failure
  throws out of its module.
- **I5 — Read-only and least privilege.** Nothing is ever written to a scanned tree. The Docker
  surface is exactly `ping`, `listContainers`, `inspect`. Tokens are read-only by requirement,
  the socket is mounted `:ro`, and the probe sends GET with no credential.
- **I6 — Secrets never reach the API.** Masked before serialisation; endpoints credential-free;
  a diagnostic reports a header's *name*.
- **I7 — Determinism.** Same input, same bytes out: sorted iteration everywhere order could
  vary, no clock outside injected `now`, and **no logger in the analyzer** — diagnostics are
  data.
- **I8 — Containment.** Every config-supplied path is resolved and checked before it is read
  (`resolveContained`), lexically and through symlinks; every network read is bounded in time,
  size and concurrency; and **the gate never consults scanned data**.

---

## 21. The web bundle

`web/vite.config.ts`, run as `vite build --config web/vite.config.ts` from the package root.
`root` is derived from `import.meta.url` (Vite resolves `root` against the *working
directory*, not the config file). The output settings are not preferences:

```ts
base: "./",                    // relative asset URLs, so a path-prefixed mount works
build: {
  outDir: "dist",              // → web/dist, what server.ts mounts
  emptyOutDir: true,
  target: "es2020",
  sourcemap: false,            // the map is ~13 MB and @fastify/static would serve it
  cssCodeSplit: false,
  rollupOptions: { output: {
    inlineDynamicImports: true,   // mermaid reaches for diagram types through ~38 dynamic imports
    entryFileNames: "app.js",
    assetFileNames: "styles.css",
  }},
  chunkSizeWarningLimit: 4000,
}
server: { proxy: { "/api": …, "/auth": … } }   // dev only, loopback, from LABVIEW_PORT
```

The public artifact list is therefore **exactly three files** — `index.html`, `app.js`,
`styles.css` — which is what §18's "gate the data, not the shell" depends on. The stylesheet
is imported from `main.tsx`, so `web/index.html` carries no `<link>` and points at
`/main.tsx`. `/auth` is proxied in dev because it deliberately sits outside `/api`.

**Structure.** The Stacks tab is one card per stack that expands to its services; filtering
stays **service-level**, and a collapsed stack rolls up every distinct ingress kind and every
auth mechanism its services have plus an exposure count, through `rollUpIngress` (`none` rolls
up to nothing).

**Filters.** The ingress filter is **tri-state** — off → include → exclude → off — with an
`Any / All` mode over the includes; exclusion is always AND-NOT and always wins.
`matchesTagFilter`, `describeTagFilter` and `cycleTag` live in `model/filter.ts`, not in a
component, because the smoke pass never renders the bundle. The auth filter is single-valued
and gets no Any/All: a service has one posture. `TagBars` draws per-tag gauges for ingress (the
three external counters overlap, so a stacked bar would lie); `DistributionBar` draws auth,
which partitions.

**Colour.** `web/lib/palette.ts` is the single source of categorical colour and label for every
union member — which is why adding a member is a breaking UI change (§15). `ingressVar` falls
back to `--muted`, `resolveVar` to `#888888`. `--critical` is reserved for one thing: a service
reachable from the internet with no gate. `--warning` covers an `ambiguous` match, a proxy API
answering unauthenticated, and a failed connection phase.

**Graph.** The shape is `service → network → service`, with arrowheads on the membership edges
carrying `flow` (§7). A direct `service → service` edge survives only where `via` is empty.
Three views read the same graph object through `showsNetworkNode`, `visibleSpokes` and
`networkNodeLabel`; the drawer reads `serviceConnections` off the **unpruned** graph, so a
capped spoke is still answered there. `MEMBERSHIP_NOTE` is stated once per view, not per row,
and `networkMembershipText` covers four cases (nothing else on it, co-members only,
dependencies only, both).

**Integration panels.** The matched side is derived with `useMemo` from `ov.stacks` — never a
second copy of the same relation on `meta` — and the unmatched side leads with the reason pill,
then `detail`, then the `considered` trace (§10, §11).

**Drift panel.** `collectDeclarationDrift` / `driftSummaryText`; two counts, `report.services`
(equal to `stats.declarationDrift`) and the larger `report.entries`; grouping is derived, not
stored. `StatTile` gets `role="button"`, `tabIndex` and Enter/Space handling when it is
clickable. **Not confirmed** is the same `DriftDetail` component with `variant="unconfirmed"`.

**Probe panel.** Renders when `report.probed > 0 || report.notAsked > 0`, with sections in this
order: *answered with no login page*, *answered with a login page*, *did not answer* — the
finding first. `collectProbeReport`, `probeReportSummaryText` and `probeReasonText` are in
`model/probe.ts`. Each row is four lines: the service, the verdict, the fact it rested on, the
address asked.

`Panel.tsx` owns the drawer shell; `main.tsx` holds **one** `panel` state for all five panels,
so Escape closes the panel and then the drawer. The build stamp renders as `● LabView d0e2030`
from `buildLabel` / `buildTitle` (`model/build.ts`) and sits **behind the session**.

**View state as a query string** (`model/viewstate.ts` — pure, and in `model/` because the
smoke pass cannot render the bundle):

- `ViewTab = "overview" | "graph"`;
  `ViewPanel = "authentik" | "traefik" | "drift" | "unconfirmed" | "probe"`.
- `ViewState {tab, search, ingress, auth, exposedOnly, hideAccepted, driftOnly, service?,
  panel?, network?}`, with `DEFAULT_VIEW_STATE` as above and empty tag filters.
- Parameters, and the **fixed** write order: `tab`, `q`, `ingress`, `auth`, `exposed`,
  `accepted`, `drift`, `net`, `panel`, `svc`. Defaults are omitted, so an untouched dashboard
  has an empty query and the same view always spells the same string.
- A tri-state filter is **one** parameter: `all:public,lan,-internal`. `-` prefixes an
  exclusion; the mode prefix is `all:` or `any:` on the way in and only `all:` is ever written
  out. A tag not in the dimension's vocabulary is **dropped**, because a filter with no chip is
  a view with no way back.
- Booleans are written as `1` and `readFlag` accepts only `"1"`. Free text is capped at
  `MAX_TEXT = 200` and passed through `stripControls`, which drops code points below `0x20`
  plus `0x7f` and nothing else — a Cyrillic container name or an emoji in a label survives.
- Everything read out of a URL is attacker-supplied: enumerations are checked against their
  literals, so there is no such thing as an invalid LabView URL — only one that describes less
  than it meant to.
- `isViewNavigation(prev, next)` is `prev.service !== next.service || prev.panel !== next.panel`
  — a drawer or panel is something Back should undo; a keystroke in the search box is not.

---

## 22. Build, image, CI

`tsconfig.json` (server): `target ES2022`, `module`/`moduleResolution` **NodeNext**,
`lib ["ES2023"]`, `outDir dist`, `rootDir src`, `strict`, `noUncheckedIndexedAccess`,
`noImplicitOverride`, `esModuleInterop`, `skipLibCheck`,
`forceConsistentCasingInFileNames`, `declaration: false`, `sourceMap: true`,
`resolveJsonModule`; includes `src/**/*.ts`, excludes `node_modules`, `dist`, `web`.

`tsconfig.web.json`: `module ESNext`, `moduleResolution Bundler`, `jsx react-jsx` with
`jsxImportSource preact`, `lib` adds DOM, `noEmit`, and **`types: ["vite/client"]` and nothing
else** — Node types stay out deliberately, so a `process` or `Buffer` that typechecks here
would be a runtime error in the bundle. Includes `web/**/*.ts(x)` plus `src/model/types.ts`;
excludes `web/vite.config.ts`.

`tsconfig.scripts.json`: `noEmit`, NodeNext, over `scripts/**`, `src/**`, `tools/**` and
`web/vite.config.ts` — everything that runs through `tsx`, which strips types without checking
them, so an assertion against a renamed property would read `undefined` and pass while proving
nothing.

`package.json` — `type: "module"`, `engines.node >= 20`, version `0.1.0`, private. Scripts:

| Script | Command |
|---|---|
| `build:web` | `vite build --config web/vite.config.ts` |
| `build:server` | `tsc -p tsconfig.json` |
| `build` | `build:web && build:server` |
| `dev:web` | `vite --config web/vite.config.ts` |
| `dev` | `npm run build:web && tsx watch src/index.ts` |
| `start` | `node dist/index.js` |
| `scan` | `tsx src/cli.ts` |
| `hashpw` | `tsx src/hashpw.ts` |
| `typecheck` | all three tsconfigs with `--noEmit` |
| `smoke` | `tsx scripts/smoke.ts` |
| `probe-lab` | `tsx tools/probe-lab/cli.ts` |

Dependencies: `@fastify/static ^10.1.2`, `bcryptjs ^3.0.3`, `dockerode ^5.0.1`,
`fastify ^5.1.0`, `yaml ^2.6.1`. Dev: `@preact/preset-vite ^2.10.2`, `@types/dockerode ^4.0.1`,
`@types/node ^22.10.1`, `cytoscape ^3.30.2`, `mermaid ^11.4.0`, `preact ^10.25.1`,
`tsx ^4.19.2`, `typescript ^5.7.2`, `vite ^7.1.5`.

**Dockerfile** — two stages, `node:26-alpine`:

```dockerfile
FROM node:26-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY tsconfig.json tsconfig.web.json ./
COPY web ./web
COPY src ./src
RUN npm run build
RUN npm prune --omit=dev

FROM node:26-alpine
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/web/dist ./web/dist
COPY package.json config.example.yml passwd.example ./
ARG LABVIEW_BUILD_SHA=""
ENV LABVIEW_APPS_ROOT=/data/apps \
    LABVIEW_PORT=8080 \
    LABVIEW_BUILD_SHA=${LABVIEW_BUILD_SHA}
EXPOSE 8080
USER node
CMD ["node", "dist/index.js"]
```

The COPYs name paths, so `tools/`, `fixtures/`, `scripts/` and `reports/` never enter the
image. `USER node` is what makes the socket mount `:ro` and the read-only token meaningful.
`LABVIEW_BUILD_SHA` is the `image` source of `BuildStamp` (§3.4).

`.dockerignore`: `node_modules`, `dist`, `web/dist`, `.git`, `fixtures`, `*.md`, `!README.md`,
`.DS_Store`.

Deployment: mount the compose tree at `/data/apps` read-only, and
`/var/run/docker.sock:/var/run/docker.sock:ro` when Docker enrichment is wanted.

---

## 23. Testing contract

`npm run smoke` runs the **full pipeline** — `buildOverview` with real fixture files and
injected HTTP/Docker — over seven fixture roots, then asserts classifications. `npm run
typecheck` must pass over all three projects. Both gate CI.

The harness sets `LABVIEW_DOCKER_ENABLED=false` and `LABVIEW_CONFIG=___none___` (forcing
defaults) **before importing config**, and every value import in the file is dynamic for that
reason. It then **deletes** every `LABVIEW_AUTHENTIK_*`, `LABVIEW_TRAEFIK_*`, `LABVIEW_PROBE_*`
and `LABVIEW_AUTH_*`/`LABVIEW_OIDC_*` variable, and sets `LABVIEW_TRAEFIK_ENABLED=false`
explicitly, so an operator's exported credentials can neither make the test reach the network
nor change what it asserts. The proxy read and the probe get that treatment because both would
otherwise issue real requests to addresses out of the *fixture* compose files.

| Root | What it pins |
|---|---|
| `fixtures/apps` | a representative happy-path fleet — `authentik`, `emby`, `jellyfin`, `nextcloud`, `outline`, `proxy` |
| `fixtures/edge` | one directory per previously-fixed defect (18) — interpolation, expose-only, host-port ties, tunnel origins, shared networks, sidecar variants, containment escape, declaration comparison, stale and partial drift |
| `fixtures/nets` | what *connects* two services vs what merely lets them reach each other: one `external:` network across four stacks, sidecar-declared dependencies, a co-member declaring nothing, every way a reference can fail, a dependency with no shared network, and both kinds of single-service network |
| `fixtures/authentik` | the identity-provider integration through an injected HTTP layer; canned responses in `fixtures/authentik-api.json` |
| `fixtures/traefik` | the proxy integration the same way; `fixtures/traefik-api.json` also carries the Authentik payload, because the three-way cross-check reads all three sources at once |
| `fixtures/probe` | 18 answer shapes — one address per fixture the stub is keyed on. Canned answers live in `smoke.ts`, not a JSON payload, because a probe reads a status, three headers and a fragment of HTML |
| `fixtures/auth` | not a fleet: `passwd.ok`, `passwd.messy`, `passwd.empty` for LabView's own login |

Plus `fixtures/outside-root.env` and `fixtures/outside-root.labview`, which exist to be
**refused** by `resolveContained`.

`phase(title, root)` opens a phase, `section(title)` a section, and `report()` prints
`PASS/FAIL — N assertion(s) in M section(s) across P phase(s), F failure(s)` and exits non-zero
on any failure. `PROBE_LAN_HOST = "192.0.2.10"` (I2). Two pinned strings that must keep reading
the same way:

- `14 of 16 applications (2 recovered from providers), 17 providers, 2 outposts`
- `37 requests: one for each of the 20 services asked, one fallthrough, and 16 second requests`

**The fixture-revert contract.** Every fixture exists because a rule exists, and every fixture
must **fail** smoke if its rule is reverted — a fixture that still passes against the old
behaviour is documentation, not a test. Two of the probe fixtures are deliberate traps
(`public-portal/blog`'s `/auth/` veto and `passwordless/news`'s cross-origin newsletter form):
they look like the case they are next to and must come out the other way.

Beyond the roots, the pure rules are asserted as **tables of literals** rather than through
fixtures wherever they can be: `readGate`'s eight signals, `readLoginForm`'s field detection,
`probeReasonText`'s branches, `readStateGate`, `saysLogin`/`saysLogout`,
`compareDeclaredAuth`'s four outcomes, `parseSidecar`'s validation warnings,
`readViewState`/`writeViewState`'s round trip, `matchesTagFilter`, `phaseForCode`/`phaseForStatus`,
`resolveAccessMode`, session sign/verify, and the `ProbeLabObservation` → verdict identity
`buildReport(obs).verdict.gate === readGate(...)`.

---

## Appendix A — `src/model/types.ts`

The declarations below are the payload contract, verbatim minus comments. Where a union's
member semantics are not evident from its name, they are given in the section that owns it —
`ConnectionPhase` in §14, `NoAuthReason` / `AuthConfidence` in §15, `IngressKind` in §7,
`OriginKind` in §8, `ProbeGate` in §12, `DeclaredAuthMechanism` in §13,
`LoginFailureReason` in §15.

```ts
export interface EnvVar {
  key: string;
  value: string | null;
  masked: boolean;
  source: "env_file" | "environment" | "shell-default";
}

export interface PortMapping {
  published?: string;
  target: string;
  protocol: string;
  raw: string;
}

export interface MountSpec {
  type: "bind" | "volume" | "tmpfs" | "npipe" | "unknown";
  source?: string;
  target: string;
  readOnly: boolean;
  raw: string;
}

export interface OriginTarget {
  address: string;
  host: string;
  port: string;
  kind: OriginKind;
  hopKey?: string;
  evidence: string;
}

export type OriginKind =
  | "self-network"
  | "self-host-port"
  | "fleet-service"
  | "unresolved";

export interface CloudflareRoute {
  hostname: string;
  service: string;
  path?: string;
  access?: {
    group?: string;
    policy?: string;
    emails?: string[];
  };
  noTlsVerify?: boolean;
  raw: Record<string, string>;
  origin?: OriginTarget;
}

export interface TraefikRoute {
  router: string;
  rule?: string;
  hosts: string[];
  pathPrefixes: string[];
  entrypoints: string[];
  tls: boolean;
  certResolver?: string;
  middlewares: string[];
  servicePort?: string;
  service?: string;
}

export interface TraefikLiveMiddleware {
  name: string;
  type: string;
  address?: string;
  errors: string[];
  viaChain?: string;
  viaEntrypoint?: boolean;
}

export interface TraefikLiveServer {
  url: string;
  status?: string;
}

export interface TraefikLiveRouter {
  router: string;
  provider: string;
  status?: string;
  errors: string[];
  rule?: string;
  hosts: string[];
  entryPoints: string[];
  middlewares: TraefikLiveMiddleware[];
  service?: string;
  servers: TraefikLiveServer[];
  tls: boolean;
  evidence: string[];
}

export type AuthMethod =
  | "authentik-forward-auth"
  | "authentik-oauth"
  | "authentik-ldap"
  | "forward-auth"
  | "other-oauth"
  | "ldap"
  | "basic-auth"
  | "none";

export type AuthConfidence =
  | "confirmed"
  | "observed"
  | "inferred";

export type AuthentikProviderKind =
  | "proxy"
  | "oauth2"
  | "ldap"
  | "saml"
  | "radius"
  | "scim"
  | "other";

export interface AuthentikProvider {
  name: string;
  kind: AuthentikProviderKind;
  rawKind: string;
  mode?: string;
  internalHost?: string;
  externalHost?: string;
  redirectUris?: string[];
  backchannel: boolean;
  outposts: string[];
}

export interface AuthentikApplication {
  name: string;
  slug: string;
  group?: string;
  launchUrl?: string;
  providers: AuthentikProvider[];
  discoveredVia: "list" | "provider";
}

export type AuthentikMatchStrength = "address" | "hostname" | "name";

export interface AuthentikMatch {
  applications: AuthentikApplication[];
  evidence: string[];
  strength: AuthentikMatchStrength[];
}

export type ConnectionPhase =
  | "disabled"
  | "not-configured"
  | "not-found"
  | "credential"
  | "resolve"
  | "connect"
  | "tls"
  | "timeout"
  | "authenticate"
  | "authorize"
  | "path"
  | "status"
  | "protocol"
  | "partial"
  | "connected";

export interface ConnectionAttempt {
  endpoint: string;
  why: string;
  phase: ConnectionPhase;
  code?: string;
  detail: string;
}

export interface ConnectionReport {
  target: string;
  ok: boolean;
  phase: ConnectionPhase;
  endpoint?: string;
  source?: "config" | "discovered" | "default";
  detail?: string;
  code?: string;
  hint?: string;
  read?: string;
  attempts: ConnectionAttempt[];
}

export type UnmatchedReason = "ambiguous" | "no-candidate" | "internal";

export interface UnmatchedApplication {
  application: AuthentikApplication;
  reason: UnmatchedReason;
  detail: string;
  considered: string[];
}

export interface AuthentikSummary {
  enabled: boolean;
  configured: boolean;
  reachable: boolean;
  endpoint?: string;
  endpointSource?: "config" | "discovered";
  error?: string;
  applications: number;
  applicationsConfigured?: number;
  applicationsWithheld: number;
  applicationsRecovered: number;
  providers: number;
  outposts: number;
  matchedServices: number;
  unmatchedApplications: UnmatchedApplication[];
}

export interface UnmatchedRouter {
  router: TraefikLiveRouter;
  reason: UnmatchedReason;
  detail: string;
  considered: string[];
}

export interface TraefikSummary {
  enabled: boolean;
  configured: boolean;
  reachable: boolean;
  endpoint?: string;
  endpointSource?: "config" | "discovered";
  credential: "none" | "basic";
  version?: string;
  entrypointsRead: boolean;
  error?: string;
  routers: number;
  middlewares: number;
  services: number;
  matchedServices: number;
  unmatchedRouters: UnmatchedRouter[];
}

export interface AuthPosture {
  method: AuthMethod;
  detail: string;
  evidence: string[];
  confidence: AuthConfidence;
  exposedWithoutAuth: boolean;
}

export type ProbeVantage = "public" | "traefik" | "lan";

export type ProbeGate =
  | "challenge"
  | "redirect-origin"
  | "redirect-login"
  | "meta-refresh-login"
  | "sso-form"
  | "password-form"
  | "credential-form"
  | "state-challenge";

export interface ProbeRedirect {
  to: string;
  crossOrigin: boolean;
}

export interface ProbeState {
  asked: number;
  refusedAt?: string;
  status?: number;
  challenge?: boolean;
}

export interface ProbeAnon {
  textChars: number;
  links: number;
  loginHref?: string;
  loginLabel?: string;
}

export interface LoginFormShape {
  password: boolean;
  username: boolean;
  submit: boolean;
  otp: boolean;
  action?: string;
}

export interface ServiceProbe {
  endpoint: string;
  vantage: ProbeVantage;
  phase: ConnectionPhase;
  status?: number;
  gate?: ProbeGate;
  mediaType?: string;
  redirect?: ProbeRedirect;
  refresh?: ProbeRedirect;
  truncated?: boolean;
  form?: LoginFormShape;
  state?: ProbeState;
  anon?: ProbeAnon;
  detail: string;
  attempts: ConnectionAttempt[];
}

export type DeclaredAuthMechanism =
  | "app-local-accounts"
  | "app-ldap"
  | "app-oidc"
  | "app-saml"
  | "app-token"
  | "mtls"
  | "network-restricted"
  | "external-proxy"
  | "other";

export interface DeclaredAuth {
  mechanism: DeclaredAuthMechanism;
  detail?: string;
}

export type AuthFamily = "oidc" | "ldap" | "proxy";

export type DeclaredAuthAgreement =
  | "supplies"
  | "redundant"
  | "conflicts"
  | "supplements";

export interface DeclaredLink {
  label: string;
  url: string;
}

export interface DeclaredDependency {
  name: string;
  detail?: string;
}

export interface DeclaredServiceDependency {
  ref: string;
  detail?: string;
}

export interface Declaration {
  file: string;
  description?: string;
  owner?: string;
  criticality?: string;
  notes?: string;
  data?: string;
  links: DeclaredLink[];
  dependencies: DeclaredDependency[];
}

export interface ServiceDeclaration extends Declaration {
  auth: DeclaredAuth[];
  dependsOn: DeclaredServiceDependency[];
  unauthenticatedAccepted?: { reason: string };
  expectedIngress?: IngressKind[];
  drift: string[];
  unconfirmed: string[];
  authAgreement?: DeclaredAuthAgreement;
}

export interface DockerState {
  id: string;
  name: string;
  image: string;
  imageDigest?: string;
  state: string; 
  status: string; 
  health?: "healthy" | "unhealthy" | "starting" | "none";
  running: boolean;
  restartCount?: number;
  createdAt?: string;
  startedAt?: string;
  networks: string[];
  ipAddresses: Record<string, string>;
  publishedPorts: PortMapping[];
}

export interface Service {
  name: string;
  containerName: string;
  image?: string;
  restart?: string;
  command?: string;
  dependsOn: string[];
  networks: string[];
  ports: PortMapping[];
  expose: string[];
  mounts: MountSpec[];
  env: EnvVar[];
  labels: Record<string, string>;
  cloudflare: CloudflareRoute[];
  traefik: TraefikRoute[];
  ingress: IngressKind[];
  auth: AuthPosture;
  docker?: DockerState;
  authentik?: AuthentikMatch;
  traefikLive?: TraefikLiveRouter[];
  declared?: ServiceDeclaration;
  probe?: ServiceProbe;
  notes: string[];
}

export interface AppStack {
  id: string;
  name: string;
  dir: string;
  composeFile: string;
  hasEnvFile: boolean;
  projectName: string;
  services: Service[];
  declaredNetworks: NetworkDecl[];
  declaredVolumes: VolumeDecl[];
  declared?: Declaration;
  warnings: string[];
}

export interface NetworkDecl {
  name: string;
  external: boolean;
  driver?: string;
}

export type NetworkScope = "external" | "stack-local";

export interface VolumeDecl {
  name: string;
  external: boolean;
  driver?: string;
}

export interface GraphNode {
  id: string;
  label: string;
  kind: "service" | "network" | "volume" | "external";
  stack?: string;
  auth?: AuthMethod;
  ingress?: IngressKind;
  running?: boolean;
  role?: "proxy";
  scope?: NetworkScope;
  memberCount?: number;
  stackCount?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: "network" | "depends_on" | "volume" | "ingress" | "auth";
  label?: string;
  flow?: "to-network" | "to-service" | "both";
  flowSource?: "observed" | "declared" | "both";
  declaredBy?: { file: string; detail?: string };
  via?: string[];
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export type IngressKind = "public" | "traefik" | "lan" | "internal" | "none";

export interface OverviewStats {
  stacks: number;
  services: number;
  running: number;
  publicServices: number;
  traefikServices: number;
  lanServices: number;
  internalServices: number;
  noIngressServices: number;
  authProtected: number;
  exposedWithoutAuth: number;
  byAuthMethod: Record<string, number>;
  declaredAuth: number;
  declaredAuthProtected: number;
  declaredAuthUnconfirmed: number;
  exposureAccepted: number;
  declarationDrift: number;
  declaredDependencies: number;
  probeGated: number;
  probeOpen: number;
  networks: number;
  connectingNetworks: number;
  crossStackNetworks: number;
  soloLocalNetworks: number;
}

export interface ScanMeta {
  scannedAt: string;
  appsRoot: string;
  dockerAvailable: boolean;
  dockerError?: string;
  authentik?: AuthentikSummary;
  traefik?: TraefikSummary;
  connections: ConnectionReport[];
  probe: ProbeRun;
  durationMs: number;
  warnings: string[];
  build: BuildStamp;
}

export interface ProbeRun {
  enabled: boolean;
  source: "config" | "request";
  skipped: number;
}

export interface BuildStamp {
  version: string;
  commit?: string;
  source: BuildStampSource;
}

export type BuildStampSource = "image" | "checkout" | "unknown";

export interface Overview {
  meta: ScanMeta;
  stats: OverviewStats;
  stacks: AppStack[];
  graph: Graph;
}

export interface ScanRequest {
  probe?: boolean;
}

export type LoginMethod = "passwd" | "oidc";

export type LoginFailureReason =
  | "credentials"
  | "throttled"
  | "method-unavailable"
  | "session-expired"
  | "oidc-state"
  | "oidc-provider"
  | "oidc-token"
  | "oidc-identity";

export interface AccessMode {
  enforced: boolean;
  methods: LoginMethod[];
  notes: string[];
}

export interface SessionInfo {
  enforced: boolean;
  methods: LoginMethod[];
  notes: string[];
  user?: { name: string; via: LoginMethod };
  oidcLabel?: string;
}
```
