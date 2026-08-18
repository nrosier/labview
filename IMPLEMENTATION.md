# LabView — Build Specification

This is the normative specification for LabView: what the program must do, what it must
never do, the exact contract of its HTTP payload, and the environment it runs in. It does
not describe a source layout and does not assume one.

**MUST / MUST NOT / SHOULD / MAY** carry their RFC 2119 meanings. Anything in a table, in a
fenced block, or in `code font` is exact — field names, union members, environment variable
names, paths, patterns, thresholds and numeric limits are contract, not suggestion. Prose
in *italics* is example wording and is not normative.

An implementation conforms when it satisfies every MUST, reproduces the payload contract of
Appendix A in field names and union members exactly, and reaches the same conclusions as the
test corpus in §23. §21 states eight invariants that outrank every other rule here: where
this document seems to permit something an invariant forbids, the invariant wins.

---

## 1. Purpose and prohibitions

LabView is a **read-only documentation generator for a Docker Compose fleet**. It reads a
tree of compose files, optionally enriches them with live state from the Docker Engine, an
Authentik identity provider, a Traefik reverse proxy and an active HTTP probe, derives how
each service is reached and what authenticates it, and serves the result as a JSON payload
plus a browser UI.

It MUST NOT write to the scanned tree, reconfigure anything it inspects, or hold state that
survives a restart.

**Nothing about a particular fleet may be built in.** No hostname, domain, container name,
network name or IP address. No assumption that a proxy, a tunnel or an SSO provider exists.
No naming convention read as a role — `auth.*` is not Authentik, `db` is not a database. No
assumption that the Docker Engine is reachable, or that whatever sits in front of LabView
authenticates anything.

The only names that MAY ship as defaults are ones the upstream projects publish about
themselves: the label prefixes `dockflare` and `traefik`, the string `authentik`, the domain
`goauthentik.io`, and the path `/var/run/docker.sock`.

---

## 2. Runtime and distribution

### 2.1 Implementation language

The service MUST be implemented in **Go (1.23 or later)** and MUST build to a single
statically linked binary with `CGO_ENABLED=0`.

It is a requirement, not a preference: a process that mounts a Docker socket and a whole compose
tree should ship with no interpreter, no package manager, no shell and no dependency resolver at
runtime, and every capability this program needs — HTTP client and server, unix-socket transport,
TLS, HMAC, constant-time comparison, embedded assets, bounded concurrency — is in the standard
library.

Third-party runtime dependencies MUST be limited to: a YAML 1.2 parser, a bcrypt
implementation, and JWT/JWKS verification (which MAY instead be built on the standard
library's crypto packages). An HTTP framework, a router library beyond simple pattern
matching, an ORM, a dependency-injection container and a Docker client library MUST NOT be
added — the Engine API is three HTTP requests (§10) and is simpler to call directly than to
wrap.

### 2.2 Frontend

The UI toolchain is unconstrained. Its **output** is constrained:

- The build MUST produce static assets only, served from `/` with **relative** URLs, so a
  path-prefixed mount works.
- The assets MUST be **embedded in the binary**. The runtime image MUST NOT need a separate
  asset directory, and serving the UI MUST NOT depend on a filesystem read.
- The assets MUST contain **no fleet data** — they are served without a session (§19).
- The UI MUST make no network request at runtime other than to LabView's own API. No CDN, no
  font service, no telemetry, no map tile server. A homelab dashboard has to work with no
  internet access.
- The build MUST be reproducible offline from a committed lockfile.

### 2.3 Image

Two stages. The final stage MUST be `scratch` or a distroless static base, and MUST contain
no shell and no package manager. It MUST:

- run as a **non-root numeric UID**, and function with a read-only root filesystem;
- `EXPOSE 8080`, and default `LABVIEW_APPS_ROOT=/data/apps` and `LABVIEW_PORT=8080`;
- accept the build identity as a build argument set into `LABVIEW_BUILD_SHA` (§3.4);
- carry an example configuration file and an example passwd file for reference;
- contain **only** the binary and those examples — no test corpus, no diagnostic tool, no
  source, no build cache.

Requesting no Linux capabilities and writing nothing to disk at runtime are both requirements,
not consequences: the process holds no cache, no session store and no scratch space.

### 2.4 Filesystem and network contract

These paths are the deployment interface and MUST NOT change:

| Path | Mode | Meaning |
|---|---|---|
| `/data/apps` | read-only mount | default scan root; overridden by `LABVIEW_APPS_ROOT` |
| `/config/passwd` | read-only | default local credential file; overridden by `LABVIEW_AUTH_PASSWD_FILE` |
| `./config.yml` | read-only | default configuration file; overridden by `LABVIEW_CONFIG` |
| `/var/run/docker.sock` | read-only mount | default Docker endpoint; overridden by `LABVIEW_DOCKER_SOCKET` |

Inbound: one HTTP listener, default `0.0.0.0:8080`. Outbound: the Docker endpoint, the
Authentik API, the Traefik API, the OIDC issuer, and probe targets — nothing else.

**Certificate verification MUST stay enabled on every outbound TLS connection, and there MUST
be no configuration option to disable it.** A homelab certificate that does not verify is
reported as a `tls` connection phase (§15); it is not a reason to trust the wire.

### 2.5 The one-shot mode

Besides the server, the binary MUST offer a subcommand that runs one scan and writes the
`Overview` payload to stdout as JSON, with all diagnostics on stderr so stdout stays
parseable, and a subcommand that hashes a password into a `user:hash` line at cost 12 (§19).

---

## 3. Configuration

Precedence, lowest to highest: **built-in defaults** → **configuration file** (path from
`LABVIEW_CONFIG`, default `./config.yml`) → **environment**. Arrays replace, never merge.

A malformed configuration file MUST log *`[config] failed to parse <path>: <message>; using
defaults`* and fall back to defaults rather than exiting. Merging MUST deep-copy: environment
overrides are applied onto the merged tree in place, so a shallow copy would leak one load's
overrides into the next. Unknown keys MUST be preserved, because retired-key detection reads
them (§3.3).

### 3.1 Defaults

```yaml
appsRoot:          "/data/apps"
composeFilenames:  ["compose.yml","compose.yaml","docker-compose.yml","docker-compose.yaml"]
sidecarFilenames:  [".labview",".labview.yml",".labview.yaml"]
docker:   { enabled: true, host: "", port: 2375, socketPath: "/var/run/docker.sock",
            maxConcurrency: 8, timeoutMs: 5000, bodyCapBytes: 8388608 }   # 8 MiB
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
blankCredentialVars: []          # populated by environment resolution only
```

The built-in default socket path MUST stay distinguishable from an operator-supplied endpoint,
because a connection report says `default` in one case and `config` in the other (§15).

**`enabled` everywhere means *allowed*, not *on*:** an integration or a login method is live
only when it is also usable. No default TCP Docker host, no default `authentik.url`, no
default `traefik.url` and no host-naming convention may ever ship (I2).

### 3.2 Environment

Booleans are true unless the value is exactly `false` — the variable being present at all
means the operator meant something. Numbers are parsed, required finite, floored, and
**rejected in favour of the default when out of range**: `maxConcurrency` needs `>= 1`,
timeouts `> 0`, `ttlMinutes` / `maxFailedAttempts` / `lockoutSeconds` `>= 1`, and
`docker.bodyCapBytes` at least the shared 64 KiB read cap — a Docker cap below what every other
read already gets can only make a read fail, and it is the shape of the likeliest mistake,
which is writing `8` for eight megabytes.

| Env | Setting | Rule |
|---|---|---|
| `LABVIEW_CONFIG` | — | configuration file path, default `./config.yml` |
| `LABVIEW_APPS_ROOT` | `appsRoot` | scan root and containment boundary (I8) |
| `LABVIEW_SIDECAR_FILENAMES` | `sidecarFilenames` | comma-separated, trimmed, empties dropped; ignored when the result is empty |
| `LABVIEW_DOCKER_HOST` / `DOCKER_HOST` | `docker.host`+`port` | accepts `tcp://h:p`, `http(s)://h:p`, `h:p`, bare `h` (port defaults 2375), `unix:///p`, `/p`. A socket form sets `socketPath` and clears `host`. `LABVIEW_DOCKER_HOST` wins |
| `LABVIEW_DOCKER_PORT` | `docker.port` | parsed, unvalidated |
| `LABVIEW_DOCKER_SOCKET` | `docker.socketPath` | always wins; clears `host` |
| `LABVIEW_DOCKER_ENABLED` | `docker.enabled` | `false` = configuration-only scan |
| `LABVIEW_DOCKER_MAX_CONCURRENCY` | `docker.maxConcurrency` | bounded inspect fan-out |
| `LABVIEW_DOCKER_TIMEOUT` | `docker.timeoutMs` | per-request socket **inactivity**, not total time |
| `LABVIEW_DOCKER_BODY_CAP` | `docker.bodyCapBytes` | **bytes**, not megabytes; how much of one Engine response to read. Floor 64 KiB, ceiling 32 MiB (I8) |
| `LABVIEW_MASK_SECRETS` | `secrets.maskValues` | |
| `LABVIEW_CACHE_TTL` | `cacheTtlSeconds` | parsed, unvalidated |
| `LABVIEW_PORT` / `LABVIEW_HOST` | `server.port` / `host` | |
| `LABVIEW_LOG_LEVEL` | — | log level, default `info` |
| `LABVIEW_BUILD_SHA` | — | **environment only, no configuration key** (§3.4) |
| `LABVIEW_AUTHENTIK_TOKEN` | `authentik.token` | credential. Unset = no request is made; set-and-empty = `credential` phase |
| `LABVIEW_AUTHENTIK_URL` | `authentik.url` | skips discovery |
| `LABVIEW_AUTHENTIK_ENABLED` | `authentik.enabled` | |
| `LABVIEW_AUTHENTIK_TIMEOUT` | `authentik.timeoutMs` | per request; `authentik.maxPages` is file-only |
| `LABVIEW_TRAEFIK_URL` | `traefik.url` | skips discovery; one of the two things that make an endpoint eligible for a credential (§12) |
| `LABVIEW_TRAEFIK_USERNAME` | `traefik.username` | an Authentik user, or the reserved `goauthentik.io/token` |
| `LABVIEW_TRAEFIK_PASSWORD` | `traefik.password` | credential; an app password, not an API token |
| `LABVIEW_TRAEFIK_ENABLED` | `traefik.enabled` | on by default — needs no credential |
| `LABVIEW_TRAEFIK_TIMEOUT` | `traefik.timeoutMs` | per request |
| `LABVIEW_PROBE_ENABLED` | `probe.enabled` | the **default**, not the authority (§13.7). Any value but `false` turns it on |
| `LABVIEW_PROBE_LAN_HOST` | `probe.lanHost` | empty skips the LAN vantage entirely; never guessed |
| `LABVIEW_PROBE_TIMEOUT` | `probe.timeoutMs` | per request |
| `LABVIEW_PROBE_MAX_CONCURRENCY` | `probe.maxConcurrency` | services at once. Addresses *per* service is not configurable (§13.6) |
| `LABVIEW_AUTH_PASSWD_ENABLED` | `auth.passwd.enabled` | `false` = form off, file never read |
| `LABVIEW_AUTH_PASSWD_FILE` | `auth.passwd.file` | `user:hash` lines |
| `LABVIEW_AUTH_MAX_FAILED_ATTEMPTS` | `auth.maxFailedAttempts` | per **username** |
| `LABVIEW_AUTH_LOCKOUT_SECONDS` | `auth.lockoutSeconds` | window and `Retry-After` |
| `LABVIEW_AUTH_COOKIE_SECURE` | `auth.session.secure` | only `auto`\|`true`\|`false` accepted; anything else keeps the default |
| `LABVIEW_OIDC_ENABLED` | `auth.oidc.enabled` | |
| `LABVIEW_OIDC_ISSUER` | `auth.oidc.issuer` | with a client id, this turns OIDC on |
| `LABVIEW_OIDC_CLIENT_ID` | `auth.oidc.clientId` | |
| `LABVIEW_OIDC_CLIENT_SECRET` | `auth.oidc.clientSecret` | credential. Unset = public client (PKCE either way); set-and-empty = startup note and public client, **never** a refusal to start |
| `LABVIEW_OIDC_REDIRECT_URI` | `auth.oidc.redirectUri` | empty derives it from the request, honouring `X-Forwarded-Proto`/`-Host` |
| `LABVIEW_OIDC_SCOPES` | `auth.oidc.scopes` | split on `[,\s]+`; `openid` is sent whether listed or not |
| `LABVIEW_OIDC_USERNAME_CLAIM` | `auth.oidc.usernameClaim` | |
| `LABVIEW_OIDC_LABEL` | `auth.oidc.label` | empty = *Sign in with \<issuer host>* |
| `LABVIEW_OIDC_TIMEOUT` | `auth.oidc.timeoutMs` | discovery, token exchange, JWKS |
| `LABVIEW_SESSION_SECRET` | `auth.session.secret` | credential. Unset = a random secret per start, so restarts sign everyone out |
| `LABVIEW_SESSION_TTL_MINUTES` | `auth.session.ttlMinutes` | also the cookie `Max-Age` |
| `LABVIEW_SESSION_COOKIE_NAME` | `auth.session.cookieName` | the OIDC transient cookie is this name plus `_oidc` |

### 3.3 Credentials come from the environment

Exactly four settings are credentials: `authentik.token`, `traefik.password`,
`auth.oidc.clientSecret`, `auth.session.secret`. Each has exactly one variable and **there
MUST be no path form** — no `tokenFile`, no `*_FILE`. All four are in `secrets.keysAlways`.
Rotation therefore requires a restart. `auth.passwd.file` is exempt and is still re-read on
change.

- **`blankCredentialVars`** holds the **names** of credential variables that were present and
  carried nothing (defined, but empty after trimming). That distinction survives nowhere else,
  so it MUST be recorded here: it becomes a `credential` phase for a scan target (§15) and a
  startup note for LabView's own login (§19). It is assigned, never appended — a configuration
  file setting the same key has no standing. **Names only, never values** (I6).
- **Retired settings** are recognised for the single purpose of saying they are gone. Neither
  the value nor the path is echoed. Both entry points report them: the server as a warning, the
  one-shot scan on stderr.

| Retired variable | Retired configuration key | Message |
|---|---|---|
| `LABVIEW_AUTHENTIK_TOKEN_FILE` | `authentik.tokenFile` | *`<was>` is no longer read — put the value in `<now>` instead* |
| `LABVIEW_TRAEFIK_PASSWORD_FILE` | `traefik.passwordFile` | same |
| `LABVIEW_OIDC_CLIENT_SECRET_FILE` | `auth.oidc.clientSecretFile` | same |
| `LABVIEW_SESSION_SECRET_FILE` | `auth.session.secretFile` | same |

A retired configuration key produces *`<block>.<field>` in the configuration file is no longer
read — put the value in `<now>` instead*, and is reported when the held value is a non-blank
string.

**`LABVIEW_BUILD_SHA` MUST NOT have a configuration-file key.** The configuration file is
editable while LabView runs, so a key there would let a running instance claim to be a
different build than it is (I1). Nothing ever writes the variable.

### 3.4 The build stamp

Version `0.1.0`. Short commit form is 7 characters, maximum accepted length 40.

1. **Environment first.** `LABVIEW_BUILD_SHA`, trimmed, MUST match `^[A-Za-z0-9._-]+$` —
   anything else is treated as absent, not trimmed into a different string. A full 40-hex
   object id is shortened to 7; anything else is used as given, because a tag is a deliberate
   answer. ⇒ `source: "image"`.
2. **Else the checkout.** Walk up at most 4 directory levels looking for `.git/HEAD`. A `.git`
   that is a *file* (worktree or submodule pointer) **ends the walk with no answer** rather than
   following it. `HEAD` is either a full sha (shortened to 7) or `ref: <name>`, where the name
   MUST match `^refs/[A-Za-z0-9._\-/]+$` and contain no `..` (I8 in the small); then the loose
   ref file, then the packed-refs file, ignoring peeled (`^`) and comment lines. Refuse to read
   a git file larger than 256 KiB. ⇒ `source: "checkout"`.
3. **Else** `{version, source: "unknown"}` — with **no** `commit` key at all, never an empty
   string.

The UI label is *`● LabView d0e2030`*, falling back to the version when there is no commit, and
the tooltip has one sentence per `source`, so *built from that commit* and *started in a tree at
that commit* are distinguished in one place.

### 3.5 Endpoint resolution orders

- **Docker:** explicit socket → configured or environment TCP host → default socket path. Which
  of the three was used is the connection's `source` (`config` | `discovered` | `default`).
- **Authentik:** configured `url` → discovered internal container addresses → discovered public
  hostnames.
- **Traefik:** configured `url` → discovered internal container addresses (each declared
  container port, plus `8080`) → discovered public hostnames.

Internal addresses always before public ones, deduplicated and capped. An address is a fact
about the operator's fleet: discovered or supplied, never defaulted (I2).

### 3.6 The one request-scoped setting

`probe.enabled` is the only setting a request may override, and only for the single build that
request starts (§13.7). The override MUST produce a **copy** of the configuration — neither the
configuration nor its probe block may be mutated — because the cache may have another build in
flight holding the old value. Everything else is fixed for the life of the process (I7).

---

## 4. Vocabulary

Every set below is **closed**. The member spellings are contract: they appear in the JSON
payload, they key the UI's colours and labels, and a filter in a shared URL is written from
them. Adding, renaming or reordering a member is a breaking change to both the payload and the
UI, and MUST be treated as one.

Where a set has a canonical order, it is the order given here.

### 4.1 Reachability

**`IngressKind`** — how a service can be reached, most to least exposed. A service carries a
**set** of these, never one (§8).

| Member | Evidence that produces it |
|---|---|
| `public` | a Cloudflare tunnel route with a hostname |
| `traefik` | a Traefik route with hosts or a rule |
| `lan` | `ports:` is non-empty — published on the host |
| `internal` | `expose:` is non-empty, **or** a real network is shared with another scanned service — **and** none of the three above holds |
| `none` | none of the above |

`public`, `traefik` and `lan` together are the **external** kinds: something outside the
container network can answer. That grouping is a single definition, used by the exposure
finding and by the stale-acceptance check alike, and it MUST be expressed as its own question
over its own three kinds rather than as "not `internal`".

**`NetworkScope`** — `external` (the network is declared `external:` by at least one stack, so
it can carry stacks and containers this scan never saw) | `stack-local` (created by one compose
project, so only that project's services can ever join). Not a severity: it says who *can* be
on the network.

**`NetworkRelation`** — what one service is to another across a named shared network:
`depends-on` | `required-by` | `peer`. `peer` is the **absence** of a relation — a co-member,
reachable and no more — so nothing is ever labelled with it and no rule returns it.

**`OriginKind`** — what a tunnel's declared origin resolved to (§9): `self-network` |
`self-host-port` | `fleet-service` | `unresolved`.

### 4.2 Authentication

**`AuthMethod`** — the gate in front of a service, in precedence order:
`authentik-forward-auth`, `authentik-oauth`, `authentik-ldap`, `forward-auth`, `other-oauth`,
`ldap`, `basic-auth`, `none`.

**`AuthConfidence`** — how the gate was established, and never a severity:

| Member | Means |
|---|---|
| `confirmed` | an API reported the gate **and** named the service |
| `observed` | a scanned configuration value states it, or an API tied it to the service by name alone |
| `inferred` | it rests on a middleware *name* — and a service note MUST say so |

Rank order is `confirmed` < `observed` < `inferred`. When two accounts of one service disagree,
the stronger is reported and the weaker is kept as evidence.

**`NoAuthReason`** — derived for display, not stored in the payload; it explains why no method
is named:

| Member | Renders as |
|---|---|
| `gap` | *No proxy auth* — styled as a finding. The only finding in this set |
| `not-reachable` | *None expected* |
| `declared` | *Declared, not detected* (§14) |
| `unnamed-gate` | *None named — gate confirmed* |
| `probed-gate` | a login page answered (§13); its own reason with its own statistic |

The `none` bucket of the per-method statistic is labelled *None detected*.

### 4.3 Integrations

**`AuthentikProviderKind`** — `proxy` | `oauth2` | `ldap` | `saml` | `radius` | `scim` |
`other`.

**`AuthentikMatchStrength`** — `address` | `hostname` | `name`. Absent MUST read as `name`,
never as the strongest.

**`UnmatchedReason`** — why an application or a router could not be tied to a service:
`ambiguous` (more than one candidate) | `no-candidate` | `internal`.

**`discoveredVia`** — `list` (the application list returned it) | `provider` (it was rebuilt
from a provider record because the list withheld it, §11).

**Endpoint `source`** — `config` (the operator named it) | `discovered` (the scan found it) |
`default` (a built-in fallback path).

**Traefik `credential`** — `none` (the API answered without one, which is itself evidence about
how that API is exposed) | `basic`.

### 4.4 The probe

**`ProbeVantage`** — `public` | `traefik` | `lan`, the same order as the external ingress kinds,
walked most-exposed first.

**`ProbeGate`** — the eight signals, strongest first: `challenge`, `redirect-origin`,
`redirect-login`, `meta-refresh-login`, `sso-form`, `password-form`, `credential-form`,
`state-challenge`. Firing conditions in §13.3 and §13.4.

### 4.5 Declarations

**`DeclaredAuthMechanism`** — what an operator may claim in a sidecar file:
`app-local-accounts`, `app-ldap`, `app-oidc`, `app-saml`, `app-token`, `mtls`,
`network-restricted`, `external-proxy`, `other`. `other` MUST carry a `detail`.

**`AuthFamily`** — `oidc` | `ldap` | `proxy`, the three families a declared and a detected
mechanism can be compared within (§14).

**`DeclaredAuthAgreement`** — `supplies` | `redundant` | `conflicts` | `supplements` (§14).

### 4.6 Connections

**`ConnectionPhase`** — one taxonomy for every outbound target, in order. The first four stop
before the network and are outcomes rather than faults:

| Phase | Means |
|---|---|
| `disabled` | switched off in configuration |
| `not-configured` | nothing to talk to — no token, no URL, nothing discovered |
| `not-found` | the thing to talk to does not exist, e.g. a missing socket path |
| `credential` | a credential was needed and was absent or blank |
| `resolve` | DNS said no |
| `connect` | refused, unreachable, or no route |
| `tls` | handshake failed |
| `timeout` | no answer inside the budget, **established by the clock** |
| `authenticate` | answered 401 |
| `authorize` | answered 403 |
| `path` | answered 404 or 405 — right host, wrong route |
| `status` | answered with any other non-2xx |
| `protocol` | answered, but not as this API — HTML where JSON was due |
| `partial` | read enough to be useful, not all of it. `ok` stays **true** |
| `connected` | full read |

`authenticate` and `authorize` MUST stay separate everywhere: a wrong token and a token without
permission need different fixes.

### 4.7 LabView's own login

**`LoginMethod`** — `passwd` | `oidc`. **Naming hazard, stated once:** `passwd` is a file of
bcrypt hashes and has nothing to do with HTTP Basic authentication. No identifier in an
implementation may call it `basic`.

**`LoginFailureReason`** — eight codes, each with fixed wording: `credentials`, `throttled`,
`method-unavailable`, `session-expired`, `oidc-state`, `oidc-provider`, `oidc-token`,
`oidc-identity`. A redirect carrying anything else MUST be rejected rather than displayed.

**Session rejection** (internal, logged not served) — `malformed` | `signature` | `expired` |
`revoked`.

### 4.8 Scan detail

**`EnvVar.source`** — `env_file` | `environment` | `shell-default`.
**`MountSpec.type`** — `bind` | `volume` | `tmpfs` | `npipe` | `unknown`.
**`DockerState.health`** — `healthy` | `unhealthy` | `starting` | `none`.
**`BuildStampSource`** — `image` | `checkout` | `unknown`.
**Graph node kind** — `service` | `network` | `volume` | `external`; node `role` may only ever
be `proxy`.
**Graph edge kind** — `network` | `depends_on` | `volume` | `ingress` | `auth`.
**Edge `flow`** — `to-network` | `to-service` | `both`, or absent.
**Edge `flowSource`** — `observed` | `declared` | `both`.

---

## 5. The pipeline

One scan is a **pure function of (configuration, filesystem, Docker state, injected clock)**
producing one `Overview`. It MUST take no logger: diagnostics are data on `meta.connections`,
which callers print (I7).

| Stage | Produces |
|---|---|
| 1. Discover | one entry per immediate subdirectory of the scan root holding a compose file, sorted by id |
| 2. Parse | stacks and services — ports, mounts, interpolated environment, labels, declarations |
| 3. Docker snapshot | live container state, keyed three ways (§10) |
| — | one connection report per outbound target → `meta.connections` (§15) |
| 4. Middleware registry | every Traefik middleware *defined* anywhere, by bare name |
| 5. Pass 1 — routes | per-service Cloudflare routes, Traefik routes, Docker state attachment |
| 5b. Ingress classification | `ingress` for every service, over the whole fleet at once; builds the network index |
| 6. Fleet index and origins | published host ports, DNS names, container IPs, declared hostnames; each route's resolved `origin` |
| 6b. Declared dependencies | resolved sidecar `depends_on` pairs with the network they share; drift for the rest |
| 7. Identity provider API | the Authentik snapshot, or a reason it is absent. Skipped entirely with no token |
| 8. Reverse proxy API | the Traefik snapshot, or a reason. Concurrent with stage 7 |
| 8b. Active probe | `probe` for eligible services. Off unless switched on; runs between the halves of stage 12 |
| 9. Provider discovery | hint strings identifying the SSO provider *in this fleet* |
| 10. Application matching | per-service Authentik matches, plus unmatched applications with reasons |
| 11. Live router matching | per-service live routers, plus unmatched routers with reasons |
| 12. Pass 2 — auth | **2a** every service's posture, and the set of services with detected authentication (the probe's eligibility). **2b** after the probe: exposure verdicts and notes; then secrets are masked |
| 13. Graph | services, networks, shared volumes, resolved ingress paths, auth hubs |
| 14. Statistics | the counters of Appendix A |

**Two passes, because six conclusions need the whole fleet.** A middleware reference such as
`authentik@docker` is usually defined in another stack (stage 4). Which hostnames represent the
SSO provider is learned from the stack that *runs* it (stage 9, after 5). A tunnel origin
routinely names a proxy in another stack (stage 6). An application is matched against the fleet
as a whole (stage 10, reusing stage 6's index). A live router names its backend by container
address and its hosts by rule (stage 11). And `internal` ingress is a claim about *other*
containers, so every service's networks MUST be counted before any service is classified
(stage 5b). Stage 6b needs both indexes — stage 6's to resolve a name in any stack, stage 5b's
to know which network the pair shares — and runs before the graph, because that is where a
resolved pair lands.

A rule that needs fleet-wide knowledge belongs in a new pass or in stage 4 or 9, never in a
per-service function reaching for shared mutable state.

**Scheduling.** A *configured* endpoint depends on nothing in the scan, so its request MUST
start before the Docker snapshot and be awaited after, overlapping the two. A *discovered*
endpoint cannot be found until pass 1 has parsed the routes, so it runs after — and both
discovered exchanges go out concurrently. Origin resolution runs **ahead** of the discovered
reads, because a resolved origin structurally identifies the service acting as reverse proxy,
which is one of Traefik discovery's three signals. An endpoint that answered the Authentik API
becomes an input to stage 9: having answered as an Authentik API is stronger evidence of
identity than any name match, and it is what attributes an OIDC issuer correctly when the
provider runs outside the scanned root.

**The probe MUST NOT join the concurrent reads.** Whether this scan found any authentication is
unknown until both API reads land and posture has been derived, so pass 2 splits: 2a derives
posture and collects the services with detected authentication, the probe runs, 2b attaches
results and settles exposure. An enabled probe therefore adds its own wall-clock time; what it
buys is not asking an SSO endpoint a question whose answer could not have changed anything.

---

## 6. Scanning the compose tree

A **stack** is one immediate subdirectory of the scan root containing a compose file — the
configured filenames tried in order. Its directory name is its id and its default compose
project name. A **service** is one entry under `services:`, keyed as `svc:<stack>/<service>`,
and matched to a live container by the `com.docker.compose.project` and
`com.docker.compose.service` labels first, then by container name.

**Interpolation** MUST be Compose-compatible: `${VAR}`, `${VAR:-default}`, `${VAR-default}`,
`${VAR:?err}`, `${VAR?err}`, and `$$` as an escape. Recursion is bounded at 32 levels and names
match `^[A-Za-z_][A-Za-z0-9_]*`. Every resolved variable records its source (§4.8). An
unresolved `${VAR}` is a service note, never a failure (I4).

**Containment (I8).** Every file read out of a stack directory MUST pass one check that returns
nothing for anything escaping the scan root **lexically** (`../../etc/shadow`) **or through a
symlink**. Both the literal scan root and its fully resolved form are accepted, because an apps
root is often reached through a symlink or a bind mount. This applies to `env_file` targets and
the sidecar today, and by rule to anything added later. A refusal MUST surface as a service
note or a sidecar warning, never as silence.

A YAML parse error puts a warning on the stack and **still lists the stack**. An unreadable
stack directory produces a scan-level warning.

### 6.1 The sidecar declaration file

Candidate names come from `sidecarFilenames`; **the first that exists wins**, so two sidecars in
one directory can never half-apply. The file is untrusted input served verbatim on the API, so:
maximum size 64 KiB (over-size ⇒ ignored, with a warning naming the size and the limit),
2000 characters per string, 32 entries each for `links` / `dependencies` / `depends_on`, and 8
`auth` entries per service. It MUST **not** be interpolated with the stack's environment:
declarations are prose, so `${VAR}` stays exactly as written.

Accepted keys — anything else is named in a warning:

| Level | Keys |
|---|---|
| top | `description`, `owner`, `criticality`, `notes`, `data`, `links`, `dependencies`, `services` |
| `services.<name>` | those minus `services`, plus `depends_on`, `auth`, `unauthenticated`, `expected` |

A declaration for a service the compose file does not define MUST be reported rather than
silently doing nothing. The recorded file name MUST be the **basename**, never a full path (I2).

Every rejection is a warning and every warning is formulaic — `${where}: <what was wrong>;
ignored`, where `where` is the file, the file plus `services.<name>`, or that plus the field and
index (`… .links[2].url`). The shapes, which the test corpus asserts:

- **a wrong type** — `expected a mapping`, `expected text`, `expected a list`,
  `expected {label, url}`, `expected a name or {name, detail}`,
  `expected "stack/service" or {service, detail}`,
  `expected a mechanism name or {mechanism, detail}`, `expected {intentional, reason}`,
  `expected {ingress}`
- **a missing required half** — `needs a "url"`, `needs a "name"`, `needs a "service"`,
  `needs a "mechanism"`, `needs "intentional: true" to apply`
- **a value outside a closed set** — `"${x}" is not a known mechanism (<the list>)`,
  `"${kind}" is not one of <the ingress kinds>`,
  `"${ref}" is not a service reference — write "stack/service", or the service name on its own`
- **a cap** — `truncated to 2000 characters` (with `…` appended to the value),
  `.links: more than 32 entries; the rest ignored`, `.auth: more than 8 entries; …`
- **a typo** — `unknown key(s) "a", "b"; ignored`
- **the two that explain rather than name a type** — `"depends_on" is a service-level key — at
  stack level it cannot say which service depends on the target`, and `"intentional: true" needs
  a "reason" — an acceptance with no reason cannot be told from a mistake`

Three details an implementation gets wrong by default: a link URL MUST be passed through
credential redaction **before** the label falls back to the URL, or a password lands in visible
link text; a value that may be either a list or a scalar MUST be tried as a **list first**, or a
list reaching the scalar reader is reported as the wrong type; and an all-empty declaration
block MUST produce **no** declaration rather than an empty one.

---

## 7. Labels, middlewares and provider hints

**Cloudflare tunnel labels** (`dockflare` prefix) yield routes: hostname, origin service, path,
access policy (group / policy / emails), TLS-verification flag, and the raw label map retained.
Both the flat and the indexed multi-route label forms MUST be read, and an `enable` flag
honoured.

**Traefik labels** yield routes: router name, rule, hosts parsed out of the rule, path prefixes,
entrypoints, TLS flag, certificate resolver, middleware references, service port, service name.

**The middleware registry** collects every `traefik.http.middlewares.<name>.<type>` label found
in *any* stack, keyed by **bare name** — a reference's `@docker` or `@file` provider suffix is
stripped. On a name collision an auth type MUST win over a non-auth type, so a `headers`
middleware cannot shadow a `forwardauth` one.

**Posture from labels** is derived from routes, environment and that registry:

- Middleware classification MUST read the **registry definition first**, and fall back to the
  middleware *name* only when no definition was found anywhere — and then mark the result
  `inferred` and write a service note saying so. A middleware called `authentik` that points
  elsewhere is not Authentik (I3).
- Hint matching MUST be at **token boundaries, never bare substrings**: `auth` must not match
  `oauth.bigcorp.example.com`.
- A mechanism whose provider could not be named carries the evidence line *provider not
  identified from the scanned config*.

**Hints** are strings identifying the SSO provider, either configured (`labels.authentik.hostHints`)
or discovered, matched at token boundaries against forward-auth addresses, issuer URLs and LDAP
hosts.

**Provider discovery (stage 9)** walks the parsed fleet for a service that is identifiably
Authentik — its image mentions `authentik`, or one of its labels defines a forward-auth address
containing `goauthentik.io` — and adopts that service's container name and every hostname it
answers on as hints. Two properties are required:

- **It cannot invent a provider.** No such service ⇒ nothing learned, every issuer stays
  generic. This is what makes a fleet with no Authentik report honestly.
- **A hint MUST be specific.** Short or bare words are rejected, because upstream Authentik names
  its own services `server` and `worker`, and learning `server` verbatim would make every
  `OIDC_ISSUER=https://server.example.com` look like Authentik.

---

## 8. Ingress and networks

Kinds and their evidence are in §4.1. This section is about the operations on them.

A service carries an ingress **set**. There MUST be exactly one constructor for that set:
deduplicated, in canonical order, never empty, and **withholding `internal`** from any set that
already carries `public`, `traefik` or `lan` — so the set answers *is a neighbour the only way
in*. A stack carries the union of its services' sets, and that roll-up is the one place the
withholding MUST NOT apply. Nothing may combine two kinds into a third. Exactly one rule picks
a single winner, and it exists solely because a graph node has one fill colour.

`ports:` and `expose:` are two different reachability claims and both MUST be read: `ports:`
publishes on the host, so it is `lan`; `expose:` only records that the container listens, so it
is `internal`. Any entry counts, including the short form with no host side (`ports: ["9100"]`)
— for both keys the **presence** of an entry is the signal, never a parsed port number.

A sidecar disagreement about ingress MUST be reported in **both** directions
(*missing: lan; unexpected: traefik*).

**Real networks** are the networks a service is demonstrably on. Deriving them MUST materialize
the implicit `default` network, resolve `${project}_${key}` naming, and honour `external:` under
its **verbatim** name — so two services in one file are mutually reachable without either
declaring a network, and two *stacks* on one external network are too. `depends_on` is
deliberately **not** evidence of reachability: a dependency across two disjoint networks is not
reachability.

**One fleet-wide membership index** MUST be built once over real networks and shared. By name it
gives each real network its members (`stack/service`, in scan order), the distinct stacks among
them, and whether any stack declares it `external:`; by service it gives the reverse. The
`internal` ingress rule, the graph's network nodes and the network statistics MUST all read that
one index, so they are provably one relation.

**Counted on the node, not inferred from the drawing:** how many *scanned* services are attached
and from how many distinct stacks. Neither may count what the scan cannot see (I1) — the spokes
beside a node are capped, the counts are not.

**Edges.**

- `flow` on a membership edge is where the dependency arrowhead sits: `to-network` (this service
  is the dependent), `to-service` (something else on that network depends on it), `both`, or
  **absent** — the common case, meaning the service is on the network and nothing crosses it.
- `flowSource` distinguishes `observed` from `declared`; a leg every one of whose dependencies
  was declared renders dashed, and `both` stays solid.
- `declaredBy` on a dependency edge carries the sidecar file and optional detail. Absent means it
  was read from a compose file, which is what renderers test for dashed versus solid.
- `via` on a dependency edge is the real networks the pair shares, in the dependent's compose
  order. **Non-empty is normal and means the direct edge is not drawn**, because `flow` on the
  two membership edges already shows it. **Empty means compose orders the two containers' startup
  yet neither can address the other** — then the direct edge is the only honest drawing, and the
  finding MUST also be stated in words on the dependent's notes.

**A declared dependency is two halves of one fact, kept apart.** What the sidecar wrote (the
reference exactly as typed, plus an optional detail) is stored **unresolved**, because the parser
cannot see other stacks and because that is the object a rescan compares. What resolution made of
it — source, target, file, detail and shared networks — is a separate record.

**A service's view of one network splits by whether anything crosses it**: a list of dependencies
on one side, a *number* of merely-reachable co-members on the other. That number MUST hold no
names, not even truncated ones; the names are answered under the network's own heading.

**Caps are presentation defaults, not analysis** (§16): the payload carries every spoke. A view MAY
cap what it draws — the defaults are 12 spokes per network node in a diagram and 12 member chips
before a row in the networks list expands — provided spokes that carry **dependencies are kept
first**, every cap reports what was left out (a capped node labelled *+k not drawn*), and the full
set stays answerable in the drawer (§22.4).

**Network counters** — total networks, connecting networks (2+ services), cross-stack networks
(2+ stacks), and solo-local networks (stack-local, single service). The last is *exactly* what
the fleet graph omits, so **drawn network nodes + solo-local networks = total networks** is a
checkable identity. The declared-dependency counter counts references that **resolved** to an
edge; the ones that failed are counted as drift.

---

## 9. Tunnel origin resolution

A tunnel rarely terminates at the container whose labels declare it: the declared origin normally
names a reverse proxy that forwards over a shared network. Resolution MUST be from evidence, and
the conclusion recorded on every route whose origin service is non-empty.

- **An IP literal addresses the host**, so its port is a *published host port*, and a host port
  can only be held by one service — a match identifies rather than suggests.
- **A bare name addresses a container**, so the port says nothing about ownership and the *name*
  is the evidence: compose publishes a service's name and its `container_name` as DNS aliases on
  its networks.
- **Network membership breaks a port tie.** A fleet may declare one host port on several
  services; a candidate sharing no network with the service it supposedly fronts cannot forward
  to it.
- **Repeated declarations by one service are not rivals.** `443:443/tcp` beside `443:443/udp`, or
  a name equal to the service's own `container_name`, reach the index twice and MUST be collapsed
  by service key.
- **A genuine tie stays unresolved** — never a winner picked by iteration order. So do an FQDN,
  and a port nobody publishes.

| Kind | Meaning | Graph |
|---|---|---|
| `self-network` | the origin host is this service's own name or `container_name` | direct `tunnel → service` |
| `self-host-port` | the origin port is a host port *this* service publishes | direct `tunnel → service` |
| `fleet-service` | it resolves to another scanned service sharing a network with this one, named as the hop | chained `tunnel → hop → service` |
| `unresolved` | no match, an FQDN, or a tie between reachable candidates | direct `tunnel → service`, plus a service note stating which reason applied |

`unresolved` keeps the direct edge deliberately: an invented hop would be a claim about the path,
and dropping the edge would hide a route that exists. Every resolved origin carries the address,
host, port, kind, optional hop and an evidence string.

**No image, vendor or naming convention may be consulted anywhere in this resolution** — the
proxy is identified structurally, by what it publishes and what it can reach.

The same stage MUST produce the **fleet index** later stages share: published host ports,
container DNS names, container IPs, declared hostnames, and lookups from a name or a URL to
candidate services.

**Proxy role.** A node's `role: "proxy"` is set on a service another service's origin resolved
to, or on the service whose Traefik API answered. It stays an ordinary service node — same kind,
same drawer, same click target — and the role only lets the UI colour it as infrastructure. No
service is ever *declared* a proxy.

---

## 10. Docker Engine

The snapshot MUST never throw out of its own boundary: a failure becomes a connection report and
an absent snapshot (I4).

**Endpoint.** `unix://<socketPath>` when `docker.host` is empty, else `tcp://<host>:<port>`. The
report's `source` is `default` when the socket path is still the built-in default, else `config`.

**Exactly three Engine requests and no others** (I5) — this is the whole permitted surface:

| Request | Purpose |
|---|---|
| `GET /_ping` | liveness |
| `GET /containers/json?all=1` | the container list, with labels and summary status |
| `GET /containers/{id}/json` | one inspect per listed container |

No `exec`, no logs, no attach, no events, no writes. A read-only token or a `:ro` socket mount
MUST be sufficient.

**A unix socket MUST be diagnosed before the HTTP client sees it.** One `stat`/`access` check —
its only filesystem access — distinguishing four states: absent; present but **not a socket** (a
bind mount of a missing host path creates an empty *directory*, which is the usual cause);
present but not accessible to this uid (which is `authorize`, not `connect`); and present and
answering.

**The container list and the inspects MUST be read under `docker.bodyCapBytes`, not under the
shared 64 KiB cap** (I8, §3.1). These are the only reads in the program whose size is a fact about
*this fleet* rather than about a document somebody else authored: a list entry runs roughly a
kilobyte per container, so 64 KiB is about forty containers, and an inspect grows with the labels
and mounts a service was deployed with. Past the cap the body arrives cut mid-array, fails to
unmarshal, and is classified `protocol` / `not-json` — LabView's own ceiling reported as the far end
not speaking Docker, with a hint sending the operator to find out what is answering on the Docker
path. Where a cap did the cutting, the detail MUST name **the cap that actually applied** and say
the answer was incomplete rather than wrong (§15). The `_ping` keeps the shared default: it answers
two bytes, and anything larger on that path is the finding.

**Inspects** run under a bounded fan-out (`docker.maxConcurrency`). A refused inspect is skipped
and counted, and turns the read `partial` with `read: "<n> containers, <k> could not be
inspected"` — those containers' ports, networks and health are missing, so they MUST be left out
of every conclusion rather than guessed.

**The index MUST be written in list order**, so a duplicate key's winner does not depend on which
inspect finished first. Three keys per container: the compose key (project and service from the
`com.docker.compose.project` / `.service` labels, joined by a separator that cannot occur in
either), the container name, and the 12-character short id.

**Fields taken from one inspect**, with their Engine API sources:

| Field | Source |
|---|---|
| `id` | the id, first 12 characters |
| `name` | `Name` with the leading `/` stripped |
| `image` | `Config.Image` |
| `imageDigest` | `Image` when it starts `sha256:`, sliced to 19 characters |
| `state` | `State.Status` |
| `status` | the summary `Status` string from the list response |
| `health` | `State.Health.Status`, else `none` |
| `running`, `restartCount` | `State.Running`, `RestartCount` |
| `createdAt`, `startedAt` | `Created`, `State.StartedAt` |
| `networks` | the keys of `NetworkSettings.Networks` |
| `ipAddresses` | per network, only where non-empty — this is what container-IP lookup is built from |
| `publishedPorts` | from `NetworkSettings.Ports`: one entry per binding, with `raw` as `` `${HostIp?HostIp+":":""}${HostPort}->${portKey}` ``, or one entry with no `published` where a port is exposed and unbound |

**A timeout MUST be established by the clock, not by trusting the transport.** Many HTTP clients
implement a request timeout by tearing the socket down, so a silent endpoint surfaces as a
connection reset rather than as a timeout. Classify as `timeout` when the elapsed time reached the
configured budget, there is no HTTP status, and the error is either absent or a teardown
condition. A genuinely slow `403` keeps its status.

---

## 11. Identity provider (Authentik)

Two responsibilities that MUST stay separated by the I/O boundary: the **read** does all network
work, holds no fleet knowledge and never throws — a failure becomes a reason string; the **match**
does no network work and ties applications onto services using the fleet index.

**Endpoints read**, all under `/api/v3`: `core/applications/`, `providers/proxy/`,
`providers/oauth2/`, `outposts/instances/`. Paged at 100 per page, up to `authentik.maxPages`.

**"This is Authentik"** has exactly one definition, shared with hint discovery (§7): the image
matches `goauthentik|authentik` case-insensitively, **or** a label whose key matches
`forwardauth\.address$` has a value containing `goauthentik.io`. Both are things Authentik
publishes about itself, never an assumption about how the operator named anything (I2).

**Endpoint selection.** A configured `authentik.url` is used verbatim. Otherwise candidates come
from services whose image identifies Authentik, ordered internal addresses before public
hostnames, and capped. Each candidate is probed on `/api/v3/root/config/` (which upstream allows
anonymously), and **only a candidate that answers with a JSON object may receive the token** — a
discovered endpoint is a guess, and a guess must never be handed a credential. On a candidate that
*did* answer, a 401 or 403 is conclusive: later candidates MUST NOT be tried and nothing further
sent.

**Enumerating applications is not a plain list read.** The upstream list view drops hidden
applications, paginates, and *then* runs its policy engine over the page as the token's own user —
skipped only when `superuser_full_list=true` is sent **and** the token belongs to a superuser. So
the default answer to a least-privilege token is "what may this user launch", and a service
protected by an application the token cannot launch would read as having no gate (I1). Two
properties make that recoverable:

- Pagination runs **before** the filter, so the reported total count is the **unfiltered** total.
  It MUST be kept for every read, and MUST stay optional — some envelopes carry no pagination
  block at all, and a non-numeric or negative count is treated as no count.
- Both provider lists name their application, and neither applies a policy filter.

Application assembly is therefore **two passes**: pass one is the listed applications, tagged
`discoveredVia: "list"`; pass two walks both provider lists, skips any slug pass one produced (the
list response wins — it alone carries the launch URL and the group) and rebuilds the rest as
`discoveredVia: "provider"`, **in slug order** (I7). A rebuilt record is thinner — no launch URL,
no group, only the providers this token may read — so it can be tied by address or name but never
by a launch URL. That MUST be stated as the first line of its match trace, and the UI MUST tag the
row *rebuilt*.

`superuser_full_list=true` is sent unconditionally on that one request. It is ignored for a
non-superuser, so it can only ever widen the answer. There is no configuration knob for it.

| Count | Meaning |
|---|---|
| `applications` | listed **plus** recovered |
| `applicationsConfigured` | what Authentik says exists — the unfiltered total (optional) |
| `applicationsWithheld` | configured − listed |
| `applicationsRecovered` | of those, how many a readable provider let LabView rebuild |

`withheld − recovered` MUST be derived where needed and never stored. **The connection is
`partial` only when that difference is non-zero**, and the hint names both fixes: a superuser
token for the exact list, or check this token's permissions.

**Matching** — four rules in descending strength, each requiring **exactly one** candidate. An
ambiguous match MUST be discarded and the application reported unmatched:

1. A proxy provider's internal host, through the address lookup — the provider naming its own
   target. → strength `address`
2. A **bare-name** host inside a URL the provider hands out (launch URL, external host, OAuth2
   redirect URI), through the fleet index. → `address`
3. A **hostname** named by one of those URLs and declared by the service in a Cloudflare or
   Traefik label. → `hostname`
4. A **name** — application slug, application name, or any of its providers' names — when it
   identifies exactly one service's stack, compose or container name. → `name`

Rule 2 resolves **only** a name host: an IP literal in a redirect URI addresses the host, where
the standard ports belong to the proxy, so reading it through the published-port table would
attach the application to whatever answers on 443.

Rule 4 compares three forms, narrowing only when the wider one found nobody: the name as written,
the name with separators removed, and the name with mechanism words removed. Three constraints:

- **Separate raw and tight indexes.** Merged, a stack `foo-bar` and a service `foobar` would
  collide into a contested key and both be discarded.
- **The first form with any entry decides**, and a contested entry decides *against* a match.
- **A derived key shorter than 3 characters MUST NOT match**, so a one- or two-character residue
  cannot pin an application to whichever service happens to be short.

The mechanism-word list holds protocol and English words only, nothing fleet-specific, and
`authentik` is deliberately **absent** from it. Stripping applies to the **Authentik side only**.

Three details the corpus pins: a launch URL may contain `%(username)s`-style placeholders and a
per-user template MUST NOT be matched on; an external host is matched **except** in
`forward_domain` mode, where it is the shared authentication domain; and one service naming one
hostname in both Cloudflare *and* Traefik labels is one candidate — the hostname index
deduplicates by service key.

**Why it was not matched is part of the answer.** Every unmatched application MUST carry a reason
(§4.3), a one-line detail, and a trace with one line per rule tried, in the order tried. A rule
that found more than one service is *contested*; a rule that found usable evidence and
deliberately declined to resolve it (an IP literal, a `forward_domain` external host) is *blocked*.
The detail is the first of contested, then blocked, then a generic fallback; the reason is
`ambiguous` **exactly when** something was contested. A rule that could not run MUST say so
(*No proxy provider, so there is no forwarded address to resolve*) rather than being omitted. The
trace may carry only what the payload already holds — slugs, provider names, service keys,
hostnames — never an environment value (I2, I6).

**What a provider means:**

| Provider kind | Enforced by | A gate exists when |
|---|---|---|
| `proxy`, `ldap`, `radius` | an **outpost** in the request path | at least one outpost lists it |
| `oauth2`, `saml` | the Authentik server itself | always |
| `scim` | nothing — it is outbound provisioning | never |

A proxy provider assigned to no outpost MUST be reported as protecting nothing, with that as the
stated reason. LDAP and SCIM are **backchannel** providers, so the backchannel provider list MUST
be read as well as the primary one — reading only the primary misses every LDAP gate. A provider
Authentik records is taken as being in use by the service it matched; for OAuth2 that is the whole
of the available evidence. Whether *any* enforced gate was confirmed is a separate question, and
it is what keeps a protected service out of the exposure finding when its provider kind maps to no
`AuthMethod`.

**Confidence follows the match, not the provider:** `address` → `confirmed`, `hostname` →
`confirmed`, `name` → `observed` with *— tied to this service by name alone* in the detail. This
changes **no** posture roll-up: precedence sorts by mechanism before confidence, and neither the
gate test nor the exposure verdict reads confidence at all.

A service's Authentik match carries three **parallel** arrays — applications, evidence, strength —
where index *i* describes one match. The label-derived account and the API's account are merged by
confidence rank, the loser kept as evidence. The summary reports the endpoint, whether it was
configured or discovered, the four counts, how many services matched, the unmatched applications
with reason and trace, and any error.

---

## 12. Reverse proxy (Traefik)

The same split. The read fetches `/api/version`, `/api/rawdata` and `/api/entrypoints` and never
throws; the match ties live routers onto services with the fleet index. It resolves three things a
file scan cannot see: a router the labels declare that Traefik is **not** serving, a middleware
named in a label that is **not** in the chain the proxy built, and a middleware defined in a
Traefik **file provider** — which has no definition in any scanned stack and would otherwise only
ever be `inferred`.

**Endpoint selection.** A configured `traefik.url` is used verbatim. Otherwise a scanned service
becomes a candidate on one of three signals, each recorded as that candidate's `why`:

| Signal | Why it is evidence |
|---|---|
| a router of its own whose service is `api@internal` | the operator's own label saying this container serves the proxy API — and it yields the exact public hostname |
| another service's tunnel origin resolved to it (§9) | an observed reverse proxy, established without consulting any image or name |
| it runs the Traefik image | last resort, same precedent as the Authentik test |

Per candidate the URLs are `http://<name|container_name>:<port>` for each declared container port
plus `8080` (the port Traefik's dedicated API entrypoint conventionally serves), followed by its
Cloudflare and Traefik hostnames. Internal before public, deduplicated, capped — exactly as for
Authentik.

**The credential rule.** Every candidate is probed on `/api/version`, which needs no
authentication; a candidate that answers is used **with no credential at all, and none is sent**.
A credential may be sent only to a candidate that is either configured by hand or a hostname the
scan proved belongs to the service whose own labels declare `api@internal` — that is ownership
evidence. A hostname that merely looks like a proxy MUST never receive one. A 401, 403 or a
redirect on such a host triggers the authenticated retry, and cookies set during that exchange
MUST be replayed on its remaining requests, because an Authentik outpost expects its session
cookie echoed. **An Authentik API token is not a valid credential here.** Which was needed is
recorded as `none` or `basic`; `none` is evidence about how the proxy's API is exposed on that
network and MUST be reported as a note on the proxy service.

**Matching** — exactly one candidate, or no match:

1. **The backend address** — the load-balancer server URLs, the proxy naming its own target. An
   IP-form URL resolves **only** through container-IP lookup; a name-form URL through the name
   branch of the address lookup. (The generic address lookup reads an IP literal's port as a
   *published host port*, which is right for a tunnel origin and wrong for a container IP. With no
   Docker state the rule is skipped rather than guessed.)
2. **The router name**, `@docker` routers only — Traefik derives those names from the labels of the
   container it found them on, so an exact match against a label-derived router name is that label
   round-tripping. A `@file` router's name was typed by hand in a file this scan cannot read, so
   this rule MUST NOT apply to it.
3. **The host rule**, through the same hostname index the Authentik matcher uses.

Unmatched routers are reported as the mirror of unmatched applications: the whole live router plus
reason, detail and trace. One deliberate asymmetry — this matcher tracks *contested* but **not**
*blocked*, because rule 2's skip applies to every non-docker router and promoting it would displace
the answer a reader needs. Because such a router demonstrably **exists**, it MUST never produce a
"declared but not live" note on anybody.

**What the live read may conclude** is decided once per scan: `reachable` (the API answered), and
`chainComplete` = reachable **and** the entrypoints were read. Only a complete read lets a live
chain supersede a label list, because a gate attached at an *entrypoint* appears in no router's own
middleware list. A partial read notes the gap and changes no posture.

Where a router matched and the chain is complete, **the live chain is the chain**:

- a resolved forward-auth middleware whose address resolves to a provider identity yields
  `authentik-forward-auth` at `confirmed`;
- basic or digest auth yields `basic-auth`;
- a `chain` middleware is resolved recursively to a depth of **5**, each entry recording which
  chain it came from;
- a middleware attached to the router's entrypoint is merged in, marked as such;
- **a label declaring an auth middleware the live chain does not contain is downgraded** —
  detection suppressed, the service free to land in the exposure finding, and a note naming the
  discrepancy.

A router the proxy reports as disabled, or carrying errors, counts as neither protection nor
working ingress, and its errors MUST be quoted verbatim. A middleware's type MUST be taken from the
definition Traefik *holds*, so a file-provider middleware is knowable and an unmodelled type is
still reported by name. A live server carries one backend URL plus the status Traefik last
observed; **absent status means nothing is known and MUST NOT read as healthy.** Routers are
reported as `name@provider`, and the provider half decides whether rule 2 may apply.

The declared-but-absent check MUST run against **every router in the snapshot**, not only the
matched ones.

**Three-way cross-check.** When the live forward-auth address resolves to the service the
Authentik API answered on, and Authentik reports an outpost serving a provider for an application
matched to *this* service, the note records labels, proxy and identity provider agreeing.
Disagreement is the finding: a forward-auth address pointing at an instance with no matching
application, or a matched provider whose mode means the request never reaches the outpost. A
provider in `proxy` mode is exempt — there the outpost *is* the backend.

The summary reports the endpoint, its source, whether a credential was used, whether the API
answered unauthenticated, the version, the counts, how many services matched, the unmatched
routers and any error. The proxy service gets `role: "proxy"` and every matched router is drawn
from it.

---

## 13. The active probe

Every other source says what a service is *configured* to do; this says what it **answers**, for
one blind spot: an application with its own login page carries no label, no environment key and no
entry in anybody's API. One GET to the service's own address, and a login page answering is
evidence in the sense I1 means it.

It is the only integration that **defaults to off**, the only one that sends a request to something
the fleet's own documents named, and the only one a reader can turn on from the UI for a single
rescan.

**Every rule here MUST be pure and independently testable, with none of it in the code that
fetches.** Five jobs: what may be asked, what an answer means, whether a second question is worth
asking, what the page showed a caller who sent nothing, and which fact a decision rested on.

### 13.1 Eligibility

Two separate questions: whether there is an HTTP address at all, and whether asking could tell
anyone anything.

**Detected authentication** is true when authentication was *detected* — a method other than `none`
from labels or the live Traefik chain, a Cloudflare Access policy on the tunnel route, or an
Authentik provider the API reports as enforced. It MUST be the **same** expression that the
exposure verdict uses for configured edge authentication, evaluated once and shared, so
eligibility and the notes explaining the outcome cannot come apart. An `inferred` posture counts as
detected. Neither a probe result nor a declaration counts.

The exposure verdict computes `hasEdgeAuth = configuredEdgeAuth || probeGate`, so withholding a
request can only ever leave a service *in* the exposed count, never take one out. The two terms
MUST stay written as two even though they are provably disjoint, because that is what keeps the
probe-gated figure a subtractable statistic.

**Not asked and no address are different facts.** The address test runs first, so a service with
no HTTP address is not counted as skipped — it was never a candidate. The skipped count is
withheld candidates only, and a run whose candidates were *all* skipped is a success, not
`not-found`. No new no-auth reason is needed: a skipped service has detected authentication, so it
is never asked why none was found.

### 13.2 Addresses

From evidence already on the service, never from a port number and never from an image name:

| Vantage | Eligible on | Asked at |
|---|---|---|
| `public` | a tunnel route with a resolved hostname whose origin scheme is `http`, `https` or absent | `https://<hostname>/` |
| `traefik` | a Traefik router's own host — only HTTP routers are parsed, so a non-empty route list *is* the evidence this is HTTP | `https://<host>/` when the router declares TLS, else `http://<host>/` |
| `lan` | a service one of the two above already found to be HTTP, **and** `probe.lanHost` set, **and** a published port whose bind address answers there | `http://<lanHost>:<published port>/` |

The walk goes most- to least-exposed and **stops at the first address that answers**, meaning an
HTTP response arrived whatever its status — a 401 is the best outcome available here. Only a
transport failure falls through to the next address. **A service with `ports:` and no route of
either kind yields no address at all**, which is what keeps the probe off a database without
consulting a port number or an image name. An empty `lanHost` means no LAN vantage, never a
guessed one.

### 13.3 Seven signals from one response, strongest first

| Signal | Fires on |
|---|---|
| `challenge` | 401 or 407 **with** a `WWW-Authenticate` header |
| `redirect-origin` | a 3xx whose `Location` resolves to a different origin |
| `redirect-login` | a 3xx that stayed on the origin and landed on a login path (prefix match) |
| `meta-refresh-login` | a 200 whose HTML carries `<meta http-equiv="refresh">` whose `url=` resolves cross-origin or onto one of those paths, through the same redirect rule |
| `sso-form` | a 200 carrying a hidden `SAMLRequest` or `SAMLResponse` input |
| `password-form` | a 200 whose HTML carries `<input type="password">` or `autocomplete="current-password"`, anywhere on the page |
| `credential-form` | a 200 where **one** form has a username field *and* a submit control *and* a login-intent marker, with no password field |

The last four read a 200's body, which is the only condition under which a body was kept — so the
presence of a body is itself the evidence that HTML answered.

**The login-path list** is the one rule that decides on a *name*. Ten prefixes, in this order:
`/login`, `/signin`, `/sign-in`, `/users/sign_in`, `/sso`, `/oauth2`, `/auth/`,
`/outpost.goauthentik.io`, `/if/flow/`, `/flows/-/`. Only `redirect-login` and
`meta-refresh-login` consult it, and both only ever *add* a gate to a target that stayed on the
origin — so a missing hand-rolled login path costs a gate and never invents one. Three spellings
are load-bearing: `/auth/` keeps its trailing slash (bare `/auth` matches `/authors`); `/flows/-/`
keeps the `-`, which is Authentik's own placeholder for no application context, where a bare
`/flows` would read a workflow tool as a login page; and `/users/sign_in` is Devise's own path.

**Nothing else read off that one response is a gate**: not a bare 401 with no challenge header, not
a 403, not a same-origin redirect to `/dashboard`, not a meta refresh with no `url=`, not a homepage
with the words "Sign in" and no form. All read as *answered, no gate observed*, which leaves the
exposure finding standing. The asymmetry is the point — this rule can only ever take a service
**out** of the exposed count.

Signals that MUST NOT be added, each of which would buy false comfort: `<title>` or body-text
matching; product-name markers (a *link* to one matches); a `Set-Cookie` on a 200; a cross-origin
form `action` with no SAML field; a 401 or 403 that serves a login form — the body is read as
evidence on a 200 only.

**Form composition is read per `<form>` element, never page-wide**; when several qualify the
strongest wins and the first of equals, so one page yields one answer and yields it twice (I7):

| Field | Read from |
|---|---|
| `password` | `type="password"`, or `autocomplete="current-password"` — **not** `new-password` |
| `username` | `type="email"`, or a `text`/`tel` input whose `name`, `id` or `autocomplete` contains one of: username, user, uname, userid, uid, login, email, e-mail, identifier, account. `q`, `search` and `query` are absent on purpose |
| `submit` | `<input type="submit">`, `type="image"`, or a `<button>` whose `type` is `submit` or absent |
| `otp` | `autocomplete="one-time-code"` |
| `action` | the form's `action`, **only** when it stays on this origin and prefix-matches a login path |

The loose username match is affordable only because it is never sufficient alone. A **cross-origin
action MUST be rejected** rather than read as a hand-off: a hosted newsletter signup has the
identical shape and the opposite meaning. The shape is attached to the probe record whenever a form
was found — **including when nothing was concluded from it**.

`credential-form` is the one clause holding several facts together, deliberately: passwordless
sign-in has no single marker, and without it every magic-link and passkey login reads as reachable
without authentication. All three parts MUST be present on **one** form.

Three patterns are load-bearing and are given verbatim. They use only constructs available in
RE2-style engines, so they port as written:

```text
meta tag        <meta\b[^>]*>                                     (global, case-insensitive)
SAML field      <input\b[^>]*\bname\s*=\s*["']?saml(?:request|response)\b
password input  <input\b[^>]*(?:\btype\s*=\s*["']?password\b|\bautocomplete\s*=\s*["']?current-password\b)
```

### 13.4 The eighth signal: `state-challenge`

One shape defeats every clause above in principle: **HTTP 200, `text/html`, and no `<form>`
anywhere in the body** — a login screen assembled by a JavaScript bundle, indistinguishable from a
public single-page application at any body cap, and the commonest miss in a real fleet. For that
one shape only, the scan asks a second question: *does this page's own client get served without a
credential?*

The condition is exactly that — no gate read, status 200, HTML, no form. The addresses are the
constant list `/api/`, `/api/me`, `/api/v1/me`, `/api/v1/user`, walked in that order against **the
origin that answered**, until one **refuses** with 401 or 407. Nothing is parsed out of the page.
The answers reduce to: how many were asked, which refused, with what status, and whether that
refusal named a scheme.

**The gate rests on that last fact alone.** A refusal carrying `WWW-Authenticate` is a `challenge`
one address over. A **bare** 401 is **not** a gate — an anonymous-enabled Grafana and a
world-readable Gitea both answer that way while serving everybody, so reading it as a gate would
take genuinely open applications out of the exposed count. 403 is excluded too, because nginx 403s
a directory with no index. A bare refusal is still recorded and named as a place to look, in the
same sentence that says the finding stands.

Bounded like everything else: the walk is **sequential** regardless of `probe.maxConcurrency`
(that budget is across *services*), stops on the first refusal, parses nothing from what comes back
— only a status and whether a scheme was named — and its addresses stay **out** of the recorded
attempt list, the request count travelling on the state record instead.

### 13.5 The opposite question: what an anonymous caller was shown

One pure function over the body already fetched — no second request (I8) — recording the visible
text length, the link count, and optionally one login link's resolved path and its label. It keeps
no header, no cookie and no attribute value except that path and a label shorter than 24
characters (I6).

**It MUST be structurally incapable of gating.** The gate rule takes a response; this record is not
on one, and the gate rule MUST NOT be able to read it. The worst a mistake here can do is put a
wrong sentence on a service that stays in the exposed count.

| What was read | The rule says |
|---|---|
| content served, no sign-in offer | the narrower sentence — the application's own content, not a shell |
| a sign-in offer, no content served | nothing; the page is left to §13.4 |
| both | says so, and names the link or the control in the words the page used |

**A logout link MUST be skipped before its path is read**: login-path matching is by prefix, so
`/auth/logout`, `/oauth2/sign_out` and `/sso/logout` are login paths *by name*, and a page carrying
one is a page somebody is already signed in to.

**Drawn markup, not served markup.** Every number MUST come from a body with comments, `<script>`,
`<style>`, `<template>`, `<noscript>` and `<svg>` removed first. Self-closing `<svg/>` must be
dropped before either arm, because SVG is the one place in HTML where `/>` really closes an element.

The login-label and not-a-login-label vocabularies are private and multi-language: a path stays
`/login` in every locale, the label is what gets translated. Three details are pinned by the corpus:
**word boundaries**, without which `log[\s_-]?in` matches `Blog index`; *continue with* deliberately
**absent**, because it is a login label only when a provider name follows it; and sign-up
deliberately absent from the veto, so *Sign in / Sign up* still reads as a login affordance.

*Content was served* means **at least 200 characters of visible text and at least 2 links**. Both
MUST hold: a login page can carry 200 characters of boilerplate, and a page of nothing but
navigation can carry ten links. These are **wording thresholds, not verdict thresholds**.

The record is attached whenever an HTML 200 was read, gate or no gate, because it describes a
*response*; the *sentence* is reached only after the §13.4 shortfall. The verdict label stays
*No login page*.

### 13.6 Recorded facts, verdicts, bounds

The facts a verdict rested on travel beside the verdict, one field per fact a sentence has to name:
media type (a 200 that was not a page), redirect (a 3xx that stayed put), refresh (a meta refresh
that was not a gate), truncated (a form below the body cap), state (§13.4 — the only one recording a
request rather than a reading, which is why the asked count is on it), and the anonymous reading
(§13.5). There MUST be **no** field for `WWW-Authenticate`: a 401 with no `challenge` gate already
means the header was absent.

There MUST be exactly one rule for "where does this point", shared by the redirect signal, the meta
refresh and the media-type reading. All three reduce what they record (I6): a recorded redirect
target drops query and fragment and keeps the origin **only** when the target left the origin, with
a cross-origin flag beside it; a media type drops its parameters.

The reason sentence is pure and branches in the signals' own precedence order — one sentence per
signal naming the fact that fired, and for a negative verdict the clause that came *closest* and
what it lacked. The mapping from signal to wording MUST be **exhaustive**, such that adding a signal
without its wording fails the build.

**Both findings are findings.** A login page answering: the service leaves the exposure count, is
counted as probe-gated, and the no-auth reason is `probed-gate` with the method untouched at `none`.
An answer with no login page: the exposure note gains a clause saying LabView requested the address
and was served the application. A service that did not answer is neither — counted in neither
statistic, claiming no measurement, and worded *No answer* rather than *No login page*.

**A probe never becomes a mechanism** (I3): `probed-gate` is its own reason with its own statistic,
and the probe record sits beside the Authentik and Traefik records, never inside the posture.

**Two things it does not override.** A detected gate that answered with no login page keeps its
posture and gets a note saying the request came from LabView's own vantage point. A declaration
supplying the only protection is not overridden by an open answer either — that is recorded as
**unconfirmed**, not drift (§14).

**Containment** (I8): GET only, no query string; **no credential, and not by omission** — no call
path into the fetch may have one in scope; **no redirect followed**, because where a 3xx points is
the evidence; a per-request timeout and a bounded number in flight; at most **4 addresses per
service**; and the body read only when the content type is HTML, then only to **64 KiB**, with the
stream cancelled at the cap. That is the shared default cap, and the probe keeps it deliberately:
the size of a page somebody else wrote is not a fact about this fleet, so a probe willing to read a
megabyte of it has no bound worth the name. The Docker reads are the exception and say why (§10).
Disabled, nothing eligible, or nothing answering each return a report that explains itself (I4).
The recorded attempt list is truncated to **8** entries.

The report is one `meta.connections` entry: `disabled` when off, `not-found` when nothing was
eligible, `partial` when part of the fleet did not answer (still `ok`), and `connected` otherwise —
*31 services probed — 12 gated, 17 open, 2 did not answer — 9 extra requests at current-user
addresses*, the last segment summed from the state records and present only when there were some,
plus *— 1 service not asked (authentication already detected)* from the skipped count.

### 13.7 The switch beside Rescan

`probe.enabled` is the **default**, not the authority. `POST /api/rescan` takes an optional body
`{"probe": true}` and the value is fully authoritative for that build: `true` probes where
configuration says off, `false` skips where configuration says on. **It lasts exactly one rescan** —
a TTL rebuild, a timer and a page load all carry no request and fall back to the configured value.
So the payload always states what it did, in `meta.probe` = `{enabled, source: "config" | "request"}`.

Three mechanics are required. The override produces a **copy** of the configuration, never a
mutation, because the configuration object is captured by the in-flight build and read again by the
next timer rebuild. The value is threaded as a **parameter of the build**, so the build that
*starts* owns the override and a coalesced caller's value is discarded. And the body is
**validated, not coerced** — one known key, one known type; a missing body, an array, a JSON
`null`, `{"probe":"yes"}` and `{"probe":1}` all mean *use configuration*, while unknown fields are
ignored rather than rejected (I4). The UI checkbox re-syncs from `meta.probe.enabled` on every
payload received.

Security consequence, stated rather than mitigated: when LabView is not enforcing a login,
`POST /api/rescan` is unauthenticated, so this switch lets any visitor start fleet-wide outbound
requests.

*A diagnostic CLI that points the same rules at one URL and writes a report is useful and
optional. If one exists it MUST reuse these rules rather than reimplement them, MUST inherit the
same transport bounds, and MUST NOT be present in the runtime image.*

---

## 14. Declarations

The sidecar file is **operator input and explicitly not evidence**. Three rules govern
everything that may be done with it.

**1. A declaration never changes a detection.** Declaring things writes notes, drift and
agreement only. It MUST NOT touch a service's authentication posture, ingress set, identity-
provider match, live proxy records or probe result. Declared LDAP does not become an
`AuthMethod`; a declared expected ingress does not become an ingress kind. The words on the page
change; the conclusion does not.

**2. A declaration can change exactly one verdict, in the open.** Declared authentication clears
the *finding*, because a service authenticating its own users is not an exposure — that is a true
statement about the world, and refusing to make it is what turns a real finding into noise. It is
confined to one boolean:

```text
exposedWithoutAuth = reachable AND NOT hasEdgeAuth AND declaredAuth is empty
```

with an agreement of `supplies`, a *Protected — declared* badge, its own statistic, and a note
naming which mechanism and which file said so. The method stays `none`, the no-auth reason is
`declared` (*Declared, not detected*), and the headline states the split. **Nothing anyone typed
makes an undetected gate detected.**

**3. An accepted exposure is still an exposure.** An intentional-unauthenticated declaration is
counted in its own statistic and **MUST NOT** be subtracted from the exposed count; the headline
renders both figures (*23/28* — 28 exposed, 23 accepted). Its `reason` is mandatory (§6.1): an
acceptance with no reason cannot be told from a stray key.

**Comparison** takes the declared mechanisms, the detected posture, and whether the service
*would be* exposed. Three families, compared only **within a layer**:

| Family | Detected members | Declared members |
|---|---|---|
| `oidc` | `authentik-oauth`, `other-oauth` | `app-oidc` |
| `ldap` | `authentik-ldap`, `ldap` | `app-ldap` |
| `proxy` | `authentik-forward-auth`, `forward-auth` | `external-proxy` |

Both mappings are **partial**, so an unmapped mechanism has no family and cannot conflict. The
layers are *the application authenticating its own users* (`oidc`, `ldap`) and *a gate in front of
it* (`proxy`); a forward-auth gate and an application's own OIDC are both true at once, so they
MUST never be compared. Four outcomes, tested in order:

1. `supplies` — the service would be exposed and a declaration is the only protection. This is
   rule 2.
2. `redundant` — declared and detected in the same family. Rendered **nowhere**; agreement is
   silent.
3. `conflicts` — same layer, different family (declared `app-oidc`, detected `authentik-ldap`).
   A drift entry.
4. `supplements` — declared in a layer with nothing detected in it, while the other layer has a
   gate. Noted, not drift.

The third input is *would be exposed*, not *reachable*, so `supplies` implies the method is
`none` and can never be reported on a service that has a detected gate.

**Declared dependencies** are service-level only — one entry at stack level cannot say which
service depends on the target, so that mistake gets its own warning rather than being lumped in
with unknown keys. Resolution prefers **the declaring stack's own service** for a bare name, then
the fleet:

| Case | Result |
|---|---|
| exactly one service | an edge with the declaring file, a detail, and `via` |
| a local service **and** others, written bare | the local one wins, silently |
| two or more in other stacks, written bare | drift, no edge — the operator must write `stack/service` |
| nothing, or itself | drift, no edge |
| a pair the compose files already resolved | one edge, silently — the declaration only adds a detail |

Declared once, shown from both ends: the target's drawer lists it as `required-by` without its own
sidecar mentioning it. It is **not** evidence and **not** reachability — `via` may be empty, and an
empty `via` is itself the finding (§8).

**Four drift checks:**

1. A stale acceptance — an unauthenticated declaration on a service no longer externally
   reachable (tested with the external-reachability rule, so `lan`-only still counts as
   reachable).
2. A `conflicts` mechanism.
3. A declared dependency that no longer names exactly one service.
4. An expected-ingress mismatch, reported **in both directions**: *missing: lan; unexpected:
   traefik*.

The **fifth** collection is not drift: `unconfirmed` holds a declaration that nothing contradicts
and nothing corroborates — a declared mechanism in a layer where the scan detected nothing, and a
probe that answered with no login page on a service whose only protection is declared. Drift and
unconfirmed MUST be collected by **one walk with two selectors**, so a service can never end up in
one list and not the other by accident. They render through one presentation with two
introductions: drift as critical, unconfirmed as a plain note.

The declaration block MUST stay **out** of the volatile-field deny-list (§17), and change
comparison MUST compare the declaration *as written* — everything except the two derived fields
(drift, agreement), which are conclusions about this scan and not the file.

---

## 15. Connection reporting

Every outbound target reports through **one shape** with a closed phase taxonomy (§4.6). The
phases MUST be produced by a single shared classification: one mapping from a transport error to a
phase, one from an HTTP status to a phase, and one JSON read that returns the phase and the
underlying code **beside** the error, so that no caller re-derives a phase from a message string.
The Docker endpoint adds its own two classifiers (Engine errors, and the socket pre-check of
§10).

**Report:** the target, `ok`, the phase, a **credential-free** endpoint, its `source` (`config` |
`discovered` | `default`), a detail, a hint, `read` — what actually came back, as prose (*86
containers*; *Traefik 3.1.2, 10 routers, 5 middlewares*) — and the rejected candidates.

**Attempt:** one rejected candidate — credential-free endpoint, the `why` that made it a
candidate, phase, code, detail.

Each phase MUST map to prose, and each (target, phase) pair to **one action to take**. Formatting
is one line for the report plus one indented line per rejected candidate.

**A response that could not be read MUST account for what arrived instead**, in the detail: its
size, whether the body cap of I8 cut it, and the beginning of the body itself. The phase and the
code are not a diagnosis on their own — a socket proxy's refusal, an SSO login page and a container
list cut at the cap all report `protocol` / `not-json`, and the body is the only thing that
separates them. The **code** stays a shape and MUST NOT carry content (I6); the **detail** carries
the excerpt, rendered so that it cannot damage the line it lands in: credentials in it masked
(§20), runs of whitespace collapsed to one space so a body cannot forge the indented candidate
lines, quoted so a control character is escaped rather than acted on, bounded in the **rendered**
text and not in the bytes that produced it, and bytes that are not valid UTF-8 described rather
than shown. Where the cap did the cutting, the detail MUST say so **and MUST name the cap that
actually applied**, not the shared default: that failure is LabView's, the hint for the phase points
at the far end, and a line naming a cap that had nothing to do with the cut sends the operator to
raise the wrong setting (I8's size bound is per read).

**Comparing two scans' connections MUST compare target, `ok`, phase and endpoint, and MUST NOT
compare `read`** — otherwise a container count ticking up re-announces a working target on every
rescan. A banner is shown for `partial`, and for any failure whose phase is neither `disabled` nor
`not-configured`. A working target logs at info; `partial` and failures log at warn; the first
scan logs all of them.

---

## 16. Payload rules

- **The analysis emits the complete truth; the presentation decides what is drawn.** Every cap,
  roll-up and label in §8 and §17 is a presentation rule and MUST NOT be applied in the analysis
  stages. A capped spoke is still answerable from the payload.
- Because the API and the UI are separate programs, every pure rule the corpus asserts (filters,
  roll-ups, view state, probe wording, declaration comparison) MUST live where it can be tested
  **without rendering**, and MUST NOT be implemented twice.
- A line between two services requires a **dependency**, never co-membership.
- Resolution reads a declaration and never writes to it.
- **A field describing the build is never optional** — the probe mode, the build stamp, the
  skipped and not-asked counts. The build stamp's `source` is required, so an unknown build says
  *unknown* rather than being absent.
- **A fact about one response is optional, and its absence is the fact** — media type, redirect,
  refresh, truncation, the state-challenge record, the anonymous reading. Inside the state record
  the asked count is *not* optional (a request was made) while the refusal fields are, and
  `challenge` is `false` rather than absent for a bare refusal.
- **Adding or renaming a union member is a breaking change**, because presentation keys colour and
  label off the member name (§4).
- `detail` is one line about one record; `evidence` is the string a conclusion rests on; `notes`
  are service-level sentences a reader needs. They MUST NOT be used interchangeably.
- A username anywhere in the payload or a log line satisfies `^[A-Za-z0-9._@-]{1,64}$`, with `?`
  as the fallback.

---

## 17. Rescan and the change note

**A forced request may only be answered by a build that started after it arrived.** That is the
whole of the cache contract, and five consequences MUST be asserted: a forced request never
receives an in-flight build's result; two forced requests arriving together share one build; a
forced build resets the TTL; a non-forced request during a forced build joins it; and the
built-callback fires exactly **once per build**, not once per waiter. The clock and the build
function MUST be injectable, so all five are testable without waiting.

Change detection compares the **parsed configuration**, not the enriched payload, through
canonical serialisation. The volatile-field list omits live Docker state, the identity-provider
match, live proxy records, ingress, authentication, notes and tunnel-route state — it is a
**deny-list**, so a newly added field is compared by default and a genuinely volatile one has to
be named.

Cadence: the first build states the baseline (*LabView read 56 stacks, 86 services from
/data/apps*); a change always speaks; a **forced** rescan answers even when nothing moved
(somebody asked); only a quiet **timer** rebuild stays silent, and quiet means **both** diffs.
The UI renders *scanned 12:04:11 · +1 stack, +2 services*. One line per stack that moved, capped
at **12** lines with the remainder stated rather than silently dropped.

A rescan re-runs both API exchanges but does **not** re-read credentials — they are
environment-only (§3.3), so rotating one needs a restart.

**The integration diff is a second structure beside the configuration diff and MUST NOT be folded
into it**: *no config changes; authentik +1 application, -3 withheld*.

- **Reachability is decided before any count.** Neither side read → no entry. Both read →
  unchanged or moved, with deltas and named records. Not-read → read = `started`; read →
  not-read = `stopped`. Those two are not numeric comparisons and MUST NOT be phrased as ones.
- Counts are compared only where **both** sides have a value, so an optional count appearing or
  vanishing is not a delta.
- Nouns are pluralised; modifiers stay identical in both directions (`+1 application`,
  `-3 withheld`). The proxy's own service count renders as **`live service`**, because *service*
  in this payload already means a compose service.
- Named records are read back off the payload — application slugs, router names — and sorted (I7).
  Name lists truncate at **12 names per line**, not 12 lines, with the remainder stated: each
  target contributes at most three lines, so a fleet with forty applications still puts forty
  names into one of them.

---

## 18. HTTP surface

| Route | Session | Behaviour |
|---|---|---|
| `GET /api/overview` | yes | the cached payload; rebuilds past `cacheTtlSeconds` |
| `POST /api/rescan` | yes | forced rebuild; optional body `{"probe": true\|false}` (§13.7) |
| `GET /api/healthz` | **no** | `{"ok": true}`; runs no scan |
| `GET /api/session` | **no** | the session/posture summary |
| `POST /api/login` | **no** | local credential login |
| `POST /api/logout` | **no** | clears the cookie |
| `GET /auth/oidc/start` | **no** | 302 to the provider's authorize URL |
| `GET /auth/oidc/callback` | **no** | code → session cookie → 302 `/`, or 302 `/?login_error=<code>` |
| `GET /*` | **no** | the embedded UI, with a single-page fallback to the index document. A 404 under `/api/` MUST stay JSON |

"Needs a session" is conditional on enforcement (§19): with no method configured, everything is
open.

Concurrent requests share one in-flight build unless one is forced. The cache MUST be warmed in
the background at startup so the first reader does not wait. The API MUST NOT depend on the
presence of UI assets.

Everything the server registers — routes, hooks, headers — MUST be registered in one place that a
test can construct **without opening a listening socket**. A route registered only on the path
that binds the port is invisible to every test.

---

## 19. Access control

**Open unless configured.** With no method enabled the dashboard is reachable as it was before
authentication existed — LabView is a read-only viewer, and a lock nobody asked for is a
regression.

**Naming hazard, stated once:** the methods are **`passwd`** and **`oidc`**. The passwd file holds
bcrypt hashes and has nothing to do with HTTP Basic. No identifier in the implementation may call
it basic.

Posture resolution MUST be pure, returning what is enforced, which methods are live, and notes.
`passwd` is live when it is enabled **and** the file parsed to at least one usable entry; `oidc`
is live when it is enabled **and** both issuer and client id are non-empty. Enabled means
*allowed*, not *on*. An enabled-but-unusable method produces a note and a warning and **never** a
lock-out — a typo in a path MUST NOT make the dashboard unopenable. Posture is re-resolved per
request and cached for **5000 ms**, so dropping a passwd file in takes effect without a restart;
the summary is re-logged only when it changes, and reports **counts, never names**.

**The gate** is one request hook, one response hook and five routes. Three rules:

- **The gate never consults scanned data** (I8). A login screen that waits on a fleet scan is a
  login screen that times out, so no path from the gate to the scan may exist at all.
- **A reply says less than the log.** `401 {"error":"authentication required"}` to the client, the
  reason to the log. A username is sanitised to `?` when it falls outside the username pattern, so
  a hostile username cannot forge a log line.
- **The public-path test is an exact-match allowlist** over a normalised path — query and fragment
  stripped, duplicate slashes collapsed, any `..` refused — holding exactly `/api/healthz`,
  `/api/session`, `/api/login`, `/api/logout`. A prefix test would open
  `/api/healthz/../overview`.

**Scope: gate the data, not the shell.** The UI assets stay public, because they contain no fleet
data and gating them means the reader gets a JSON 401 instead of a login form. The OIDC routes sit
outside `/api` so the allowlist stays about the API.

Responses carry `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and
`X-Frame-Options: DENY` unconditionally, plus `Cache-Control: no-store` on `/api/*` while
enforcing. **No CSP** — the UI is self-contained behind a header that already forbids framing, and
a CSP would be one more thing to get subtly wrong.

**The passwd file.** `user:hash`, one per line; `#` comments and blank lines ignored. The
algorithm is read from the `$id$` prefix and only `$2a$`, `$2b$` and `$2y$` are honoured; any
other id is skipped with a warning naming **the algorithm only**. A value containing no `$` MUST
never be accepted — it would be a plaintext password. Duplicate usernames: first wins. **A warning
never contains a hash.** A malformed line is skipped, not fatal. Caps: **64 KiB**, **1000
entries**, **1024 password characters** (bcrypt truncates at 72 bytes; this cap is about the work
of hashing a megabyte). Reads are cached on size, mtime and inode. The unreadable cases —
missing, is-a-directory, over-size, permission denied — MUST be distinguished.

**An unknown username is verified against a decoy hash**, so a failure takes the same time as a
known name's. The decoy is generated lazily from 32 random bytes per cost factor and memoised —
**never a committed constant**.

**Throttle**, keyed on the case-folded sanitised username: `maxFailedAttempts` inside
`lockoutSeconds` → `429` with a retry-after, **regardless of whether the password was right**,
because the lock is on the name. The counter resets on success. At most **4096** distinct
usernames are tracked, oldest evicted. Minted hashes use cost **12**.

**Sessions are signed, not stored:** `v1.<base64url(payload)>.<base64url(HMAC-SHA256)>` over
`{u, via, iat, exp, jti}`, checked in exactly that order — shape, then MAC, then expiry, then
revocation — with rejections reported as `malformed` | `signature` | `expired` | `revoked`.
Comparison MUST hash both sides before comparing, so a length difference leaks nothing. There is
no session store; logout adds the identifier to one revocation set, pruned by expiry on every
write and capped at **10 000** entries with the **earliest expiry** evicted first. The cookie is
`HttpOnly`, `SameSite=Lax`, `Path=/`, with `Max-Age` from the TTL and `Secure` following the
**effective** scheme — `X-Forwarded-Proto` first, since LabView normally sits behind the very
proxy it documents. CSRF defence is `SameSite=Lax` plus an `Origin` check on every POST while
enforcing, ordered **before** the session check and returning no `Set-Cookie`; a **missing**
`Origin` passes, because non-browser clients omit it.

**OIDC** is authorization code with **PKCE S256**, issued through the same HTTP chokepoint as
every other target (§15), so a provider that will not resolve reports the same phases. Every pure
part takes the current time as a parameter. Discovery is cached for **10 minutes**; the document's
own issuer MUST equal the configured one (trailing slashes forgiven); every endpoint MUST be
`https`, loopback excepted. The start route puts `{state, nonce, verifier, exp}` in a signed
transient cookie scoped to the callback path, with a **300-second** window re-checked from the
payload.

ID-token checks, in order: signature → `iss` exactly → `aud` contains the client id → `azp` equal
when present → `exp` and `iat` within **60 seconds** of skew → `nonce`. **Asymmetric algorithms
only**: no `alg: none`, every HMAC algorithm refused, and no configuration to re-enable them —
with a client secret in the environment, an `HS256` token forged with that secret would verify. An
unknown key id triggers exactly **one** JWKS refetch. The username comes from the configured
claim → `preferred_username` → `email` → `sub`, and MUST satisfy the username pattern. Every
failure redirects to `/?login_error=<code>` with one of the eight codes in §4.7.

Deliberate non-goals: no roles or per-service permissions, no trusted-header mode, no session
persistence across restarts, no rate limiting beyond the login route.

---

## 20. Secrets

Masking happens **before serialisation, never at render time** (I6). Any environment key matching
the sensitive-name patterns is replaced with a mask that preserves shape and not content. URI
credentials are redacted, and that redaction runs **before** a sidecar link's label falls back to
its URL (§6.1). A configured token, password or client secret MUST NOT appear in a connection
report, an attempt, a note, a warning or a log line: one credential-free origin formatter produces
every endpoint field in the payload. Masking runs at the end of pass 2b, so no later stage can
read an unmasked value.

---

## 21. Invariants

Eight rules. A change that breaks one is wrong regardless of what it adds.

- **I1 — Evidence only.** Every conclusion names what it rests on. No heuristic that guesses a
  gate from a port number, an image name or a naming convention. Where evidence is missing, the
  answer is *not identified*, with the reason.
- **I2 — No fleet identifiers in artifacts.** No hostname, domain, container name, IP or token
  from a real fleet in source, fixtures, documentation or a committed report. Fixtures use
  `example.com`, `192.0.2.0/24` and invented names.
- **I3 — Mechanism is not provider.** A middleware named `authentik` that forwards elsewhere is
  not Authentik. A probe result is never an `AuthMethod`.
- **I4 — Degrade, never fail.** Any enrichment may be absent, unreachable, partial or hostile; the
  scan still produces a payload and says what it could not do. No enrichment failure escapes its
  own boundary.
- **I5 — Read-only and least privilege.** Nothing is ever written to a scanned tree. The Docker
  surface is exactly `GET /_ping`, `GET /containers/json`, `GET /containers/{id}/json`. Tokens are
  read-only by requirement, the socket is mounted read-only, and the probe sends GET with no
  credential.
- **I6 — Secrets never reach the API.** Masked before serialisation; endpoints credential-free; a
  diagnostic reports a header's *name*.
- **I7 — Determinism.** Same input, same bytes out: sorted iteration everywhere order could vary,
  no clock outside an injected one, and **no logging inside the analysis** — diagnostics are data.
- **I8 — Containment.** Every configuration-supplied path is resolved and checked against the scan
  root before it is read, lexically **and** through symlinks; every network read is bounded in
  time, size and concurrency; and the gate never consults scanned data. The size bound is
  **per read, with a shared default of 64 KiB and a hard ceiling**: a read may choose its own
  cap and MUST NOT be able to express *unbounded*, and a cap above the ceiling is clamped rather
  than honoured. One number for every read is the weaker rule, not the stronger one — it forces
  the cap on a document somebody else authored and the cap on this fleet's own container list to
  be the same number, and whichever way it is set, one of the two is wrong.

---

## 22. User interface

The UI is a **reading instrument for one payload**. Its visual design, framework and component
structure are free. What follows is what it must make answerable, how the reader gets from a number
to the rows behind it, and the rules that keep it honest.

### 22.1 Governing rules

- **Payload-complete.** Every field in Appendix A MUST be reachable in the UI. Adding a payload
  field without giving it a place to appear MUST fail the coverage check of §23.
- **One source of truth.** The UI derives everything from the payload it was given. It MUST hold no
  fleet knowledge of its own, MUST NOT keep a second copy of a relation the payload already states,
  and MUST NOT issue a request to learn something the payload already contains.
- **It may relabel, never conclude.** Every aggregate the UI shows MUST be recomputable from the
  payload by a reader with the JSON in hand. The UI MUST NOT introduce a heuristic, infer a gate, or
  soften a finding (I1).
- **Evidence is never more than one interaction away.** Wherever a conclusion is shown, the
  `evidence`, `detail` or `notes` that produced it MUST be reachable from that same element.
- **Deterministic.** The same payload MUST produce the same view: sorted rows, sorted chips, stable
  diagram layout. No clock-dependent or random ordering.
- **Offline and self-contained** (§2.2): no CDN, no font service, no telemetry, no tile server, no
  external diagram renderer.
- **Keyboard and screen reader.** Every clickable statistic, chip, row and diagram node MUST be
  focusable and operable with Enter and Space, and MUST expose an accessible name. Escape closes the
  topmost layer only — panel before drawer. A layer that takes focus MUST give it back to whatever had
  it when the layer opened: focus dropped on the document returns the reader to the top of the page,
  which for a table of thirty-five rows means walking the whole shell again to get back.
- **Modern and dense, without motion.** Responsive down to tablet width; sticky table headers; one
  type scale; light and dark **defaulting** to the system preference, with an explicit override the
  browser remembers — a preference is not part of what a link describes (§22.7), so it MUST live
  beside the URL rather than in it; no transition longer than 200 ms; and **no layout shift when a
  rescan lands** — the same rows in the same places, values updated. The same rule holds for a
  preference: switching the theme or collapsing the navigation MUST NOT move a row.
- **Colour is categorical and centralised.** One mapping from every union member to a colour and a
  label, with a defined fallback for an unknown member — which is why adding a member is a breaking
  change (§16). Exactly **one** reserved emphasis colour, for exactly one condition: reachable from
  outside with no gate. A second, weaker warning colour covers an ambiguous match, a proxy API
  answering unauthenticated, and a failed connection phase. Colour MUST never be the only carrier of
  a distinction.

### 22.2 Views

Fourteen views, grouped in the navigation as Fleet · Reachability · Runtime · Enrichment ·
Operator · System. Each is one row per object, filterable (§22.6) and addressable (§22.7).

| View | The question it answers | One row is | MUST show at least |
|---|---|---|---|
| Overview | what is here, and what needs attention | a statistic | every counter in `stats`, as a card (§22.3) |
| Stacks | how the tree is laid out | a stack | *in the table:* name, service count, ingress and auth roll-ups, an exposure count in the **reserved colour**, and a **marked** warning count. *In the row's drawer:* directory, compose file, project name, whether an env file was found, declared networks and volumes, stack-level declaration, and the warnings themselves |
| Services | everything about one service, comparably | a service | *in the table:* stack, name, state, ingress set, auth method with confidence, exposure, and a **marked** drift count. *In the row's drawer:* image, declaration state, probe verdict — and everything else of §22.4 |
| Ingress | how each hostname reaches a container | a route | hostname, path, kind (tunnel or proxy router), TLS and resolver, entrypoints, middleware chain, resolved origin and its `OriginKind`, target service, the gate on that path |
| Networks | what connects services and what merely co-locates them | a network | name, scope, driver, member count, stack count, whether it connects anything, and the dependencies that cross it |
| Diagrams | the shape of the fleet | a diagram | the four diagrams of §22.5 |
| Containers | what is actually running | a container | id, name, image and digest, state, status, health, restart count, created and started, IPs per network, published ports |
| Storage | where data lives | a mount or volume | type, source, target, read-only, declaring service, whether the volume is external, and which services share it |
| Config | what each service is configured with | an env var or a label | key, **masked** value, source, owning service — plus labels grouped by prefix, and which label produced which conclusion |
| Identity | what the identity provider reported | an application | slug, name, group, launch URL, providers with kind and mode, outposts, matched service with strength, `discoveredVia` (a rebuilt record MUST be tagged *rebuilt*), and every unmatched application with reason → detail → trace |
| Proxy | what the reverse proxy is actually serving | a live router | router and provider, rule, hosts, entrypoints, TLS, middleware chain with `viaChain` / `viaEntrypoint`, backend servers and their status, errors verbatim, matched service — and every unmatched router with reason → detail → trace |
| Probe | what answered when asked | a probed service | vantage, address, phase, status, verdict, the one fact it rested on, the form shape, the state-challenge record, the anonymous reading |
| Declarations | where the operator and the scan disagree | a declaration | owner, criticality, description, notes, data, links, declared auth with agreement, declared dependencies, accepted exposures with reason, expected ingress — with **drift** and **not confirmed** as two separate readings that are never merged |
| Diagnostics | what LabView could not do | a connection report | target, phase, endpoint, source, detail, hint, what was read, and every rejected candidate with its `why`; plus scan warnings, scan duration, scanned-at, apps root, and the build stamp with its `source` |

Rules that apply across views:

- **Stacks roll up; filters do not.** A stack may collapse to one row showing every distinct ingress
  kind and auth mechanism its services have plus an exposure count (`none` rolls up to nothing), but
  filtering is always **service-level**.
- **A table compares; a drawer describes.** A view's required reading MAY be split between the two:
  what a reader compares *across* rows belongs in the table, and what only describes the one row
  belongs in that row's drawer (§22.4). Splitting MUST NOT lose anything — a field the table stops
  showing MUST appear in a non-**Raw** drawer section, which is the coverage check of §23 enforcing it
  rather than a convention. A row whose reading is split MUST itself open, and MUST be focusable and
  operable with Enter and Space like any other clickable element (§22.1). A link inside such a row wins
  the activation, so the row MUST NOT put one on the cell a reader is most likely to click to open it.
- **A count worth attention MUST be marked, and not with a reserved colour.** A stack's scan warnings
  and a service's drift entries are what a reader scans a table for, so a nonzero count MUST carry a
  visible mark beside it — an exclamation glyph, since the two reserved emphasis colours (§22.1) mean
  exactly what they mean and MUST NOT be borrowed. A zero MUST still read as `0`, and MUST NOT be
  marked: a mark on every row marks none.
- **Rank is not severity.** Every view sorts what it is about to the top, and each view is about a
  different question — unhealthy in Containers, read-write in Storage, more than one stack in
  Networks. So the emphasis a table gives its first rows MUST say *first*, not *worst*: a raised
  surface and an edge marker in the neutral accent, never one of §22.1's two reserved colours, which
  would otherwise mean eleven different things at once. Where a view counts the reserved finding
  itself, the reserved colour goes on that **cell** — a nonzero count wears the finding's own tone, a
  zero wears none — and the view's rank MUST follow the same count, so the rows a reader is pointed at
  and the reading that points at them are the same rows.
- **Overlapping counters MUST NOT be drawn as a partition.** The three external ingress counters
  overlap, so they are per-tag gauges; auth methods partition, so they may be one distribution bar.
- **Findings lead.** In the Probe view: *answered with no login page*, then *answered with a login
  page*, then *did not answer*. In Declarations: drift before not-confirmed. In Diagnostics: failures
  and `partial` before working targets. In Stacks: the exposure first, then a stack the scan could
  only partly read, then the rest — two conditions in the order §22.1 ranks them, not one.
- Every view MUST state its row count, and every list that is capped MUST say what it dropped.
- A rescan control MUST be present, MUST show the change note (§17) and the scanned-at time, and
  MUST carry the probe switch, re-synced from `meta.probe.enabled` on every payload received
  (§13.7).

### 22.3 Overview cards are links, not decoration

**Every counter in `stats` MUST have a card, and every card MUST be a link.** A card resolves to one
of exactly two destinations:

- a **view with a filter pre-applied**, addressable and shareable (§22.7) — the default for anything
  that is a set of services, networks, routes or applications; or
- a **drawer or panel** listing the records behind the number — for anything that is a small,
  bounded list (unmatched applications, unmatched routers, drift entries, failed connections, the
  build stamp).

**The destination MUST show exactly the rows the number counted**, and MUST display that same count.
A card whose number and destination disagree is a defect, not a rounding difference.

| Card | Destination |
|---|---|
| stacks, services | Stacks; Services unfiltered |
| running | Containers filtered to running |
| public, traefik, lan, internal, no-ingress services | Services with that ingress tag included |
| auth-protected | Services filtered to a detected method |
| **exposed without auth** | Services filtered to the exposure finding — the reserved colour, and the one card that MUST be visible without scrolling |
| by-auth-method distribution | one segment per member → Services filtered to that method |
| declared auth, declared-auth-protected, declared-auth-unconfirmed | Declarations, scoped to that reading |
| exposure-accepted | Declarations, accepted list — labelled as *still exposed* (§14 rule 3) |
| declaration drift | Declarations, drift |
| declared dependencies | the dependency diagram, or Networks scoped to declared edges |
| probe-gated, probe-open | Probe, scoped to that outcome |
| networks, connecting, cross-stack, solo-local | Networks with that predicate |
| identity-provider counts (applications, configured, withheld, recovered, providers, outposts, matched) | Identity, scoped; withheld and recovered MUST be shown together, since the `partial` rule is their difference (§11) |
| proxy counts (routers, middlewares, live services, matched) | Proxy, scoped |
| failing connections, warnings | Diagnostics |
| build stamp | a drawer stating version, commit, `source` and what that source means (§3.4) |

An optional count that is absent MUST render as *not reported*, never as `0`, and its card MUST say
what would make it available.

### 22.4 The service drawer

One service, everything known about it, in this order — findings first, raw last:

1. **Identity** — stack, service and container name, image with digest, command, restart policy.
2. **Verdict** — ingress set, auth method with confidence and evidence, exposure state, and the
   no-auth reason in its own words when there is one.
3. **Reachability** — every route reaching it, each with its origin resolution and the gate on that
   path; published and exposed ports.
4. **Authentication detail** — identity-provider applications with per-match strength, the live
   middleware chain with where each entry came from, and any three-way cross-check note.
5. **Probe** — what was asked, what answered, the fact the verdict rested on; or why it was not asked.
6. **Connections** — dependencies in both directions with the network each crosses, co-members
   distinguished from dependencies, and an empty `via` shown as the finding it is (§8). This section
   MUST read from the **uncapped** relation set, so a spoke a diagram dropped is still answerable
   here.
7. **Storage** — mounts and volumes.
8. **Configuration** — env vars with source and masked values, labels grouped by prefix.
9. **Declaration** — every declared field, the agreement, and this service's drift and
   not-confirmed entries.
10. **Raw** — the service's payload subtree, copyable. This exists as an escape hatch and **MUST NOT
    be how a field satisfies the §22.1 coverage rule.**

Stacks, networks, routes, applications, routers and probed services get equivalent drawers. One panel
or drawer is open at a time. The stack drawer is where the Stacks table's roll-up stops being a
summary: the scan warnings in their own words first, then where the stack is and what the Engine
labels its containers with, its declared networks and volumes, its stack-level declaration (§14), and
raw last — its services are not repeated there, since each is a row with a drawer of its own.

### 22.5 Diagrams

Four diagrams are required. The renderer is free — a text-to-diagram tool such as Mermaid, a
force/DAG layout library, or hand-drawn SVG — provided it is bundled (§2.2).

| Diagram | Nodes | Edges |
|---|---|---|
| Dependencies | services, grouped by stack | `depends_on` and declared dependencies, labelled with the shared network; a declared edge marked as declared; an empty `via` drawn direct and marked |
| Networks | services and networks | membership, with arrowheads carrying `flow` and styling carrying `flowSource`; network nodes carrying scope and member count |
| Ingress paths | outside → hostname → tunnel or router → origin → service | one path per route, with the gate drawn **on** the path and an ungated external path in the reserved colour |
| Identity and auth | providers, applications, outposts, proxies, services | which application protects which service, at what strength; forward-auth middleware to provider; unmatched records shown as unattached, not hidden |

Requirements for all of them:

- Derived from `graph` and the payload only. A `service → service` edge survives **only** where
  `via` is empty; a line between two services otherwise requires a dependency, never co-membership
  (§16). The membership caveat is stated once per diagram, not once per row.
- **Clicking a node opens that object's drawer**, and the selection is in the URL.
- A **focus mode** — one service or one stack plus its neighbourhood at a chosen depth. Above a
  stated node threshold the diagram MUST open focused rather than drawing the whole fleet.
- Caps MUST state what they dropped (*showing 12 of 31 members*) with a way to see the rest.
- **A text export** — the diagram's own source (Mermaid, DOT or equivalent) MUST be copyable, and
  MUST be deterministic for a given payload so it can be asserted as a literal in a test.
- **A tabular equivalent** for every diagram, reachable from it: an edge list. A fact that exists
  only inside a picture is unreadable to a reader who cannot see it, and unusable at fleet scale.

### 22.6 Filters and search

Dimensions: ingress kind, auth method, auth confidence, container state, health, stack, network,
probe verdict, declaration state (drift / not confirmed / accepted / declared-protected), integration
match state (matched / unmatched / rebuilt / ambiguous), and free text.

- **The ingress filter is tri-state** — off → include → exclude → off — with an `Any / All` mode over
  the includes. Exclusion is always AND-NOT and always wins. Every other multi-valued dimension
  follows the same grammar.
- **Auth method is single-valued** and gets no Any/All: a service has one posture.
- Free text searches names, images, hostnames, router names, label keys and **env var keys** — never
  env var values, masked or not (I6).
- Active filters MUST be shown as individually removable chips with a clear-all, the result count
  MUST always be visible, and an empty result MUST name the filter to remove.
- Filtering never mutates the payload and never changes a count shown elsewhere as a total.

### 22.7 View state is a shareable URL

Every view, filter, diagram selection, drawer and panel MUST be expressible as a query string, and
reading one back MUST reproduce that state. The grammar is contract even though the view set is not:

| Parameter | Holds |
|---|---|
| `view` | the view slug; omitted for the overview |
| `q` | free text |
| `ingress`, `auth`, `conf`, `state`, `health`, `probe`, `decl`, `match` | tag filters |
| `stack`, `net` | scope to one stack or one network |
| `exposed`, `accepted`, `drift` | boolean narrowings |
| `diagram`, `focus`, `depth` | which diagram, what it is focused on, at what depth |
| `panel`, `svc` | the open panel and the open drawer |

- Parameters are written in a **fixed order** — the table's order — and defaults are **omitted**, so
  an untouched dashboard has an empty query and the same view always spells the same string.
- A tag filter is **one** parameter: `all:public,lan,-internal`. `-` prefixes an exclusion; the mode
  prefix is `all:` or `any:` on the way in, and only `all:` is ever written out. A tag outside the
  dimension's vocabulary is **dropped**, because a filter with no chip is a view with no way back.
- Booleans are written as `1`, and only the exact string `"1"` reads back as true.
- Free text is capped at **200** characters and stripped of control code points — everything below
  `0x20` plus `0x7f`, and **nothing else**, so a Cyrillic container name or an emoji in a label
  survives.
- **Everything read out of a URL is attacker-supplied.** Enumerations are checked against their
  literals, so there is no such thing as an invalid LabView URL — only one that describes less than
  it meant to.
- A history entry is pushed on **navigation-scale** change only — view, drawer, panel or diagram
  focus. A keystroke in the search box is not something Back should undo.

### 22.8 Degraded states are part of the UI

Nothing may render as a bare empty table (I4):

| Situation | What the reader sees |
|---|---|
| Docker disabled or unreachable | runtime columns read *not read*, **never** *stopped*; the Containers view explains the socket mount and links to Diagnostics |
| an integration disabled or not configured | the view says which setting turns it on, and what it would add |
| an integration reachable but `partial` | the rows it did read, plus a banner naming what is missing and the fix (§15) |
| the probe off, or nothing eligible | the Probe view explains the switch, and that a service with a detected gate is deliberately not asked |
| an optional count absent | *not reported*, with what would supply it |
| a failed connection | a banner on every affected view, linking to Diagnostics — shown for `partial` and for any failure whose phase is neither `disabled` nor `not-configured` |
| first load, scan in flight | a loading state; the health route never waits on a scan (§18) |
| login enforced, no session | the login form, served from public assets with no fleet data in them (§19) |

---

## 23. Test corpus

One test entry point MUST run the **full pipeline** — the real scan over real fixture files, with
the Docker, identity-provider, proxy and probe transports injected — over the seven roots below,
and then assert classifications. It gates CI. The harness's shape, output format and assertion
style are free.

**Hermeticity is not.** The corpus MUST run with Docker disabled, with configuration-file loading
forced to defaults, and with **every** `LABVIEW_AUTHENTIK_*`, `LABVIEW_TRAEFIK_*`,
`LABVIEW_PROBE_*`, `LABVIEW_AUTH_*` and `LABVIEW_OIDC_*` variable removed from the environment
before anything reads configuration, and the proxy read explicitly disabled. An operator's exported
credentials MUST be unable to make the corpus reach the network or change what it asserts — the
proxy read and the probe would otherwise issue real requests to addresses taken out of the *fixture*
compose files. The LAN probe host is `192.0.2.10` (I2).

| Root | What it pins |
|---|---|
| `fixtures/apps` | a representative happy-path fleet — an identity provider, a proxy, and four ordinary applications |
| `fixtures/edge` | one directory per previously-fixed defect (18) — interpolation, expose-only, host-port ties, tunnel origins, shared networks, sidecar variants, containment escape, declaration comparison, stale and partial drift |
| `fixtures/nets` | what *connects* two services vs what merely lets them reach each other: one `external:` network across four stacks, sidecar-declared dependencies, a co-member declaring nothing, every way a reference can fail, a dependency with no shared network, and both kinds of single-service network |
| `fixtures/authentik` | the identity-provider integration through an injected transport, with canned API responses |
| `fixtures/traefik` | the proxy integration the same way. Its canned responses **also** carry the identity-provider payload, because the three-way cross-check reads all three sources at once |
| `fixtures/probe` | 18 answer shapes, one address per fixture that the stub is keyed on. Canned answers are held as code, not as a payload document, because a probe reads a status, three headers and a fragment of HTML |
| `fixtures/auth` | not a fleet: a good, a messy and an empty passwd file for LabView's own login |

Plus two files outside the scan root — one environment file and one sidecar — which exist to be
**refused** by containment (I8).

**The fixture-revert contract.** Every fixture exists because a rule exists, and **every fixture
MUST fail if its rule is reverted** — a fixture that still passes against the old behaviour is
documentation, not a test. Two probe fixtures are deliberate traps, and MUST come out the opposite
way from the case they sit next to: a public portal whose only login-shaped signal is a
`/auth/`-prefixed *logout* link, and a passwordless page whose form posts cross-origin to a
newsletter service.

Beyond the roots, the pure rules MUST be asserted as **tables of literals** rather than through
fixtures wherever they can be: the eight probe gate signals, login-form field detection, the probe
reason wording, the state-challenge rule, the login and not-a-login label vocabularies, the four
declaration-comparison outcomes, sidecar validation warnings, the view-state round trip, tag
filtering, both phase mappings (transport error and HTTP status), posture resolution, and session
signing and verification.

Two summary lines are *examples of wording*, but **their numbers are required conclusions** for
their fixture roots:

- *14 of 16 applications (2 recovered from providers), 17 providers, 2 outposts*
- *37 requests: one for each of the 20 services asked, one fallthrough, and 16 second requests*

**Three checks belong to the UI** and MUST also gate CI:

1. **Payload coverage** (§22.1). A checked-in list of every Appendix A field path, each mapped to the
   view or drawer section that renders it. A field present in the schema and absent from the list —
   or mapped only to the raw subtree view — MUST fail. This is what keeps *collected but unviewable*
   from happening as the payload grows.
2. **Card destinations** (§22.3). For each `stats` counter: the card exists, it is a link, and its
   destination selects exactly that many rows against a fixture payload. A count that disagrees with
   its destination MUST fail.
3. **Diagram export** (§22.5). The text export for each of the four diagrams over `fixtures/nets` is
   asserted as a literal, which pins both determinism and the edge rules — a `service → service`
   edge only where `via` is empty, and no line from co-membership alone.

---

## Appendix A — Payload schema

This is the wire contract. **Field names and union members are exact**; the notation is not.
`str` `num` `bool` are scalars, `T[]` a list, `map[str]T` an object keyed by string, `X?` a field
that MAY be omitted — and whose absence is meaningful (§16). Unions are written as their member
literals and are **closed**: a consumer receiving an unlisted member is receiving a different
protocol (§16). Member semantics are in §4.

```text
Overview       { meta: ScanMeta, stats: OverviewStats, stacks: AppStack[], graph: Graph }
ScanRequest    { probe?: bool }                          // POST /api/rescan body

ScanMeta       { scannedAt: str, appsRoot: str, dockerAvailable: bool, dockerError?: str,
                 authentik?: AuthentikSummary, traefik?: TraefikSummary,
                 connections: ConnectionReport[], probe: ProbeRun,
                 durationMs: num, warnings: str[], build: BuildStamp }
ProbeRun       { enabled: bool, source: "config"|"request", skipped: num }
BuildStamp     { version: str, commit?: str, source: "image"|"checkout"|"unknown" }

OverviewStats  { stacks, services, running,
                 publicServices, traefikServices, lanServices, internalServices,
                 noIngressServices,
                 authProtected, exposedWithoutAuth, byAuthMethod: map[str]num,
                 declaredAuth, declaredAuthProtected, declaredAuthUnconfirmed,
                 exposureAccepted, declarationDrift, declaredDependencies,
                 probeGated, probeOpen,
                 networks, connectingNetworks, crossStackNetworks, soloLocalNetworks }
                 // every field num; byAuthMethod is keyed by AuthMethod
```

```text
AppStack       { id: str, name: str, dir: str, composeFile: str, hasEnvFile: bool,
                 projectName: str, services: Service[],
                 declaredNetworks: NetworkDecl[], declaredVolumes: VolumeDecl[],
                 declared?: Declaration, warnings: str[] }
NetworkDecl    { name: str, external: bool, driver?: str }
VolumeDecl     { name: str, external: bool, driver?: str }

Service        { name: str, containerName: str, image?: str, restart?: str, command?: str,
                 dependsOn: str[], networks: str[], ports: PortMapping[], expose: str[],
                 mounts: MountSpec[], env: EnvVar[], labels: map[str]str,
                 cloudflare: CloudflareRoute[], traefik: TraefikRoute[],
                 ingress: IngressKind[], auth: AuthPosture,
                 docker?: DockerState, authentik?: AuthentikMatch,
                 traefikLive?: TraefikLiveRouter[], declared?: ServiceDeclaration,
                 probe?: ServiceProbe, notes: str[] }

EnvVar         { key: str, value: str|null, masked: bool,
                 source: "env_file"|"environment"|"shell-default" }
PortMapping    { published?: str, target: str, protocol: str, raw: str }
MountSpec      { type: "bind"|"volume"|"tmpfs"|"npipe"|"unknown",
                 source?: str, target: str, readOnly: bool, raw: str }
DockerState    { id: str, name: str, image: str, imageDigest?: str,
                 state: str, status: str,
                 health?: "healthy"|"unhealthy"|"starting"|"none",
                 running: bool, restartCount?: num, createdAt?: str, startedAt?: str,
                 networks: str[], ipAddresses: map[str]str, publishedPorts: PortMapping[] }
```

```text
IngressKind    "public"|"traefik"|"lan"|"internal"|"none"
AuthMethod     "authentik-forward-auth"|"authentik-oauth"|"authentik-ldap"|"forward-auth"
               |"other-oauth"|"ldap"|"basic-auth"|"none"
AuthConfidence "confirmed"|"observed"|"inferred"
AuthPosture    { method: AuthMethod, detail: str, evidence: str[],
                 confidence: AuthConfidence, exposedWithoutAuth: bool }

CloudflareRoute{ hostname: str, service: str, path?: str,
                 access?: { group?: str, policy?: str, emails?: str[] },
                 noTlsVerify?: bool, raw: map[str]str, origin?: OriginTarget }
OriginTarget   { address: str, host: str, port: str, kind: OriginKind,
                 hopKey?: str, evidence: str }
OriginKind     "self-network"|"self-host-port"|"fleet-service"|"unresolved"

TraefikRoute   { router: str, rule?: str, hosts: str[], pathPrefixes: str[],
                 entrypoints: str[], tls: bool, certResolver?: str,
                 middlewares: str[], servicePort?: str, service?: str }
```

```text
AuthentikProviderKind  "proxy"|"oauth2"|"ldap"|"saml"|"radius"|"scim"|"other"
AuthentikProvider      { name: str, kind: AuthentikProviderKind, rawKind: str, mode?: str,
                         internalHost?: str, externalHost?: str, redirectUris?: str[],
                         backchannel: bool, outposts: str[] }
AuthentikApplication   { name: str, slug: str, group?: str, launchUrl?: str,
                         providers: AuthentikProvider[],
                         discoveredVia: "list"|"provider" }
AuthentikMatchStrength "address"|"hostname"|"name"          // absent reads as "name"
AuthentikMatch         { applications: AuthentikApplication[], evidence: str[],
                         strength: AuthentikMatchStrength[] }   // three parallel arrays
UnmatchedReason        "ambiguous"|"no-candidate"|"internal"
UnmatchedApplication   { application: AuthentikApplication, reason: UnmatchedReason,
                         detail: str, considered: str[] }
AuthentikSummary       { enabled: bool, configured: bool, reachable: bool,
                         endpoint?: str, endpointSource?: "config"|"discovered", error?: str,
                         applications: num, applicationsConfigured?: num,
                         applicationsWithheld: num, applicationsRecovered: num,
                         providers: num, outposts: num, matchedServices: num,
                         unmatchedApplications: UnmatchedApplication[] }
```

```text
TraefikLiveMiddleware  { name: str, type: str, address?: str, errors: str[],
                         viaChain?: str, viaEntrypoint?: bool }
TraefikLiveServer      { url: str, status?: str }        // absent status = nothing known
TraefikLiveRouter      { router: str, provider: str, status?: str, errors: str[], rule?: str,
                         hosts: str[], entryPoints: str[],
                         middlewares: TraefikLiveMiddleware[], service?: str,
                         servers: TraefikLiveServer[], tls: bool, evidence: str[] }
UnmatchedRouter        { router: TraefikLiveRouter, reason: UnmatchedReason,
                         detail: str, considered: str[] }
TraefikSummary         { enabled: bool, configured: bool, reachable: bool,
                         endpoint?: str, endpointSource?: "config"|"discovered",
                         credential: "none"|"basic", version?: str, entrypointsRead: bool,
                         error?: str, routers: num, middlewares: num, services: num,
                         matchedServices: num, unmatchedRouters: UnmatchedRouter[] }
```

```text
ConnectionPhase   "disabled"|"not-configured"|"not-found"|"credential"|"resolve"|"connect"
                  |"tls"|"timeout"|"authenticate"|"authorize"|"path"|"status"|"protocol"
                  |"partial"|"connected"
ConnectionAttempt { endpoint: str, why: str, phase: ConnectionPhase, code?: str, detail: str }
ConnectionReport  { target: str, ok: bool, phase: ConnectionPhase, endpoint?: str,
                    source?: "config"|"discovered"|"default", detail?: str, code?: str,
                    hint?: str, read?: str, attempts: ConnectionAttempt[] }
```

```text
ProbeVantage   "public"|"traefik"|"lan"
ProbeGate      "challenge"|"redirect-origin"|"redirect-login"|"meta-refresh-login"
               |"sso-form"|"password-form"|"credential-form"|"state-challenge"
ProbeRedirect  { to: str, crossOrigin: bool }
ProbeState     { asked: num, refusedAt?: str, status?: num, challenge?: bool }
ProbeAnon      { textChars: num, links: num, loginHref?: str, loginLabel?: str }
LoginFormShape { password: bool, username: bool, submit: bool, otp: bool, action?: str }
ServiceProbe   { endpoint: str, vantage: ProbeVantage, phase: ConnectionPhase, status?: num,
                 gate?: ProbeGate, mediaType?: str, redirect?: ProbeRedirect,
                 refresh?: ProbeRedirect, truncated?: bool, form?: LoginFormShape,
                 state?: ProbeState, anon?: ProbeAnon,
                 detail: str, attempts: ConnectionAttempt[] }
                 // no WWW-Authenticate field: a 401 without gate "challenge" already
                 // means the header was absent
```

```text
DeclaredAuthMechanism    "app-local-accounts"|"app-ldap"|"app-oidc"|"app-saml"|"app-token"
                         |"mtls"|"network-restricted"|"external-proxy"|"other"
DeclaredAuthAgreement    "supplies"|"redundant"|"conflicts"|"supplements"
DeclaredAuth             { mechanism: DeclaredAuthMechanism, detail?: str }
DeclaredLink             { label: str, url: str }
DeclaredDependency       { name: str, detail?: str }
DeclaredServiceDependency{ ref: str, detail?: str }
Declaration              { file: str, description?: str, owner?: str, criticality?: str,
                           notes?: str, data?: str,
                           links: DeclaredLink[], dependencies: DeclaredDependency[] }
ServiceDeclaration       = Declaration + { auth: DeclaredAuth[],
                           dependsOn: DeclaredServiceDependency[],
                           unauthenticatedAccepted?: { reason: str },
                           expectedIngress?: IngressKind[],
                           drift: str[], unconfirmed: str[],
                           authAgreement?: DeclaredAuthAgreement }
```

```text
NetworkScope   "external"|"stack-local"
GraphNode      { id: str, label: str, kind: "service"|"network"|"volume"|"external",
                 stack?: str, auth?: AuthMethod, ingress?: IngressKind, running?: bool,
                 role?: "proxy", scope?: NetworkScope,
                 memberCount?: num, stackCount?: num }
GraphEdge      { id: str, source: str, target: str,
                 kind: "network"|"depends_on"|"volume"|"ingress"|"auth", label?: str,
                 flow?: "to-network"|"to-service"|"both",
                 flowSource?: "observed"|"declared"|"both",
                 declaredBy?: { file: str, detail?: str }, via?: str[] }
Graph          { nodes: GraphNode[], edges: GraphEdge[] }
```

```text
LoginMethod        "passwd"|"oidc"
LoginFailureReason "credentials"|"throttled"|"method-unavailable"|"session-expired"
                   |"oidc-state"|"oidc-provider"|"oidc-token"|"oidc-identity"
AccessMode         { enforced: bool, methods: LoginMethod[], notes: str[] }
                   // enforced == methods is non-empty
SessionInfo        { enforced: bool, methods: LoginMethod[], notes: str[],
                     user?: { name: str, via: LoginMethod }, oidcLabel?: str }
```

Four closed sets in §4 are **derived, not payload fields**, and appear only in rendered text:
`NoAuthReason`, `AuthFamily`, `NetworkRelation` and the session-rejection reasons. They are
nonetheless contract, because §14, §16 and §19 assert conclusions in their terms.
