# LabView

A self-hosted overview of a Docker-Compose homelab. Point it at the directory
where your per-container stacks live (`/mnt/apps/<container>/compose.yml`, with
optional `.env` files) and it produces a structured website showing **every app,
how it's set up, how it's reached, what protects it, and how everything is wired
together**.

It understands a specific, common TrueNAS Scale pattern:

- **Public ingress via a Cloudflare tunnel**, configured with **DockFlare**
  labels (`dockflare.hostname`, `dockflare.service`, …).
- **Proxy ingress via Traefik**, configured with `traefik.*` labels (routers,
  rules, entrypoints, TLS, middlewares) — and, when its API answers, checked
  against the runtime config Traefik actually built from them.
- **SSO via Authentik** — as a Traefik **forward-auth** middleware
  (`authentik@docker`), or via **OAuth/OIDC** or **LDAP** wired through a
  service's environment.

None of it is required, and none of it is hard-coded. Every hostname, container
name and network name is read from your files or discovered from your fleet at
scan time; a stack with none of those labels is reported just as accurately, and a
fleet running a different SSO provider is described by mechanism rather than
mislabelled with a vendor it never mentions.

LabView reads all of that from your compose files, optionally enriches it with
live state from the Docker API, and never needs an agent inside each app.

---

## What you get

- **Dashboard** — stat tiles (stacks, services, running, public, LAN,
  no-ingress, auth-protected, and a highlighted **exposed-without-auth** count),
  a per-tag gauge for each of the five **ingress** kinds, and a part-to-whole bar
  for **authentication method**. Ingress gets gauges rather than one bar because a
  service can be several things at once, so the segments would sum past the total.
  Every row doubles as a filter: click once to require the tag, again to exclude
  it (`¬ Internal`, struck through), a third time to clear it. An `Any` / `All`
  switch decides whether the required tags are OR'd or AND'd, exclusions are
  always AND-NOT, and a line beside `Clear filters` reads the whole expression
  back — `ingress: all of Public, LAN; not Internal` — so a three-part filter
  never has to be inferred from which chips look bright. Where a `.labview` has gone
  out of date the tiles carry a **declaration drift** count too, and that one is a
  button: it opens a panel naming every drifting service under its stack, with the
  file it was declared in and each disagreement spelled out, and each row opens that
  service's own drawer.
- **Stack list** — one card per stack, which is the unit you actually deploy. It
  rolls up its services: live status dots, hostnames, every distinct **ingress** tag and
  **auth mechanism** present, and a count of anything reachable without auth. A missing
  gate is not a mechanism and gets no badge — that count is where it is reported, and only
  for services something outside the container network can reach. Click to
  expand the services underneath, and again on one to open its detail. Search and
  filters are per service — exposure is a property of a service, not of a directory
  — and a stack shows up whenever one of its services matches.
- **Detail drawer** — for each service: a **Mermaid diagram** of its connections,
  Cloudflare routes **with what each origin resolves to and why**, Traefik routers
  (rule, hosts, entrypoints, TLS, middlewares), the **live routers Traefik reports
  serving it** when its API was read (status, entrypoints, the resolved middleware
  chain, and each backend with the health Traefik itself reports for it), the
  **derived auth posture with the evidence that led to it**, the matched
  **Authentik applications and providers** when that API was read (including which
  outpost, if any, is actually serving each one), **each network it is on, what it
  depends on across that network, and who else is merely attached** — the two are
  separate lists, because sharing a network means reachable and nothing more; the
  diagram draws only the dependencies, each a link to that service, marked where the
  dependency was declared rather than read from a compose file — ports, volumes,
  environment (secrets masked), and live container state. A network with nothing else on
  it says which kind of nothing that is: no other scanned service, on a network external
  to the scan, is not the same answer as a network only this stack could ever join.
- **Relationship graph** — an interactive [cytoscape](https://js.cytoscape.org/)
  graph of the whole fleet: services colored by exposure, plus network, volume,
  and tunnel / proxy / SSO hub nodes, connected by network membership,
  `depends_on` — from a compose file or from a sidecar, the declared ones **dashed**,
  since a declaration is a statement and not an observation — shared volumes, ingress,
  and auth edges. This is the one view where a membership spoke is drawn for its own
  sake: it is the fleet's membership picture, and an arrowhead is what marks the
  spokes a dependency actually crosses. Click a service to open
  its detail. A hub appears only when something observed calls for it — and an
  SSO gate whose provider could not be identified gets its own generic hub rather
  than being drawn as a vendor. Tunnel ingress is drawn as the path the config
  describes: where a route's origin resolves to another service, that service is
  drawn as the hop (`tunnel → proxy → service`) and highlighted as the
  infrastructure it was observed to be.

  **Services are connected *through* their networks, with the network drawn in
  between.** A network is not a label hanging off one service, and a dependency is not
  a line straight between two containers — both hide half the answer. So an
  `external:` network shared by several stacks is **one** node with a spoke from every
  service on it, labelled with how many services and stacks it joins, and a `depends_on`
  is drawn as arrowheads on the two spokes either side of the network that carries it:
  `web ──▶ (net: app_inner) ──▶ api`. A row of databases in separate stacks and the one
  service that backs them all up declare nothing about each other — compose cannot
  express that across projects — and they still show up joined, because the network they
  share is the relationship. Where a `depends_on` pair shares *no* network
  the direct line is kept and the service says why: docker orders the startup, but
  neither container can reach the other. Networks that connect nothing are counted
  rather than drawn, and a network with more members than fits states how many spokes
  it left out.
- **Networks** — one collapsible row per network that connects something, on the
  overview: its scope (external, or created by one stack), how many services and stacks
  it joins, every service on it as a chip that opens that service's drawer, and each
  dependency it carries written out — `web depends on api over this network`. This is
  the list answer to "who else is on this network", which no graph layout answers well,
  and it is what disambiguates a busy hub the arrowheads alone cannot. Clicking a
  network node in the graph jumps to its row.
- **Integration panel** — the `authentik: 13 apps · 9 matched` and
  `traefik: 10 routers · 8 matched` counts in the topbar are buttons, because a count
  states an outcome and hides the two questions behind it. Click one for the whole
  join: every matched pair, with the evidence and how firmly the match was made
  (`address`, `hostname` or `name`), and every application or router that could **not**
  be placed — each with its reason (`ambiguous` where two services claim it,
  `no-candidate` where nothing did), a one-line why, and the rule-by-rule trace of what
  was tried. Clicking a matched row closes the panel and opens that service's own
  drawer. When the integration is unreachable the pill shows the failed stage and the
  same panel opens on the failure: what failed, the address, every candidate that was
  tried with its own stage, and the suggested fix. `Escape` closes the panel first, the
  service drawer second.
- **Rescan** — re-reads every `compose.yml` and `.env` under the apps root *and*
  re-runs both API exchanges, then reports what moved on each side, inline beside
  `scanned <time>`: `+1 stack, 2 services changed · authentik +2 applications`, with
  the names on hover. New stacks, deleted stacks, added services and edited files all
  show up in the first note; applications, providers, routers and middlewares that
  came or went show up in the second. Live state changing on its own does not appear
  in either. When everything is the same as last time it says so — `no config changes
  · authentik and traefik unchanged` — rather than leaving you to guess whether it
  looked.
- **Light / dark** theme (follows the OS, with a manual toggle).

Colors follow a validated, colorblind-safe palette. The ingress and auth-method
hue orderings were run through a CVD/contrast validator in **both** light and
dark modes (adjacent segments stay distinguishable for colorblind viewers);
low-contrast segments always carry a direct text label, and status colors always
ship with an icon and label, never color alone.

---

## Quick start (local)

```bash
cd labview
npm install
npm run build            # bundles the web UI + compiles the server
LABVIEW_APPS_ROOT=/path/to/your/apps npm start
# open http://localhost:8080
```

Live state comes from `/var/run/docker.sock` by default, so a local run needs no
extra setup — and if the socket isn't reachable the scan degrades cleanly to
config-only. To read the Engine over TCP instead (a socket proxy, typically), name
the endpoint:

```bash
LABVIEW_APPS_ROOT=/path/to/your/apps LABVIEW_DOCKER_HOST=tcp://your-proxy:2375 npm start
```

Just want a one-shot report on the terminal (no server)?

```bash
LABVIEW_APPS_ROOT=/path/to/your/apps npm run scan -- --summary
```

That digest counts the stacks and services it found, what is reachable and from where,
and the outcome of each optional API read. Its `networks:` line counts every real docker
network, then how many of them carry two or more services and how many span two or more
stacks — the difference between a fleet full of networks and a fleet where networks
connect things. Without `--summary` the same scan prints the whole `Overview` as JSON.

Live-reloading development:

```bash
npm run dev              # esbuild --watch for the UI + tsx server with reload
```

---

## Deploy on TrueNAS Scale

LabView runs as one more container next to the apps it inspects. Mount your stacks
**read-only** and — recommended — read live Docker state through a
[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) over TCP,
so LabView never touches the raw socket. It never writes anything either way.

**Prerequisites:** a reverse-proxy network to join, plus (for live state) a
socket-proxy container and its network. LabView only needs the proxy's read
endpoints (`CONTAINERS`, `NETWORKS`, `VOLUMES`, `IMAGES`, `INFO`, `PING`). The
names used below — `proxy`, `dockerproxy`, `/mnt/apps` — are this example's; use
whatever yours are called.

1. Copy this `labview/` directory to your box, e.g. to
   `/mnt/apps/labview/`.
2. Review [`compose.yml`](compose.yml) — the example mounts `/mnt/apps` →
   `/data/apps:ro`, reaches Docker via a socket proxy, and joins a reverse-proxy
   network. It deliberately publishes **no** host port: reach it through your
   proxy so the SSO middleware actually applies (see below).
3. Deploy it one of two ways:
   - **Apps → Custom App → Install via YAML**, pasting the compose file, or
   - drop it at `/mnt/apps/labview/compose.yml` and run
     `docker compose up -d` (it builds the image locally).

```yaml
services:
  labview:
    build: .
    container_name: labview
    restart: unless-stopped
    environment:
      LABVIEW_APPS_ROOT: /data/apps
      # Whatever your socket-proxy container is called. Omit to use
      # /var/run/docker.sock (then mount it read-only).
      LABVIEW_DOCKER_HOST: tcp://dockerproxy:2375
      LABVIEW_PORT: "8080"
    volumes:
      - /mnt/apps:/data/apps:ro
    # No `ports:` — a published port answers directly at <host-ip>:<port>,
    # bypassing Traefik and therefore the Authentik middleware below.
    networks:
      - default
      - proxy
      - dockerproxy

networks:
  proxy:
    external: true
  dockerproxy:
    external: true
```

To run **config-only** (no live state), set `LABVIEW_DOCKER_ENABLED: "false"`
and drop the `dockerproxy` network.

### Put it behind your own edge (recommended)

LabView exposes your topology and (masked) config, so don't publish it raw. It has a
login of its own — off until you configure it, see [Access control](#access-control) —
and an edge is still the recommendation: it gets you the same SSO, the same audit trail
and the same certificate as everything else in the fleet, and the two are complementary
rather than alternatives. Expose it the same way as your other apps by adding labels;
[`compose.yml`](compose.yml) has a ready-to-adapt example for
**Traefik + Authentik forward-auth** and/or **DockFlare**:

```yaml
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=proxy"
      - "traefik.http.routers.labview.rule=Host(`labview.example.com`)"
      - "traefik.http.routers.labview.entrypoints=websecure"
      - "traefik.http.routers.labview.tls.certresolver=cloudflare"
      - "traefik.http.routers.labview.priority=100"
      - "traefik.http.routers.labview.middlewares=authentik@docker"
      - "traefik.http.services.labview.loadbalancer.passhostheader=true"
      - "traefik.http.services.labview.loadbalancer.server.port=8080"
      # And/or via the Cloudflare tunnel. Point the origin at Traefik, not at
      # this container — `dockflare.service=http://labview:8080` would put the
      # dashboard on the internet with the SSO middleware skipped entirely.
      - "dockflare.enable=true"
      - "dockflare.hostname=labview.example.com"
      - "dockflare.service=https://<traefik-host-ip>"
```

Two things LabView will tell you about itself once it is running: if you publish a
host port it picks up the `lan` tag alongside whatever else it has, and if you point
a tunnel origin straight at a container it shows up with no auth even though the
Traefik route looks protected.

---

## Configuration

Everything works out of the box. To tune, copy
[`config.example.yml`](config.example.yml) to `config.yml` (or point
`LABVIEW_CONFIG` at it). Environment variables override the file:

| Variable | Default | Purpose |
|---|---|---|
| `LABVIEW_APPS_ROOT` | `/data/apps` | Root directory of your stacks |
| `LABVIEW_DOCKER_ENABLED` | `true` | Enrich with live Docker state |
| `LABVIEW_DOCKER_HOST` | *(unset)* | Docker API endpoint. Accepts `tcp://host:port`, `host:port`, or a `unix://`/absolute socket path. Unset = the socket path below. The standard **`DOCKER_HOST`** is honoured too; `LABVIEW_DOCKER_HOST` wins when both are set |
| `LABVIEW_DOCKER_PORT` | `2375` | TCP port (when the host has no port) |
| `LABVIEW_DOCKER_SOCKET` | `/var/run/docker.sock` | Socket path. Setting it always wins and disables the TCP host |
| `LABVIEW_DOCKER_MAX_CONCURRENCY` | `8` | Max concurrent container inspects per scan |
| `LABVIEW_DOCKER_TIMEOUT` | `5000` | Per-request socket-inactivity timeout, ms. Reset whenever bytes arrive, so a large fleet's listing is unaffected; it exists to turn an endpoint that accepts the connection and then says nothing into a reported `timeout` |
| `LABVIEW_PORT` | `8080` | HTTP port (container-internal) |
| `LABVIEW_HOST` | `0.0.0.0` | Bind address |
| `LABVIEW_CACHE_TTL` | `60` | Seconds a scan is cached before refresh; Rescan ignores it |
| `LABVIEW_MASK_SECRETS` | `true` | Mask secret-looking env values |
| `LABVIEW_CONFIG` | `config.yml` | Path to a config file |
| `LABVIEW_AUTHENTIK_ENABLED` | `true` | Whether to read the Authentik API at all. With no token it does nothing either way |
| `LABVIEW_AUTHENTIK_TOKEN` | *(unset)* | A read-only API token. Set it to confirm auth posture from the provider itself; leave it unset and nothing is requested. See [Where the credentials go](#where-the-credentials-go) |
| `LABVIEW_AUTHENTIK_URL` | *(discovered)* | Base URL incl. scheme and port, e.g. `http://authentik-server:9000`. Needed only when Authentik is outside `appsRoot` or discovery picks the wrong endpoint |
| `LABVIEW_AUTHENTIK_TIMEOUT` | `5000` | Per-request timeout, ms. On timeout the scan continues without the API |
| `LABVIEW_TRAEFIK_ENABLED` | `true` | Whether to read the reverse proxy's API at all. Needs no credential and no configuration; if nothing answers the scan continues from the labels |
| `LABVIEW_TRAEFIK_URL` | *(discovered)* | Base URL incl. scheme and port, e.g. `http://traefik:8080`. Needed only when the proxy is outside `appsRoot` or discovery picks the wrong endpoint |
| `LABVIEW_TRAEFIK_USERNAME` | *(unset)* | Only for an API reachable solely through an Authentik-gated hostname: an Authentik user, or the reserved `goauthentik.io/token` |
| `LABVIEW_TRAEFIK_PASSWORD` | *(unset)* | That user's **app password** — not an API token, see [`config.example.yml`](config.example.yml). See [Where the credentials go](#where-the-credentials-go) |
| `LABVIEW_TRAEFIK_TIMEOUT` | `5000` | Per-request timeout, ms. On timeout the scan continues from the labels alone |

The default Docker endpoint is the conventional local socket, since it is the one
endpoint that needs no assumption about your container names; a socket proxy is
opted into with `LABVIEW_DOCKER_HOST`.

The config file also controls the secret key-patterns, the DockFlare/Traefik
label prefixes, and the Authentik detection hints — see the comments in
`config.example.yml`. Your own SSO hostnames do **not** belong in those hints:
they are discovered from your fleet at scan time (see below), and adding a
host-naming convention like `auth.` is how unrelated providers get mislabelled.

### Where the credentials go

LabView has four single-value credentials, and each one comes from an environment
variable: `LABVIEW_AUTHENTIK_TOKEN`, `LABVIEW_TRAEFIK_PASSWORD`,
`LABVIEW_OIDC_CLIENT_SECRET` and `LABVIEW_SESSION_SECRET`. Keep the values in a
`.env` file beside `compose.yml` and name them in the compose file:

```yaml
environment:
  LABVIEW_AUTHENTIK_TOKEN: ${LABVIEW_AUTHENTIK_TOKEN:-}
  LABVIEW_SESSION_SECRET: ${LABVIEW_SESSION_SECRET:-}
```

```dotenv
# .env, beside compose.yml, not in version control
LABVIEW_AUTHENTIK_TOKEN=ak-...
LABVIEW_SESSION_SECRET=...
```

Yes, a value in the environment is readable with `docker inspect`. That is worth
knowing and is narrower than it sounds: `docker inspect` needs the Docker socket,
and anyone holding that is already root-equivalent on the host — they can read a
mounted secret file just as easily. The exposure a `.env` **does** close is the one
that actually bites, which is a compose file committed to a repository with a
credential inside it.

Two consequences of naming a variable rather than pointing at a path:

- **A name with no value is reported, not guessed at.** `${LABVIEW_AUTHENTIK_TOKEN:-}`
  with no matching `.env` entry arrives as an empty variable, which LabView reports
  as *set and carries nothing* — a `credential` fault on that integration, or a
  startup note for its own login. It does not stop the container from starting,
  which is why the compose examples use `:-` and not `:?`.
- **Rotating one needs a restart.** An environment variable is fixed for the life of
  the process. `docker compose up -d labview` after editing `.env` is the whole
  procedure. The one credential still read from a path is `auth.passwd.file`, the
  `user:hash` database — it is re-read on change, because a user list is edited over
  the life of an install rather than set once.

An earlier version of LabView also accepted `LABVIEW_AUTHENTIK_TOKEN_FILE`,
`LABVIEW_TRAEFIK_PASSWORD_FILE`, `LABVIEW_OIDC_CLIENT_SECRET_FILE` and
`LABVIEW_SESSION_SECRET_FILE`, along with `tokenFile`, `passwordFile`,
`clientSecretFile` and `secretFile` in `config.yml`. None of them is read now. If one
is still set, LabView says so at startup and names the variable to move the value
to, rather than ignoring it and leaving you with a provider that refuses every
sign-in for no visible reason.

### The Authentik API token

Optional. Without it, auth posture is derived from labels and env vars alone;
with it, LabView reports what Authentik itself says about each gate.

Create a **service account** in Authentik (*Directory → Users → Create service
account*), leave it out of every group, and grant only three global permissions:
`view_application`, `view_provider`, `view_outpost`. Then issue a token for it and
put it in the `.env` beside your compose file:

```yaml
environment:
  LABVIEW_AUTHENTIK_TOKEN: ${LABVIEW_AUTHENTIK_TOKEN:-}
```

LabView only ever issues `GET`s, so anything beyond those three permissions is
authority an attacker who reached this container would inherit for free.

**Why the app count may be lower than Authentik's own.** `/core/applications/`
filters its answer through the policy engine as the requesting user, so a
least-privilege service account is served only the applications it is allowed to
launch. LabView reads the total Authentik reports for that endpoint alongside the
subset it was handed, and rebuilds the missing ones from the providers assigned to
them — the provider endpoints are not policy-filtered, and every provider names its
application. A rebuilt application is marked `rebuilt` in the drawer, because the
record is thinner: no launch URL and no group, and only the providers this token can
read. Anything neither returned nor rebuildable is stated as a count in the banner
rather than left out of the total.

Two ways to close that gap, both optional. Grant the service account the policies it
needs to see the applications in question, or make it a **superuser** — LabView asks
for the full list on every scan, and a superuser token is given it verbatim, so
nothing is withheld and nothing needs rebuilding. Neither is required; the three
`view_*` permissions remain the recommendation, and the shortfall is reported rather
than hidden.

The endpoint is discovered when Authentik runs among the scanned stacks: LabView
finds it by image, then tries its **container address first** and public hostnames
only after, so the exchange stays on the container network. Discovery probes each
candidate on `/api/v3/root/config/`, which needs no authentication, and sends the
token only to a candidate that answers as an Authentik API — so a wrong guess
never receives a credential. Set `LABVIEW_AUTHENTIK_URL` when Authentik lives
outside `appsRoot`.

If your instance serves HTTPS with a private CA, point `NODE_EXTRA_CA_CERTS` at
the CA. There is deliberately no option to skip certificate verification: a bearer
token sent to an unverified endpoint is a token handed over.

Every failure here is soft. An unreachable host, a rejected token, a timeout or a
malformed response leaves the scan running on label-derived evidence, with the
reason reported in `meta.authentik.error` and in the UI.

### The Traefik API

On by default, and in the recommended setup it needs no credential and no
configuration at all. Labels say what you asked the proxy for; only the proxy knows
what it built, and three differences are invisible to a compose scan:

- a **router the labels declare that Traefik is not serving** — a typo in a rule, a
  missing entrypoint, a container it never picked up;
- a **middleware named in a label that is not in the chain the proxy built**, so the
  service reads "protected" here and answers without a login;
- a **middleware defined in a Traefik file provider**, which has no definition
  anywhere in the scanned stacks and is therefore only ever `inferred`.

LabView reads `/api/version`, `/api/rawdata` and `/api/entrypoints` — three GETs,
no writes, no pagination — and replaces all three guesses with Traefik's own
account at `confirmed` confidence.

**Enabling it safely.** Give the API its own entrypoint on the container network and
do **not** publish that port:

```yaml
# traefik static config
api: {}                       # not `api.insecure` on a published port
entryPoints:
  traefik:
    address: ":8080"          # reachable only from the docker network
```

Then no credential is involved: LabView reaches it by container address and sends
nothing. When the read succeeds that way, the proxy service gets a note saying its
API answered with no credential — so you also learn whether the API is open on that
network, which is worth knowing either way.

**Discovery.** A scanned service is taken to be the proxy when one of its own
routers targets `api@internal` (the operator's own label saying "this container
serves the proxy API", which also yields the exact public hostname), when another
service's tunnel origin structurally resolved to it, or — last resort — when it runs
the Traefik image. Candidate URLs are its container addresses on declared ports plus
`8080`, tried before any public hostname. Set `LABVIEW_TRAEFIK_URL` when the proxy
is outside `appsRoot` or discovery guesses wrong.

**The credential rule.** Every candidate is probed on `/api/version`, which needs no
authentication, and a candidate that answers is used as-is with nothing sent. A
credential is only ever sent to an endpoint you configured by hand, or to a hostname
this scan proved belongs to the service whose own labels declare `api@internal` —
ownership evidence, not a guess. Cookies the gate sets during that exchange are
echoed back on the remaining requests of the same exchange, which is what the
Authentik outpost expects.

**An Authentik API token is not a valid credential here.** A proxy provider accepts
HTTP Basic with an Authentik user and an **app password** — per authentik's
[header authentication docs](https://docs.goauthentik.io/add-secure-apps/providers/proxy/header_authentication/),
the credentials are used internally with the OAuth2 machine-to-machine flow, which
an API token cannot drive — or the reserved username `goauthentik.io/token` with a
token as the password. Either way the provider needs **"Intercept header
authentication"** enabled, or it answers the request itself instead of passing it
through. `LABVIEW_TRAEFIK_PASSWORD` holds it ([where the credentials
go](#where-the-credentials-go)); it is always masked in LabView's own output, and no
credential is ever interpolated into an error message.

Every failure here is soft too: nothing answering, a rejected credential, a timeout
or a shape the parser doesn't recognize leaves the posture exactly as the labels
described it, with the reason in `meta.traefik.error`.

---

## Access control

LabView can require a login of its own — a password form backed by `/config/passwd`,
OIDC against your provider, or both. It is **off until you configure it**, so pulling a
newer image never locks you out of a running deployment, and an existing setup behind
Traefik + Authentik keeps behaving exactly as it did.

Whichever posture applies, LabView says so in one line at startup:

```text
LabView access control: none — the HTTP surface is open to anyone who can reach it, relying on your edge
LabView access control: password login (3 users) — /api requires a session
LabView access control: password login (3 users) + OIDC (authentik.example.com) — /api requires a session
```

Counts, never names: a user list in a log file is an inventory of accounts to try. The
line is re-printed when it changes, so creating `/config/passwd` on a running LabView
tells you it was picked up instead of leaving you to guess.

### The three postures

| Posture | How you get it | What happens |
|---|---|---|
| **Open** | the default — no passwd entries, no OIDC issuer | Every route answers as it always has. Nothing is gated |
| **Password** | a `/config/passwd` with at least one usable entry | `/api` needs a session; the UI renders a login card |
| **OIDC** | `auth.oidc.issuer` **and** `auth.oidc.clientId` set | Same, with a "Sign in with …" button. Both methods can be live at once |

A method that is switched on but unusable — `passwd.enabled: true` with an empty file, an
issuer with no client id — is a **warning in the log, never a lock-out**. Enforcement
turns on only when at least one method can actually let someone in.

**What is gated.** Everything under `/api/` needs a session, except four exact paths:
`/api/healthz`, `/api/session`, `/api/login` and `/api/logout`. The SPA itself —
`index.html`, `styles.css`, `app.js` — stays public and renders the login card, which is
safe because those files carry nothing about your fleet: they are the same bytes in every
deployment. Nothing describing a stack, a host or a container is served before you sign
in.

The allowlist is an exact match on a normalised path, not a prefix — `/api/healthz/../overview`
and `/api/sessionx` are both gated, which the obvious `startsWith` version would not be.

### Users in `/config/passwd`

One `user:hash` per line, `#` comments and blank lines ignored — `/etc/shadow`'s and
`htpasswd`'s format, with the algorithm named by the hash's own `$id$` prefix:

```text
# /config/passwd
alice:$2b$12$…      # 60 characters in full: $2b$, the cost, then salt+digest
bob:$2y$12$…
```

- **bcrypt** (`$2a$`, `$2b$`, `$2y$`) is what LabView verifies — what `htpasswd -nbB`
  writes and what Traefik's own basicauth takes.
- Any other prefix (`$5$`, `$6$`, `$argon2id$`) is **skipped with a warning naming the
  algorithm**, never the hash.
- A line with no `$` prefix is a plaintext password. It is skipped; LabView never accepts
  one.
- A username may contain letters, digits and `. _ @ -`, up to 64 characters — narrow
  because a username reaches log lines and the topbar.
- On a duplicate username the **first line wins** and the duplicate is warned about.
- One bad line never breaks the file: every other user still signs in.

The file is **re-read when it changes** (size, mtime, inode), so adding a user needs no
restart. [`passwd.example`](passwd.example) is the annotated version of the above, with a
line you can copy the shape from.

Three ways to make a line:

```bash
# in the container — prompts with echo off, prints one line to stdout
docker exec -it labview node dist/hashpw.js alice >> ./config/passwd

# from a checkout
npm run hashpw -- alice

# with apache2-utils, if you have it
htpasswd -nbB alice '<password>'
```

The first two never take the password as an argument, because `ps`, `/proc` and your
shell history can all read a command line; `htpasswd` does, which is worth knowing before
you use it. `--cost N` (default 12) sets how slow verification is — every sign-in pays
it, and 12 is roughly 250 ms on a homelab CPU.

**Failed sign-ins are throttled per username**: `auth.maxFailedAttempts` (5) within
`auth.lockoutSeconds` (60) and the next attempt gets a `429` with `Retry-After`, even if
the password is right. Keyed on the username rather than the address, because behind a
tunnel and a reverse proxy every request shares one source address — keying on the
address would let one wrong password lock out the fleet. An unknown username and a wrong
password produce the same message in the same amount of time, so the form is not a way to
enumerate accounts.

### Sessions

A signed cookie, `labview_session` by default, and nothing stored server-side: a restart
signs everyone out, which is a better trade for a dashboard than a session database. Two
replicas behind the same proxy work with no shared state beyond `auth.session.secret`.

- `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` from `auth.session.ttlMinutes` (720).
- `Secure` when the request arrived over https. `auth.session.secure: auto` reads
  `X-Forwarded-Proto`; set `"true"`/`"false"` only if your proxy does not send it. A
  `Secure` cookie over plain http is never stored, and the symptom is a login form that
  takes the password and comes straight back with nothing in any log.
- Signing out revokes the token rather than merely dropping the browser's copy.
- Every POST is checked for a matching `Origin` while enforcing, on top of `SameSite`. A
  **missing** `Origin` is allowed, so `curl` and health checkers still work; a present one
  from another host gets a `403`.

Set **`LABVIEW_SESSION_SECRET`** if you would rather a restart did not sign everyone out.
With it unset, LabView generates one at startup and says so.

### OIDC with Authentik

Ten minutes, and the last two steps are the ones people miss.

1. **A signing key must be RSA or EC.** In Authentik, *Applications → Providers → Create
   → OAuth2/OpenID Provider*, and set **Signing Key** to a certificate (the built-in
   *authentik Self-signed Certificate* is fine). Leave it empty and Authentik signs ID
   tokens with **HS256** using the client secret — LabView refuses every HMAC algorithm,
   deliberately, because a symmetric alg beside a published JWKS is a known key-confusion
   vector. The log says `signed with HS256, which LabView does not accept` if you hit it.
2. **Client type: Confidential.** Public works too (PKCE is used either way), but
   confidential is one fewer thing to reason about for a server-side app.
3. **Redirect URI — strict.** Set *Redirect URIs/Origins* to `Strict` with exactly:

   ```text
   https://labview.example.com/auth/oidc/callback
   ```

   The path is fixed. Use the hostname a browser actually types, not the container name.
4. **Scopes**: `openid`, `profile`, `email` — the default set. `openid` is sent whatever
   you configure; `profile` is what carries `preferred_username`.
5. **Create the Application** (*Applications → Applications → Create*), give it a
   **slug** — say `labview` — and assign the provider you just made.
6. **Copy the issuer, client id and secret.** The provider page shows them; the issuer is
   the app slug's OIDC base:

   ```text
   https://authentik.example.com/application/o/labview/
   ```

   LabView checks that the discovery document's own `issuer` equals this exactly (a
   trailing slash either way is forgiven, nothing else is) — the standard mix-up defence.
7. **Restrict who may sign in.** An Application with no policy binding is launchable by
   every authenticated user. Bind a group: *the Application → Policy/Group/User Bindings →
   Bind existing group*. LabView has no roles of its own — everyone who gets in sees the
   same read-only overview — so this binding is the whole authorization story.
8. **Configure LabView** and restart it:

   ```yaml
   environment:
     LABVIEW_OIDC_ISSUER: https://authentik.example.com/application/o/labview/
     LABVIEW_OIDC_CLIENT_ID: ${LABVIEW_OIDC_CLIENT_ID:-}
     LABVIEW_OIDC_CLIENT_SECRET: ${LABVIEW_OIDC_CLIENT_SECRET:-}
     LABVIEW_OIDC_REDIRECT_URI: https://labview.example.com/auth/oidc/callback
   ```

   The id and the secret are one credential pair and are set one way, from the `.env`
   beside the compose file ([where the credentials go](#where-the-credentials-go)).
   `LABVIEW_OIDC_REDIRECT_URI` may be omitted — LabView then derives it from the
   request, honouring `X-Forwarded-Proto`/`-Host`, which is right behind a single proxy and
   wrong as soon as two hostnames reach the same LabView.

The button reads *Sign in with authentik.example.com* by default, which tells a visitor
who has not signed in yet what your provider's hostname is. Set `auth.oidc.label` to
`"Sign in with SSO"` if you would rather it did not.

What LabView checks on the way back, all of it non-negotiable: `state` against the signed
transient cookie, the ID token's signature against `jwks_uri` (asymmetric algorithms
only, one JWKS refetch on an unknown `kid` for key rotation), `iss` exactly, `aud`
containing the client id, `azp` when present, `exp`/`iat` within 60 s, and `nonce`
matching this attempt. The username comes from `auth.oidc.usernameClaim`, falling back
`preferred_username` → `email` → `sub`.

### When a sign-in fails

The browser is told a **code**; the reason goes to the log. That split is deliberate — a
provider's complaint can name an endpoint or a claim value, and the login screen is not
the place for either.

| Code | Means | Where to look |
|---|---|---|
| `credentials` | Wrong password, or no such user — one message for both | The log names the username that was tried |
| `throttled` | Too many failed attempts for that username | Wait out `Retry-After`; the log gives the seconds |
| `method-unavailable` | The method used is not live — an OIDC start with no issuer, a login POST with an empty passwd file | The startup line says which methods are live |
| `session-expired` | A gated request 401'd mid-session: the TTL passed, or LabView restarted with a generated secret | Set `auth.session.secret` to survive restarts |
| `oidc-state` | The callback did not match a sign-in attempt — the 5-minute window passed, cookies were blocked, or a stale bookmark was opened | Start again from `/` |
| `oidc-provider` | Discovery failed, or the provider refused the sign-in | The log gives the stage: resolve, connect, authenticate, path, timeout — or the provider's own code, e.g. `access_denied` from a policy binding |
| `oidc-token` | The token exchange or the ID-token check failed | The log names the check: client credentials, redirect URI, signature, `iss`, `aud`, `nonce`, algorithm |
| `oidc-identity` | The ID token had no usable username | Add the `profile` or `email` scope, or set `auth.oidc.usernameClaim` |

Failures redirect to `/?login_error=<code>`, and the code is validated against that
closed set before anything is rendered — a crafted `?login_error=` cannot put text on the
login screen.

### If your edge already does SSO

You may not want any of this. When LabView sits behind Traefik with an
`authentik@docker` forward-auth middleware, the request has already been authenticated
before it reaches the container, and LabView's own login is a second password to manage
for no gain. Leave it unconfigured — the default — and the startup line will say the
surface is open, relying on your edge, which is the accurate description of that setup.

The case for switching it on anyway is narrow and real: a published host port bypasses
the middleware entirely (LabView will tell you so about itself, with a `lan` tag), a
tunnel origin pointed at the container instead of at the proxy does the same, and neither
is visible from the browser. A passwd file is the backstop for the day one of those is
misconfigured.

To turn the password form off explicitly — because you want OIDC only, or your edge only —
set `auth.passwd.enabled: false` (or `LABVIEW_AUTH_PASSWD_ENABLED=false`). The file is
then not read at all.

There is deliberately **no trusted-header mode**: LabView will not take
`X-Forwarded-User` or `X-authentik-username` as proof of identity, because trusting a
header is only safe when the edge is guaranteed to strip it, and LabView cannot verify
that. If you trust your edge that much, the open posture is what you want.

---

## When a connection fails

Every outbound read — the Docker endpoint, the Authentik API, the Traefik API —
reports the **stage** it stopped at, because "unreachable" covers a dozen different
fixes. On startup and on any change you get one line per target:

```text
LabView scanning /data/apps
LabView connected to docker at tcp://dockerproxy:2375 (config) — 86 containers
LabView could not connect to authentik at https://sso.example.com (config) — resolve: fetch failed (ENOTFOUND)
  No candidate hostname resolved. Set LABVIEW_AUTHENTIK_URL to the API's address — …
  · http://authentik-server:9000 (runs the Authentik image): resolve — fetch failed (ENOTFOUND)
LabView read 56 stacks, 86 services from /data/apps
```

That last line closes the startup block with the number the root produced, so a
mistyped `LABVIEW_APPS_ROOT` shows up as `read 0 stacks` rather than as an empty
dashboard. Every later scan reports the difference from the one before it instead:

```text
LabView rescanned /data/apps — +1 stack, 1 stack changed, +1 service; authentik +2 applications, +1 matched (57 stacks, 87 services)
  · added: monitoring (1 service)
  · changed: wiki — services added: search-sidecar
  · authentik: +2 applications, +1 matched
  · authentik appeared: monitoring, grafana
```

The same lines print under `npm run scan -- --summary`, the same phase and reason
appear in a banner under the topbar, and the whole set is in `meta.connections` on
`/api/overview`. A target nobody switched on is logged at `debug` and shows no
banner — an optional integration being off is not a fault.

| Phase | What it means | Where to look |
|---|---|---|
| `disabled` | switched off in config | `LABVIEW_*_ENABLED` |
| `not-configured` | nothing was asked for | no token / no endpoint — nothing to fix unless you expected otherwise |
| `not-found` | a credential is configured with no address to use it against | set `LABVIEW_AUTHENTIK_URL` / `LABVIEW_TRAEFIK_URL`; discovery only finds an instance that is itself one of the scanned stacks |
| `credential` | the variable holding the token or password is set and carries nothing | most often an unresolved `${…}` in the compose file with no matching `.env` entry |
| `resolve` | the name does not exist here | the hostname, and whether LabView shares a network with it |
| `connect` | nothing accepted the connection | the port; for a unix socket, whether it is mounted, is really a socket, and has a daemon behind it |
| `tls` | the certificate was not trusted | `NODE_EXTRA_CA_CERTS` — verification is never skipped |
| `timeout` | accepted, then silent | `LABVIEW_*_TIMEOUT`, or whether the address really is the API's |
| `authenticate` | the credential is missing or wrong (HTTP 401) | the token; for a gated Traefik API, an Authentik **app password**, not an API token |
| `authorize` | the identity was accepted and the access refused (HTTP 403) | **the socket proxy's `CONTAINERS=1`**, or the token's permissions; on a unix socket, the container user's group membership |
| `path` | no API of this kind answered here (HTTP 404/405) | the base URL — no `/api/v3` suffix for Authentik, `api: {}` enabled for Traefik |
| `status` | some other error status | the endpoint's own logs |
| `protocol` | something answered, but not this API | almost always an SSO login page in front of it — point at the internal address instead |
| `partial` | connected, part of the read failed | the reason is on the line; the posture is unchanged, and nothing is concluded from the missing part |

The most common two in practice, both of which read like a network problem and are
neither: `authorize` from a socket proxy that was never given `CONTAINERS=1`, and
`protocol` from a URL that reaches an identity provider's login page rather than the
API behind it.

---

## How it works

```text
discover stacks → parse compose (+ .env interpolation) → enrich from Docker
      → build middleware registry → classify ingress
      → build the fleet index → resolve tunnel origins
      → read the Authentik API ∥ read the Traefik API   (one round trip, not two)
      → discover Authentik hostnames
      → match Authentik applications ∥ match live routers to services
      → derive auth posture → build graph → serve /api/overview
```

- **Compose parsing** understands both label/env syntaxes (list `- k=v` and map
  `k: v`), YAML anchors, `${VAR}` / `${VAR:-default}` interpolation from adjacent
  `.env` files — including nested forms like `${A:-${B:-fallback}}` — and the
  full port/volume short and long forms.
- **DockFlare `enable`** is honoured: an explicit `dockflare.enable=false`
  suppresses the route even when the `hostname`/`service` labels are still
  present, so a staged-but-disabled route is not reported as public.
- **DockFlare** labels become public **Cloudflare routes** (hostname → origin,
  Access policy, TLS options).
- **Traefik** labels become local **routes** (router rule → hosts/path prefixes,
  entrypoints, TLS/cert-resolver, referenced middlewares, service port).
- A global **middleware registry** classifies referenced middlewares by *type*,
  so `authentik@docker` (forward-auth) counts as SSO while a `headers` or
  `redirect` middleware does not — even when it's defined in a different stack.
- **Authentik auto-discovery** learns your Authentik hostnames from the fleet
  itself — whichever stack runs the `goauthentik` image or defines the outpost
  forward-auth address — so an OIDC issuer or LDAP host pointing at
  `sso.example.com` is recognized as Authentik even though the string "authentik"
  never appears in it. The same mechanism is what keeps it honest elsewhere: with
  no Authentik in the fleet nothing is learned, and every issuer stays generic.
  Hints are matched at **token boundaries**, so `oauth.bigcorp.example.com` is not
  read as Authentik on the strength of four shared letters.
- **Tunnel origins are resolved, not assumed.** A tunnel rarely terminates at the
  container whose labels declare it — the origin normally names a reverse proxy,
  which forwards on over a shared network. The origin address says which: an IP
  literal addresses the *host*, so its port is a published host port and identifies
  exactly one service; a bare name addresses a *container*, so the DNS name is the
  evidence. A tie between two services declaring one port is broken by network
  membership, since a candidate sharing no network with the service it supposedly
  fronts cannot forward to it. Where that proves a hop, the diagrams draw
  `tunnel → proxy → service`; where nothing proves one, the direct edge stays and
  the service says why the hop is unknown. No image, vendor or naming convention is
  consulted.
- **Ingress is a set of independent tags, not one label.** A service carries as
  many of the three external ones as apply, because a container behind the tunnel,
  behind the proxy and with a published port is all three of those things and each
  is separately true. A stack carries the union of its services'.

  | tag | what it means | the evidence |
  |---|---|---|
  | `public` | reachable from the internet through the tunnel | a Cloudflare route with a hostname |
  | `traefik` | reached through the reverse proxy | a Traefik route with hosts or a rule |
  | `lan` | answerable on the server's own network | a `ports:` entry — which publishes on the host, unlike `expose:`, so the service answers at `<host-ip>:<port>` with no proxy and no SSO in the path |
  | `internal` | another container can reach it, **and nothing else can** | an `expose:` port, **or** a resolved network shared with another scanned service — and none of the three above |
  | `none` | nothing reaches it at all | none of the above |

  `internal` is the one tag that yields. Almost every service in a real fleet shares
  a network with a neighbour, so reporting it everywhere would put the same tag on
  nearly everything and tell a reader nothing; what they are looking for is the
  service reachable *only* from the container network — the database behind a
  frontend — so that is the only place it is shown. The frontend in the same stack
  shows `public`, `traefik` or `lan` alone. Nothing is invented and nothing is
  hidden: the evidence for `internal` is unchanged, and where the tag is withheld
  the drawer's **Networks** section and the graph's network edges still show the
  neighbour that can reach it. The cost, stated plainly: from the tags of an
  externally-reachable service you cannot tell whether a sibling reaches it too.

  The **stack row is the exception**, and deliberately so: its badges are the union of
  its services', not a service's own set, so a stack with a public UI and a database
  only that UI can reach shows **both** `Public` and `Internal` — which is how a
  collapsed row tells you there is something inside worth expanding for. Withholding
  there would let the UI's exposure erase the database from the only view that starts
  out visible.

  `internal` is also **positive evidence, not a fallback**: it says a neighbour
  demonstrably can reach this service. When neither an exposed port nor a shared
  network says so, the answer is `none` — a real category with its own tile, not a
  bucket for everything unclassified. Shared networks are counted on the names
  docker actually uses, so the implicit `default` network compose gives a file that
  declares none is enough to make two services in one stack mutually reachable, and
  an `external:` network is enough across two stacks. `depends_on` is deliberately
  not evidence: a dependency across two disjoint networks is not reachability.

  Because the tags overlap, the five counts do **not** sum to the service count, and
  the CLI summary says so on the line. A service that is both proxied and published
  keeps `traefik` *and* `lan`, and the LAN bypass of the proxy's SSO is still raised
  as a note — the note explains it, the tag makes it filterable.

  `network_mode: host` is not modelled (it is not parsed either), so a
  host-networked service is classified from its routes and `ports:` alone.
- **What connects two services is the network between them, so that is what is drawn.**
  The same resolved network names build one fleet-wide membership index — who is on which
  network, from which stacks, and whether any stack declared it `external:` — and that
  index is what the `internal` tag, the graph's network nodes and the Networks list all
  read, so they cannot come to disagree. On top of it, one further question is asked per
  service and per network: does a `depends_on` involving this service have its other end
  on *this* network? Where it does, the dependency is drawn as arrowheads along the path
  through the network instead of as a separate line, and the pair is named in words. Where
  a `depends_on` pair shares no network at all, that is reported rather than smoothed
  over: compose orders their startup, yet neither container can address the other.
- **Auth posture** resolves to one of `authentik-forward-auth`,
  `authentik-oauth`, `authentik-ldap`, `forward-auth`, `other-oauth`, `ldap`,
  `basic-auth`, or `none`, each with the evidence that produced it.
- **A provider is named only when something proves it.** The mechanism and the
  provider are two separate conclusions, and only the mechanism is usually
  certain: a `forwardauth` middleware definition proves a gate exists, but naming
  *whose* gate requires a value that says so — the forward-auth address, an issuer
  URL, or an LDAP host matching a discovered identity. Where it can't be
  established, the mechanism is reported (`forward-auth`, `other-oauth`, `ldap`)
  rather than the most likely vendor. So an oauth2-proxy gate reads as
  `forward-auth`, and an OpenLDAP or AD directory reads as plain `ldap`. The
  *address* also outranks the *name*: a middleware called `authentik` that points
  somewhere else is not Authentik.
- **`confirmed` vs `observed` vs `inferred`.** Each posture carries a confidence.
  `confirmed` means the identity provider's own API reported the gate. `observed`
  means a value in the config states it. `inferred` means the referenced
  middleware was defined nowhere in the scanned stacks — a Traefik file provider,
  say — so only its name was available; the UI labels it, and the service gets a
  note saying the definition could not be found. Reading the reverse proxy's API is
  what retires that last case: the proxy has the definition, so the same middleware
  comes back `confirmed`. When two accounts disagree the stronger one is reported
  and the weaker is kept as evidence beneath it, so you can see both.
- **The Authentik API, when a token is given, is read as evidence like any other.**
  Applications, providers and outposts are fetched, then each application is tied to
  a service by one of four things, strongest first:
  1. a proxy provider's `internal_host` resolving to exactly one service — the
     provider naming its target outright, and the strongest evidence available;
  2. a **bare-name host inside a URL the provider hands out** — a launch URL, an
     external host, or an OAuth2 redirect URI — resolving to exactly one service.
     `http://app:3000/oauth/callback` is the provider addressing a container, and
     compose publishes that name as the container's network alias. This is what
     reaches a service with **no public hostname at all**, which for OIDC is the
     normal case: an OIDC gate leaves no trace in the compose file, so the API is
     the only place it can be seen;
  3. a **hostname** named by one of those URLs *and* declared by the service in its
     DockFlare or Traefik labels — one hostname, observed on both sides;
  4. a **name** — the slug, the application name, or any of its providers' names —
     when it identifies exactly one service's stack, compose or container name.
     Compared with separators removed and with the words naming the mechanism
     dropped, because Authentik's own wizard produces `Provider for X` and someone
     writing `Home Assistant` means the `home-assistant` stack.

  Anything that could name two services names neither, and is reported as an
  unmatched application instead — with the reason it was not placed and one line per
  rule that ran, so "two services claim this slug" (yours to settle) never reads the
  same as "nothing in this application names anything scanned" (LabView's to explain).
  `external_host` is used for matching except in
  `forward_domain` mode, where it is the authentication domain shared by every
  application in it and so identifies no single service. An **IP literal** in a
  redirect URI is deliberately not resolved: it addresses the host, where port 443
  belongs to the reverse proxy, so reading it as a published port would attach the
  application to whatever answers there.
- **How firmly the match was made is part of the answer.** Rules 1–3 are addressed —
  the provider points at the service — and report `confirmed`. Rule 4 is only that the
  operator chose similar words on each side, so it reports **`observed`** and the
  detail ends `— tied to this service by name alone`. The gate itself is not in doubt;
  which service owns it is, and the confidence says which of the two you are reading.
  Give the application a redirect URI naming the container and the same match moves up
  to rule 2. No exposure count reads confidence, so this never moves a service between
  "protected" and "exposed".
- **A provider Authentik records is taken as being in use.** An OAuth2 provider needs
  no outpost, and the client configuration lives in the application rather than in any
  compose file, so the identity provider's own record is the whole of the available
  evidence — and it is authoritative about its own configuration. Requiring a second
  source would mean an OIDC gate could never be reported at all.
- **A provider only counts as protection if something is enforcing it.** Proxy,
  LDAP and RADIUS providers are enforced by an **outpost** standing in the request
  path; a provider assigned to no outpost stops nothing, however complete it looks
  in the admin UI, and LabView reports the service as unprotected with that as the
  reason. OAuth2 and SAML providers are served by the Authentik server itself, so
  they need no outpost. SCIM provisions users outbound and gates nothing at all —
  it is listed as a provider but never as a gate.
- **A confirmed gate the model cannot name is still a gate.** SAML has no
  `AuthMethod` of its own, so such a service reports `none` — but it is *not*
  counted as exposed-without-auth, and the provider is shown verbatim in the
  drawer. Reporting a protected service as reachable without authentication would
  be the one error worth failing over.
- **The reverse proxy's API is read the same way** — as evidence, matched only on
  something addressed. A live router is tied to a service by the backend URL the
  proxy itself names, by a `@docker` router name (Traefik derives those from the
  labels of the very container it found them on, so an exact match is that label
  round-tripping), or by a host rule resolving to exactly one service. Two
  candidates is not an ambiguity to arbitrate but a match not made: the router lands
  in `meta.traefik.unmatchedRouters`, reported as ingress LabView could not
  attribute — carrying the whole router, so its rule, entrypoints, chain and backends
  stay reviewable, plus the same reason and trace as an unmatched application.
  A `@file` router's name was typed by hand in a file this scan cannot
  read, so its resembling a label is a coincidence with no evidentiary weight and
  the name rule does not apply to it.
- **A backend address needs its own index.** A docker-provider backend is
  `http://<container-ip>:<container-port>`, and the origin resolver reads an IP
  literal's port as a *published host port* — the wrong table entirely, which would
  produce confidently wrong matches. Container IPs get a separate index built from
  live Docker state, and an IP-form backend resolves only through it. With no Docker
  state that rule is skipped rather than guessed; the router-name and host-rule
  rules still cover the docker provider.
- **Where a router matched, the live chain is the chain.** A `forwardAuth` whose
  address resolves to a discovered identity becomes `authentik-forward-auth` at
  `confirmed`; one that resolves nowhere identifiable stays the mechanism,
  `forward-auth`. `basicAuth`/`digestAuth` become `basic-auth`. A `chain` middleware
  is resolved recursively (depth-capped), and the evidence line says how the gate was
  reached — `via chain secured@file`. Middlewares attached at the **entrypoint** are
  merged in, because a gate there protects the router without appearing in its own
  list. A middleware type LabView has never heard of is still reported by name.
- **A label that overstates the config is downgraded.** If the labels claim an auth
  middleware and the chain Traefik built contains none, the detection is suppressed:
  the service reports `none`, lands in exposed-without-auth, and carries a note
  naming what was declared and what was actually built. This is the one conclusion
  that can mislead in a dangerous direction, so it fires only when **both**
  `/api/rawdata` and `/api/entrypoints` were read — a partial read notes the gap and
  changes no posture — and a router the proxy reports as `disabled`, or carrying
  `error[]`, is treated as neither protection nor working ingress with those errors
  quoted verbatim.
- **The declared-but-absent check runs against every router in the snapshot**, not
  just the ones matched to the service. A router the proxy is demonstrably serving
  but that LabView could not attribute to anybody must not be reported as missing.
- **Three-way cross-check.** When the live `forwardAuth` address resolves to the
  service the Authentik API answered on, and Authentik reports an outpost serving a
  provider for an application matched to *this* service, the note records labels,
  proxy and identity provider agreeing. When they disagree the disagreement is the
  finding — a forward-auth address pointing at an instance with no matching
  application, or a matched provider whose mode means the request never reaches the
  outpost. A provider in `proxy` mode is exempt: there the outpost *is* the backend,
  so no forward-auth middleware exists and none should be expected.
- **Exposed-without-auth**: a service that is reachable — `public`, `traefik` or
  `lan` — with no detected *proxy/SSO* auth is flagged. Note this is honest about
  *proxy* auth only: apps with their own built-in login (Emby, Home Assistant,
  Authentik itself) will appear here, and the note wording says exactly that. Where
  that built-in login is the answer, a `.labview` sidecar is how you say so — see
  [Declaring what the scan cannot see](#declaring-what-the-scan-cannot-see).
- **Rescan re-reads everything, and says what moved.** Nothing is remembered
  between scans: every `compose.yml` and `.env` under the apps root is read again,
  the directory is re-walked, and the whole pipeline runs from scratch — so a new
  stack directory, a deleted one, an added service and an edited file are all picked
  up. What the operator gets back is a comparison against the previous scan, beside
  `scanned <time>` and in the log: `+1 stack, 2 services changed`, with the stack and
  service names in the tooltip. Two things about that comparison are worth knowing.
  It is over the **parsed configuration**, not file timestamps, so a comment-only
  edit or a rewrite that produces the same document reports nothing, while an `.env`
  change that alters what a compose file interpolates to reports as a changed
  service. And it deliberately ignores everything that moves on its own — container
  status, health, addresses, whether an API answered this time — because a container
  restarting is not a configuration change, and a diff that fires on every rescan is
  a diff nobody reads. When nothing in the files differs it says **`no config
  changes`**, which is the answer most rescans have and the one the button used to
  leave unsaid.
- **The integration reads are re-run too, and reported beside the files.** A rescan
  redoes endpoint discovery and every Authentik and Traefik request, re-reading the
  credential files with them, so a rotated token takes effect on the next press. That
  half gets its own note and its own log clause — `authentik +2 applications, +1
  matched`, with the applications and routers that came or went named on hover —
  because the configuration diff excludes live API answers by design, so an
  application count going 18 → 40 used to produce no line anywhere. Two rules keep it
  trustworthy. Nothing is compared across a **failed** read: a read that stopped
  working says `authentik not read`, never `-40 applications` about an instance the
  scan never reached. And a failure that was already failing last time is not
  re-reported as a change — the banner already says it, continuously.

### Security

- Stacks are mounted **read-only** and Docker is reached through the
  **socket-proxy** with read-only endpoints only; LabView never writes.
- Secret-looking env values (`*PASS*`, `*SECRET*`, `*TOKEN*`, `*KEY*`, …) are
  **masked** in both the API and UI by default. Keys stay visible; values are
  replaced with a placeholder.
- Independently of the key name, values shaped like
  `scheme://user:password@host` have the **password stripped** — this is what
  catches connection strings such as `DATABASE_URL` and `REDIS_URL`, whose keys
  match none of the patterns above. Scheme, user and host stay readable.
- Files referenced by a compose document (`env_file`) are **confined to the apps
  root**. A `env_file: ../../../secrets.env` entry is refused and noted on the
  service rather than read, both for lexical `..` escapes and for symlinks
  pointing out of the tree.
- **Published host ports are treated as real exposure.** Any service with a
  `ports:` mapping is tagged `lan`, counted in its own stat tile, and — with no
  proxy or SSO in front — flagged exposed-without-auth, because it answers on the
  LAN whatever your Traefik config says. When a proxy *is* in front, the service
  holds `traefik` and `lan` together and gains an explicit note that the published
  port bypasses the proxy and its SSO.
- The **Authentik API token is optional and read-only** (`view_application`,
  `view_provider`, `view_outpost` on a groupless service account — LabView only
  issues `GET`s). A discovered endpoint is probed unauthenticated first and the
  token is sent only to a host that answered as an Authentik API, so a wrong guess
  never receives it. It comes from `LABVIEW_AUTHENTIK_TOKEN` and nowhere else, so a
  `.env` outside version control is where it belongs ([where the credentials
  go](#where-the-credentials-go)). Certificate verification cannot be
  disabled — use `NODE_EXTRA_CA_CERTS` for a private CA. The cost of that narrow
  token is stated rather than hidden: Authentik withholds the applications the
  account may not launch, so LabView reports how many, rebuilds what the providers
  name, and says what is left.
- **The reverse proxy's API is read with no credential wherever possible.** Every
  discovered candidate is probed on `/api/version`, which needs no authentication,
  and one that answers is used as-is with nothing sent. A credential goes only to an
  endpoint configured by hand or to a hostname this scan proved belongs to the
  service whose own labels declare `api@internal` — never to a guessed host. The
  recommended setup (`api: {}` plus an unpublished container-network entrypoint)
  involves no credential at all, and when the read succeeds that way the proxy
  service is noted as having an API that answers unauthenticated on that network.
  `LABVIEW_TRAEFIK_PASSWORD` is in the always-masked key list, so LabView scanning
  its own stack cannot print its own credential, and no credential is interpolated
  into any error string.
- **LabView's own login is off until configured, and gates the data when it is.** With a
  `/config/passwd` entry or an OIDC issuer, `/api` needs a session; the SPA shell stays
  public because it carries nothing fleet-specific. Passwords are bcrypt, failed attempts
  are throttled per username, sessions are `HttpOnly` signed cookies with an `Origin`
  check on every POST, and there is no trusted-header mode — see
  [Access control](#access-control). Unconfigured, the surface is open and the startup log
  says so: put it behind your own edge (see above).

---

## Declaring what the scan cannot see

Some things are true about a service and written nowhere a scanner can read. Emby's
built-in login is not a compose label. That a status page is *deliberately* open to
the LAN is a decision, not a config value. Who owns a stack, what breaks if it stops,
where its admin UI lives — none of it is in the files LabView reads.

Drop a **`.labview`** file next to a `compose.yml` and it will be read with it.
[`.labview.example`](.labview.example) is the annotated skeleton; copy it and delete
what you do not need. `.labview.yml` and `.labview.yaml` work too, and the file name
LabView actually used is reported back on every field it produced, so a stack with two
of them is never ambiguous about which one is in effect.

```yaml
# /mnt/apps/emby/.labview
description: Media server for the house.
owner: platform-team
criticality: high

services:
  emby:
    # Authentication the scan cannot detect, because it is inside the app.
    auth:
      - mechanism: app-local-accounts
        detail: Built-in user database.
      - mechanism: app-ldap
        detail: LDAP bind against the directory for staff accounts.
```

### Three rules that make it trustworthy

Everything here is **a second source, never stronger evidence**. Three rules hold that
line, and each is deliberate:

1. **A declaration never changes what was detected.** `svc.auth.method` stays
   `none`, the detected-method distribution does not move, and the declared
   mechanisms are counted only in their own statistic (`stats.declaredAuth`) and
   badged as *declared*. A reader can always tell what LabView proved from what you
   told it. What a declaration does change is what gets *said* about the absence: the
   drawer's `Method` row reads *Declared, not detected* rather than warning about a
   missing gate, because a warning there would argue with the declaration beside it.
   LabView takes the declaration at face value and says it cannot verify it — it does not
   both believe you and keep asking.
2. **It can change one verdict, and only in the open.** `exposedWithoutAuth` is not a
   measurement, it is a conclusion — *reachable, and nothing authenticates it* — and a
   declared login is an answer to the second half. So a service that is reachable, has
   no gate the scan could find, and declares that the app logs users in itself leaves
   that count. It does not go quiet: it gets a *Protected — declared* badge, its own
   tile and CLI line (`stats.declaredAuthProtected`), and a note on the service saying
   the verdict rests on a statement this scan cannot verify. The number that left the
   alarm is always visible as a number.
3. **Declaring an exposure intentional does not clear it.** A service reachable with
   no auth at all stays in `exposedWithoutAuth`, and the tile still shows the number the
   scan found — as `23/28`: 28 findings, 5 accepted, 23 still wanting an answer. The
   red goes away only once the *unaccepted* remainder hits zero, the badge says
   *Exposed, accepted*, and your reason is on the finding itself. A decision you can no
   longer see is a decision nobody will revisit. The `reason` is required for exactly
   that purpose — an acceptance with no reason cannot be told apart from a stray key,
   so it is refused and warned about.

Rules 2 and 3 are two different statements and not interchangeable: `auth` says there
*is* a login the scan cannot see, `unauthenticated` says there is *not* one and that is
fine here. Only the first can take a service out of the count.

### What you can declare

| field | scope | why it helps |
|---|---|---|
| `description`, `notes` | stack and service | what a future reader needs and cannot work out from the compose file |
| `owner`, `criticality` | stack and service | who to ask, and what breaks if it stops |
| `links` | stack and service | admin UI, upstream docs, the runbook |
| `dependencies` | stack and service | the off-fleet things it needs — a NAS share, a DNS resolver |
| `depends_on` | service | a dependency on another **scanned** service, drawn as a relation — see below |
| `data` | stack and service | what lives in the volumes, and whether it is backed up |
| `auth` | service | authentication the scan cannot see, from the fixed mechanism list below |
| `unauthenticated` | service | that reachable-without-auth is a decision, with the reason |
| `expected.ingress` | service | a tripwire: the reachability you expect, checked against the scan |

The `auth` mechanisms are a **fixed vocabulary of mechanisms, not products**. Naming a
product (`authentik-proxy`) is refused with the vocabulary quoted back, because a
mechanism is observable and a vendor is an attribution — the same rule the scan holds
itself to. `other` needs a `detail`, since on its own it says nothing.

Three of them name something LabView can also detect for itself, so those three are
**compared** against the scan rather than only shown beside it. The rest are invisible
to any scanner, which is what makes them worth declaring — and also means they can
never disagree with anything:

| mechanism | family | compared against |
|---|---|---|
| `app-oidc` | `oidc` | detected `authentik-oauth`, `other-oauth` |
| `app-ldap` | `ldap` | detected `authentik-ldap`, `ldap` |
| `external-proxy` | `proxy` | detected `authentik-forward-auth`, `forward-auth` |
| `app-local-accounts`, `app-saml`, `app-token`, `mtls`, `network-restricted`, `other` | — | nothing; always shown, never drift |

A family sits in one of two **layers** — `oidc` and `ldap` are the app logging users in
itself, `proxy` is a gate in front of it — and two statements are only compared inside a
layer. That is the whole rule, and it exists to stop the obvious version of this feature
from warning about every layered setup there is: declaring `app-oidc` while the scan
detects `forward-auth` is defence in depth and correct, while declaring `app-oidc` where
the scan found an `ldap` bind is two answers to one question, so one of them is stale.

The four outcomes, in the order they are decided:

| outcome | when | what you see |
|---|---|---|
| supplies | reachable, nothing detected | rule 2 above — leaves the exposed count, gains its own badge and counter |
| conflicts | same layer, different family | a drift entry naming both, and the declaration shown without any "not detected" claim |
| redundant | the scan detected the same family | **nothing** — repeating it would send a reader to check two sources that agree |
| supplements | anything else | the declaration, shown as declared, no warning |

### A dependency on another service

`dependencies` and `depends_on` look alike and are not the same key. `dependencies` is
prose about things outside the fleet, so nothing about it is checked. `depends_on` names a
service LabView **scanned**: the target is looked up, the pair becomes a relation in both
graphs, and a reference that resolves to nothing is reported as drift. That is the whole
reason for a second key — a list that mixes prose with references cannot tell a typo from
a sentence.

Write it where compose cannot say it, which is most of the time:

- **Across stacks.** Compose's own `depends_on` reaches no further than its own project,
  so nothing in a compose file can name another stack's service. Two databases in two
  stacks backed up by an agent in a third share a network and, as far as any scan can tell,
  nothing else.
- **Inside one stack, where the compose key would be the wrong claim.** That key orders
  container startup; "reads the cache" is a different statement, and writing the compose
  one to express it changes how the stack boots.

```yaml
# stacks/media/.labview
services:
  emby:
    depends_on:
      - service: backups/restic-agent          # stack/service
        detail: Nightly dump target; the agent connects inbound over backup-net.
      - postgres                               # this stack's own database
```

**Declare it once, on the service that needs the other.** The target reports it from its
own side automatically — `restic-agent`'s drawer lists both databases as *required by*,
with nothing in its own sidecar, and it stays correct when a fourth database appears. A
`required_by` key would mean editing the agent's file every time anything new depended on
it, which is exactly the work this avoids.

A reference resolves in one of four ways, and three of them draw nothing:

| the reference | outcome |
|---|---|
| `stack/service`, or a bare name matching one service | resolved: an edge, drawn through the network the pair shares |
| a bare name matching this stack's own service **and** others | resolved to the local one, as compose's own key would read it |
| a bare name matching two services in other stacks | **drift**, naming both candidates and asking you to qualify it |
| a name matching nothing, or this service itself | **drift**, quoting what you wrote |

Resolution never edits the declaration. The reference is stored exactly as you wrote it —
which is what makes adding one an edit that Rescan reports — while the target it resolved
to lives on the graph. Storing it in the file's parsed form would make a rename in someone
else's stack read as *this* sidecar having changed.

Two things a declared dependency deliberately does not do. It is **not evidence**: it
changes no ingress class, no exposed count and no auth posture, so it is dashed wherever
it is drawn and its chip names the file it came from. And **resolving is not reachability**
— a pair that shares no docker network still gets the relation, plus a note saying that if
those two communicate it is over something the scan cannot see.

### Drift

The failure mode a sidecar actually has is not a typo, it is going quietly out of
date. So every checkable field is checked on every scan, and a disagreement is
reported as **drift** on the service, one entry per disagreement, with its own counter
in the summary:

- An acceptance the scan can see **no longer applies** — the port was withdrawn, the
  route was removed, or something now authenticates the service, including the
  mechanism declared in the same file — says so instead of sitting there implying a
  risk that is gone.
- A declared `auth` mechanism that **disagrees with a detected one at the same layer**
  names both: `declares "OIDC login by the app", but the scan detected ldap (LDAP bind
  against …) — both describe the app's own login, so one of the two is out of date`.
- A `depends_on` reference that **no longer names one scanned service** quotes what you
  wrote and says which way it failed: `declares depends_on "nope/missing", which names no
  scanned service`, or `names 2 services (layered/probe, shared-d/probe) — qualify it as
  "stack/service"`. No relation is drawn for it, because a guess is worse than a gap.
- An `expected.ingress` that disagrees with the classification names the difference in
  both directions: `expects ingress "public, lan"; the scan classified this service
  as "public, traefik" (missing: lan; unexpected: traefik)`. Order is irrelevant —
  the two are compared as sets, so `[public, lan, traefik]` and `[traefik, public,
  lan]` are the same expectation.

Agreement is silent, in both directions: an expectation that matches renders no row,
and a declaration that repeats what the scan found renders nothing at all. A sidecar
that is right about everything is invisible except for the prose you wrote. An
expectation is read through the same rule that builds the classification, so an
`internal` written beside `public`, `traefik` or `lan` is dropped from it quietly rather
than drifting against a rule the file has no way of knowing — writing down everything
that is true of a service is not a mistake worth a warning.

On the dashboard that counter is a button. The **Declaration drift** tile opens a panel
listing every drifting service under the stack it belongs to, with the file it was
declared in and its disagreements in the wording above — so reading them does not mean
opening one service drawer after another, and each row is a link into the drawer where
the declaration sits beside the evidence the scan collected. The tile counts *services*
and one service can drift several ways at once, so the panel states both figures —
`3 services in 3 stacks · 4 disagreements`. The `⚠ Declaration drift` filter is still
there and still does the other thing: it holds the same services in the stack list, in
place, with everything else the scan says about them.

The classification always stands. Drift is a report, never an override.

### Safety

- **Never put a secret in a `.labview`.** It is prose: it is shown as written, no
  masking is applied to it, and there is no key-name heuristic that could apply.
  Credentials embedded in a declared link URL are the one exception — those are
  redacted — but that is a backstop, not a feature.
- Every mistake in the file is a **warning, never a failure**. A malformed sidecar
  costs you the fields it got wrong and nothing else; the scan completes. Unknown keys
  are named rather than ignored, so a mistyped `descripton` is visible instead of
  silently doing nothing.
- The file is read from **inside the stack directory only**, with the same containment
  rule as `env_file`, and every text field is length-capped.

---

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/overview` | GET | **Needs a session.** The full analyzed model (JSON) |
| `/api/rescan` | POST | **Needs a session.** Re-read the apps root and return the rebuilt overview |
| `/api/healthz` | GET | Liveness probe |
| `/api/session` | GET | The posture and who you are: `{enforced, methods, notes, user?, oidcLabel?}` |
| `/api/login` | POST | `{username, password}` → a session cookie. `401 {error:"credentials"}`, or `429 {error:"throttled", retryAfterSeconds}` |
| `/api/logout` | POST | Revokes the session and clears the cookie |
| `/auth/oidc/start` | GET | 302 to the provider's authorize URL |
| `/auth/oidc/callback` | GET | The provider's redirect target; 302 to `/`, or to `/?login_error=<code>` |

"Needs a session" applies only while [access control](#access-control) is configured. With
none configured, every route answers as it always has. A gated request with no valid
session gets `401 {"error":"unauthorized"}` and `Cache-Control: no-store`; the four public
`/api` paths are an exact-match allowlist, not a prefix.

The web UI is a static SPA served from the same origin, and stays readable without a
session — it is what renders the login card.

One field shape matters if you read that JSON yourself.
`meta.authentik.unmatchedApplications` and `meta.traefik.unmatchedRouters` are
**objects, not names**:

```jsonc
{
  // the whole application, as it is elsewhere in the payload
  "application": { "name": "Paired app", "slug": "pair", "providers": [ /* … */ ] },
  "reason": "ambiguous",                    // "ambiguous" | "no-candidate" | "internal"
  "detail": "its slug \"pair\" matches 2 scanned services — pair/blue, pair/green — so it identifies none of them.",
  "considered": [                           // one line per rule that ran, strongest first
    "no proxy provider, so there is no forwarded address to resolve.",
    "no launch URL, external host or redirect URI, so there is no URL to read.",
    "its slug \"pair\" matches 2 scanned services — pair/blue, pair/green — so it identifies none of them.",
    "no stack, compose or container name equals \"paired app\" or \"pairedapp\" or \"paired\", tried for its name \"Paired app\".",
    "the name of its oauth2 provider \"Provider for pair\" matches 2 scanned services — pair/blue, pair/green — so it identifies none of them."
  ]
}
```

`detail` is the most actionable line in `considered`, not a fifth restatement: a rule
that was *contested* outranks one LabView deliberately *declined* to resolve, and both
outrank the generic miss.

`ambiguous` means two or more services claimed the entry and LabView declined to pick
one; `no-candidate` means nothing claimed it; `internal` is defensive only. Both fields
were `string[]` in earlier versions, so this is a **breaking change** for any external
consumer. It was made instead of adding a second, parallel list so that why a match did
not happen has one home rather than a name in one place and a reason in another.

The **ingress vocabulary** is a third **breaking change**, in three steps. The first was
a pure rename, every value mapping one-to-one onto the old one:

| was | is |
|---|---|
| `service.ingress: "public+host-port"` | `"public+lan"` |
| `service.ingress: "public+local"` | `"public+traefik"` |
| `service.ingress: "local"` | `"traefik"` |
| `service.ingress: "host-port"` | `"lan"` |
| `stats.localOnlyServices` | `stats.traefikServices` |
| `stats.hostPortServices` | `stats.lanServices` |

The old `local` meant *proxy route*, which collided with the separate LAN concept —
a stat tile reading "Local" for something that was not the LAN.

The second step made **`service.ingress` an array** of independent tags, which is
breaking in shape as well as in value:

| was | is |
|---|---|
| `service.ingress: "public+lan"` | `["public", "lan", …]` |
| `service.ingress: "public+traefik"` | `["public", "traefik", …]` |
| `service.ingress: "traefik"` | `["traefik", …]` — plus `lan` if it also publishes a port |
| `service.ingress: "internal"` | `["internal"]` **or** `["none"]`, depending on the evidence |
| `expected.ingress` in a `.labview` | a single kind or a list of kinds |
| — | `stats.noIngressServices` (new) |

The two combined values are gone; nothing combines any more. Three consequences worth
planning for if you consume the JSON:

- **The three external `stats.*Services` counters overlap** and no longer sum to
  `stats.services`. `internalServices` and `noIngressServices` are each exclusive of
  every other counter.
- **`internalServices` changed meaning twice** — see the third step below for where it
  landed. The question the old single-value field answered — *how many are reachable
  by nothing at all* — is `noIngressServices`.
- **A `traefik` service may also be `lan`.** Under the old vocabulary a proxied
  service that published a port was classified `traefik` alone, and the LAN path was
  a note only. The note is still there; the tag is new.

The third step **withholds `internal` from any service that also carries `public`,
`traefik` or `lan`**, so the tag now marks the services reachable *only* from the
container network. This is breaking in value, not in shape:

| was | is |
|---|---|
| `["public", "lan", "internal"]` | `["public", "lan"]` |
| `["traefik", "internal"]` | `["traefik"]` |
| `["internal"]` | `["internal"]` — unchanged, and now the only place it appears |
| `expected: ingress: [public, lan, internal]` in a `.labview` | read as `[public, lan]`, silently — no drift |

Two consequences for a consumer:

- **`internalServices` drops sharply** — on a fleet of 86 services it went from 82 to
  25 — because it now counts internal-*only* services instead of every service with a
  neighbour. It is the count the Internal badge, the Internal filter chip and the
  dashboard gauge have always shown; those three simply became worth reading.
- **Nothing else moved.** The evidence for `internal` is unchanged, no other tag and no
  `stats` counter changed, and the graph keeps both its node colours and its network
  edges — so the database-behind-a-frontend path is still drawn where the tag no longer
  says it.

No exposure or auth measure moved in any of the three steps: `exposedWithoutAuth` asks
whether any of `public`, `traefik` or `lan` is present, which is exactly what
`ingress !== "internal"` used to mean.

`meta.authentik.applications` changed meaning in the same spirit, which is also
**breaking**: it counts the applications the list endpoint withheld and LabView rebuilt
from their providers, so the figure moves for an unchanged Authentik. Three counts state
the arithmetic behind it — `applicationsConfigured` (what Authentik says exists),
`applicationsWithheld` (what its policy filter removed) and `applicationsRecovered` (how
many of those were rebuilt) — and each application carries `discoveredVia`, `"list"` or
`"provider"`, naming the read that produced it. Leaving `applications` alone would have
kept a headline number that under-reports, which is the defect these fields exist to fix.

**The network connections are additive, and the payload is not pre-pruned.** Every
`network` node carries `scope` (`external` | `stack-local`), `memberCount` and
`stackCount`; every membership edge carries `flow` (`to-network` | `to-service` | `both`,
absent for plain membership) saying where the dependency arrowhead sits; every
`depends_on` edge carries `via`, the real networks the pair shares — empty meaning
compose orders their startup while neither can address the other. `stats` gains
`networks`, `connectingNetworks`, `crossStackNetworks` and `soloLocalNetworks`. Nothing
was removed: the `depends_on` edges are all still there, `via` and all, so a consumer
that drew them directly keeps working. The caps and the "don't draw a network that
connects nothing" rule are applied by the *views*, not by the API — `soloLocalNetworks`
is exactly what the graph tab omits, which is how you can tell the two apart.

`GET /api/overview` is served from a cache for `LABVIEW_CACHE_TTL` seconds.
`POST /api/rescan` ignores the cache and is answered only by a scan that started
**after** the request arrived — so a rescan issued a second after you save a file can
never be handed a scan that read the old one, even when another scan was already
running. Concurrent requests still coalesce into one sweep, so a double click does
not double the load on the socket proxy, and a failed scan leaves the previous
overview readable and is retried by the next caller.

---

## Development

**Read [../IMPLEMENTATION.md](../IMPLEMENTATION.md) before changing the scanner or
analyzer.** It documents the requirements, the pipeline stage by stage, and the
invariants that keep the output trustworthy — evidence-only conclusions, no
fleet-specific identifiers, mechanism vs. provider, degrade-never-fail — plus a
decision log explaining why the non-obvious choices are what they are.

```text
src/
  scan/       discover + compose/.env parsing
  labels/     dockflare, traefik, auth derivation
  analyze/    two-pass pipeline, middleware registry, network index,
              declared-dependency resolution, graph, stats
  enrich/     docker snapshot (dockerode) + authentik and traefik API clients
              over a shared http.ts (fetch, timeouts, injectable fetchImpl)
  model/      types.ts — the shared backend⇄frontend contract
              changes.ts — what moved between two scans, and its wording
              networks.ts — which network connections are drawn, and their wording
  server/     fastify server + static hosting, scan cache and force semantics
web/          preact UI (grid, detail drawer, cytoscape graph, mermaid)
fixtures/
  apps/       a representative happy-path fleet
  edge/       regression cases for previously-fixed defects
  authentik/  a fleet with an identity provider in it
  nets/       what connects two services and what only lets them reach each other:
              shared networks cross-stack and stack-local, sidecar-declared
              dependencies, and every way a reference can fail to resolve
  authentik-api.json   canned API responses for the above
  traefik/    a fleet whose labels and live proxy config disagree
  traefik-api.json     canned proxy + identity responses for the above
```

```bash
npm run typecheck    # tsc for both server and web
npm run smoke        # runs the pipeline against fixtures/ and asserts results
npm run build        # web bundle + server compile
```

`npm run smoke` runs the whole pipeline against five fixture roots — `apps` for
the expected classifications, `edge` for the regression cases (URL credential
redaction, `env_file` containment, `dockflare.enable=false`, LDAP attribution,
nested interpolation, LAN-port exposure — `ports:` vs `expose:`, the
tunnel-straight-at-the-container pattern and the bypass note on a proxied service
— and provider attribution in a fleet whose SSO is *not* Authentik, where every
mechanism is observable but nothing may be attributed to a vendor), `nets` for what
is and is not a connection between two services, `authentik` for the
identity-provider integration, and `traefik` for the reverse-proxy integration.

Both API roots drive canned responses (`fixtures/authentik-api.json`,
`fixtures/traefik-api.json`) through an injected HTTP layer, so the tests need no
network, no Authentik and no proxy.

The `authentik` root pins each match rule in isolation, the rejection of an
ambiguous match, the unserved-provider outcome, pagination, and the rule that a
token is never sent to a host that has not answered the unauthenticated probe.

The `traefik` root is a fleet built so the labels and the live config disagree in
every way that matters, and its stub demands Basic auth on the gated hostname while
answering unauthenticated only on the internal one. Seven runs over it pin: which
endpoint was chosen and why; a file-provider middleware reached through a `chain`
coming back `confirmed`; the **downgrade** on a router whose declared middleware is
absent from the built chain, and the false-positive guard where the same gate sits on
the entrypoint instead; a declared router the proxy is not serving, versus a router
the proxy *is* serving that no service could be attributed; a `disabled` router with
its errors; all three sources agreeing, and the `mode` that makes them disagree;
`serverStatus: DOWN`; the note that the API answered with no credential; that no
credential is sent anywhere when the internal endpoint answers, even with one
configured; that Basic goes only to the gated host and the session cookie is echoed;
that a partial read changes no posture; that a `fetchImpl` which throws leaves the
scan complete and the posture untouched; and the container-IP trap, asserted
directly on the index because a container IP only exists in live Docker state.
Each API root also runs its fleet **without** the API and asserts the difference in
both directions, so the contribution is measured rather than assumed.

Every fixture is written so it fails if the corresponding logic is reverted — for
both API integrations that was checked by actually backing each rule out one at a
time and confirming the expected assertions broke.

The web bundle is intentionally self-contained (mermaid + cytoscape are inlined,
~3 MB) so the dashboard works fully offline with no CDN dependency.

## Limitations

- Reads Compose stacks laid out as `appsRoot/<stack>/compose.yml`. Swarm and
  Kubernetes manifests are out of scope.
- Live state (status, health, IPs) requires access to the Docker API (via the
  socket proxy); without it the
  scan degrades cleanly to config-only.
- Auth detection is label/env-driven and reports its evidence so you can verify
  each conclusion. It describes *configuration*, not enforcement. Reading the two
  APIs narrows that considerably — an outpost assignment is enforcement rather than
  intent, and a middleware in Traefik's runtime chain is the config the proxy is
  actually running — but it is still configuration, not a request being challenged.
  LabView never sends a request through a gate to see what happens.
- The reverse-proxy integration is Traefik-specific: it reads Traefik's runtime API.
  Another proxy (Caddy, nginx, HAProxy) is still classified from its labels, and its
  routers are simply not verified. Traefik's static config file is not parsed —
  nothing guarantees it lives under `appsRoot`, and the API supersedes it. Response
  shapes come from Traefik v3's runtime model rather than a published schema, so a
  mismatch degrades to `reachable: false` with a reason instead of breaking the scan.
  Only `/api/rawdata` is used; there is no fallback to the paginated granular
  endpoints, and no write call of any kind exists.
- The Authentik integration reads applications, providers and outposts. Policy
  bindings are not read, so an application whose access policy denies everyone
  still reads as protected — which it is — and a flow customization that weakens a
  gate is not visible.
- **The applications endpoint does not hand over every application.** It runs the
  policy engine as the token's own user, so a least-privilege service account is served
  only what it may launch. LabView reports the total that endpoint declares, rebuilds
  the withheld applications from the providers assigned to them, and marks those
  `rebuilt` — such a record has no launch URL, no group, and only the providers the
  token can read, so it can be tied to a service by address or by name but never by a
  launch URL. An application whose only provider is a kind LabView does not read (SAML,
  LDAP-only) cannot be rebuilt at all and is reported as a count, which is why a
  narrow token can leave a `partial` banner that no scan will clear. Superuser on that
  account removes the filter; the three read permissions are still the recommendation.
- An application LabView cannot tie to exactly one service is reported as unmatched
  rather than guessed, in `meta.authentik.unmatchedApplications` — the gates it can see
  but cannot place, behind the `authentik` count in the topbar. Four rules are not every
  naming convention, and an application whose names and URLs fit two services equally is
  discarded on purpose, so expect some. Each one carries the rule-by-rule trace of what
  was tried, which is what makes the fix findable: a name or a redirect URI that agrees
  with the compose file, not a looser rule — every loosening trades a visible gap for an
  invisible wrong answer.
- A name match cannot be verified, only reported. LabView can tell that *two*
  candidates exist and decline; it cannot tell that a single candidate is the wrong
  service. That is what `observed` and "by name alone" are for.
- Traefik middlewares defined in a dynamic config **file** rather than in labels
  are invisible to the scan — a reference to one resolves to nothing, which is why
  the name-based fallback and the `inferred` confidence exist.
- **A network's members are the ones this scan can see.** An `external:` network can carry
  containers from outside the apps root, and nothing in a compose file names them — so a
  network node reports its scope and its *scanned* member count, and one with a single
  visible member says which kind of nothing is on the other end rather than reading as
  empty. Sharing a network also means reachable in principle, never that anything is
  listening; that is what ports and `expose:` answer.
- **Sharing a network is never read as a dependency.** Thirty services on a proxy network
  are thirty members, not four hundred and thirty-five connections, so a service's diagram
  draws a leg only where a dependency crosses that network — from a compose `depends_on`
  or from a [declared one](#a-dependency-on-another-service) — and everything else on it is
  a count in a sentence: *n other services are on it, reachable but not dependent*. Which
  ones they are is a fact about the network rather than about this service, so the network's
  name in the row is a link to its row in the **Networks** list, where every member is named.
  Nothing is ever inferred from co-membership, from a container name in an environment value,
  or from a port.
- **A busy network node cannot show which arrow pairs with which.** The arrowheads belong
  to a service, not to a pair, so a network carrying two dependencies draws four of them.
  The Networks list writes every pair out in words for exactly that reason, and the drawer
  separates "depends on" from "required by" per dependency.
- **A large network is summarised, not drawn whole.** The graph draws at most 12 spokes
  per network; the drawer names at most 8 dependencies and no co-members at all, and the
  Networks list 12 chips before you expand the row. Each says how many it left out, and the
  drawer reads the unpruned data so nothing is unreachable. The drawer has one cap because
  it has one list: with co-members reduced to a number, nothing that is merely reachable can
  crowd a real dependency out of the diagram. A monitoring network with forty members is a
  count plus a list under the network's own heading rather than forty lines — deliberately,
  since forty lines is what makes the small, informative networks impossible to find.
- **No filesystem watcher.** A compose or `.env` edit is picked up by the next scan —
  the `LABVIEW_CACHE_TTL` refresh, or Rescan — not the moment you save it. Rescan
  stays an explicit action; nothing auto-refreshes the page.
- LabView's own `config.yml` and environment are read once at startup. Rescan re-reads
  the fleet, not LabView's configuration: changing a configured endpoint, or rotating
  any of the four credentials, needs a restart. The one exception is the `user:hash`
  file behind the password login, which is re-read whenever it changes.
