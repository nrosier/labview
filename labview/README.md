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
  service's own drawer. A **Not confirmed** tile beside it opens the same kind of panel
  for the opposite case — a declared login the probe asked about and could not settle
  either way — and carries no warning colour, because nothing there is wrong yet.
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
  **derived auth posture with the evidence that led to it**, what the service answered
  with when the [probe](#probing-a-service-directly) asked it — which address, whether a
  login page came back, and which fact that verdict rested on — the matched
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
- **A scan that can ask, not only read** — everything above comes from configuration.
  Switch the [probe](#probing-a-service-directly) on and the scan also sends a
  `GET /` per HTTP service **it found no authentication for**, and reads the answer for a
  login page, which is the largest class of protection no compose file mentions. A login
  page takes the service out of the exposed count with its own badge; an answer *without*
  one turns an exposure that was inferred into one that was measured — and where the page
  served real content beside a sign-in link, the same response is read as *proof* the
  service is open rather than as an absence of evidence that it is closed. Off by default,
  since it is the only stage that sends a request to your own services — and even when
  it is on, a service already behind a detected gate is left alone, because its answer
  could not change the verdict.
- **Login probe panel** — the `Login probe 12` tile is a button for the same reason the
  integration counts are: the number is an outcome and the cases are behind it. Click it
  for one row per service asked — the address tried and the vantage it came from, what
  came back, and **why** that was or was not read as a login page, naming the fact the
  verdict rested on rather than restating the verdict. Grouped with the answers that
  cleared nothing first, and the services that never answered kept separate from both,
  since nothing was measured about those at all. The tile also says how many services
  were **not** asked, so a count of 13 in a fleet of 14 HTTP services reads as a fleet
  with a gate rather than a service that got lost.
- **Rescan** — re-reads every `compose.yml` and `.env` under the apps root *and*
  re-runs both API exchanges, then reports what moved on each side, inline beside
  `scanned <time>`: `+1 stack, 2 services changed · authentik +2 applications`, with
  the names on hover. New stacks, deleted stacks, added services and edited files all
  show up in the first note; applications, providers, routers and middlewares that
  came or went show up in the second. Live state changing on its own does not appear
  in either. When everything is the same as last time it says so — `no config changes
  · authentik and traefik unchanged` — rather than leaving you to guess whether it
  looked.
- **Which build you are looking at** — the short commit beside the wordmark, since while
  this is pre-release every build calls itself `0.1.0` and only the sha tells two of them
  apart. The tooltip adds the version and, more usefully, *how* the commit is known: an
  image built from it, or a checkout that was at it — which says nothing about uncommitted
  edits, and says so. See [Which build am I looking
  at](#which-build-am-i-looking-at).
- **Light / dark** theme (follows the OS, with a manual toggle).

Colors follow a validated, colorblind-safe palette. The ingress and auth-method
hue orderings were run through a CVD/contrast validator in **both** light and
dark modes (adjacent segments stay distinguishable for colorblind viewers);
low-contrast segments always carry a direct text label, and status colors always
ship with an icon and label, never color alone.

---

## Quick start (local)

Go 1.23 or newer, and nothing else — no Node, no bundler, no package manager. The web
UI is committed under `internal/webui/dist` and embedded by `go:embed` at compile time,
so `go build` is the whole build:

```bash
cd labview
LABVIEW_APPS_ROOT=/path/to/your/apps go run ./cmd/labview
# open http://localhost:8080
```

Or build the binary once and run that:

```bash
go build -o labview ./cmd/labview
LABVIEW_APPS_ROOT=/path/to/your/apps ./labview
```

Live state comes from `/var/run/docker.sock` by default, so a local run needs no
extra setup — and if the socket isn't reachable the scan degrades cleanly to
config-only. To read the Engine over TCP instead (a socket proxy, typically), name
the endpoint:

```bash
LABVIEW_APPS_ROOT=/path/to/your/apps LABVIEW_DOCKER_HOST=tcp://your-proxy:2375 ./labview
```

Just want a one-shot report on the terminal (no server)?

```bash
LABVIEW_APPS_ROOT=/path/to/your/apps ./labview scan
```

That writes the whole `Overview` payload to **stdout** as indented JSON and every
diagnostic to **stderr**, so the two never mix and stdout stays parseable — pipe it
straight into `jq`. `-compact` writes one line instead, and `-probe true|false`
overrides `probe.enabled` for that scan alone.

The stderr side is the digest: one `[conn]` line per outbound read naming the stage it
stopped at and why (with the candidate addresses it tried, indented beneath), then one
`[scan]` line counting what it found.

```text
warn  [conn] docker: connect unix:///var/run/docker.sock (default) — refused, unreachable, or no route …
warn  [conn] probe: disabled — set LABVIEW_PROBE_ENABLED=true, or tick the box beside Rescan …
info  [scan] 6 stacks, 9 services in 329ms
```

The digest the old `--summary` flag used to print is `jq .stats` — it is in the payload
rather than in a second reporting path in the binary, so the numbers on the terminal and
the numbers in the UI cannot disagree:

```bash
./labview scan | jq .stats
```

That object counts the stacks and services found, how many are public, LAN-only, internal
or without ingress, the auth breakdown by mechanism, the declaration counters, and the
probe outcomes. Its four network counters are the ones worth reading together —
`networks`, then `connectingNetworks`, `crossStackNetworks` and `soloLocalNetworks`: the
difference between a fleet full of networks and a fleet where networks connect things.

The other two subcommands are `labview hashpw <user>` (§19's `user:hash` line, password
on stdin — see [Access control](#access-control)) and `labview version` (the build
stamp). No arguments at all means `serve`.

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
| `LABVIEW_PROBE_ENABLED` | `false` | Whether a scan **asks** each HTTP service it found no authentication for — services already behind a detected gate are never asked, since the answer could not change the verdict. Off until you turn it on: this is the only stage that sends a request to a scanned service. It is also the *default* rather than the last word: the switch beside Rescan decides one rescan either way. See [Probing a service directly](#probing-a-service-directly) |
| `LABVIEW_PROBE_LAN_HOST` | *(unset)* | Your host's LAN address, so a published port can be asked at `<lanHost>:<port>`. LabView sees only its own container's interfaces and cannot work this out. Unset means published ports are not asked |
| `LABVIEW_PROBE_TIMEOUT` | `5000` | Per-request timeout, ms. A service that does not answer in time is recorded as a timeout, which is its own finding |
| `LABVIEW_PROBE_MAX_CONCURRENCY` | `4` | Services asked at once. Kept low because these requests fan out across the fleet and many of them land on one reverse proxy |
| `LABVIEW_BUILD_SHA` | *(unset)* | The commit this build came from, so the page can name it. Set at **image build time** — `--build-arg LABVIEW_BUILD_SHA=$(git rev-parse HEAD)`; the published image sets it from the workflow. A full object id is shortened to seven characters, anything else is used as given, and unset is fine: LabView falls back to the checkout it is running from, then to saying it does not know. See [Which build am I looking at](#which-build-am-i-looking-at) |

The default Docker endpoint is the conventional local socket, since it is the one
endpoint that needs no assumption about your container names; a socket proxy is
opted into with `LABVIEW_DOCKER_HOST`.

`LABVIEW_BUILD_SHA` is the only variable with no `config.yml` equivalent, because
it describes the build rather than the fleet: a value in a file you can edit while
the same bytes keep running is a value that can start lying about which bytes those
are.

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

### Probing a service directly

**Off by default.** With `LABVIEW_PROBE_ENABLED=true` — or the switch beside **Rescan**,
for one rescan at a time — a scan stops only reading configuration and starts *asking*:
a `GET /` per eligible service, and it reads what comes back for the signs of a login
page. One shape of answer costs a second request, and only that one — see [what it
sends](#probing-a-service-directly) at the end of this section.

This exists because the largest class of real protection there is — an application's
own login form — leaves no trace anywhere a compose scan can look. No middleware, no
env key, no Authentik application. Before the probe the only way to keep such a service
out of the exposed count was a [declaration](#declaring-what-the-scan-cannot-see), which
nothing could check. Asking is evidence; a declaration is a claim.

It cuts both ways, and the second half matters just as much: a service that answers
with **no** login page turns an exposure that was inferred from configuration into one
that was measured. And where that answer was a page a visitor could actually read, the same
response says something stronger than "nothing refused me" — see [what the page showed a
visitor](#what-the-page-showed-a-visitor), below.

**What gets asked, and at which address.** Two conditions, and a service has to meet
both.

First, LabView must have already *observed* HTTP for it — an `http`/`https` tunnel origin,
or a `traefik.http.routers.*` label.

Second, **this scan must have found no authentication for it.** A Traefik auth middleware,
an OIDC issuer in its environment, an enforced Authentik provider, a Cloudflare Access
policy on its route — any one of those and the service is not asked at all. The reason is
arithmetic rather than politeness: authentication LabView detected already keeps the
service out of the exposed count, so the probe's answer could not move the verdict either
way. What the request *could* do is put traffic on somebody's SSO endpoint to confirm
something already known. There is no setting for this, because a setting to turn it off
would only buy extra requests with no answer attached.

A service that merely [*declares*](#declaring-what-the-scan-cannot-see) authentication is
still asked. A declaration is a claim, not detection, and checking claims is what the
probe is for.

Addresses are tried most- to least-exposed, and the walk stops at the first one that
answers:

| Vantage | Address | Note |
|---|---|---|
| `public` | `https://<tunnel hostname>/` | **This request leaves your fleet.** It goes out to the tunnel provider's edge and back in, exactly as a visitor's would |
| `traefik` | `http(s)://<router host>/` | The proxy hostname from the label; `https` when the router declares TLS |
| `lan` | `http://<lanHost>:<published port>/` | Only when `LABVIEW_PROBE_LAN_HOST` is set. Unset means this vantage is skipped |

A service with a `ports:` mapping and no route is **not** eligible, and that is the rule
that keeps the probe off your database ports — a Postgres port is never asked, whatever
`LABVIEW_PROBE_LAN_HOST` is set to. The cost is stated plainly: a LAN-only service with
no route stays inferred rather than measured. So does a `tcp://` tunnel, which is not
HTTP no matter what is behind it.

**What counts as a login page.** Eight signals. Seven of them read the response to
`GET /` and nothing more:

| Signal | Fires on |
|---|---|
| Credential requested | 401 or 407 **with** a `WWW-Authenticate` header |
| Redirected off-site | a 3xx whose `Location` is a different origin |
| Redirected to a login path | a 3xx to a login path — `/login`, `/signin`, `/sign-in`, `/users/sign_in`, `/sso`, `/oauth2`, `/auth/`, `/outpost.goauthentik.io`, `/if/flow/` or `/flows/-/` |
| Sent to a login by refresh | a 200 whose HTML carries a `<meta http-equiv="refresh">` pointing at either of the two above |
| SSO hand-off served | a 200 carrying a hidden `SAMLRequest` or `SAMLResponse` input — the SAML POST binding *is* that page |
| Login form served | a 200 whose HTML carries an `<input type="password">` (or `autocomplete="current-password"`) |
| Passwordless login form served | a 200 with a form that has a username field, a submit control and a login-intent marker — an `action` on one of the login paths above, or a `one-time-code` field — and no password anywhere. This is what magic-link and passkey sign-in look like |

The eighth needs a **second** request, because it is the one page no reading of a body can
judge. **`Credential requested behind the page`** fires on a 200 of HTML with no `<form>`
anywhere in it — a login screen drawn in the browser is not in the served markup — where one
of four current-user addresses then answered **401 or 407 with a `WWW-Authenticate` header** to
a request carrying no credential. The addresses are a fixed list, the same four every scan:
`/api/`, `/api/me`, `/api/v1/me`, `/api/v1/user`. They are asked in that order and the walk
stops at the first refusal, so the usual cost is one extra request.

Nothing else. A bare 401 with no challenge header, a 403, a `/` → `/dashboard` redirect —
whether by `Location` or by refresh — a homepage with the words "Sign in" on it, a
newsletter box that posts an email address to a hosted list service: all read as *not* a
gate. So does a current-user address that refuses without naming a scheme, and that one is
the near miss worth knowing about: it is exactly what an anonymous-enabled Grafana or a
world-readable Gitea answers, pages that serve everybody while truthfully reporting that
nobody is signed in. The drawer says where it was found and what it said; the service stays
in the exposed count. All of these still show as what was measured, and none of them clears
an exposure. That asymmetry is deliberate: a false finding costs you a look, while false
comfort is the thing this tool exists to remove.

Every signal but one rests on a single fact. `Passwordless login form served` cannot — a
username field and a button are also a newsletter signup — so it requires three things
together, and the login-intent marker is what separates the two. Where a form was found, the drawer says
what it was made of (`a password field, a username field and a submit button`) whether or
not anything was concluded from it, so a page that looks like a login and did not count
shows you why.

When a signal does fire, the service leaves the exposed count and its badge reads
**Login page answered**. What it does *not* get is a mechanism: `auth.method` stays
`none`, because a password field does not say whose login form it is. A probe is
evidence of a gate and never a name for one.

Two things it will not do. It will not contradict a gate your configuration declares — a
response from LabView's own vantage point may not have travelled the gated path, so an
answer with no login page could only ever be a note, never a downgrade. That rule is now
also the reason such a service is not asked in the first place: eligibility and the
non-downgrade both read the same predicate, so a service can never be skipped for a
reason its own notes contradict. And it will not make a stale
[declaration](#declaring-what-the-scan-cannot-see) look right: an acceptance for an
exposure the probe now finds gated is reported as drift.

It will not go the other way either. A declared login the probe asked about and did not
find is **not** reported as drift — one request to `/` returning no login page is equally
consistent with a login a route deeper, so it is recorded as *unconfirmed* instead, with no
warning attached. Only the first of these two is a contradiction.

**What it sends.** `GET`, and no credential is in scope anywhere on this code path.
Redirects are read rather than followed, at most four addresses per service, and a response
body is read only when it is HTML and under a size cap. The URLs come out of your compose
files, so they are treated as untrusted input.

The first request is always `GET /`. A **second** goes out only for the answer the eighth
signal is about — a 200 of form-less HTML that gated nothing — and only to the four
current-user paths above, at the origin that already answered. Nothing is taken from the
page: the paths are a fixed list, which is what stops a scanned document from choosing where
LabView asks next. The walk is sequential and stops at the first refusal, so a service costs
one extra request in the ordinary case and four at most. Every scan prints the total it sent:

```text
probe    20 services probed — 10 gated, 9 open, 1 did not answer — 2 services not asked
         (authentication already detected) — 16 extra requests at current-user addresses
```

Failures are soft here too, and reported as their own outcome rather than folded into
either verdict: a service that does not resolve, refuses the connection or times out is
**No answer**, and its posture rests on configuration exactly as it did before. The
aggregate reads like `31 services probed — 12 gated, 17 open, 2 did not answer — 9
services not asked (authentication already detected)`, and that mixed case is reported as
`partial` rather than as a success: some of the fleet answered, and what was read is
sound, but part of the picture is missing and the line says which part.

The last segment appears only when something was withheld — `0 not asked` on every
unauthenticated fleet would be a fact about nothing. A fleet where *everything* with an
HTTP address is already authenticated reads
`9 services not asked — authentication was already detected for every service with an
HTTP address` and is a **success**, not a failure: the stage ran, decided about every
candidate, and the decision was that none of them needed asking. Only a fleet with the
probe on and no HTTP address anywhere is reported as having found nothing, since that is
a fact about the labels.

#### What the page showed a visitor

Everything above asks *is there a login page?* and an answer of no is an **absence** — none
of the eight signals fired. An absence is easy to discount, and rightly, because it is also
what a login page this rule cannot read looks like.

So the same response is read a second time, the other way round: **what did the page show a
caller who sent nothing?** No extra request, no new signal, nothing that can change a
verdict — just the body that was already read, measured for two things at once:

- **content** — how many characters of visible text and how many same-origin links came
  back, with scripts, styles, comments, `<template>` and `<noscript>` removed first, so a
  shell full of undrawn markup does not read as a finished page; and
- **an offer to sign in** — an `<a href>` on one of the login paths, or an anchor or button
  whose own short label says so in any of a dozen languages. A *sign-out* link is skipped
  before its path is read, because a page carrying one is a page somebody is already signed
  in to.

Both together is the finding, and it is the first thing LabView can report *for* an open
verdict rather than in explanation of one:

```text
It answered HTTP 200 with a page and no login form. It also served 358 characters of text
and 3 links to a caller carrying no credential, beside a sign-in link to /login labelled
"Sign in". That is an application with an optional account rather than a gate in front of
one: a visitor who never signs in is shown this page.
```

Content with no offer gets the narrower half of that — *what came back is the application's
own content and not a shell* — which is still worth having, since it rules out the one page
no body-reading rule can judge.

An offer with **no** content says nothing at all, and that silence is the point: a sign-in
link on a page that rendered nothing is a login screen whose form has not been drawn yet,
which is the opposite conclusion. That case is left to the eighth signal's current-user
addresses, which are the right question for it.

This can only ever *add a sentence* to a service that stays in the exposed count. It cannot
gate anything, take anything out of the count, or turn into a mechanism — the rule that
decides gates cannot see this reading at all.

#### Reading the results

A **Login probe** tile appears on the overview whenever a scan asked anything — or
*decided not to*, since a fleet where everything with an HTTP address is already behind a
gate would otherwise show no sign the stage had run at all. It shows how many services
were asked, and where that is none, its subtitle says how many were already
authenticated. Clicking it opens a panel with one row per service, and each row answers
the three questions a count cannot:

- **the address tried**, with the vantage it came from — a public hostname answering
  means something a published host port answering does not
- **what came back** — the status, the outcome badge, and the composition of the form if
  a form was found
- **why that was or was not read as a login page**, naming the fact the verdict rested
  on: `It answered HTTP 302 and sent the request to /dashboard, which is on its own
  origin and is not a login path — routing rather than a gate.`

The rows are grouped by what the answer was worth, and the group that **cleared nothing**
comes first: those are the services the probe left exactly as it found them. Then the
gated ones. Then, separately and last, the ones that did not answer — nothing arrived
from those addresses, so the probe added nothing either way, and the panel says so rather
than letting an empty result read as "no login page found".

The panel's own header says how many services were **not** asked and why, so the count of
rows is never mistaken for the size of the HTTP fleet. A service that was not asked has no
row: there is nothing to report about a request that was never sent, and its drawer shows
its posture with no probe block at all.

Nothing in the panel is tinted red, deliberately. A service in the first group is not by
itself a finding: a service whose `.labview` file *declares* a mechanism is asked anyway —
a declaration is a claim, not detection — so it can land there while staying out of the
exposed count. And a signal that did not fire is not a fact about anything: the rule is
strict, so a page it does not recognise may still be a login page. The panel is where you
check *what was measured*; **Exposed, no auth** is where a fleet finding is claimed. Every row links through to that service's own drawer, which shows the same
result beside everything else known about it — and the drawer carries the same "why"
line, so following a row through reads as one result rather than a second account of it.

#### The switch beside Rescan

`probe.enabled` decides what a startup scan and every scheduled rebuild do. The
checkbox in the header decides what **one** rescan does, in either direction and
whatever the configuration says — probing on for a fleet configured with it off, or off
for one configured with it on. It sends an optional body with the rescan:

```bash
curl -X POST localhost:8080/api/rescan -H 'content-type: application/json' -d '{"probe":true}'
```

No body, or anything that is not a JSON boolean, means "use the configuration" — so
existing `POST /api/rescan` callers are unaffected.

Two things worth knowing before you use it:

- **It is not sticky.** The next scheduled rebuild comes back to `probe.enabled`, which
  means probe results appear when you ask and leave again when the cache expires. So the
  payload says what actually happened — `meta.probe` carries `enabled` and whether
  `config` or the `request` decided it — and the checkbox re-syncs from that on every
  scan it receives. The switch moving back on its own is the revert, not a bug. To have
  probing on for good, set `probe.enabled: true`.
- **`POST /api/rescan` needs a session only while [access
  control](#access-control) is configured.** Without a passwd file or an OIDC issuer,
  anyone who can reach the page can ask for a probing scan — a request per eligible
  service, some of them to public hostnames. They can already read your whole inventory
  from `/api/overview`, so the login is what closes this, not the switch.

---

### Which build am I looking at

The topbar names it, next to the wordmark:

```text
● LabView d0e2030
```

Those seven characters are the commit the build came from — the same identifier as the
`:<sha>` image tag and as `git rev-parse --short HEAD`. While LabView is pre-release the
version number is not the useful one (it is `0.1.0` on every build), so the commit leads
and the version sits in the tooltip, together with **where the commit came from**:

| Tooltip says | What it means |
|---|---|
| `image built from commit d0e2030` | `LABVIEW_BUILD_SHA` was set at image build time, so those bytes were compiled from that commit |
| `running from a checkout at commit d0e2030` | Read from the `.git` directory this process started in. Uncommitted changes are **not** reflected — a file read sees `HEAD`, never your working tree |
| `does not record which revision it came from` | Neither was available. The label falls back to `0.1.0` |

The published image carries the first, set from the commit the workflow built. Building
your own:

```sh
docker build --build-arg LABVIEW_BUILD_SHA=$(git rev-parse HEAD) -t labview:mine ./labview
```

Leaving the argument off is supported, not an error — the build simply says it does not
know, and `go run ./cmd/labview` from a checkout finds the commit without any argument at all. The
stamp is **behind the login**: it is drawn from `/api/overview`, so the login card shows no
build, and a visitor who cannot sign in cannot use it to match a known issue to your
instance.

A linked worktree or a submodule reports no revision rather than guessing: its `.git` is a
file pointing into another repository's layout, and the enclosing repository's commit is
not this build's. `LABVIEW_BUILD_SHA` is the answer for those trees.

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
# in the image — no shell in there, so the binary is the entrypoint and stdin is the password
printf 'the password' | docker run --rm -i labview hashpw alice >> ./config/passwd

# from a checkout
printf 'the password' | go run ./cmd/labview hashpw alice

# with apache2-utils, if you have it
htpasswd -nbB alice '<password>'
```

The first two **read the password from stdin and never from an argument**, because `ps`,
`/proc` and your shell history can all read a command line; `htpasswd` takes it as an
argument, which is worth knowing before you use it. `printf` rather than `echo` because
`printf` sends no trailing newline — though `hashpw` strips one if it arrives, so both
produce the same hash, and a password that legitimately ends in a space is left alone.

There is no cost flag: the cost is fixed at **12**, because the hash has to be made by
the same implementation that verifies it, and a per-line cost would be a credential
format this program's verifier had an opinion about. Every sign-in pays it, and 12 is
roughly 250 ms on a homelab CPU. The username must match `^[A-Za-z0-9._@-]{1,64}$` —
`hashpw` refuses anything else rather than minting a line that can never be signed in to.

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

Every outbound read — the Docker endpoint, the Authentik API, the Traefik API, and
the [direct probe](#probing-a-service-directly) when it is switched on — reports the
**stage** it stopped at, because "unreachable" covers a dozen different fixes. On
startup and on any change you get one line per target:

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

The same lines print on stderr under `labview scan`, the same phase and reason
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
      → read the Authentik API ∥ read the Traefik API ∥ ask each HTTP service
                                          (one round trip; the third is opt-in)
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
  that built-in login is the answer, there are two ways to say so: switch on the
  [direct probe](#probing-a-service-directly) and let the login page answer for itself,
  which is evidence, or write a `.labview` sidecar, which is a claim — see
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
- **The one read that goes to a scanned service is off by default.** The
  [direct probe](#probing-a-service-directly) is the only stage that sends a request to
  something in your fleet, and it does nothing until `LABVIEW_PROBE_ENABLED=true` or a
  rescan asks for it. Turned
  on it is `GET /` with no credential in scope on that code path, redirects read rather
  than followed, at most four addresses per service, a body read only when it is HTML and
  under a size cap, and only ever to a service where HTTP was *observed* — a database
  port is never asked. A public hostname means the request leaves the fleet and comes
  back through your edge, which is the point of that vantage and worth knowing before you
  switch it on.
- **[The switch beside Rescan](#the-switch-beside-rescan) overrides that setting, both
  ways, for one rescan.** `POST /api/rescan` needs a session only while access control is
  configured — so with no passwd file and no OIDC issuer, anyone who can reach the page
  can ask for a probing scan. The same visitor can already read your entire inventory from
  `/api/overview`, which is why the answer is to configure the login rather than to narrow
  the switch. If you are relying on `enabled: false` to mean *no traffic leaves, ever*,
  configure the login too.
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
   alarm is always visible as a number. Where the login probe went and asked about one of
   these and came back no wiser, that is visible too, as its own subset count
   (`stats.declaredAuthUnconfirmed`) — see *Declared, not confirmed* below.
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

### Declared, not confirmed

There is a fifth check, and it is deliberately *not* drift. When a service is kept out of
the exposed count by a declared login and the login probe reaches its address and finds no
login page, that is recorded as **unconfirmed** — its own count, its own `Not confirmed`
tile, and no warning anywhere:

> `.labview` declares the service authenticates itself (Local accounts in the app). LabView
> requested `https://portal.example.com` and no login page answered (HTTP 200) — an absence
> of evidence rather than a disagreement, since a login one route deeper, a sign-in screen
> drawn by the client, or a mechanism that does not sit in front of this address would each
> answer exactly this way. The declaration stands, unconfirmed.

The probe asks one address, at `/`, once. A login a route deeper, a sign-in screen the
browser draws after the page loads, a token guarding an API rather than a landing page, and
a network restriction LabView is on the permitted side of all answer exactly like a service
with nothing in front of it. So the answer is worth telling you about and is not worth
warning you about, and the two are different channels: drift means *the file and the scan
contradict each other*, and an alarm that also fires on *we could not tell* is one you learn
to ignore. Your declaration still stands, the service is still out of the exposed count, and
the entries render as plain notes rather than in the drift red.

The `Not confirmed` tile opens the same kind of panel as drift — every unconfirmed service
under its stack, each row a link into the drawer. Read it as *the sidecars worth checking by
hand*, not as a list of things that are wrong. The CLI prints it without the `!` that marks
drift and warnings:

```text
  declared-protected: 2  (reachable, no detected auth, declared self-authenticating — unverified)
  unconfirmed:      1  (of those, probed and no login page seen — neither confirmed nor contradicted)
```

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
| `/api/rescan` | POST | **Needs a session.** Re-read the apps root and return the rebuilt overview. Optional JSON body `{"probe": true \| false}` decides active probing for that one scan; no body, or anything that is not a boolean, uses the configuration ([the switch](#the-switch-beside-rescan)) |
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

The [direct probe](#probing-a-service-directly) is **additive** — nothing in the payload
changed shape for it. `service.probe` is present only for services that were asked, and
absent for every service when the stage is off:

```jsonc
{
  "endpoint": "https://app.example.com",     // origin only, credential-free
  "vantage": "public",                       // "public" | "traefik" | "lan"
  "phase": "connected",                      // `connected` = a response arrived, whatever its status
  "status": 302,
  "gate": "redirect-origin",                 // absent unless one of the eight signals fired
  "mediaType": "text/html",                  // parameters dropped; absent if no content type came back
  "redirect": { "to": "https://sso.example.com/", "crossOrigin": true },
  "refresh": { "to": "/dashboard", "crossOrigin": false },   // where a <meta refresh> pointed
  "truncated": true,                         // the body continued past the 64 KiB read
  "form": { /* what a login form was made of, when one was found */ },
  // Present only when a second request went out — a 200 of form-less HTML that gated
  // nothing. Absent, which is the ordinary case, means one request was sent and no more.
  "state": {
    "asked": 1,                              // how many current-user addresses were asked
    "refusedAt": "/api/",                    // absent when none of them refused
    "status": 401,
    "challenge": true                        // the refusal named a scheme — this is the gate
  },
  // What the same page showed a caller who sent nothing. Present whenever a body was read
  // as HTML, gate or no gate, because it describes the response rather than the verdict.
  "anon": {
    "textChars": 358,                        // visible text: scripts, templates, noscript removed
    "links": 3,                              // distinct same-origin links that are not login or logout
    "loginHref": "/login",                   // absent unless the page linked to one
    "loginLabel": "Sign in"                  // absent unless a short label said so
  },
  "detail": "HTTP 302 — redirected off-site",
  "attempts": [ /* one per address tried, in vantage order — same shape as every other target's */ ]
}
```

`phase` reads differently here than on the API clients: `connected` means *an HTTP
response arrived*, so a 401 is the best possible outcome rather than a failure, and
every other value (`resolve`, `connect`, `tls`, `timeout`) means nothing answered — at
which point `gate` is necessarily absent. `stats.probeGated` and `stats.probeOpen` are
the two counts that follow from it, and `meta.connections` gains a fourth entry with
`target: "probe"`, `disabled` when the stage is off.

The four fields between `gate` and `form` are the **facts the verdict rested on**, and
each is absent exactly when the response had no such thing: no `redirect` because nothing
was a 3xx, no `refresh` because the page carried no `<meta>` tag, no `truncated` because
the body fitted. They are what lets the UI say *why* rather than only *what* — a 302 to
`/dashboard` and a 302 to `/login` are the same status and the opposite finding. Both
redirect targets are reduced before they are recorded: the query and the fragment are
dropped, and the origin is kept only when the target actually left the origin. That is
not tidying — an OAuth `Location` carries `state` and `code`, and a login redirect carries
`?next=`, and neither has any business in an API response.

`anon` is the one field here that is not a fact a verdict rested on, because it points the
other way: it is [what the page showed a visitor](#what-the-page-showed-a-visitor), and no
gate rule reads it. Its two strings are the only page content that reaches the payload at
all, and both are reduced the same way the redirects are — a path with no query, and a label
short enough to be a label.

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

**`meta.version` is gone, replaced by `meta.build`** — breaking, and the smallest of these:

```jsonc
{
  "version": "0.1.0",       // internal/config.Version — the one place it is written
  "commit": "d0e2030",      // short commit; absent when source is "unknown"
  "source": "image"         // "image" | "checkout" | "unknown"
}
```

`meta.version` is the constant `internal/config.Version` and nothing else — there is no
manifest for it to drift against, which is the point: a build file carrying a second copy
of the same number would be a fresh duplicate, not a kept promise. `source` is never absent and
`commit` may be, because they answer different questions: a build genuinely may not know
its revision, while *how* it knows is what says whether the sha describes the running bytes
or only the tree they were started in. See [Which build am I looking
at](#which-build-am-i-looking-at) for what each source is entitled to claim.

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

A `{"probe": …}` body rides along the same machinery, and coalescing decides who gets
their way: the build that *starts* owns the override, and a caller that arrived while it
was already running gets that build's result rather than its own. `meta.probe` therefore
describes the scan you were handed, not the request you sent — which is also what makes
the checkbox in the header correct after a rebuild it did not ask for.

---

## Development

**Read [../IMPLEMENTATION.md](../IMPLEMENTATION.md) before changing the scanner or
analyzer.** It documents the requirements, the pipeline stage by stage, and the
invariants that keep the output trustworthy — evidence-only conclusions, no
fleet-specific identifiers, mechanism vs. provider, degrade-never-fail — plus a
decision log explaining why the non-obvious choices are what they are.

Every package names the section it implements in its doc comment, so `go doc` and the
spec are the same table of contents:

```text
cmd/labview/  main + the three subcommands (§2.5): serve, scan, hashpw
internal/
  config/     §3   defaults, the configuration file, the environment, retired keys
  scan/       §6   the compose tree, interpolation, env files, sidecars, containment
  labels/     §7   the two label vocabularies, the middleware registry, provider hints
  fleet/      §8+9 what needs the whole fleet: ingress sets, the network index,
                   tunnel origins, the graph, declared dependencies, stats
  declare/    §14  what a sidecar file may do, comparison and drift
  dockerapi/  §10  the container snapshot over a socket or TCP, and its classifiers
  authentik/  §11  the identity-provider read and the match that ties it to services
  traefikapi/ §12  the proxy read and the match that ties its live routers to services
  probe/      §13  the active probe: eligibility, addresses, the eight signals
  pipeline/   §5   one scan, from a compose tree to one Overview
  payload/    Appendix A — every type on the wire, plus normalisation and vocabulary
  changes/    §17  what moved between two scans, and what to say about it
  cache/      §17  one scan shared by every reader, and what makes a rebuild
  conn/       §15  one shape for every outbound target, and every phase in it
  transport/  the one HTTP chokepoint — injectable, which is what makes tests hermetic
  httpapi/    §18  the whole HTTP surface, the asset handler, the auth routes
  access/     §19  LabView's own login: passwd, bcrypt, sessions, OIDC, throttling
  secrets/    §20  the mask, and credentials embedded in URIs
  webui/      §22  the view/vocabulary/diagram tables, the generated contract, the
                   embedded bundle under dist/ (hand-authored: no bundler, no Node)
  corpus/     §23  the full pipeline over the fixture roots — the CI gate
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
  probe/      a fleet the scan asks: every login-page signal, every near-miss,
              and the services that must never be asked at all
  auth/       not a fleet: a good, a messy and an empty passwd file for §19's login
  outside-root.env, outside-root.labview
              two files outside every scan root, which exist to be refused (I8)
```

```bash
go build ./...                 # every package, including the three subcommands
go vet ./...
go test ./...                  # unit tables + the corpus: this is the CI gate
go test -race ./...
go mod tidy -diff              # the dependency surface §2.1 caps at three
```

There is no separate typecheck, no bundler step and no smoke script: the compiler is the
typecheck, and the smoke suite is `internal/corpus`, which is an ordinary Go test. After
changing any table in `internal/webui`, regenerate the committed browser contract — a test
fails while it is stale:

```bash
go test ./internal/webui -run TestContractAsset -update
```

**Where the probe's harder rules came from.** An earlier revision carried a `probe-lab`
diagnostic — point it at a URL and it reported which of the signals fired, what evidence no
signal read yet, and what a ninth would have to be. It is not part of this implementation
(§2.3 permits no diagnostic tool in the image, and the questions it answered have been
answered), but two of its findings are rules now, and both are worth knowing when reading
`internal/probe`:

- **A redirect to an Authentik flow executor** needed no new signal at all. The first
  `Location` was already the evidence; the path was simply missing from the list, so the fix
  was two entries and a fixture.
- **The form-less shell** became `state-challenge` (§13.4). The scan asks four current-user
  addresses itself when that is the shape it got back, because a `401` from a request
  carrying no credential is an application refusing an anonymous caller — and the served
  markup of such a page could never have said so.

The general finding is the one to keep: when the probe was wrong about a service, **the login
was not misread, it was somewhere the scan does not look.** That is why a widened address
list is a cheaper fix than a new signal, and why §13.3 is a list of paths as much as a list
of rules.

`internal/corpus` runs the whole pipeline against seven fixture roots — `apps` for
the expected classifications, `edge` for the regression cases (URL credential
redaction, `env_file` containment, `dockflare.enable=false`, LDAP attribution,
nested interpolation, LAN-port exposure — `ports:` vs `expose:`, the
tunnel-straight-at-the-container pattern and the bypass note on a proxied service
— and provider attribution in a fleet whose SSO is *not* Authentik, where every
mechanism is observable but nothing may be attributed to a vendor), `nets` for what
is and is not a connection between two services, `authentik` for the
identity-provider integration, `traefik` for the reverse-proxy integration,
`probe` for the [direct probe](#probing-a-service-directly), and `auth` — not a fleet at
all — for the passwd parsing behind [LabView's own login](#access-control).

Both API roots drive canned responses (`fixtures/authentik-api.json`,
`fixtures/traefik-api.json`) through an injected HTTP layer, so the tests need no
network, no Authentik and no proxy. The probe root's stub is keyed by URL for the
same reason — which address was asked is half of what there is to assert.

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
that a partial read changes no posture; that a `RoundTripper` which fails leaves the
scan complete and the posture untouched; and the container-IP trap, asserted
directly on the index because a container IP only exists in live Docker state.
Each API root also runs its fleet **without** the API and asserts the difference in
both directions, so the contribution is measured rather than assumed.

The `probe` root is a fleet of eighteen stacks built so that every login-page signal
and every near-miss appears exactly once, and it is run **twice** — once with the probe
off and once on — so what the stage contributes is measured rather than assumed. It
pins: each of the eight signals clearing an exposure, and each near-miss (a bare 401
with no challenge header, a 403, a same-origin `/dashboard` redirect — by `Location` and
again by meta refresh — a page with "Sign in" on it and no password field, a
newsletter box with the same email field and button as a magic-link login but nothing
marking it as one, a redirect to `/flows/123` that is a workflow tool rather than an
identity provider, and a form-less page whose current-user address refuses *without*
naming a scheme, which is what an anonymous-enabled Grafana answers) leaving the exposure
standing; the second request going out for exactly the one answer that needs it and
stopping at the first refusal; the vantage walk
stopping at the first address that answers, and falling through only on a transport
failure; a `tcp://` tunnel and a service with `ports:` and no route never being asked
at all; a service that does not answer coming back as a third outcome rather than
either verdict; a configured gate that is *not* downgraded by an open answer, and a
stale acceptance that *is* reported as drift.

**One stack points the other way.** `public-portal` is the only pair whose finding is
*open*: one service serves a landing page with a `Sign in` link and must produce the
sentence naming it, character count and all, while its sibling serves an article index
whose headline reads *How to log in to your router* beside a sign-out link and must
produce the narrower sentence with no offer in it. Between them they pin the label
vocabulary in both directions — loosen it and the second fails; back the sentence out
altogether and the first does.

**Two stacks are there to be left alone.** A service with a Traefik auth middleware named
by an unfound definition and one with a Cloudflare Access policy both have HTTP addresses
and are both eligible on every other count — and neither is asked, because this scan
already found authentication for them. Their entries in the URL-keyed stub stay in place,
which is what makes the check a trap rather than a tautology: the stub *would* have
answered, so an empty call log proves the request was withheld rather than that there was
nothing to withhold. Their verdicts are asserted byte-identical with the probe on and off,
which is the safety argument for the restriction stated as a test. The counted outcome is
pinned too — `skipped` is exact and the connection line names it — and no service
anywhere in the root carries both detected authentication and a probe result.

Three cross-cutting checks run over both passes: that the exposed count with the probe on
equals the count with it off minus exactly the services a login page answered for (I1),
that no service's mechanism or confidence moved between the two runs (I3), and that the
whole set of requests the stage sent was `GET` at `/` or at one of the four constant
current-user paths and nothing else, with no credential, no address asked twice, every
second request at an origin the first had already reached, and nothing sent anywhere near a
published database port (I8). The request total is pinned exactly, and against the count the
payload itself carries — which is what makes the walk's short-circuit falsifiable: removing
it changes no verdict in the root, only how many requests went out.

A separate group asserts the eight gate signals, the login-form field detection, the
reason wording and the state-challenge rule as **tables of literals** rather than through
fixtures — §23 requires that of every rule that can be stated without a fleet, because a
rule asserted only through a fixture is a rule you cannot read.

Every fixture is written so it fails if the corresponding logic is reverted — for both
API integrations and for the probe that was checked by actually backing each rule out
one at a time and confirming the expected assertions broke.

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
- **A login page the probe cannot recognise reads as an exposure**, and that direction is
  deliberate: a gate can only ever take a service *out* of the exposed count, so a rule
  loose enough to catch the rest would clear exposures that are real. Four known misses.
  A login shell built by JavaScript in an empty `<div id="root">` has no form in the HTML
  and there is no headless browser here — though this one is now narrower than it reads: a
  page that *rendered* is no longer part of it, because content served to an anonymous
  caller beside an offer to sign in is [read as proof the service is
  open](#what-the-page-showed-a-visitor). What is left is a body that drew nothing.
  A form below the 64 KiB the probe reads is never
  seen — and if the read stops mid-tag, that element is simply not counted rather than
  raising anything; the one thing that *is* said is that it happened, since a truncated
  read now adds "the page continued past what was read" to the reason. A magic-link form
  posting to a path nothing recognises as a login
  (NextAuth's `/api/auth/callback/email` and its neighbours) looks exactly like a
  newsletter box. And the *shape* of a 401/403 page is never read, since bodies are only
  parsed on a 200 — no exposure is missed there, because a challenge is already a gate,
  but the drawer cannot say what such a form was made of. When one of your own services
  lands in the wrong half of this, the drawer is where you find out which miss it is: it
  records the status, the headers and the reason for every signal that did and did not fire
  (§13.6), which is the same evidence a diagnostic would have printed. The
  JavaScript-rendered case is largely settled already — a client-rendered login screen is
  invisible in the markup, but the application behind it still answers `401` to an
  anonymous request at its current-user address, and `state-challenge` (§13.4) asks. For the
  body that genuinely drew nothing and whose API answers a
  *bare* `401`, the remedy is a line in the sidecar rather than a bigger probe: an `auth:`
  declaration (see [`.labview.example`](.labview.example)) takes the service out of the
  exposed count, is counted as *declared* rather than detected while doing it, and leaves
  what the probe read untouched. Rendering the page or fetching its bundle would not close
  that gap honestly — an application ships the same JavaScript whether the deployment gated
  it or not, so nothing inside it is evidence about *this* deployment.
- **A service behind a detected gate is no longer measured at all.** It is not asked, so
  there is no answer to report and its drawer carries no probe block — the posture rests
  on the configuration that already established it. What that costs is a corroboration
  LabView used to print and no longer does. What it buys is that no request is sent to
  somebody's SSO endpoint to confirm something already known, and the direction is the
  safe one: not asking can only ever leave a service *in* the exposed count, never take
  one out. The count is reported rather than hidden, on the read line and on the tile, so
  a fleet where nothing needed asking says so instead of looking like a stage that did not
  run.
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
