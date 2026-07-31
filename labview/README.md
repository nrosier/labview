# LabView

A self-hosted overview of a Docker-Compose homelab. Point it at the directory
where your per-container stacks live (`/mnt/apps/<container>/compose.yml`, with
optional `.env` files) and it produces a structured website showing **every app,
how it's set up, how it's reached, what protects it, and how everything is wired
together**.

It understands a specific, common TrueNAS Scale pattern:

- **Public ingress via a Cloudflare tunnel**, configured with **DockFlare**
  labels (`dockflare.hostname`, `dockflare.service`, …).
- **Local ingress via Traefik**, configured with `traefik.*` labels (routers,
  rules, entrypoints, TLS, middlewares).
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

- **Dashboard** — stat tiles (stacks, services, running, public, local-only,
  auth-protected, and a highlighted **exposed-without-auth** count) plus
  part-to-whole bars for **ingress exposure** and **authentication method**. The
  bar legends double as filters.
- **Stack list** — one card per stack, which is the unit you actually deploy. It
  rolls up its services: live status dots, hostnames, every distinct **ingress** /
  **auth** badge present, and a count of anything reachable without auth. Click to
  expand the services underneath, and again on one to open its detail. Search and
  filters are per service — exposure is a property of a service, not of a directory
  — and a stack shows up whenever one of its services matches.
- **Detail drawer** — for each service: a **Mermaid diagram** of its connections,
  Cloudflare routes **with what each origin resolves to and why**, Traefik routers
  (rule, hosts, entrypoints, TLS, middlewares), the **derived auth posture with the
  evidence that led to it**, the matched **Authentik applications and providers**
  when the API was read (including which outpost, if any, is actually serving each
  one), networks, ports, volumes, environment (secrets masked), and live container
  state.
- **Relationship graph** — an interactive [cytoscape](https://js.cytoscape.org/)
  graph of the whole fleet: services colored by exposure, plus network, volume,
  and tunnel / proxy / SSO hub nodes, connected by network membership,
  `depends_on`, shared volumes, ingress, and auth edges. Click a service to open
  its detail. A hub appears only when something observed calls for it — and an
  SSO gate whose provider could not be identified gets its own generic hub rather
  than being drawn as a vendor. Tunnel ingress is drawn as the path the config
  describes: where a route's origin resolves to another service, that service is
  drawn as the hop (`tunnel → proxy → service`) and highlighted as the
  infrastructure it was observed to be.
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

LabView has **no built-in authentication** — it exposes your topology and
(masked) config, so don't publish it raw. Expose it the same way as your other
apps by adding labels; [`compose.yml`](compose.yml) has a ready-to-adapt example
for **Traefik + Authentik forward-auth** and/or **DockFlare**:

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

Two things LabView will tell you about itself once it is running: if you publish
a host port it appears as `host-port` / `public+host-port` exposure, and if you
point a tunnel origin straight at a container it shows up with no auth even
though the Traefik route looks protected.

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
| `LABVIEW_PORT` | `8080` | HTTP port (container-internal) |
| `LABVIEW_HOST` | `0.0.0.0` | Bind address |
| `LABVIEW_CACHE_TTL` | `60` | Seconds a scan is cached before refresh |
| `LABVIEW_MASK_SECRETS` | `true` | Mask secret-looking env values |
| `LABVIEW_CONFIG` | `config.yml` | Path to a config file |
| `LABVIEW_AUTHENTIK_ENABLED` | `true` | Whether to read the Authentik API at all. With no token it does nothing either way |
| `LABVIEW_AUTHENTIK_TOKEN_FILE` | *(unset)* | Path to a file holding a read-only API token (docker secret, mounted file). Wins over `LABVIEW_AUTHENTIK_TOKEN` |
| `LABVIEW_AUTHENTIK_TOKEN` | *(unset)* | The token itself. Works, but is visible in `docker inspect` — prefer the file form |
| `LABVIEW_AUTHENTIK_URL` | *(discovered)* | Base URL incl. scheme and port, e.g. `http://authentik-server:9000`. Needed only when Authentik is outside `appsRoot` or discovery picks the wrong endpoint |
| `LABVIEW_AUTHENTIK_TIMEOUT_MS` | `5000` | Per-request timeout. On timeout the scan continues without the API |

The default Docker endpoint is the conventional local socket, since it is the one
endpoint that needs no assumption about your container names; a socket proxy is
opted into with `LABVIEW_DOCKER_HOST`.

The config file also controls the secret key-patterns, the DockFlare/Traefik
label prefixes, and the Authentik detection hints — see the comments in
`config.example.yml`. Your own SSO hostnames do **not** belong in those hints:
they are discovered from your fleet at scan time (see below), and adding a
host-naming convention like `auth.` is how unrelated providers get mislabelled.

### The Authentik API token

Optional. Without it, auth posture is derived from labels and env vars alone;
with it, LabView reports what Authentik itself says about each gate.

Create a **service account** in Authentik (*Directory → Users → Create service
account*), leave it out of every group, and grant only three global permissions:
`view_application`, `view_provider`, `view_outpost`. Then issue a token for it and
mount it:

```yaml
environment:
  LABVIEW_AUTHENTIK_TOKEN_FILE: /run/secrets/authentik_token
volumes:
  - /mnt/apps/labview/authentik-token:/run/secrets/authentik_token:ro
```

LabView only ever issues `GET`s, so anything beyond those three permissions is
authority an attacker who reached this container would inherit for free.

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

---

## How it works

```text
discover stacks → parse compose (+ .env interpolation) → enrich from Docker
      → build middleware registry → classify ingress → read the Authentik API
      → discover Authentik hostnames → resolve tunnel origins
      → match Authentik applications to services → derive auth posture
      → build graph → serve /api/overview
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
- **Ingress** is classified `public` / `public+host-port` / `public+local` /
  `local` / `host-port` / `internal`. A `ports:` entry publishes on the host
  (unlike `expose:`), so the service answers at `<host-ip>:<port>` with no proxy
  and no SSO in the path — that is real reachability and it is classified as such.
  `host-port` is reported when nothing else fronts the service; when Traefik
  *does* front it, the kind is unchanged and the bypass is raised as a note
  instead, since most services in a fleet publish a port and folding that into
  the kind would flatten the whole distribution.
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
  note saying the definition could not be found. When two accounts disagree the
  stronger one is reported and the weaker is kept as evidence beneath it, so you
  can see both.
- **The Authentik API, when a token is given, is read as evidence like any other.**
  Applications, providers and outposts are fetched, then each application is
  matched to a service only on something addressed:
  1. a proxy provider's `internal_host` resolving to exactly one service — the
     provider naming its target outright, and the strongest evidence available;
  2. a launch URL or OAuth2 redirect URI whose hostname is one the service is
     configured to serve, per its DockFlare or Traefik labels;
  3. the application slug, when it equals exactly one service's stack, compose or
     container name — operator-chosen on both sides, so it is the last resort.

  Anything that could name two services names neither, and is reported as an
  unmatched application instead. `external_host` is used for matching except in
  `forward_domain` mode, where it is the authentication domain shared by every
  application in it and so identifies no single service.
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
- **Exposed-without-auth**: a service reachable (public or local) with no detected
  *proxy/SSO* auth is flagged. Note this is honest about *proxy* auth only — apps
  with their own built-in login (Emby, Home Assistant, Authentik itself) will
  appear here; the note wording says exactly that.

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
- **Published host ports are treated as real exposure.** A service with a
  `ports:` mapping and no proxy in front is `host-port`, counted in its own stat
  tile, and flagged exposed-without-auth — it answers on the LAN whatever your
  Traefik config says. When a proxy *is* in front, the service keeps its kind and
  gains an explicit note that the published port bypasses the proxy and its SSO.
- The **Authentik API token is optional and read-only** (`view_application`,
  `view_provider`, `view_outpost` on a groupless service account — LabView only
  issues `GET`s). A discovered endpoint is probed unauthenticated first and the
  token is sent only to a host that answered as an Authentik API, so a wrong guess
  never receives it. Prefer `LABVIEW_AUTHENTIK_TOKEN_FILE`; a token in the
  environment is readable via `docker inspect`. Certificate verification cannot be
  disabled — use `NODE_EXTRA_CA_CERTS` for a private CA.
- No built-in auth — put it behind your own edge (see above).

---

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/overview` | GET | The full analyzed model (JSON) |
| `/api/rescan` | POST | Force a fresh scan, returns the rebuilt overview |
| `/api/healthz` | GET | Liveness probe |

The web UI is a static SPA served from the same origin.

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
  analyze/    two-pass pipeline, middleware registry, graph, stats
  enrich/     docker snapshot (dockerode) + authentik API client
  model/      types.ts — the shared backend⇄frontend contract
  server/     fastify server + static hosting
web/          preact UI (grid, detail drawer, cytoscape graph, mermaid)
fixtures/
  apps/       a representative happy-path fleet
  edge/       regression cases for previously-fixed defects
  authentik/  a fleet with an identity provider in it
  authentik-api.json   canned API responses for the above
```

```bash
npm run typecheck    # tsc for both server and web
npm run smoke        # runs the pipeline against fixtures/ and asserts results
npm run build        # web bundle + server compile
```

`npm run smoke` runs the whole pipeline against three fixture roots — `apps` for
the expected classifications, `edge` for the regression cases (URL credential
redaction, `env_file` containment, `dockflare.enable=false`, LDAP attribution,
nested interpolation, host-port exposure — `ports:` vs `expose:`, the
tunnel-straight-at-the-container pattern and the bypass note on a proxied service
— and provider attribution in a fleet whose SSO is *not* Authentik, where every
mechanism is observable but nothing may be attributed to a vendor), and
`authentik` for the API integration.

That last root drives canned responses (`fixtures/authentik-api.json`) through an
injected HTTP layer, so the test needs no network and no Authentik: it pins each
match rule in isolation, the rejection of an ambiguous match, the unserved-provider
outcome, pagination, and the rule that a token is never sent to a host that has not
answered the unauthenticated probe. It also runs the same fleet **without** a token
and asserts the difference, so the API's contribution is measured rather than
assumed.

Every fixture is written so it fails if the corresponding logic is reverted — for
the API integration that was checked by actually backing each rule out one at a
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
  each conclusion. It describes *configuration*, not enforcement: a middleware
  reference proves the gate was configured, not that Traefik is currently running
  with that config. Reading the Authentik API narrows this — an outpost assignment
  is enforcement rather than intent — but it is still configuration, not a request
  actually being challenged.
- The Authentik integration reads applications, providers and outposts. Policy
  bindings are not read, so an application whose access policy denies everyone
  still reads as protected — which it is — and a flow customization that weakens a
  gate is not visible.
- An application LabView cannot tie to exactly one service is reported as unmatched
  rather than guessed. In a fleet where hostnames live only in Authentik and never
  in a compose label, expect several: the fix is a matching `dockflare.hostname` or
  slug, not a looser rule.
- Traefik middlewares defined in a dynamic config **file** rather than in labels
  are invisible to the scan — a reference to one resolves to nothing, which is why
  the name-based fallback and the `inferred` confidence exist.
