# FleetView

A self-hosted overview of a Docker-Compose homelab. Point it at the directory
where your per-container stacks live (`/mnt/apps/<container>/compose.yml`, with
optional `.env` files) and it produces a structured website showing **every app,
how it's set up, how it's reached, what protects it, and how everything is wired
together**.

It is built for a specific, common TrueNAS Scale pattern:

- **Public ingress via a Cloudflare tunnel**, configured with **DockFlare**
  labels (`dockflare.hostname`, `dockflare.service`, …).
- **Local ingress via Traefik**, configured with `traefik.*` labels (routers,
  rules, entrypoints, TLS, middlewares).
- **SSO via Authentik** — as a Traefik **forward-auth** middleware
  (`authentik@docker`), or via **OAuth/OIDC** or **LDAP** wired through a
  service's environment.

FleetView reads all of that from your compose files, optionally enriches it with
live state from the Docker socket, and never needs an agent inside each app.

---

## What you get

- **Dashboard** — stat tiles (stacks, services, running, public, local-only,
  auth-protected, and a highlighted **exposed-without-auth** count) plus
  part-to-whole bars for **ingress exposure** and **authentication method**. The
  bar legends double as filters.
- **App grid** — one card per service with a live status dot, image, hostnames,
  and colored **ingress** / **auth** badges. Search and filter across the fleet.
- **Detail drawer** — for each service: a **Mermaid diagram** of its connections,
  Cloudflare routes, Traefik routers (rule, hosts, entrypoints, TLS, middlewares),
  the **derived auth posture with the evidence that led to it**, networks, ports,
  volumes, environment (secrets masked), and live container state.
- **Relationship graph** — an interactive [cytoscape](https://js.cytoscape.org/)
  graph of the whole fleet: services colored by exposure, plus network, volume,
  and Cloudflare/Traefik/Authentik hub nodes, connected by network membership,
  `depends_on`, shared volumes, ingress, and auth edges. Click a service to open
  its detail.
- **Light / dark** theme (follows the OS, with a manual toggle).

Colors follow a validated, colorblind-safe palette. The ingress and auth-method
hue orderings were run through a CVD/contrast validator in **both** light and
dark modes (adjacent segments stay distinguishable for colorblind viewers);
low-contrast segments always carry a direct text label, and status colors always
ship with an icon and label, never color alone.

---

## Quick start (local)

```bash
cd fleetview
npm install
npm run build            # bundles the web UI + compiles the server
FLEETVIEW_APPS_ROOT=/path/to/your/apps npm start
# open http://localhost:8080
```

Just want a one-shot report on the terminal (no server)?

```bash
FLEETVIEW_APPS_ROOT=/path/to/your/apps npm run scan -- --summary
```

Live-reloading development:

```bash
npm run dev              # esbuild --watch for the UI + tsx server with reload
```

---

## Deploy on TrueNAS Scale

FleetView runs as one more container next to the apps it inspects. It mounts your
stacks **read-only** and (optionally) the Docker socket **read-only** for live
state — it never writes to either.

1. Copy this `fleetview/` directory to your box, e.g. to
   `/mnt/apps/fleetview/`.
2. Review [`compose.yml`](compose.yml) — the defaults mount `/mnt/apps` →
   `/data/apps:ro` and the docker socket read-only, and publish port `8080`.
3. Deploy it one of two ways:
   - **Apps → Custom App → Install via YAML**, pasting the compose file, or
   - drop it at `/mnt/apps/fleetview/compose.yml` and run
     `docker compose up -d` (it builds the image locally).

```yaml
services:
  fleetview:
    build: .
    container_name: fleetview
    restart: unless-stopped
    environment:
      FLEETVIEW_APPS_ROOT: /data/apps
      FLEETVIEW_DOCKER_SOCKET: /var/run/docker.sock
      FLEETVIEW_PORT: "8080"
    volumes:
      - /mnt/apps:/data/apps:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro   # remove to run config-only
    ports:
      - "8080:8080"
```

### Put it behind your own edge (recommended)

FleetView has **no built-in authentication** — it exposes your topology and
(masked) config, so don't publish it raw. Expose it the same way as your other
apps by adding labels; [`compose.yml`](compose.yml) has a ready-to-adapt example
for **Traefik + Authentik forward-auth** and/or **DockFlare**:

```yaml
    labels:
      traefik.enable: "true"
      traefik.http.routers.fleetview.rule: "Host(`fleet.example.com`)"
      traefik.http.routers.fleetview.entrypoints: "websecure"
      traefik.http.routers.fleetview.tls: "true"
      traefik.http.routers.fleetview.middlewares: "authentik@docker"
      traefik.http.services.fleetview.loadbalancer.server.port: "8080"
```

---

## Configuration

Everything works out of the box. To tune, copy
[`config.example.yml`](config.example.yml) to `config.yml` (or point
`FLEETVIEW_CONFIG` at it). Environment variables override the file:

| Variable | Default | Purpose |
|---|---|---|
| `FLEETVIEW_APPS_ROOT` | `/data/apps` | Root directory of your stacks |
| `FLEETVIEW_DOCKER_ENABLED` | `true` | Enrich with live Docker state |
| `FLEETVIEW_DOCKER_SOCKET` | `/var/run/docker.sock` | Docker socket path |
| `FLEETVIEW_PORT` | `8080` | HTTP port |
| `FLEETVIEW_HOST` | `0.0.0.0` | Bind address |
| `FLEETVIEW_CACHE_TTL` | `60` | Seconds a scan is cached before refresh |
| `FLEETVIEW_MASK_SECRETS` | `true` | Mask secret-looking env values |
| `FLEETVIEW_CONFIG` | `config.yml` | Path to a config file |

The config file also controls the secret key-patterns, the DockFlare/Traefik
label prefixes, and the Authentik detection hints — see the comments in
`config.example.yml`.

---

## How it works

```text
discover stacks → parse compose (+ .env interpolation) → enrich from Docker
      → build middleware registry → classify ingress → discover Authentik
      → derive auth posture → build graph → serve /api/overview
```

- **Compose parsing** understands both label/env syntaxes (list `- k=v` and map
  `k: v`), YAML anchors, `${VAR}` / `${VAR:-default}` interpolation from adjacent
  `.env` files, and the full port/volume short and long forms.
- **DockFlare** labels become public **Cloudflare routes** (hostname → origin,
  Access policy, TLS options).
- **Traefik** labels become local **routes** (router rule → hosts/path prefixes,
  entrypoints, TLS/cert-resolver, referenced middlewares, service port).
- A global **middleware registry** classifies referenced middlewares by *type*,
  so `authentik@docker` (forward-auth) counts as SSO while a `headers` or
  `redirect` middleware does not — even when it's defined in a different stack.
- **Authentik auto-discovery** learns your Authentik hostnames (e.g. from the
  `goauthentik` image or the outpost forward-auth address), so an OIDC issuer or
  LDAP host pointing at `sso.example.com` is recognized as Authentik even though
  the string "authentik" never appears.
- **Ingress** is classified `public` / `local` / `public+local` / `internal`.
- **Auth posture** resolves to one of `authentik-forward-auth`,
  `authentik-oauth`, `authentik-ldap`, `other-oauth`, `basic-auth`, or `none`,
  each with the evidence that produced it.
- **Exposed-without-auth**: a service reachable (public or local) with no detected
  *proxy/SSO* auth is flagged. Note this is honest about *proxy* auth only — apps
  with their own built-in login (Emby, Home Assistant, Authentik itself) will
  appear here; the note wording says exactly that.

### Security

- Stacks and the Docker socket are mounted **read-only**; FleetView only reads.
- Secret-looking env values (`*PASS*`, `*SECRET*`, `*TOKEN*`, `*KEY*`, …) are
  **masked** in both the API and UI by default. Keys stay visible; values are
  replaced with a placeholder.
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

```text
src/
  scan/       discover + compose/.env parsing
  labels/     dockflare, traefik, authentik derivation
  analyze/    two-pass pipeline, middleware registry, graph, stats
  enrich/     docker socket snapshot (dockerode)
  model/      types.ts — the shared backend⇄frontend contract
  server/     fastify server + static hosting
web/          preact UI (grid, detail drawer, cytoscape graph, mermaid)
fixtures/     sample stacks used by the smoke test
```

```bash
npm run typecheck    # tsc for both server and web
npm run smoke        # runs the pipeline against fixtures/ and asserts results
npm run build        # web bundle + server compile
```

The web bundle is intentionally self-contained (mermaid + cytoscape are inlined,
~3 MB) so the dashboard works fully offline with no CDN dependency.

## Limitations

- Reads Compose stacks laid out as `appsRoot/<stack>/compose.yml`. Swarm and
  Kubernetes manifests are out of scope.
- Live state (status, health, IPs) requires the Docker socket; without it the
  scan degrades cleanly to config-only.
- Auth detection is heuristic and label/env-driven; it reports the evidence so
  you can verify each conclusion.
