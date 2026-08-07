# syntax=docker/dockerfile:1

# LabView's image (§2.3): two stages, and a final stage with no shell and no package
# manager in it.
#
# The build needs nothing but Go. §2.2 requires the frontend bundle to be committed
# under internal/webui/dist and embedded at compile time, so there is no Node stage,
# no lockfile install and no bundler here — `go build` reads the bundle off disk
# through `go:embed`, which is also what makes `go test` work in a checkout with no
# Node installed.

# ---- build stage -------------------------------------------------------------
# Pinned to the floor §2.1 sets rather than to the newest toolchain: this is the
# version the module declares it needs, so building with it is the check that the
# declaration is true.
FROM golang:1.23-alpine AS build
WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module cache.
# `go mod download` and not `go mod tidy`: a build must never edit go.mod, and a
# tidy that quietly dropped a requirement would turn a broken commit into a green
# image.
COPY go.mod go.sum ./
RUN go mod download

# The module. Only what the binary compiles from — the build context excludes the
# fixtures, the frontend sources and the documentation (see .dockerignore), so
# §2.3's *no test corpus, no source* holds for the build stage too and a fixture
# hostname cannot reach a build layer (I2).
COPY cmd ./cmd
COPY internal ./internal

# §2.1's single statically linked binary.
#
#   CGO_ENABLED=0   no libc at runtime, which is what lets the final stage be static
#   -trimpath       no build-machine paths in the binary, so two builds of one commit
#                   produce the same bytes wherever they ran
#   -ldflags -s -w  no symbol table and no DWARF: this binary is not debugged in
#                   production, and the panic traces that matter survive both
#
# The build identity is deliberately *not* linked in with `-X`. §3.4 reads it from
# the environment at startup, so it is one ARG set into one ENV below — and a
# `-ldflags -X` copy of the same fact would be a second place for it to be wrong.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/labview \
        ./cmd/labview

# The examples §2.3 requires the image to carry. Staged here rather than copied
# straight into the final image so the final stage copies from exactly one place.
COPY config.example.yml passwd.example /out/

# ---- runtime stage -----------------------------------------------------------
# A distroless static base rather than `scratch`, and the difference is one file:
# the CA bundle. §2.4 requires certificate verification on every outbound TLS
# connection with no option to disable it, and a `scratch` image has no root store —
# so every HTTPS Authentik, OIDC or probe target would report a `tls` phase (§15)
# and there would be no way to fix it that §2.3 permits. This base is still no
# shell, no package manager and no libc; it adds the root store, /etc/passwd for the
# numeric user, and tzdata.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

# Which commit this image was built from.
#
# It has to be an argument: `.git` is at the repository root, this build context is
# ./labview, and .dockerignore excludes .git anyway — so the image can never read
# it. Unset is a supported state and not a build failure: LabView then reports that
# it does not know its revision (§3.4), which is honest and is what a local
# `docker build` with no --build-arg gets.
ARG LABVIEW_BUILD_SHA=""

# Container defaults (§2.3). Only paths LabView owns are set here: the Docker
# endpoint is deliberately left unset, because any default TCP host would be a
# guess about someone else's container names. Unset means the conventional local
# socket, and a socket-proxy endpoint is opted into with LABVIEW_DOCKER_HOST (or
# the standard DOCKER_HOST) — see compose.yml for the recommended proxy setup.
ENV LABVIEW_APPS_ROOT=/data/apps \
    LABVIEW_PORT=8080 \
    LABVIEW_BUILD_SHA=${LABVIEW_BUILD_SHA}

# The whole image: one binary and the two reference files, at the root, so §2.4's
# default relative config path (`./config.yml`) resolves to /config.yml.
WORKDIR /
COPY --from=build /out/labview /labview
COPY --from=build /out/config.example.yml /out/passwd.example /

EXPOSE 8080

# A non-root numeric UID (§2.3). Numeric rather than the `nonroot` name the base tag
# already implies, because Kubernetes' runAsNonRoot check reads the UID and cannot
# resolve a name — and because it should be visible here what this runs as.
#
# Nothing is written at runtime, so this needs no writable path: the process holds
# no cache, no session store and no scratch space (§2.3), which is what lets the
# root filesystem be mounted read-only.
USER 65532:65532

# No HEALTHCHECK. There is no shell and no HTTP client in this image to write one
# with, and adding either would break §2.3's *no shell, no package manager*. The
# probe belongs to whatever runs the container: `GET /api/healthz` answers
# `{"ok": true}` without running a scan (§18), so an orchestrator can poll it
# directly.

# ENTRYPOINT rather than CMD, so §2.5's subcommands are reachable in an image with
# no shell: `docker run --rm labview scan` and `docker run --rm -i labview hashpw
# ada` both work, and no arguments at all means serve (§2.5).
ENTRYPOINT ["/labview"]
