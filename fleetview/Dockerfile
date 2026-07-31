# ---- build stage -------------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app

# Install all deps (incl. dev) for the build.
COPY package.json package-lock.json* ./
RUN npm install

# Build the web bundle and compile the server.
COPY tsconfig.json tsconfig.web.json ./
COPY scripts ./scripts
COPY web ./web
COPY src ./src
RUN npm run build

# Prune to production dependencies for the runtime image.
RUN npm prune --omit=dev

# ---- runtime stage -----------------------------------------------------------
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/web/dist ./web/dist
COPY package.json ./
COPY config.example.yml ./

# The web root and apps root are configurable; these are the container defaults.
ENV FLEETVIEW_APPS_ROOT=/data/apps \
    FLEETVIEW_DOCKER_SOCKET=/var/run/docker.sock \
    FLEETVIEW_PORT=8080

EXPOSE 8080
# Run as an unprivileged user; mount the docker socket group-readable if you
# want live enrichment (see README for the gid trick on TrueNAS).
USER node

CMD ["node", "dist/index.js"]
