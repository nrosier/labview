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

# Container defaults. Only paths LabView owns are set here: the Docker endpoint
# is deliberately left unset, because any default TCP host would be a guess about
# someone else's container names. Unset means the conventional local socket, and
# a socket-proxy endpoint is opted into with LABVIEW_DOCKER_HOST (or the standard
# DOCKER_HOST) — see compose.yml for the recommended proxy setup.
ENV LABVIEW_APPS_ROOT=/data/apps \
    LABVIEW_PORT=8080

EXPOSE 8080
# Run as an unprivileged user. With a socket proxy no socket mount is needed at
# all; if you mount the raw socket instead, mount it read-only.
USER node

CMD ["node", "dist/index.js"]
