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

# Container defaults. Live Docker state is read via the docker-socket-proxy over
# TCP by default (see compose.yml); set LABVIEW_DOCKER_SOCKET to use a socket.
ENV LABVIEW_APPS_ROOT=/data/apps \
    LABVIEW_DOCKER_HOST=tcp://dockerproxy:2375 \
    LABVIEW_PORT=8080

EXPOSE 8080
# Run as an unprivileged user. No socket mount is needed — the socket proxy
# handles Docker access on its own network.
USER node

CMD ["node", "dist/index.js"]
