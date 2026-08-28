ARG NODE_IMAGE=node:22-bookworm-slim
FROM ${NODE_IMAGE} AS build
WORKDIR /app

COPY package.json package-lock.json tsconfig.base.json ./
COPY apps/server/package.json apps/server/package.json
COPY apps/web/package.json apps/web/package.json
# tests/ is the @sentinel/pentest workspace package the server depends on;
# it must be present before npm ci so the workspace links and the root
# "prepare" build (which compiles the pentest library) can run.
COPY tests ./tests
RUN npm ci

COPY apps ./apps
RUN npm run build
RUN npm prune --omit=dev

FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production
WORKDIR /app

ARG DEBIAN_MIRROR=""
ARG DEBIAN_SECURITY_MIRROR=""

RUN if [ -n "$DEBIAN_SECURITY_MIRROR" ]; then \
      find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
        -exec sed -i "s|http://deb.debian.org/debian-security|$DEBIAN_SECURITY_MIRROR|g" {} +; \
    fi \
    && if [ -n "$DEBIAN_MIRROR" ]; then \
      find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
        -exec sed -i "s|http://deb.debian.org/debian|$DEBIAN_MIRROR|g" {} +; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git ripgrep \
    && npm install --global @openai/codex@0.111.0 \
    && codex --version \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/apps/server/package.json ./apps/server/package.json
COPY --from=build /app/apps/server/dist ./apps/server/dist
COPY --from=build /app/apps/web/dist ./apps/web/dist
# The @sentinel/pentest workspace package is linked into node_modules via a
# relative symlink to ../../tests; the built library (tests/dist) must be
# present in the runtime image for /api/pentest.
COPY --from=build /app/tests ./tests

RUN mkdir -p /app/data /app/workspaces /app/codex-home \
    && chown -R node:node /app

USER node
EXPOSE 3000
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "apps/server/dist/index.js"]
