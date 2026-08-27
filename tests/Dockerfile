# Test-suite image: runs the middleware pentest suite (baseline, per-middleware,
# regression, perf) in a disposable container. Build via docker-compose.tests.yml
# at the repo root:
#
#   docker compose -f docker-compose.tests.yml up --build
#
# The suite needs the server workspace's devDependencies (tsx, vitest) plus the
# server sources it imports, so this image mirrors the root layout. No runtime
# secrets (ARK keys etc.) are required — every suite uses test fixtures.

ARG NODE_IMAGE=node:22-bookworm-slim
FROM ${NODE_IMAGE} AS build
WORKDIR /app

# Dependencies first: the workspace root + server package manifest pin the lock.
COPY package.json package-lock.json tsconfig.base.json ./
COPY apps/server/package.json apps/server/package.json
COPY apps/web/package.json apps/web/package.json
RUN npm ci

# Sources: server (read-only reference for the harness) + the suite itself.
COPY apps ./apps
COPY tests ./tests

FROM ${NODE_IMAGE} AS runtime
WORKDIR /app

ENV NODE_ENV=test
ENV CI=1

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/tsconfig.base.json ./tsconfig.base.json
COPY --from=build /app/apps ./apps
COPY --from=build /app/tests ./tests

# Default: full suite (baseline + per-middleware + regression + perf).
# Override the command to run a subset, e.g.:
#   docker compose -f docker-compose.tests.yml run --rm pentest \
#     npx tsx tests/runner.ts --suite baseline
CMD ["npx", "tsx", "tests/runner.ts"]
