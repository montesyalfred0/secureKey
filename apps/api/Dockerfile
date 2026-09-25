# syntax=docker/dockerfile:1.7
#
# Imagen de la API. Tres etapas clearly separadas:
#   deps    -> instalacion completa (para compilar y testear)
#   build   -> codigo TypeScript compilado
#   runtime -> solo dependencias de produccion, usuario sin privilegios
#
# El contexto de build es la RAIZ del repositorio porque el proyecto usa npm
# workspaces: los dos paquetes (shared y api) se resuelven entre si.

ARG NODE_VERSION=22-alpine

# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS deps
WORKDIR /app
ENV npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false
# Solo los manifiestos: mientras no cambien, la capa de dependencias se
# reutiliza y `docker compose build` es incremental de verdad.
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund

# ---------------------------------------------------------------------------
FROM deps AS build
COPY tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY apps/api ./apps/api
RUN npm run build --workspace @securekey/shared \
 && npm run build --workspace @securekey/api

# ---------------------------------------------------------------------------
# Imagen de desarrollo: fuentes + tsx watch, con las devDependencies.
FROM deps AS dev
COPY tsconfig.base.json ./
COPY packages ./packages
COPY apps ./apps
EXPOSE 3000
CMD ["npm", "run", "dev", "--workspace", "@securekey/api"]

# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false

# tini como PID 1: Node no reenvia senales por defecto y sin esto
# `docker compose down` mata la API a mitad de una peticion.
RUN apk add --no-cache tini

COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
RUN npm ci --omit=dev --no-audit --no-fund --workspace @securekey/api --include-workspace-root \
 && npm cache clean --force

COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/apps/api/dist ./apps/api/dist

# El usuario `node` viene en la imagen oficial (uid 1000). Nunca root.
USER node

EXPOSE 3000

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "apps/api/dist/index.js"]
