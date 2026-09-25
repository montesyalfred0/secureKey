# syntax=docker/dockerfile:1.7
#
# Imagen del frontend: build de Vite + nginx sirviendo el resultado.
# El codigo fuente nunca llega a la imagen final, solo los assets.

ARG NODE_VERSION=22-alpine
ARG NGINX_VERSION=1.27-alpine

# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS build
WORKDIR /app
ENV npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false

COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund

COPY tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY apps/web ./apps/web
RUN npm run build --workspace @securekey/shared \
 && npm run build --workspace @securekey/web

# ---------------------------------------------------------------------------
# Imagen de desarrollo: fuentes + servidor de Vite con HMR.
FROM node:${NODE_VERSION} AS dev
WORKDIR /app
ENV npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false

COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund

COPY tsconfig.base.json ./
COPY packages ./packages
COPY apps ./apps

EXPOSE 5173
CMD ["npm", "run", "dev", "--workspace", "@securekey/web"]

# ---------------------------------------------------------------------------
FROM nginx:${NGINX_VERSION} AS runtime

# Configuracion propia + sustitucion del index por el de Vite (hashes).
COPY infra/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/web/dist /usr/share/nginx/html

# nginx oficial corre como root para escuchar en :80 y luego baja a `nginx`.
# En un despliegue sin TLS y detras de Caddy, :80 dentro de la red no esta
# expuesto, asi que mantener el puerto 80 simplifica la configuracion.
EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -qO- http://127.0.0.1/healthz > /dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]
