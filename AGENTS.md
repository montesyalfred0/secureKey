# AGENTS.md

SecureKey: gestor de contrasenas con cifrado zero-knowledge en el navegador.
Monorepo: `apps/api` (Fastify + PostgreSQL), `apps/web` (Preact), `packages/shared`
(protocolo y esquemas compartidos).

Este fichero es lo unico que hace falta leer para desplegar. Si buscas el
porque de una decision de seguridad, esta al final.

---

## Subir un cambio hecho en local a la VPS

**1. En el portatil.** Commit y push:

```bash
git add -A
git commit -m "descripcion breve de lo que cambia"
git push origin main
```

**2. En la VPS.** Traer el cambio y reconstruir:

```bash
ssh root@62.171.157.89
cd /opt/apps/securekey
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

**3. Comprobar.** Desde la propia VPS:

```bash
curl -I https://securekey.yal99.com/            # 200, HSTS, CSP con wasm-unsafe-eval
curl  https://securekey.yal99.com/api/v1/health # {"status":"ok",...}
```

Y que las otras webs de la VPS siguen en pie, que comparten el mismo nginx:

```bash
curl -s -o /dev/null -w "jwaddresses: %{http_code}\n" https://jwaddresses.yal99.com/
curl -s -o /dev/null -w "paulina-yalfred: %{http_code}\n" https://paulina-yalfred.yal99.com/
```

Los dos deben dar 200.

---

## Tres cosas que hay que saber

**El `--build` no es opcional.** Las imagenes se construyen en la VPS, no en un
registro. Sin `--build`, compose reutiliza la imagen anterior: `git pull` baja el
codigo, todo parece correcto, y el cambio no llega a ejecutarse nunca.

**No uses `docker compose up -d` a secas en la VPS.** Eso es el despliegue de
desarrollo: puerto 8443 y certificado interno. Necesita los dos ficheros compose,
el de produccion encima.

**No toques los puertos.** El 443 lo tiene SecureKey desde que se desplego, y el
80 lo tiene el nginx que sirve las otras aplicaciones de esa VPS. No se puede
anadir ni quitar nada de ahi sin romper algo.

---

## Para trabajar en local

```bash
docker compose up --build -d --wait        # http://localhost:8443
```

Comprobar antes de commitear:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml --profile test run --rm test
```

Ese es el paso obligatorio: 293 tests con su propia base de datos. El primer
build tarda; los siguientes, segundos.

---

## Documentos

Solo si la pregunta es de fondo, no de procedimiento:

| Documento | De que va |
| --- | --- |
| [`docs/modelo-de-amenazas.md`](docs/modelo-de-amenazas.md) | Que se protege, de que y de quien |
| [`docs/criptografia.md`](docs/criptografia.md) | Derivacion, HKDF y formato de los mensajes |
| [`docs/despliegue-vps.md`](docs/despliegue-vps.md) | Puesta en marcha desde cero, con nginx ya instalado |
| [`docs/certificado.md`](docs/certificado.md) | Importar la CA de Caddy en el navegador |
