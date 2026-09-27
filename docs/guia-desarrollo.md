# Guia de desarrollo y despliegue

Como se edita SecureKey en local y como llega a la VPS. Todo por Docker: en el
portatil y en el servidor **no hace falta Node instalado**.

Si prefieres los atajos de `package.json` y tienes Node, `npm test`,
`npm run dev` y demas hacen lo mismo. En la VPS no se puede contar con eso.

---

## 1. Poner en marcha el entorno local

```bash
git clone https://github.com/montesyalfred0/secureKey.git
cd secureKey
cp .env.example .env

# Genera POSTGRES_PASSWORD, DATABASE_APP_PASSWORD, AUTH_PEPPER e INVITE_SECRET.
# Solo rellena lo que este vacio: si el .env ya tiene algo, no lo toca.
docker run --rm -v .:/app -w /app node:22-alpine node scripts/gen-secrets.mjs

docker compose up --build -d --wait
```

`-d --wait` no es opcional en la practica: sin el, `docker compose up` se
queda en primer plano y parece colgado.

Abre **https://localhost:8443**. El certificado lo genera Caddy con su CA
interna, asi que el navegador dira que no es de confianza. Son los pasos 2 y 3 de
la seccion "Empezar" del README.

---

## 2. Del portatil a la VPS: el ciclo completo

Este es el camino completo de un cambio, de principio a fin. **Cada bloque se
ejecuta en una maquina distinta**, y confundirlas es el error mas comun:

| Bloque | Donde |
| --- | --- |
| 1 a 4 | **tu portatil** |
| 5 a 7 | **la VPS** (`ssh root@62.171.157.89`) |

---

### EN TU PORTATIL

**1. Partir de la version desplegada**, para no subir cambios a medias que
alguien ya tiene en produccion:

```bash
git pull
```

**2. Levantar el entorno y hacer el cambio**

```bash
docker compose up --build -d --wait
```

Abre https://localhost:8443 y edita lo que necesites. Para trabajar con recarga
en caliente, en otra terminal:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

**3. Comprobar que esta verde**

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml --profile test run --rm test
```

Ojo: el `e2e` y los checks HTTP usan la imagen `securekey/api-dev`, que **no**
reconstruye `docker compose build`. Si tocaste algo que esos tests tocan:

```bash
docker build -f apps/api/Dockerfile --target dev -t securekey/api-dev .
```

Ver "La imagen vieja" en la seccion 4.

**4. Guardar y subir**

```bash
git add -A
git commit -m "descripcion breve de lo que cambia"
git push origin main
```

---

### EN LA VPS

**5. Entrar y situarte en el directorio del proyecto**

```bash
ssh root@62.171.157.89
cd /opt/apps/securekey
```

**6. Traer los cambios y reconstruir**

```bash
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Dos comandos, y en ese orden. El `--build` **no es opcional**: las imagenes se
construyen aqui, no en un registro. Sin el, compose reutiliza la imagen anterior
y tu cambio de codigo no llega a ejecutarse. Es el motivo numero uno de "lo he
subido y no se ve".

**7. Comprobar que salio bien**

```bash
curl -I https://securekey.yal99.com/     # 200, HSTS, CSP con wasm-unsafe-eval
curl  https://securekey.yal99.com/api/v1/health
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
```

Y que **tus otras webs siguen en pie**, que comparten el mismo nginx:

```bash
curl -s -o /dev/null -w "jwaddresses: %{http_code}\n" https://jwaddresses.yal99.com/
curl -s -o /dev/null -w "paulina-yalfred: %{http_code}\n" https://paulina-yalfred.yal99.com/
```

Los dos deben dar 200. Si uno falla, mira la seccion 5.

---

### Los tres errores mas frecuentes

| Error | Que pasa |
| --- | --- |
| `git pull` en el portatil y `git push` en la VPS | La VPS no tiene commits propios. Push desde ahi falla o no hace nada. El push va **siempre** desde el portatil. |
| Olvidar el `--build` en el paso 6 | `git pull` descarga el codigo pero los contenedores siguen con la imagen vieja. `docker compose ps` lo delata: no cambia el tiempo de creacion. |
| Cambiar el puerto 443 en algo que no sea Caddy | El 443 lo tiene SecureKey desde el despliegue. Ver `despliegue-vps.md` antes de tocar nginx. |

---

## 3. Detalle del trabajo diario

### Comprobar antes de commitear

```bash
# Suite completa: typecheck + 293 tests, con su propia base de datos
docker compose -f docker-compose.yml -f docker-compose.test.yml --profile test run --rm test

# Protocolo completo contra el stack levantado
docker run --rm --network securekey_edge -e API_URL=http://api:3000/api/v1 \
  securekey/api-dev node apps/api/test/e2e.mjs

# Cabeceras, CSP y assets tal como los recibe un navegador
docker run --rm --network container:securekey-caddy-1 \
  -e NODE_TLS_REJECT_UNAUTHORIZED=0 -e APP_URL=https://localhost:8443 \
  securekey/api-dev node apps/web/test/http-checks.mjs
```

Los dos ultimos necesitan el stack levantado (`up -d --wait`). El primero no.

### Si tocaste criptografia o el protocolo

Vuelve a ejecutar el `e2e`: comprueba que un cliente y el servidor siguen
hablando el mismo idioma. Es el unico test que cubre el protocolo entero.

---

## 4. Lo que se rompe si no lo sabes

Estos son los errores que cuestan una hora. Todos me han pasado o casi.

### La imagen vieja (la mas peligrosa)

`docker compose build` construye `securekey/api`, pero el `e2e` y los checks
HTTP se ejecutan con **`securekey/api-dev`**, que es **otra imagen** y **no se
reconstruye** al hacer `build`. Lleva las fuentes dentro.

Pasa esto: cambias un test o unas fuentes, la API se reconstruye y todo lo demas
va bien, pero el `e2e` sigue ejecutando la copia antigua del test que hay dentro
de la imagen. El resultado es un fallo que **no corresponde al codigo actual**, y
es muy facil acabar pensando que has roto algo.

Sintoma tipico: el `e2e` falla con 401 en el registro, un 401 que el codigo que
tienes delante no puede producir. Se diagnostica comparando la fecha de la
imagen con la del fichero:

```bash
docker images --format "table {{.Repository}}\t{{.CreatedSince}}" | grep securekey
grep -c <lo-que-añadiste> apps/api/test/e2e.mjs          # en tu disco
docker run --rm --entrypoint sh securekey/api-dev -c 'grep -c <lo-que-añadiste> /app/apps/api/test/e2e.mjs'
```

Si el numero del disco es mayor que el de la imagen, la imagen esta vieja.
Reconstruir:

```bash
# El contexto es la RAIZ del monorepo, no apps/api
docker build -f apps/api/Dockerfile --target dev -t securekey/api-dev .
```

Regla practica: **si tocaste algo que el e2e exercise, reconstruye `api-dev`
antes de fiarte del resultado.**

### El limite de registros

El registro acepta **5 cuentas por hora y por IP**, y esta en memoria, asi que se
limpia reiniciando la API:

```bash
docker compose restart api
```

Si el `e2e` falla con 429 en el registro, no es un fallo del producto: es el
limite haciendo su trabajo. Ojo: reiniciar la API **invalida las sesiones
abiertas**, asi que en desarrollo no importa, pero no lo hagas en produccion.

### Local y produccion NO son el mismo despliegue

| | Local | VPS |
| --- | --- | --- |
| Puerto | 8443 | 443 |
| Caddyfile | `Caddyfile` | `Caddyfile.prod` |
| Certificado | CA interna de Caddy | Let's Encrypt |
| Certificado DNS | no | si, necesita `CF_API_TOKEN` |
| Imagen de Caddy | `caddy:2-alpine` | la que compila `infra/caddy/Dockerfile` |

**Consecuencia directa: si tocas `infra/caddy/Caddyfile`, en la VPS no se ve
absolutamente nada.** Son dos ficheros distintos para propositos distintos. Y
si tocas el `Dockerfile` de Caddy, el build de produccion necesita unos minutos
que el de desarrollo no gasta.

### El `.env` no esta en git, y eso es bueno

`git pull` nunca toca el `.env` de la VPS. Tu `CF_API_TOKEN` y tus contrasenas
siguen ahi.

Pero el otro lado: **una variable nueva que anadas a `.env.example` no aparece
sola en la VPS**. Hay que copiarla a mano, o el compose fallara con
`falta X en el .env`. Es a proposito, con el mensaje `:?` para que falle claro.

### Las migraciones se aplican solas al arrancar

El servicio `migrate` corre en cada `up`. Si tocas `apps/api/src/db/migrations.ts`:

- **Anadir** migracion: se aplica sola al arrancar. Correcto.
- **Modificar** una migracion que ya se aplico: no se vuelve a ejecutar. La base
  de produccion se queda con la version antigua y el codigo nuevo espera otra
  cosa. **Esto no se arregla, hay que hacer una migracion nueva.**

Antes de tocar el esquema en produccion, copia de seguridad:

```bash
bash scripts/backup.sh
```

### `npm run` en la VPS

`npm` necesita Node instalado. Si no lo hay, usa el script directamente, que es
lo mismo:

| Con Node | Sin Node |
| --- | --- |
| `npm run backup` | `bash scripts/backup.sh` |
| `npm run backup:verify` | `bash scripts/backup-verify.sh` |
| `npm run backup:cron` | `bash scripts/install-cron.sh` |
| `npm run invite -- a@b.c` | `docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm --no-deps -T api node apps/api/dist/scripts/invite.js -- a@b.c` |

---

## 5. Volver atras

Si el despliegue sale mal, hay dos caminos.

### Si el codigo esta mal

```bash
cd /opt/apps/securekey
git log --oneline -5          # nota el hash del commit bueno
git revert <hash>             # commit nuevo que deshace, sin reescribir historia
git push origin main
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

`revert` y no `reset --hard`: en un repositorio del que se despliega, reescribir
historia crea problemas a cualquiera que ya tenga el commit anterior.

### Si la base de datos esta mal

```bash
bash scripts/backup.sh                       # antes de tocar nada
bash scripts/restore.sh backups/securekey-<fecha>.dump
```

`restore.sh` levanta un PostgreSQL **aislado**, restaura ahi y comprueba que la
base resultante tiene las 4 tablas, la RLS activa y el rol `securekey_app`. No
toca la real. Solo cuando todo cuadra imprime como aplicarlo encima.

---

## 6. Antes de dar por bueno un cambio

- [ ] `docker compose -f docker-compose.yml -f docker-compose.test.yml --profile test run --rm test` en verde
- [ ] Si tocaste algo de la UI: `docker run --rm --network container:securekey-caddy-1 ...` en verde
- [ ] Si tocaste algo del protocolo: el `e2e.mjs` en verde
- [ ] Si tocaste `.env.example`: has añadido las variables nuevas al `.env` de la VPS
- [ ] Si tocaste migraciones: has hecho backup antes de desplegar
- [ ] Si tocaste Caddy: sabes que en produccion es `Caddyfile.prod`, no `Caddyfile`
- [ ] `git status` limpio, sin ficheros sin commitear
- [ ] En la VPS: `curl -I https://securekey.yal99.com/` responde 200
- [ ] En la VPS: tus otras webs siguen respondiendo

---

## 7. Documentos relacionados

| Documento | De que va |
| --- | --- |
| [`despliegue-vps.md`](despliegue-vps.md) | Puesta en marcha desde cero, con nginx ya instalado |
| [`criptografia.md`](criptografia.md) | El derivation y el formato de los mensajes |
| [`modelo-de-amenazas.md`](modelo-de-amenazas.md) | Que se protege, de que y de quien |
| [`certificado.md`](certificado.md) | Importar la CA de Caddy en el navegador |
