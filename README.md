# SecureKey

Gestor de contrasenas con **cifrado zero-knowledge en el navegador**. La contrasena
maestra nunca sale del dispositivo y el servidor es un almacen de blobs
indescifrables: ni sus administradores ni un robo de la base de datos pueden
leer lo que guardas.

```
packages/shared   protocolo y tipos compartidos (esquemas Zod)
apps/api          Fastify + PostgreSQL 17, RLS, migraciones como codigo
apps/web          Preact + Vite, WebCrypto + Argon2id (WASM)
infra             Caddy (unico puerto publicado) y nginx
```

## Empezar

Abre una terminal **en esta carpeta**. No hace falta Node, ni npm, ni PostgreSQL
instalados: todo va en Docker.

```bash
# 1. Genera los secretos (contrasena de la BD y pepper del servidor) dentro de Docker
docker run --rm -v .:/app -w /app node:22-alpine node scripts/gen-secrets.mjs

# 2. Levanta db -> migrate -> api -> web -> caddy y espera a que este sano
docker compose up --build -d --wait

# 3. Exporta el certificado raiz de la CA interna (opcional pero recomendado)
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

Abre **https://localhost:8443**.

El certificado lo genera Caddy en local, asi que el navegador mostrara un aviso
la primera vez. El paso 3 exporta `caddy-root.crt` para importarlo en tu
almacen de confianza; las instrucciones por navegador (Chrome, Edge, Firefox,
Safari) estan en [`docs/certificado.md`](docs/certificado.md), y ninguna
requiere ser administrador en el caso habitual.

`WebCrypto` solo existe en un contexto seguro. Por eso la app se sirve por HTTPS
y no por HTTP: abrirla en `http://` sin TLS deja la boveda inutilizable, y la
propia interfaz lo avisa en vez de fallar en silencio.

## Comandos

| Comando | Que hace |
| --- | --- |
| `docker compose up --build -d --wait` | Construye y levanta todo, esperando a que cada servicio este sano |
| `docker compose ps` | Estado de cada servicio |
| `docker compose logs -f api web caddy` | Sigue los logs |
| `docker compose down` | Para los contenedores, conserva los datos |
| `docker compose down -v` | Para **y borra** el volumen de PostgreSQL |
| `docker compose --profile test run --rm test` | Typecheck + 249 tests (levanta su propia base de datos de pruebas) |
| `docker run --rm --network securekey_edge -e API_URL=http://api:3000/api/v1 securekey/api-dev node apps/api/test/e2e.mjs` | El protocolo completo contra el stack ya levantado (35 checks) |
| `docker run --rm --network container:securekey-caddy-1 -e NODE_TLS_REJECT_UNAUTHORIZED=0 -e APP_URL=https://localhost:8443 securekey/api-dev node apps/web/test/http-checks.mjs` | Cabeceras, CSP y assets tal como los recibe un navegador (37 checks) |
| `docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build` | Modo desarrollo: HMR en el frontend y `tsx watch` en la API |
| `docker run --rm -v .\scripts\bundle-size.sh:/size.sh:ro securekey/web:latest sh /size.sh` | Informe del tamano del bundle |

Si ya tienes Node instalado, `package.json` tiene alias equivalentes (`npm test`,
`npm run dev`...). **No hacen falta y no son la via recomendada.**

## Como funciona el cifrado

La contrasena maestra se convierte en una clave con Argon2id (19 MiB de memoria,
el minimo de OWASP), de la que salen dos derivadas independientes por HKDF: una
envuelve la clave de boveda, la otra es el unico valor que el servidor recibe
para verificarte. Cada credencial se cifra despues con su propia clave derivada y
con AES-256-GCM.

El detalle que importa: **el texto claro no existe fuera de tu navegador**. Al
guardar, la credencial se cifra en memoria y al servidor solo viaja el ciphertext.
Al listar, el servidor devuelve blobs y el navegador los descifra. Un robo de la
base de datos entrega bytes sin significado.

El detalle que casi nobody menciona: **no hay recuperacion de contrasena por
correo**. No hay SMTP en este despliegue, y aunque lo hubiera, un servidor
zero-knowledge no puede restablecer una contrasena maestra que no posee. Si la
olvidas, la boveda se pierde. Es una consecuencia del modelo, no un fallo que se
pueda arreglar despues.

## Seguridad

- El servidor solo ve blobs AEAD y metadatos (correos, fechas, tamanos). Nunca
  contenido de credenciales.
- Contraseñas derivadas con Argon2id y pepper del servidor, comparado en tiempo
  constante. El coste real lo paga el navegador, asi que la API no sirve de
  oraculo de fuerza bruta.
- Sesiones con cookie `httpOnly`, `SameSite=Strict`, prefijo `__Host-` y CSRF de
  doble envio. El token se guarda **hasheado** en la base de datos.
- Row Level Security en PostgreSQL: la API opera bajo un rol sin permisos de DDL
  y cada peticion autenticada publica su `user_id` en una transaccion. El filtro
  por usuario en el codigo esta **ademas** de la politica: son dos capas, no una.
- Contenedores sin privilegios: `read_only`, `cap_drop: ALL`, sin root en la
  mayoria, y la base de datos en una red interna sin salida a Internet.
- CSP sin `unsafe-inline` ni `unsafe-eval`, HSTS, `no-referrer`, y las cabeceras
  de limite de tasa. Un test falla si alguien relaja la CSP.
- La CSP incluye `'wasm-unsafe-eval'` y es **imprescindible**: el Argon2id viene
  compilado como WebAssembly, y `WebAssembly.compile()` lo gobierna la directiva
  `script-src`. Sin esa fuente el navegador rechaza el modulo y no se puede
  registrar ni iniciar sesion, con un error que no apunta a la derivacion de la
  clave. Es una concesion mucho mas estrecha que `unsafe-eval`: solo habilita
  `WebAssembly.compile/instantiate`, no `eval()` ni `new Function()`, asi que un
  XSS sigue sin poder ejecutar JavaScript arbitrario. Ojo tambien en desarrollo:
  `'unsafe-inline'` cubre `<script>` embebido pero **no** compila WASM, de modo
  que `Caddyfile.dev` necesita la misma fuente.
- Analisis de contrasenas 100 % local. No se consulta Have I Been Pwned ni nada
  externo: enviar la contrasena a un tercero seria el fallo mas grave posible
  aqui.
- El portapapeles se limpia solo a los 20 segundos, y la boveda se bloquea a los
  5 minutos de inactividad.

### El portapapeles, y por que no pide permiso

Copiar una credencial programa un temporizador de 20 segundos que vacia el
portapapeles. Para no borrar lo que el usuario haya copiado en medio, la
primera version comparaba el contenido antes de vaciarlo, y esa comparacion
usa `navigator.clipboard.readText()`, que **dispara un aviso de permisos**.

El aviso salia veinte segundos despues de copiar, sin que el usuario estuviera
haciendo nada: parecia una alerta en la pantalla. Y lo grave era lo de despues:
si el usuario denegaba el permiso, el `catch` se tragaba el error y **el
borrado no ocurria**, dejando la contrasena en el portapapeles para siempre. La
proteccion fallaba en silencio justo en el caso en que mas importaba.

Ahora el modulo consulta `navigator.permissions.query({name: 'clipboard-read'})`
—que no muestra ningun aviso— y actua en consecuencia:

| Permiso de lectura | Que hace |
| --- | --- |
| `granted` | Comprueba que sigue siendo tu contrasena y vacia. Es el comportamiento completo. |
| `prompt` / `denied` / sin Permissions API | **Vacia directamente, sin preguntar.** El borrado siempre ocurre y el aviso nunca aparece. |

El intercambio es deliberado: sin permiso la app no puede saber si copiaste
otra cosa, y la borrara igualmente. Se asume que veinte segundos de una
contrasena en un portapapeles del sistema es un riesgo mayor que comerse lo que
el usuario copio en medio. Si algun dia se prefiere lo contrario, la
alternativa es pedir el permiso **en el momento de copiar**, con el toast
explicando el porqué, en lugar de veinte segundos despues a destiempo.

Dos limites que conviene conocer:

- El temporizador **no sobrevive a cerrar la pestaña**. Si copias y cierras la
  app, la contrasena se queda en el portapapeles. Ninguna solucion basada en
  temporizadores lo arregla sin meterse con un service worker.
- `clipboard-read` es un permiso invasivo: permite leer lo que el usuario haya
  copiado de cualquier parte. Por eso la app no lo pide y funciona sin el.
  `Permissions-Policy` lo acota a `(self)` para que ningun contexto embebido
  pueda leerlo.

Lo que **no** cubre, y conviene saber antes de exponerlo en Internet: verificacion
de correo electronico, segundo factor, recuperacion de contrasena y auditoria
externa. Ver [`docs/modelo-de-amenazas.md`](docs/modelo-de-amenazas.md) para el
analisis completo, y [`docs/criptografia.md`](docs/criptografia.md) para el
detalle criptografico.

## Contenedores

| Servicio | Puerto | Rol |
| --- | --- | --- |
| `caddy` | `8443` | Unico puerto publicado. TLS interno, CSP, proxy inverso |
| `web` | ninguno | nginx sirviendo el build de Vite, como usuario 101 sin privilegios |
| `api` | ninguno | Fastify, `read_only`, sin capacidades, en la red interna |
| `db` | ninguno | PostgreSQL 17 en red `internal: true`, inalcanzable desde el host |
| `migrate` | ninguno | one-shot; la API no arranca hasta que termina bien |
| `test-db` | ninguno | Solo con `--profile test`, base separada para la suite |

La base de datos no publica puerto **a proposito**: la unica via de entrada es la
API, y la API no es accesible desde fuera.

## Tests

```bash
docker compose --profile test run --rm test
```

249 tests en verde: 113 contra PostgreSQL real (RLS, cookies, CSRF, IDOR entre
usuarios, versionado optimista, limites de tasa) y 136 del cliente
(criptografia, AAD, uniformidad del generador por chi-cuadrado, traducciones).

Con el stack levantado, las dos comprobaciones que necesitan los contenedores en
marcha: `test:e2e` (35 checks del protocolo completo) y `test:http` (37 checks de
lo que recibe un navegador). **321 comprobaciones en total.**

> Si `test:e2e` responde `429` en el registro, has alcanzado el limite de 5
> cuentas por hora (3 por ejecucion). El limite esta funcionando; el contador
> vive en memoria y `docker compose restart api` lo reinicia.

## Configuracion

Todo se ajusta en `.env` (plantilla en `.env.example`, generado por
`scripts/gen-secrets.mjs`). Lo que mas te va a interesar:

| Variable | Por defecto | Que hace |
| --- | --- | --- |
| `APP_PORT` | `8443` | Puerto publicado por Caddy |
| `APP_ORIGIN` | `https://localhost:8443` | Origen de la app, para cookies y validacion de `Origin` |
| `AUTH_PEPPER` | generado | Pepper del verificador de autenticacion |
| `DATABASE_APP_PASSWORD` | generado | Contrasena del rol `securekey_api`, con el que entra la API. **Distinta** de `POSTGRES_PASSWORD` a proposito: con el rol de migracion, un RCE en la API permitia leer ficheros del host y ejecutar comandos |
| `ARGON2_MEMORY_KIB` | `19456` | Memoria de Argon2id. Subirlo cuesta CPU **a ti**, no al atacante |
| `SESSION_IDLE_MINUTES` | `30` | Minutos de inactividad antes de pedir la contrasena maestra otra vez |
| `REGISTRATION_MODE` | `open` | `invite` exige un codigo de administrador (ver `.env.example`) |

### El rol con el que entra la API

La API y el podador conectan como `securekey_api`, **sin superusuario**. El
servicio `migrate` si lo necesita (crea el rol, aplica migraciones) y por eso
lleva el rol de administracion: esa separacion es deliberada, no un descuido.

Con el rol de superusuario, un RCE en la API permitia `pg_read_file` (leer
ficheros del host), `COPY ... TO PROGRAM` (ejecutar comandos) y
`ALTER TABLE items DISABLE ROW LEVEL SECURITY`, que es eliminar de un plumazo la
unica barrera de la boveda. Con `securekey_api`, las cuatro estan bloqueadas y la
RLS es una barrera de verdad.

`test/integration/db-role.test.ts` lo comprueba, para que nadie deshaga el cambio
sin darse cuenta.

Si cambias el dominio o el puerto, actualiza tambien `APP_ORIGIN` y el
`Caddyfile`.

## Operacion diaria

```bash
npm run logs              # API en vivo
npm run ps                # estado
npm run invite -- a@b.com # emitir una invitacion
npm run backup            # volcado + verificacion de integridad
npm run prune             # forzar una poda de audit_log
```

Los access log de Caddy estan en un volumen con rotacion automatica (20 MB x 10
ficheros). Para mirarlos:

```bash
docker compose exec caddy sh -c "tail -f /var/log/caddy/access.log"
```

Van en JSON, asi que se filtran con `jq`:

```bash
# IPs que mas fallan (primer indicio de un ataque)
docker compose exec caddy sh -c \
  "jq -r 'select(.status>=400) | .request.client_ip' /var/log/caddy/access.log \
   | sort | uniq -c | sort -rn | head"
```

## Despliegue en una VPS

Todo corre en Docker, asi que la VPS solo necesita Docker y un dominio.

**Requisitos**

- Dominio con registro `A` a la IP de la VPS. Let's Encrypt **no** emite
  certificados para IPs desnudas.
- Puertos **80 y 443** abiertos. El 80 lo necesita el desafio de Let's Encrypt.
  Si tu proveedor lo bloquea, hay que pasar al desafio DNS-01.
- Al menos **1 GB** de RAM (87 MB en reposo, con picos de scrypt de 16 MB).

**Cambios en el `.env`**

| Variable | A que |
| --- | --- |
| `APP_HOST` | `boveda.tudominio.com` (nuevo, sin esquema ni barra final) |
| `APP_ORIGIN` | `https://boveda.tudominio.com` |
| `ALLOWED_ORIGINS` | `https://boveda.tudominio.com` |
| `REGISTRATION_MODE` | `invite` |

Si se olvida `APP_ORIGIN` o `ALLOWED_ORIGINS`, el registro y el login devuelven
**403** sin explicación: el hook `onRequest` rechaza cualquier `Origin` que no
esté en la lista. Es el fallo mas probable de este despliegue, y conviene
comprobarlo nada mas levantar.

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Cambios respecto al compose de desarrollo:

- Caddy pide el certificado a **Let's Encrypt** solo (nada de `tls internal`, sin
  aviso de seguridad en el navegador) y escucha en 443. El 80 queda reservado
  para el desafio de la CA y la redireccion a HTTPS: la app nunca se sirve en
  claro.
- `prune` pasa a correr **cada hora** en vez de cada seis.
- Se ajustan los limites de memoria y los parametros de Postgres
  (`max_connections`, `shared_buffers`, `log_min_duration_statement`).

**Comprobaciones tras el despliegue**

```bash
curl -I https://boveda.tudominio.com/          # 200, HSTS, CSP con wasm-unsafe-eval
curl  https://boveda.tudominio.com/api/v1/health
npm run test:http                             # 44 checks contra el TLS real
npm run test:e2e                              # 35 checks del protocolo
```

**Backups**

```bash
npm run backup                 # vuelca y verifica integridad
BACKUP_DIR=/mnt/nas npm run backup
npm run restore backups/securekey-<fecha>.dump
```

`restore.sh` levanta un PostgreSQL aislado, restaura ahi y comprueba que la base
resultante tiene las 4 tablas, la **RLS activa en las 4** y el rol `securekey_app`
—que sin el, las politicas no se aplicarian. Solo cuando todo cuadra imprime
como aplicarlo sobre la base real. Nunca restaura encima de la de produccion sin
confirmacion: el volcado sobrescribe tablas enteras y no hay deshacer.

Es **seguro almacenar** el volcado: `items` solo contiene blobs AEAD. Lo que si
es sensible son los correos, los `auth_hash` y las IPs del `audit_log`. Si el
destino no es de fiar, cifralo con `age` antes de subirlo.

Conviene un backup **diario y automatico** (cron o systemd timer). Uno que solo se
lanza a mano es un backup que no existe el dia que hace falta.

### Si hay un proxy o balanceador delante de Caddy

Caddy debe ser el unico que termine TLS, o `request.ip` sera la IP del proxy y el
limite de tasa por IP dejara de ser util. Si el TLS se termina antes, hay que
configurar tambien `trusted_proxies` en Caddy; con `trustProxy` acotado a rangos
privados en la API, una cabecera `X-Forwarded-For` que llegue desde Internet se
ignora y el limite cuenta por IP real.
