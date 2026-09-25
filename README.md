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
| `ARGON2_MEMORY_KIB` | `19456` | Memoria de Argon2id. Subirlo cuesta CPU **a ti**, no al atacante |
| `SESSION_IDLE_MINUTES` | `30` | Minutos de inactividad antes de pedir la contrasena maestra otra vez |
| `REGISTRATION_MODE` | `open` | `invite` exige un codigo de administrador (ver `.env.example`) |

Si cambias el dominio o el puerto, actualiza tambien `APP_ORIGIN` y el
`Caddyfile`.

## Despliegue

Esta configuracion sirve tal cual para uso personal o en una red de confianza. Para
exponerla en Internet, antes de nada:

1. **Dominio real con certificado de una CA publica.** La CA interna de Caddy es
   para `localhost`; en un dominio real hay que cambiar la directiva `tls`.
2. **TLS terminado antes de Caddy** si hay un proxy o balanceador delante, para
   que `request.ip` (y con el, el limite de tasa) sea real.
3. **Copia de seguridad de PostgreSQL** cifra, y **cifrado del volumen** en reposo.
4. Un limite de tasa por IP **de verdad util**: por defecto Caddy es el unico que
   ve las IP reales, y eso solo es cierto si no hay otro proxy delante.

El orden importa mas de lo que parece: sin un dominio real con TLS de confianza,
todo lo demas se puede hacer, pero cualquier acceso desde Internet seguira
pareciendo sospechoso y la CSP no podra relajarse ni un milimetro.
