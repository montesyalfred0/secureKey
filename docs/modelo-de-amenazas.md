# Modelo de amenazas

Que ataca SecureKey, que protege y, sobre todo, **que no** protege. Un gestor
de contrasenas sin un modelo de amenazas explicito es una caja negra con
ceremonia de seguridad.

## 1. Activos

En orden de importancia:

| Activo | Dónde vive | Si se pierde |
|---|---|---|
| Contrasena maestra | Solo en la memoria del navegador y en la cabeza del usuario | Se pierde la boveda entera, sin margen de error |
| Clave de boveda | Solo en la memoria del navegador | Se pierde la boveda |
| Credenciales (usuario/contrasena de sitios) | Cifradas en la tabla `items` | Perdemos acceso a cuentas de terceros |
| Tabla de sesiones | Tabla `sessions` (hashes SHA-256) | Suplantacion de sesion hasta que caduque |
| Pepper del servidor | `.env` / secreto de Docker | Un robo de BD pasa a ser atacable offline |

## 2. Adversarios

| # | Adversario | Capacidad | Resultado |
|---|---|---|---|
| A1 | Robo de la base de datos (backup filtrado, SQLi, snapshot del volumen) | La tabla completa, sin el `.env` | **Nada utilizable.** No hay texto claro y la contrasena maestra exige 19 MiB de memoria por intento |
| A2 | Robo de la BD **y** del `.env` | Pepper + tabla | Requiere romper Argon2id offline. El pepper no cambia el resultado, solo lo encarece |
| A3 | Compromiso del servidor (codigo, imagen, root) | Control de la API y la BD | Puede leer **cifrados** y **metadatos** (correos, `item_id`, fechas, tamano de las credenciales). No puede descifrar. **No** puede restablecer contrasenas maestras |
| A4 | XSS en el navegador | JavaScript en el origen de la app | **Game over.** Puede leer la clave de boveda de la memoria y exfiltrarla |
| A5 | Robo fisico del equipo | Portatil desbloqueado con la boveda abierta | Lectura de la boveda mientras este abierta. Mitigado por el bloqueo automatico a los 5 min |
| A6 | Inspeccion de memoria / swap / hibernacion | Another process en el equipo | Fuera del modelo de esta version: la clave vive en memoria de JS |
| A7 | Consumidor del portapapeles | Otra aplicacion leyendo el portapapeles | Mitigado con borrado automatico a los 20 s, **solo si** el usuario no concede permiso de lectura de portapapeles |
| A8 | Usuario anfitrion de la red (proxy TLS manipulado) | Intercepta el trafico | Nada: TLS con la CA interna y HSTS. Sin MITM con una CA publica |
| A9 | UsuarioCSRF / sitio atacante | Engana al usuario para que vis SecureKey | Mitigado: `SameSite=Strict`, CSRF de doble envio, validacion de `Origin` |

### El caso que mas nos importa: A1

Es el mas realista. En un gestor de contrasenas, el compromiso de la base de
datos es el escenario que justifica el producto. Se comprueba de dos formas
independientes:

1. La prueba end-to-end verifica que el titulo, el usuario y la contrasena de
   una credencial **no aparecen** en la respuesta de la API.
2. La inspeccion manual de `information_schema` muestra que la tabla `items`
   solo tiene `id`, `user_id`, `version`, `alg`, `kdf`, `nonce`,
   `ciphertext` y las tres fechas. **No hay ninguna columna de texto con
   contenido de credencial.**

## 3. Controles implementados

| Control | Donde |
|---|---|
| Cifrado AEAD por item, con clave derivada por item | `apps/web/src/lib/crypto.ts` |
| AAD atando ciphertext a `itemId` y `keyVersion` | `apps/web/src/lib/crypto.ts` |
| Argon2id con parametros minimos de OWASP | `crypto.ts`, publicados por el servidor en `prelogin` |
| Pepper fuera de la base de datos | `.env`, `apps/api/src/crypto/server.ts` |
| Separacion de claves con HKDF (`kek` / `auth`) | `crypto.ts` |
| Tokens de sesion hasheados en la BD | `auth/session.ts` |
| Cookies `__Host-` + `httpOnly` + `Secure` + `SameSite=Strict` | `auth/session.ts` |
| CSRF de doble envio + validacion de `Origin` | `http/context.ts`, `plugins/security.ts` |
| Row Level Security en PostgreSQL | `db/migrations.ts` |
| Rol de aplicacion sin DDL, adoptado con `SET LOCAL ROLE` | `db/withUser.ts` |
| Funciones SECURITY DEFINER con `search_path` fijo y retorno acotado | `db/migrations.ts` |
| Limitacion de tasa por IP y por cuenta con bloqueo temporal | `auth/routes`, `plugins/security.ts` |
| `trustProxy` acotado a rangos privados, no `true` | `api/src/app.ts` |
| `X-Forwarded-For` sobrescrito explicitamente por Caddy | `infra/caddy/Caddyfile` |
| Access log con rotacion (20 MB x 10) | `infra/caddy/Caddyfile` |
| Retencion de `audit_log` con doble tope (antiguedad + volumen) | `api/src/db/prune-audit.ts` |
| Registro cerrado por invitacion firmada | `api/src/scripts/invite.ts` |
| `audit_prune` con `SECURITY DEFINER`, `search_path` fijo y sin `EXECUTE` para `securekey_app` | `db/migrations.ts` |
| CSP sin `unsafe-inline` ni `unsafe-eval`, verificada por test | `infra/caddy/Caddyfile`, `apps/web/test/http-checks.mjs` |
| HSTS, nosniff, no-referrer, frame-ancestors none, Permissions-Policy | `infra/caddy/Caddyfile` |
| Contenedores sin root, `read_only`, `cap_drop: ALL` | `docker-compose.yml` |
| Base de datos sin puerto publicado, en red interna | `docker-compose.yml` |
| Cifrado del trafico con TLS interno | `infra/caddy/Caddyfile` |
| Registros sin cuerpos ni cabeceras sensibles | `api/src/app.ts` (`redact` de pino) |
| Errores 500 que nunca exponen mensajes internos | `api/src/app.ts` |
| Evaluacion de contrasenas 100 % local | `apps/web/src/lib/strength.ts` |
| Bloqueo automatico por inactividad | `apps/web/src/app.tsx` |
| Borrado automatico del portapapeles | `apps/web/src/lib/clipboard.ts` |
| Limpieza de la clave de boveda al bloquear (`fill(0)`) | `apps/web/src/state/session.ts` |
| Simetria de tiempo en el login para no revelar cuentas | `api/src/routes/auth.ts` |
| Cifrado de borrado (logico) para sincronizar entre dispositivos | `api/src/routes/items.ts` |

## 4. Lo que NO protegemos (y hay que decirlo)

### 4.1 XSS

**El riesgo residual dominante.** Si se ejecuta JavaScript en el origen de la
app, la clave de boveda esta en la memoria y es legible. Mitigaciones: CSP
estricta, tres dependencias en el frontend, todo el renderizado por
`textContent` de Preact (sin `dangerouslySetInnerHTML` en ninguna parte).

**Esto no se arregla con mas trabajo de codigo, se reduce.** Un gestor de
contrasenas de codigo abierto nunca va a ganarle a un atacante dedicado en su
propio navegador.

### 4.2 Sin recuperacion

Sin SMTP no hay verificacion de correo ni restablecimiento. Si el usuario
pierde la contrasena maestra, pierde la boveda. Es una consecuencia directa de
zero-knowledge, no una funcionalidad pendiente.

### 4.3 Sin segundo factor

`2FA` (TOTP) esta en la hoja de ruta, no implementado. Para una instancia
expuesta a Internet, con el registro abierto y sin 2FA, es un riesgo asumido
que el usuario debe conocer.

### 4.4 El servidor ve metadatos

 aunque no descifre nada, la base de datos revela: que correo existe, cuando se
creo cada credencial, cuantas hay, cuanto ocupa cada una, desde que IP se
conecta cada sesion y un registro de acciones (`audit_log`).

**No** revela contenido. Es el precio de que el servidor tenga que funcionar.

### 4.5 Registro abierto

Por defecto cualquiera con acceso crea cuentas. Un atacante puede:
- Crear cuentas de relleno (limitado: 5 por hora y por IP, lo que con 50 IPs
  siguen siendo 50 cuentas por hora).
- Usar la instancia como almacen de credenciales propias.

En una VPS publica, `REGISTRATION_MODE=invite` **no es una recomendacion, es
obligatorio**. El registro exige un codigo firmado con `INVITE_SECRET`
(`skinv_<payload>.<HMAC-SHA256>`), atado a un correo concreto y con caducidad, de
modo que no sirve para otra cuenta ni se reutiliza por accidente. No hay estado
en el servidor: no hay tabla de invitaciones que robar ni mantener.

Emitir una con `npm run invite -- correo@ejemplo.com`.

Lo que **no** resuelve:

- **No hay un solo uso ni limite de emision.** Quien tenga el `INVITE_SECRET`
  puede emitir ilimitados, y el mismo codigo vale para siempre hasta que caduca.
  Tratalo como una credencial mas (permisos 600) y rotarlo invalida todos los
  pendientes, usados o no.
- **No se verifica que el correo exista.** En zero-knowledge es inherente: el
  servidor no puede saber nada del correo sin enviar un mensaje, y hacerlo
  romperia el modelo. Una invitacion a un correo que nadie posee es una cuenta
  inutil, no una cuenta comprometida.
- **Un atacante con el secreto puede crear las cuentas que quiera**, y como el
  contenido es indescifrable, no hay forma de distinguirlas de las reales. Ahi
  solo sirve un limite de tasa por IP mas alto o una revision manual.

### 4.6 Denegacion de servicio por llenado de disco

`audit_log` recibe una fila por cada login fallido, **desde la red y sin
autenticar**. Medido: 52 filas ocupaban 64 kB, de los cuales solo 8 kB eran datos
(3 indices btree). Un atacante que dispare al limite desde muchas IPs llena el
disco sin necesitar credenciales. Cada fila cuesta cuatro escrituras: heap mas
los tres indices.

Cerrado con dos topes, aplicados por el servicio `prune`
(`apps/api/src/db/prune-audit.ts`):

- `AUDIT_KEEP_DAYS` (30): antiguedad maxima.
- `AUDIT_MAX_ROWS` (500 000): cota dura, por si el caudal de un ataque dispara la
  tabla mas rapido de lo que corre la poda. Conserva las mas recientes y recorta
  **por `id`, no por `at`**: con filas de la misma fecha — que es justo el caso de
  un pico de trafico — un corte por fecha no distingue nada. Una version
  anterior que combinaba ambos limites con `GREATEST()` no borraba nada en ese
  escenario, y esta es la razon del diseno actual.

El recorte por volumen **si** aplica sobre filas recientes, y es deliberado: es
la unica forma de que la cota sirva de algo. Perder los ultimos minutos de un
ataque que ya esta llenando el disco es un mal menor que quedarse sin disco. En
reposo la tabla nunca llega al tope, asi que la ventana de 30 dias no se pierde.

Los access log de Caddy tambien rotan (20 MB x 10). Un log sin rotar en un
servidor publico es el mismo problema por otro camino: basta con pedir URLs de 8
kB hasta llenar el volumen.

### 4.7 Confianza en el `X-Forwarded-For`

El limite de tasa por IP solo es util si la IP que ve la API es la real. Se
verifico empiricamente que **Caddy sobrescribe** la cabecera: un
`X-Forwarded-For` falsificado no cuela (se mando `203.0.113.99` y la API registro
la IP del cliente real).

Aun asi, la app no depende de ese comportamiento por defecto:

- El `Caddyfile` fija `header_up X-Forwarded-For {remote_host}` de forma explicita.
- `trustProxy` esta acotado a `loopback`, `linklocal` y `uniquelocal`, no a
  `true`. Con `true` basta con publicar el puerto de la API, o anadir un
  contenedor a la red `edge`, para que una cabecera falsificada evadiese el
  limite por completo.

Con un proxy delante de Caddy hay que configurar `trusted_proxies`; si no, Caddy
no sabra que esa cabecera viene de alguien de fiar, y la IP que llegue a la API
sera la del proxy para todo el mundo.

### 4.8 Fuerza bruta contra la contrasena maestra

Argon2id con 19 MiB la encarece, pero **no la vuelve impracticable** frente a
un atacante con GPU y paciencia. Mitigaciones presentes: limitacion de tasa,
bloqueo de cuenta, y el coste de 19 MiB por intento.

Si tu contrasena maestra es `L0nga-Contrasena-Maestra!` con un anchor
generado, el modelo aguanta. Si es `123456`, no lo salva nada.

### 4.9 Fuera de alcance

- Extensions de navegador, clientes de escritorio, apps moviles.
- Sincronizacion y resolucion de conflictos entre dispositivos.
- Compartir bovedas.
- Cifrado del volumen de PostgreSQL en reposo.
- Rotacion real de clave (cambio de `vaultKey`).
- Auditoria externa.
- WAF o CDN delante. La limitacion de tasa vive en la API, no en Caddy: si
  alguien pone un proxy delante, ese proxy no hereda el limite.
- Deteccion de intrusiones en el host. Los access log existen y rotan, pero no
  hay nadie mirandolos automaticamente.
