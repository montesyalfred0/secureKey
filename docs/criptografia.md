# Diseno criptografico

Este documento es la referencia de por que cada decision es como es. Si alguna
vez hay que cambiar un parametro, empezar por aqui.

## 1. Que es zero-knowledge y que implica

**Zero-knowledge** significa que el servidor no tiene la informacion necesaria
para descifrar los datos, ni siquiera si alguien compromete su codigo o su
base de datos. No es una cifrado "casi" del lado del cliente: la clave de
boveda **nunca** sale del navegador.

La consecuencia practica: **el servidor no puede ofrecer funciones que
requieran el texto claro** (buscar por usuario en SQL, avisar de contrasenas
debilidades en el servidor, recuperar la contrasena). Todo eso se hace en el
cliente, y es correcto.

La segunda consecuencia, incomoda pero inevitable: **el servidor no puede
restablecer una contrasena maestra**, porque no la posee. No es un bug que se
pueda corregir mas adelante.

## 2. Cadena de derivacion

### 2.1 Contrasena maestra -> masterKey

```
masterKey = Argon2id(password, salt = SHA-256(normalizar(email)), m, t, p)   32 B
```

Parametros por defecto: `m = 19456 KiB (19 MiB)`, `t = 2`, `p = 1`, que es el
minimo recomendado por la [OWASP Password Storage Cheat Sheet][owasp-pass]. El
servidor los publica en `prelogin` y puede subirlos sin romper clientes viejos
(el cliente compara `kdfVersion` y re-envuelve la boveda si ha cambiado).

**Por que el salt es `SHA-256(email)` y no aleatorio.** Un salt aleatorio obliga
a que el servidor lo almacene por usuario. Como el servidor ya guarda una fila
por cuenta, podria hacerlo, pero el salt determinista da una propiedad util:
la misma contrasena + el mismo correo producen siempre la misma clave, sin
estado adicional. La aleatoriedad ya la aporta Argon2id. El HKDF de abajo usa
ese mismo valor como `salt`, lo que ata las dos derivadas a la cuenta.

**Normalizacion NFC.** Dos tecleados visualmente identicos desde moviles
distintos pueden llegar en NFC o NFD y produzir claves distintas. Se normaliza
a NFC en el cliente. No se normaliza a NFKC ni se recorta: eso seria cambiar
la contrasena del usuario.

### 2.2 masterKey -> KEK y authKey

```
KEK     = HKDF-SHA256(masterKey, salt = SHA-256(email), info = "securekey/v1/kek")
authKey = HKDF-SHA256(masterKey, salt = SHA-256(email), info = "securekey/v1/auth")
```

Dos derivadas **independientes** de la misma masterKey. Que sean
independientes importa: compromising `authKey` (que el servidor posee) no
permite deducir la `KEK` (que no posee). `HKDF` con `info` distintos es el
mecanismo estandar de separacion de claves; es preferible a inventar una
separacion propia.

Todo con `crypto.subtle` nativo del navegador. Cero dependencias.

### 2.3 Envelope de la boveda

```
vaultKey = 32 B aleatorios (crypto.getRandomValues)
wrap     = AES-256-GCM(KEK, vaultKey, nonce = 12 B aleatorio,
                       AAD = "securekey/v1:vault:<email>:key:<keyVersion>")
```

`vaultKey` **no se deriva de la contrasena**: es aleatoria. Por eso cambiar la
contrasena maestra no obliga a re-cifrar la boveda: se re-envuelve la misma
`vaultKey` con la `KEK` nueva. Con decenas o cientos de credenciales, esto es
la diferencia entre una operacion instantanea y una que reescribe la base de
datos.

### 2.4 Credenciales

Cada item se cifra con una clave **derivada por item**, no directamente con
`vaultKey`:

```
itemKey = HKDF-SHA256(vaultKey, salt = 16 B aleatorios,
                      info = "securekey/v1/item/<keyVersion>")
item    = AES-256-GCM(itemKey, JSON del item, nonce = 12 B aleatorio,
                      AAD = "securekey/v1:item/<itemId>:key:<keyVersion>")
```

Dos razones, ambas de separacion de claves:

1. **Reutilizacion de clave.** Cifrar 200 credenciales con la misma clave
   AES-GCM es un error clasico. Un solo nonce reutilizado con la misma clave
   filtra la clave y la relacionacion entre textos claros. Con una clave por
   item, dos nonce nunca coinciden.
2. **Revocacion granular.** Se puede re-derivar un item concreto sin tocar el
   resto.

El coste es un HKDF y un AES-GCM mas por operacion: irrelevante para esta carga.

**El AAD es lo que ata el ciphertext a su fila.** `itemId` lo genera el cliente
(con `crypto.randomUUID()`) precisamente porque forma parte del AAD: si
generara el servidor, el cliente no podria cifrar antes de insertar. Si alguien
mueve un blob de la fila de Alice a la de Bob, o cambia su `id`, el descifrado
falla. Hay un test (`apps/web/test/crypto.test.ts`) que descifra el blob a mano
con WebCrypto para comprobar exactamente esto.

### 2.5 `keyVersion`: por que NO se incrementa al re-envolver

El nombre engaña si no se lee con cuidado. `key_version` es la **generacion de
la clave de boveda**, y va dentro del AAD de cada item. Por eso:

- Al **cambiar la contrasena maestra** o al **subir los parametros KDF** se
  re-envuelve la MISMA `vaultKey` y `key_version` **se queda igual**.
- Incrementarlo solo tiene sentido en una **rotacion real** de clave (cambiar
  la `vaultKey`), que obliga a re-cifrar la boveda entera y solo debe ocurrir
  como operacion planificada.

Un error en este punto es silencioso y demoledor: si el servidor incrementase
`key_version` al re-envolver, todos los items dejarian de descifrar y el usuario
perderia su boveda. Por eso hay un test end-to-end que verifica que
`key_version` sigue en 1 tras el login.

## 3. Verificacion de la contrasena maestra

```
peppered  = HMAC-SHA256(pepper, authKey)         pepper = secreto del servidor
authHash  = scrypt(peppered, salt_por_usuario, 64, N=2^14, r=8, p=1)
```

**El control de coste real no es este.** Es Argon2id, y lo paga el navegador.
Aqui solo se protege un secreto de 32 bytes que el atacante tendria que obtener
primero pasando por Argon2. Es defensa en profundidad: evita que un atacante
con la base de datos pueda usar la tabla como un oraculo de verificacion
barato, y evita que `scrypt` con coste 0 se convierta en un atajo.

**El pepper** vive en `.env` (secretos de Docker si se quisera), nunca en la
base de datos. Sin el, un robo de la BD exigiria un ataque offline por cada
cuenta; con el, ademas hace falta el `.env`.

**Todo sale de `node:crypto`.** No hay modulos nativos que compilar, lo que
permite una imagen Alpine minima sin toolchain de compilacion.

## 4. Sesiones

| Pieza | Decision | Motivo |
|---|---|---|
| Token | 32 B aleatorios, opaco | El cliente no ve nada interpretable |
| Almacenamiento | `SHA-256(token)` en la tabla | Robo de la BD != robo de sesiones |
| Cookie | `__Host-sk_session`, `httpOnly`, `Secure`, `SameSite=Strict` | El prefijo `__Host-` impide que un subdominio atacante fije la cookie |
| CSRF | Cookie legible `__Host-sk_csrf` + cabecera `X-CSRF-Token`, comparado con el hash almacenado | Doble envio: SameSite=Strict bloquea la mayoria, esto cubre el resto |
| Caducidad | Absoluta (24 h) + inactividad deslizante (30 min) | Un portatil desatendido no mantiene la sesion viva |
| Almacenamiento | Tabla `sessions` | Un JWT no se puede revocar sin lista de bloqueo, que es lo mismo que una tabla |

Ante un rechazo de CSRF, la sesion se destruye. Es un poco agresivo, pero
preferible: si el token no cuadra, puede que el navegador ya no sea quien
creemos.

## 5. Row Level Security

Cada peticion autenticada corre dentro de una transaccion:

```sql
BEGIN;
SET LOCAL ROLE securekey_app;              -- rol sin DDL, sujeto a RLS
SELECT set_config('app.user_id', $1, true);
... consultas ...
COMMIT;
```

`SET LOCAL` y `set_config(..., is_local => true)` desaparecen al hacer
COMMIT o ROLLBACK, de modo que una conexion devuelta al pool nunca arrastra el
contexto de otro usuario.

Las tablas tienen `ENABLE ROW LEVEL SECURITY` (no `FORCE`), con politicas del
tipo `USING (user_id = app_user_id())`. La API opera **siempre** bajo
`securekey_app`, asi que para ella las politicas son el unico candado. El
propietario (el rol de migracion) conserva acceso sin restricciones, que es lo
que permite que funcionen las funciones `SECURITY DEFINER` del flujo de
autenticacion.

**El filtro `WHERE user_id = $1` del codigo sigue ahi, y es intencionado.** La
RLS es la red de seguridad; el filtro deja la intencion explicita a la vista en
la revision de codigo. Que un bug en el WHERE no provoque una fuga porque la RLS
esta debajo.

### Funciones `SECURITY DEFINER`

`auth_lookup(email)` y `session_lookup(hash)` leen datos **antes** de conocer el
`app.user_id`: el login busca por correo y la sesion se resuelve por token. No
pueden pasar por el contexto RLS, asi que son `SECURITY DEFINER` con
`search_path` fijo (evita secuestro de busqueda) y con lo que devuelven
acotado: una exige conocer el email objetivo, la otra un secreto de 256 bits.

Es el punto mas delicado del diseno y el que mas conviene revisar si alguna vez
se toca el flujo de autenticacion.

## 6. Generador de contrasenas

**Rechazo por limite, no modulo.** Elegir un indice con `byte % 26` sesga
hacia los primeros caracteres del conjunto, porque 256 no es multiplo de 26: el
0 sale el 10 % de las veces y el 25 el 7,6 %. El codigo genera bytes y
**descarta** los que caen fuera del mayor multiplo de `poolSize` que cabe en
256, lo que da una distribucion uniforme exacta.

El shuffle usa el mismo mecanismo (Fisher-Yates con CSPRNG). Barajar con
`Math.random()` seria un fallo grave.

Hay una prueba de **chi-cuadrado** sobre 60 000 caracteres
(`apps/web/test/generator.test.ts`) que verifica la uniformidad, mas un test
que calcula cuanto sesgaria un `%` ingenuo (~644 frente a un limite critico de
52,3) para dejar constancia de por que existe el rechazo.

**Todos los aleatorios vienen de `crypto.getRandomValues` / `crypto.randomInt`.**
`Math.random()` no es un PRNG criptografico y no aparece en el codigo.

## 7. Evaluacion de fortaleza

Usa **zxcvbn**, cargado de forma diferida. Dos detalles que no son evidentes:

1. **`@zxcvbn-ts/core` solo trae el motor de calculo.** Sin los diccionarios
   (`@zxcvbn-ts/language-common`, `@zxcvbn-ts/language-en`) y las tablas de
   adyacencia del teclado, zxcvbn no sabe que `password123` es una contrasena
   filtrada y le da la maxima puntuacion con la etiqueta "Excelente". Hay que
   registrarlos con `zxcvbnOptions.setOptions()` **antes** de la primera
   llamada. El paquete que exporta los diccionarios no es el mismo que el del
   motor: `language-common` exporta `dictionary` y `adjacencyGraphs`, no
   `zxcvbnCommon`.

2. **No existe paquete de espanol**, pero zxcvbn acepta cualquier objeto de
   traducciones. `apps/web/src/lib/zxcvbn-es.ts` supplya el nuestro, de modo
   que el feedback y los tiempos de descifrado llegan ya en espanol. Es mejor
   que traducir el resultado: traducir cadenas literales se rompe en cuanto
   upstream cambia un texto. Un test comprueba que las claves cubren
   exactamente las del paquete ingles.

Ademas hay una **heuristica local** (`quickScore`) que corre de forma
sincrona al teclear y sirve de red de seguridad si la carga diferida falla. Es
peor que zxcvbn, pero nunca miente en la direccion peligrosa.

**Ninguna contrasena sale del dispositivo.** Ni para comprobar si esta
filtrada. En una aplicacion que se presenta como gestor de contrasenas, enviar
el secreto a un tercero seria fatal; por eso no hay integracion con Have I Been
Pwned ni ninguna otra, y el aviso de "contrasena habitual" se resuelve con una
lista corta embebida en el bundle.

## 8. Lo que falta para produccion publica

- **Segundo factor de autenticacion** (TOTP).
- **Codigos de recuperacion**: hoy, perder la contrasena maestra es perder la
  boveda.
- **Rotacion real de clave** operada como migracion, con re-cifrado de la
  boveda completa.
- **Auditoria externa** y tests de penetracion.
- **Sincronizacion entre dispositivos**: el AAD y la `key_version` ya estan
  preparados, pero no hay resolucion de conflictos mas alla del 409.
- **Cifrado en reposo del volumen de PostgreSQL** si el despliegue lo requiere.

[owasp-pass]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
