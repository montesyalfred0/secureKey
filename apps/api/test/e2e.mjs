/**
 * Prueba end-to-end del protocolo, ejecutada dentro de la red de Docker.
 *
 * Reproduce en Node exactamente lo que hace el navegador (misma
 * criptografia, mismos AAD) y comprueba las propiedades que importan:
 *
 *   1. El servidor acepta el flujo completo: prelogin -> register -> login.
 *   2. El `authKey` equivocado se rechaza (no basta con conocer el email).
 *   3. La sesion exige CSRF y esta aislada por usuario (IDOR -> 404).
 *   4. NINGUN texto en claro de una credencial aparece en lo que el servidor
 *      almacena ni devuelve: el zero-knowledge es real, no nominal.
 *   5. El AAD ata cada ciphertext a su fila, y el versionado optimista
 *      detecta ediciones concurrentes.
 *
 * REGISTRO CERRADO POR INVITACION. Con `REGISTRATION_MODE=invite` (lo que se
 * usa en un servidor publico) el registro exige un codigo valido, asi que este
 * script necesita `INVITE_SECRET` para emitir uno por cada cuenta que crea.
 *
 *     docker run --rm \
 *       --network securekey_edge \
 *       -e API_URL=http://api:3000/api/v1 \
 *       -e INVITE_SECRET=... \
 *       securekey/api-dev node apps/api/test/e2e.mjs
 *
 * `npm run test:e2e` lo pasa desde el `.env`. Sin el, el script lo dice y sale
 * con codigo 2, en vez de mostrar veinte fallos en cascada (sesion no creada,
 * IDOR que no se puede comprobar) que no explican nada.
 *
 * NOTA sobre los limites de tasa: este script crea 3 cuentas, asi que necesita
 * `RATE_LIMIT_REGISTER_MAX` de al menos 3. En produccion es 2 a proposito, y
 * este script no se ejecuta ahi; en local hay que subirlo. Con el limite
 * justo, dos ejecuciones seguidas fallan con 429, y eso es el limite
 * funcionando, no un fallo del producto. El contador vive en memoria del
 * proceso, asi que
 *
 *     docker compose up -d
 *
 * lo reinicia (y hace falta reiniciar, no solo reiniciar la API, para que
 * coja el valor nuevo del .env).
 */
import { argon2id } from 'hash-wasm';
import { createHmac } from 'node:crypto';

const BASE = process.env['API_URL'] ?? 'http://api:3000/api/v1';
const TE = new TextEncoder();
const TD = new TextDecoder();

const PROTOCOL = { KEY_BYTES: 32, NONCE_BYTES: 12, ITEM_SALT_BYTES: 16, version: 1 };
const KEK_INFO = 'securekey/v1/kek';
const AUTH_INFO = 'securekey/v1/auth';
const ITEM_INFO_PREFIX = 'securekey/v1/item/';

const toB64 = (bytes) => Buffer.from(bytes).toString('base64');
const fromB64 = (value) => new Uint8Array(Buffer.from(value, 'base64'));
const newId = () => crypto.randomUUID();

// --- Codigos de invitacion -------------------------------------------------
// Misma construccion que `issueInviteCode` en `src/crypto/server.ts`: firma
// HMAC-SHA256 del payload, truncada a 32 caracteres. Se replica aqui para que
// el script no dependa de compilar la API.
const INVITE_SECRET = process.env['INVITE_SECRET'];

function issueInviteCode(email, days = 30) {
  const payload = Buffer.from(
    JSON.stringify({ e: email.toLowerCase(), exp: Date.now() + days * 86_400_000 }),
    'utf8',
  ).toString('base64url');
  const sig = createHmac('sha256', INVITE_SECRET).update(payload).digest('base64url').slice(0, 32);
  return `skinv_${payload}.${sig}`;
}

let passed = 0;
let failed = 0;

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1;
    console.log(`  ok   ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL ${name}${detail ? ` -> ${detail}` : ''}`);
  }
}

function bail(message) {
  console.log(`\n${message}\n`);
  process.exit(2);
}

// --------------------------------------------------------------------------
// Misma cadena de derivacion que apps/web/src/lib/crypto.ts
// --------------------------------------------------------------------------

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

async function hkdfKey(ikm, salt, info, usages) {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: TE.encode(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

async function hkdfBits(ikm, salt, info, bytes) {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: TE.encode(info) },
      base,
      bytes * 8,
    ),
  );
}

const kdfSalt = (email) => sha256(TE.encode(email.trim().toLowerCase()));

async function deriveMasterKey(password, email, kdf) {
  return new Uint8Array(
    await argon2id({
      password: TE.encode(password.normalize('NFC')),
      salt: await kdfSalt(email),
      parallelism: kdf.p,
      iterations: kdf.t,
      memorySize: kdf.m,
      hashLength: PROTOCOL.KEY_BYTES,
      outputType: 'binary',
    }),
  );
}

const vaultAad = (email, keyVersion) =>
  TE.encode(`securekey/v${PROTOCOL.version}:vault:${email.trim().toLowerCase()}:key:${keyVersion}`);

const itemAad = (itemId, keyVersion) =>
  TE.encode(`securekey/v${PROTOCOL.version}:item:${itemId}:key:${keyVersion}`);

async function wrapVaultKey(vaultKey, kek, email, keyVersion) {
  const nonce = crypto.getRandomValues(new Uint8Array(PROTOCOL.NONCE_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: vaultAad(email, keyVersion), tagLength: 128 },
    kek,
    vaultKey,
  );
  return { alg: 'AES-256-GCM', nonce: toB64(nonce), ciphertext: toB64(new Uint8Array(ciphertext)) };
}

async function unwrapVaultKey(wrapped, kek, email, keyVersion) {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: fromB64(wrapped.nonce),
        additionalData: vaultAad(email, keyVersion),
        tagLength: 128,
      },
      kek,
      fromB64(wrapped.ciphertext),
    ),
  );
}

async function encryptItem(vaultKey, itemId, keyVersion, plain) {
  const salt = crypto.getRandomValues(new Uint8Array(PROTOCOL.ITEM_SALT_BYTES));
  const info = `${ITEM_INFO_PREFIX}${keyVersion}`;
  const itemKey = await hkdfKey(vaultKey, salt, info, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(PROTOCOL.NONCE_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: itemAad(itemId, keyVersion), tagLength: 128 },
    itemKey,
    TE.encode(JSON.stringify(plain)),
  );
  return {
    alg: 'AES-256-GCM',
    kdf: { alg: 'HKDF-SHA256', salt: toB64(salt), info },
    nonce: toB64(nonce),
    ciphertext: toB64(new Uint8Array(ciphertext)),
  };
}

async function decryptItem(vaultKey, itemId, keyVersion, blob) {
  const itemKey = await hkdfKey(vaultKey, fromB64(blob.kdf.salt), blob.kdf.info, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: fromB64(blob.nonce),
      additionalData: itemAad(itemId, keyVersion),
      tagLength: 128,
    },
    itemKey,
    fromB64(blob.ciphertext),
  );
  return JSON.parse(TD.decode(plaintext));
}

/** Cliente HTTP con tarro de cookies, al estilo del navegador. */
function makeClient() {
  const jar = new Map();
  return {
    jar,
    csrf() {
      return jar.get('__Host-sk_csrf') ?? '';
    },
    async fetch(method, path, body, { withCsrf = true } = {}) {
      const headers = {};
      if (body !== undefined) headers['content-type'] = 'application/json';
      if (withCsrf && method !== 'GET') headers['x-csrf-token'] = this.csrf();
      if (jar.size > 0) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

      const res = await fetch(`${BASE}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      for (const raw of res.headers.getSetCookie?.() ?? []) {
        const pair = raw.split(';')[0];
        const eq = pair.indexOf('=');
        const name = pair.slice(0, eq);
        const value = pair.slice(eq + 1);
        if (value === '') jar.delete(name);
        else jar.set(name, value);
      }
      const text = await res.text();
      return { status: res.status, body: text.length > 0 ? JSON.parse(text) : null };
    },
  };
}

/** Registra una cuenta nueva y devuelve todo lo necesario para seguir. */
async function register(client, email, masterPassword) {
  const pre = await client.fetch('POST', '/auth/prelogin', { email });
  const masterKey = await deriveMasterKey(masterPassword, email, pre.body.kdf);
  const salt = await kdfSalt(email);
  const kek = await hkdfKey(masterKey, salt, KEK_INFO, ['encrypt', 'decrypt']);
  const authKey = await hkdfBits(masterKey, salt, AUTH_INFO, 32);
  const vaultKey = crypto.getRandomValues(new Uint8Array(PROTOCOL.KEY_BYTES));
  const wrapped = await wrapVaultKey(vaultKey, kek, email, 1);
  const res = await client.fetch('POST', '/auth/register', {
    email,
    authKey: toB64(authKey),
    vault: wrapped,
    kdf: pre.body.kdf,
    // Solo se incluye si hay secreto. Con `REGISTRATION_MODE=open` sobra (el
    // esquema lo acepta) y con `invite` es lo que abre la puerta.
    ...(INVITE_SECRET === undefined ? {} : { inviteCode: issueInviteCode(email) }),
  });

  if (res.status === 401 && INVITE_SECRET === undefined) {
    bail(
      '  >>> 401 en el REGISTRO: INVITE_SECRET no esta definido en el entorno.\n' +
        '  >>> El registro esta cerrado por invitacion (REGISTRATION_MODE=invite).\n' +
        '  >>> Pasa el secreto del .env:  npm run test:e2e',
    );
  }

  // Este script crea 3 cuentas, asi que necesita un limite de registro de al
  // menos 3. En produccion el limite es 2 (a proposito: frena los registros
  // automatizados), y en la VPS este script no se ejecuta. En local hay que
  // subirlo o el 429 llega aqui.
  //
  // Sin este aviso, el 429 se manifestaria como cinco fallos en cascada (sesion
  // no creada, IDOR que no se puede comprobar) que no dicen nada del motivo.
  if (res.status === 429) {
    bail(
      '  >>> 429 en el REGISTRO: el limite de registros por IP esta agotado.\n' +
        '  >>> Este script crea 3 cuentas y necesita un limite de al menos 3.\n' +
        '  >>> El limite esta funcionando; no es un fallo del producto.\n' +
        '  >>> Para el entorno local: RATE_LIMIT_REGISTER_MAX=5 en el .env, y\n' +
        '  >>> luego  docker compose up -d  (el contador vive en memoria del\n' +
        '  >>> proceso, asi que reiniciar el contenedor tambien lo pone a cero).',
    );
  }

  return { pre, masterKey, kek, authKey, vaultKey, wrapped, res };
}

// --------------------------------------------------------------------------

async function main() {
  const stamp = Date.now();
  const emailA = `alice+${stamp}@example.test`;
  const emailB = `mallory+${stamp}@example.test`;
  const masterA = 'L0nga-Contrasena-Maestra-de-Prueba!';
  const masterB = 'Otra-Contrasena-Distinta-de-Prueba!';

  const SECRET_TITLE = `banco-${stamp}-titulo-secreto`;
  const SECRET_USER = `usuario.secreto.${stamp}@ejemplo.test`;
  const SECRET_PASS = `Sup3rS3cr3t-P@ssw0rd-${stamp}`;

  console.log('\n1. Registro y parametros KDF');
  const a = makeClient();
  const pre = await a.fetch('POST', '/auth/prelogin', { email: emailA });
  check('prelogin devuelve parametros KDF', pre.status === 200 && pre.body.kdf.alg === 'argon2id');
  check('prelogin informa que la cuenta no existe', pre.body.exists === false);
  check(
    'los parametros KDF cumplen el minimo de OWASP (19 MiB, t=2)',
    pre.body.kdf.m >= 19456 && pre.body.kdf.t >= 2,
    JSON.stringify(pre.body.kdf),
  );

  const regA = await register(a, emailA, masterA);
  check('registro aceptado', regA.res.status === 201, `status ${regA.res.status}`);
  check('registro abre sesion', a.jar.has('__Host-sk_session'));
  check('registro publica el token CSRF', a.jar.has('__Host-sk_csrf'));

  console.log('\n2. Sesion y CSRF');
  const session = await a.fetch('GET', '/session');
  check('GET /session reconoce la sesion', session.body?.authenticated === true);

  // Cliente aparte: al fallar el CSRF el servidor CIERRA la sesion (limpia
  // ambas cookies), asi que probarlo con el cliente principal nos dejaria sin
  // sesion para el resto del flujo. Ese es el comportamiento correcto.
  const probe = makeClient();
  const probeReg = await register(probe, `probe+${stamp}@example.test`, masterA);
  check('sesion de sondeo establecida', probeReg.res.status === 201);

  const sinCsrf = await probe.fetch(
    'POST',
    '/items',
    { id: newId(), blob: {} },
    { withCsrf: false },
  );
  check(
    'una peticion mutante sin token CSRF se rechaza (403)',
    sinCsrf.status === 403,
    `status ${sinCsrf.status}`,
  );
  check(
    'el rechazo por CSRF ademas invalida la sesion',
    probe.jar.get('__Host-sk_session') === undefined,
  );

  console.log('\n3. Alta de credencial cifrada');
  const itemId = newId();
  const blob = await encryptItem(regA.vaultKey, itemId, 1, {
    title: SECRET_TITLE,
    username: SECRET_USER,
    password: SECRET_PASS,
    url: 'https://banco.example.test',
    notes: 'nota secreta',
    favorite: false,
    strength: 4,
    updatedAt: new Date().toISOString(),
  });

  const created = await a.fetch('POST', '/items', { id: itemId, blob });
  check('item creado', created.status === 201, `status ${created.status} ${JSON.stringify(created.body)}`);

  const list = await a.fetch('GET', '/items');
  check('el listado devuelve 1 item', list.body?.items?.length === 1);

  const raw = JSON.stringify(list.body);
  check('el titulo NO aparece en la respuesta del servidor', !raw.includes(SECRET_TITLE));
  check('el usuario NO aparece en la respuesta del servidor', !raw.includes(SECRET_USER));
  check('la contrasena NO aparece en la respuesta del servidor', !raw.includes(SECRET_PASS));

  const roundTrip = await decryptItem(regA.vaultKey, itemId, 1, list.body.items[0].blob);
  check('el navegador si recupera su propio texto', roundTrip.password === SECRET_PASS);
  check(
    'round-trip conserva todos los campos',
    roundTrip.title === SECRET_TITLE && roundTrip.username === SECRET_USER && roundTrip.url !== '',
  );

  console.log('\n4. Aislamiento entre usuarios (IDOR)');
  const b = makeClient();
  const regB = await register(b, emailB, masterB);
  check('segundo usuario registrado', regB.res.status === 201);

  const steal = await b.fetch('GET', `/items/${itemId}`);
  check('el item de Alice es invisible para Mallory (404)', steal.status === 404, `status ${steal.status}`);

  const stealWrite = await b.fetch('PUT', `/items/${itemId}`, { blob, version: 1 });
  check('no puede escribir sobre el item de Alice (404)', stealWrite.status === 404, `status ${stealWrite.status}`);

  const stealDelete = await b.fetch('DELETE', `/items/${itemId}`);
  check('no puede borrar el item de Alice (404)', stealDelete.status === 404);

  const listB = await b.fetch('GET', '/items');
  check('la boveda de Mallory esta vacia', listB.body?.items?.length === 0);

  console.log('\n5. Verificacion de la contrasena maestra');
  const badMaster = await deriveMasterKey('Contrasena-Incorrecta', emailA, regA.pre.body.kdf);
  const badAuthKey = await hkdfBits(badMaster, await kdfSalt(emailA), AUTH_INFO, 32);
  const c = makeClient();
  const badLogin = await c.fetch('POST', '/auth/login', {
    email: emailA,
    authKey: toB64(badAuthKey),
    kdfVersion: regA.pre.body.kdf.version,
  });
  check('login con contrasena maestra incorrecta -> 401', badLogin.status === 401, `status ${badLogin.status}`);

  const goodLogin = await c.fetch('POST', '/auth/login', {
    email: emailA,
    authKey: toB64(regA.authKey),
    kdfVersion: regA.pre.body.kdf.version,
  });
  check('login correcto -> 200 con la boveda envuelta', goodLogin.status === 200 && goodLogin.body.vault !== null);

  const rewrapped = await unwrapVaultKey(
    goodLogin.body.vault,
    regA.kek,
    emailA,
    goodLogin.body.keyVersion,
  );
  check(
    'la vaultKey envuelta sigue siendo la misma tras el login',
    Buffer.from(rewrapped).equals(Buffer.from(regA.vaultKey)),
  );
  check('key_version no se mueve al re-envolver la boveda', goodLogin.body.keyVersion === 1);

  console.log('\n6. El AAD ata cada ciphertext a su fila');
  let otroIdRechazado = false;
  try {
    await decryptItem(regA.vaultKey, newId(), 1, blob);
  } catch {
    otroIdRechazado = true;
  }
  check('el ciphertext movido a otro itemId no descifra', otroIdRechazado);

  let otraVersionRechazada = false;
  try {
    await decryptItem(regA.vaultKey, itemId, 2, blob);
  } catch {
    otraVersionRechazada = true;
  }
  check('cambiar la version de clave invalida el descifrado', otraVersionRechazada);

  let otraClaveRechazada = false;
  try {
    await decryptItem(crypto.getRandomValues(new Uint8Array(32)), itemId, 1, blob);
  } catch {
    otraClaveRechazada = true;
  }
  check('otra vaultKey no descifra', otraClaveRechazada);

  let alteradoRechazado = false;
  const alterado = { ...blob, ciphertext: `${blob.ciphertext.slice(0, -4)}AAAA` };
  try {
    await decryptItem(regA.vaultKey, itemId, 1, alterado);
  } catch {
    alteradoRechazado = true;
  }
  check('un byte alterado rompe la autenticacion AEAD', alteradoRechazado);

  console.log('\n7. Versionado optimista');
  const v1 = created.body.version;
  const update1 = await a.fetch('PUT', `/items/${itemId}`, { blob, version: v1 });
  check('actualizacion con la version correcta', update1.status === 200 && update1.body.version === v1 + 1);
  const update2 = await a.fetch('PUT', `/items/${itemId}`, { blob, version: v1 });
  check('actualizacion con version obsoleta -> 409', update2.status === 409, `status ${update2.status}`);

  console.log('\n8. Validacion de entrada y cierre de sesion');
  const idInvalido = await a.fetch('GET', '/items/no-es-un-uuid');
  check('un id que no es UUID da 404, no 500', idInvalido.status === 404, `status ${idInvalido.status}`);

  const out = await a.fetch('POST', '/auth/logout');
  check('logout aceptado', out.status === 200);
  const afterLogout = await a.fetch('GET', '/items');
  check('tras logout la sesion ya no vale (401)', afterLogout.status === 401, `status ${afterLogout.status}`);

  console.log(`\n=== ${passed} correctos, ${failed} fallidos ===`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error('Error inesperado en la prueba e2e:', error);
  process.exit(1);
});
