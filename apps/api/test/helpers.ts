/**
 * Utilidades compartidas por los tests de la API.
 *
 * Lo importante aqui es el `makeClient`: las cookies de sesion y CSRF viajan en
 * cabeceras `set-cookie`, y `app.inject()` no mantiene un almacen de cookies
 * como haria un navegador. Sin un jar que reenvie las cookies, todos los tests
 * de autenticacion darian verde por el motivo equivocado.
 */
import type { FastifyInstance, InjectOptions } from 'fastify';
import type { PoolClient } from 'pg';
import { buildApp } from '../src/app.js';
import { loadConfig, resetConfigCache, type Config } from '../src/config.js';
import { ensureApiRole, runMigrations } from '../src/db/migrations.js';
import { closeAllPools, createPool } from '../src/db/pool.js';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scrypt as scryptCb,
} from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb) as (
  password: string | Buffer,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

export const CSRF_COOKIE = '__Host-sk_csrf';
export const SESSION_COOKIE = '__Host-sk_session';

const DEFAULT_DATABASE_URL = 'postgres://securekey:securekey@localhost:5432/securekey_test';
const DEFAULT_APP_URL =
  'postgres://securekey_api:securekey_test_app@localhost:5432/securekey_test';

/**
 * Pepper fijo y solo de test. Determinismo: si fuese aleatorio, dos
 * ejecuciones compararian hashes distintos y el diagnostico seria inutil.
 */
export const TEST_PEPPER = 'pepper-de-pruebas-securekey-0123456789abcdef';

export function testConfig(overrides: Record<string, string | undefined> = {}): Config {
  resetConfigCache();
  const base: Record<string, string | undefined> = {
    NODE_ENV: 'test',
    LOG_LEVEL: 'fatal',
    APP_ORIGIN: 'https://localhost:8443',
    ALLOWED_ORIGINS: 'https://localhost:8443',
    AUTH_PEPPER: TEST_PEPPER,
    // La app bajo prueba entra con el rol RESTRINGIDO, igual que en
    // produccion. Es deliberado: si los tests usaran el superusuario, no
    // detectarian que alguna consulta suya depende de privilegios que ya no
    // tiene, que es exactamente el fallo que introduce este cambio.
    DATABASE_URL: process.env.DATABASE_APP_URL ?? DEFAULT_APP_URL,
    DATABASE_APP_PASSWORD: process.env.DATABASE_APP_PASSWORD ?? 'securekey_test_app',
    // Canal de administracion para el TRUNCATE entre tests. Separate del de la
    // app a proposito: truncar exige superusuario, y no se quiere que la app
    // lo tenga.
    DATABASE_ADMIN_URL: process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL,
    // La suite completa hace cientos de peticiones en segundos. Con los
    // limites de produccion (5 registros por hora, 10 logins por minuto) el
    // rate limiting se comeria los tests. Los limites tienen su propio test
    // dedicado, con una app y un umbral propios.
    RATE_LIMIT_GLOBAL_MAX: '1000000',
    RATE_LIMIT_PRELOGIN_MAX: '1000000',
    RATE_LIMIT_REGISTER_MAX: '1000000',
    RATE_LIMIT_LOGIN_MAX: '1000000',
  };
  const merged: Record<string, string | undefined> = { ...base, ...process.env, ...overrides };
  return loadConfig(merged as NodeJS.ProcessEnv);
}

/** Aplica las migraciones y crea el rol restringido. */
export async function migrateDatabase(config: Config): Promise<void> {
  await runMigrations(config);
  await ensureApiRole(config.databaseAdminUrl, config.databaseAppPassword);
}

/**
 * Vacia todas las tablas entre tests.
 *
 * Usa el canal de administracion, no el de la app: `TRUNCATE` es DDL y exige
 * superusuario. Que la app no pueda hacerlo tambien es lo que se quiere.
 */
export async function resetDatabase(_config: Config): Promise<void> {
  // OJO: `DATABASE_ADMIN_URL`, no `DATABASE_URL`. En el contenedor de test
  // `DATABASE_URL` es la del rol restringido (a proposito, para que la app bajo
  // prueba use el mismo camino que produccion), y `TRUNCATE` es DDL: con ese
  // rol falla con "permission denied for table users".
  const adminUrl = process.env['DATABASE_ADMIN_URL'] ?? DEFAULT_DATABASE_URL;
  const client = createPool(adminUrl);
  try {
    await client.query('TRUNCATE users, items, sessions, audit_log RESTART IDENTITY CASCADE');
  } finally {
    await client.end();
  }
}

export async function closeDatabase(): Promise<void> {
  await closeAllPools();
}

/**
 * Transaccion por el canal de ADMINISTRACION, para los tests que necesitan
 * INSPECCIONAR la base en vez de usarla como lo haria la app.
 *
 * Hace falta porque la app entra con el rol restringido y la RLS hides todo lo
 * que no sea suyo: un test que consulta `users` a traves de `withSystem` ve
 * cero filas, que no es un fallo de la app sino el aislamiento funcionando.
 * Un test de la boveda SIEMPRE debe pasar por la API, que es el unico camino
 * real; para mirar debajo de la映画 esta via.
 */
export async function withAdmin<T>(
  _config: Config,
  fn: (tx: PoolClient) => Promise<T>,
): Promise<T> {
  const adminUrl = process.env['DATABASE_ADMIN_URL'] ?? DEFAULT_DATABASE_URL;
  const pool = createPool(adminUrl);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

export type TestApp = { app: FastifyInstance; config: Config };

export async function createTestApp(overrides: Record<string, string | undefined> = {}): Promise<TestApp> {
  const config = testConfig(overrides);
  await migrateDatabase(config);
  const app = await buildApp(config);
  await app.ready();
  return { app, config };
}

// ---------------------------------------------------------------------------
// Cliente con jar de cookies
// ---------------------------------------------------------------------------

type Reply = Awaited<ReturnType<FastifyInstance['inject']>>;

export type TestClient = {
  /** Jar actual, por si un test necesita inspeccionarlo. */
  cookies: Map<string, string>;
  get(url: string, headers?: Record<string, string>): Promise<Reply>;
  post(url: string, payload?: unknown, headers?: Record<string, string>): Promise<Reply>;
  put(url: string, payload?: unknown, headers?: Record<string, string>): Promise<Reply>;
  delete(url: string, headers?: Record<string, string>): Promise<Reply>;
  /** Peticion cruda: para los casos donde hay que romper el contrato a proposito. */
  raw(options: InjectOptions): Promise<Reply>;
};

/** Absorbe las `set-cookie` de una respuesta, respetando el borrado (Max-Age=0). */
function absorbCookies(setCookie: string | string[] | undefined, jar: Map<string, string>): void {
  if (setCookie === undefined) return;
  const lines = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const line of lines) {
    const [pair = '', ...attrs] = line.split(';').map((part) => part.trim());
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const name = pair.slice(0, eq);
    const value = pair.slice(eq + 1);
    const cleared = attrs.some((a) => /^max-age=0$/i.test(a));
    if (cleared || value.length === 0) jar.delete(name);
    else jar.set(name, value);
  }
}

export function makeClient(app: FastifyInstance): TestClient {
  const jar = new Map<string, string>();

  async function call(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    url: string,
    payload?: unknown,
    headers: Record<string, string> = {},
  ): Promise<Reply> {
    const merged: Record<string, string> = { ...headers };
    if (jar.size > 0) {
      merged.cookie = [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
    }
    if (payload !== undefined) merged['content-type'] = 'application/json';
    // Doble envio de CSRF: el servidor compara la cabecera con el hash guardado.
    if (method !== 'GET') {
      const csrf = jar.get(CSRF_COOKIE);
      if (csrf !== undefined && merged['x-csrf-token'] === undefined) {
        merged['x-csrf-token'] = csrf;
      }
    }

    const options: InjectOptions = { method, url, headers: merged };
    if (payload !== undefined) options.payload = JSON.stringify(payload);

    const reply = await app.inject(options);
    absorbCookies(reply.headers['set-cookie'], jar);
    return reply;
  }

  return {
    cookies: jar,
    get: (url, headers) => call('GET', url, undefined, headers),
    post: (url, payload, headers) => call('POST', url, payload, headers),
    put: (url, payload, headers) => call('PUT', url, payload, headers),
    delete: (url, headers) => call('DELETE', url, undefined, headers),
    raw: async (options) => {
      const reply = await app.inject(options);
      absorbCookies(reply.headers['set-cookie'], jar);
      return reply;
    },
  };
}

// ---------------------------------------------------------------------------
// Criptografia de cliente replicada para los tests
// ---------------------------------------------------------------------------

/**
 * El servidor nunca ve la contrasena maestra, asi que los tests de integracion
 * tienen que fabricar las mismas claves que fabrica el navegador. Aqui se
 * replica la cadena real (`apps/web/src/lib/crypto.ts`): mismo salt, mismo
 * HKDF, mismos AAD. Si un dia cambia el formato, estos helpers se rompen y lo
 * dicen, que es justo lo que queremos.
 *
 * La UNICA excepcion es el primer salto: el cliente usa Argon2id (WASM) y
 * `node:crypto` no lo trae. Se usa scrypt con el mismo perfil de coste. Da
 * igual, porque la API trata el `authKey` como 32 bytes opacos: lo que se
 * comprueba aqui es el camino de verificacion, no la funcion de derivacion
 * (esa ya la cubren los 56 tests de `apps/web/test/crypto.test.ts`).
 */
export type TestAccount = {
  email: string;
  authKey: string;
  masterKey: Buffer;
  kek: Buffer;
  vaultKey: Buffer;
  /** `vault` tal y como lo espera el cuerpo del registro. */
  wrappedVault: { alg: 'AES-256-GCM'; nonce: string; ciphertext: string };
};

function hmac(algo: string, key: Buffer | string, data: Buffer | string): Buffer {
  return createHmac(algo, key).update(data).digest();
}

/** HKDF-SHA256 completo (extract + expand). La longitud de salida es 32 B. */
function hkdf(ikm: Buffer, salt: Buffer, info: string, bytes = 32): Buffer {
  const prk = hmac('sha256', salt, ikm);
  const out: Buffer[] = [];
  let previous: Buffer = Buffer.alloc(0);
  let counter = 1;
  let total = 0;
  while (total < bytes) {
    previous = hmac('sha256', prk, Buffer.concat([previous, Buffer.from(info, 'utf8'), Buffer.from([counter])]));
    out.push(previous);
    total += previous.length;
    counter += 1;
  }
  return Buffer.concat(out).subarray(0, bytes);
}

/** Mismo salt que el cliente: SHA-256 del email normalizado. */
function kdfSalt(email: string): Buffer {
  return createHash('sha256').update(email.trim().toLowerCase(), 'utf8').digest();
}

/** `securekey:v1:item:{id}:key:{keyVersion}` */
function itemAad(itemId: string, keyVersion: number): Buffer {
  return Buffer.from(`securekey:v1:item:${itemId}:key:${keyVersion}`, 'utf8');
}

/** `securekey:v1:vault:{email}:key:{keyVersion}` */
function vaultAad(email: string, keyVersion: number): Buffer {
  return Buffer.from(`securekey:v1:vault:${email.trim().toLowerCase()}:key:${keyVersion}`, 'utf8');
}

async function gcmEncrypt(
  key: Buffer,
  aad: Buffer,
  plaintext: Buffer,
): Promise<{ nonce: Buffer; ciphertext: Buffer }> {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce, ciphertext: Buffer.concat([body, cipher.getAuthTag()]) };
}

let accountCounter = 0;

/** Crea una cuenta completa: claves derivadas y vaultKey envuelta. */
export async function makeAccount(
  email = `user-${Date.now()}-${accountCounter++}@example.test`,
  password = 'contrasena-maestra-de-prueba',
): Promise<TestAccount> {
  const normalized = email.trim().toLowerCase();
  const masterKey = await scrypt(password, kdfSalt(normalized), 32, {
    N: 1 << 14,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  const salt = kdfSalt(normalized);
  const kek = hkdf(masterKey, salt, 'securekey/v1/kek');
  const authKey = hkdf(masterKey, salt, 'securekey/v1/auth');
  const vaultKey = randomBytes(32);

  const { nonce, ciphertext } = await gcmEncrypt(kek, vaultAad(normalized, 1), vaultKey);

  return {
    email: normalized,
    authKey: authKey.toString('base64'),
    masterKey,
    kek,
    vaultKey,
    wrappedVault: {
      alg: 'AES-256-GCM',
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    },
  };
}

/** Cuerpo de registro listo para `/auth/register`. */
export function registerPayload(account: TestAccount, kdfVersion = 1, inviteCode?: string) {
  return {
    email: account.email,
    authKey: account.authKey,
    vault: account.wrappedVault,
    kdf: { alg: 'argon2id' as const, m: 19_456, t: 2, p: 1, version: kdfVersion },
    ...(inviteCode !== undefined ? { inviteCode } : {}),
  };
}

export type TestItemBlob = {
  alg: 'AES-256-GCM';
  kdf: { alg: 'HKDF-SHA256'; salt: string; info: string };
  nonce: string;
  ciphertext: string;
};

/** Cifra un item con la misma forma que usa el cliente real. */
export async function makeItemBlob(
  vaultKey: Buffer,
  id: string,
  keyVersion = 1,
  plain: Record<string, unknown> = { title: 'Prueba' },
): Promise<TestItemBlob> {
  const salt = randomBytes(16);
  const info = `securekey/v1/item/${keyVersion}`;
  const itemKey = hkdf(vaultKey, salt, info);
  const { nonce, ciphertext } = await gcmEncrypt(itemKey, itemAad(id, keyVersion), Buffer.from(JSON.stringify(plain), 'utf8'));
  return {
    alg: 'AES-256-GCM',
    kdf: { alg: 'HKDF-SHA256', salt: salt.toString('base64'), info },
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

/** Longitud del tag de autenticacion de AES-GCM (16 bytes, 128 bits). */
const GCM_TAG_BYTES = 16;

/** Descifra un blob de item. Sirve para comprobar que el servidor no lo toco. */
export async function openItemBlob(
  vaultKey: Buffer,
  id: string,
  keyVersion: number,
  blob: TestItemBlob,
): Promise<Record<string, unknown>> {
  const salt = Buffer.from(blob.kdf.salt, 'base64');
  const itemKey = hkdf(vaultKey, salt, blob.kdf.info);

  // WebCrypto devuelve `ciphertext || tag` en un solo valor; el API de Node
  // exige el tag aparte con `setAuthTag`. Sin separarlo, `final()` falla con
  // "Unsupported state or unable to authenticate data" aunque el blob sea
  // perfectlyamente valido.
  const raw = Buffer.from(blob.ciphertext, 'base64');
  const body = raw.subarray(0, raw.length - GCM_TAG_BYTES);
  const tag = raw.subarray(raw.length - GCM_TAG_BYTES);

  const decipher = createDecipheriv('aes-256-gcm', itemKey, Buffer.from(blob.nonce, 'base64'));
  decipher.setAAD(itemAad(id, keyVersion));
  decipher.setAuthTag(tag);

  const plain = Buffer.concat([decipher.update(body), decipher.final()]);
  return JSON.parse(plain.toString('utf8')) as Record<string, unknown>;
}
