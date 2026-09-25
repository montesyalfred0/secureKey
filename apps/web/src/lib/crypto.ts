/**
 * Criptografia del CLIENTE. Este modulo es el corazon de SecureKey.
 *
 * El servidor nunca ve nada de lo que hay aqui: ni la contrasena maestra, ni
 * la KEK, ni la clave de boveda, ni el texto claro de una credencial. Solo
 * recibe dos cosas: un `authKey` derivado (para verificar) y blobs AEAD.
 *
 * Cadena de derivacion:
 *
 *   masterKey = Argon2id(password, salt = SHA-256(email), m, t, p)     32 B
 *   KEK       = HKDF-SHA256(masterKey, salt, info="securekey/v1/kek")  32 B
 *   authKey   = HKDF-SHA256(masterKey, salt, info="securekey/v1/auth") 32 B
 *   vaultKey  = 32 B aleatorios            <- NO se deriva de la password
 *   wrap      = AES-256-GCM(KEK, vaultKey, nonce, aad = email|keyVersion)
 *
 *   itemKey   = HKDF-SHA256(vaultKey, salt_aleatorio, info por item)
 *   item      = AES-256-GCM(itemKey, JSON plano, nonce, aad = itemId|keyVersion)
 *
 * Todo lo de abajo usa `window.crypto` (WebCrypto) salvo Argon2id, que es WASM
 * (`hash-wasm`). La unica dependencia criptografica del bundle.
 */
import { argon2id } from 'hash-wasm';
import {
  PROTOCOL,
  type ItemBlob,
  type ItemKdf,
  type KdfParams,
  type WrappedKey,
} from '@securekey/shared';

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

// ---------------------------------------------------------------------------
// Utilidades de codificacion
// ---------------------------------------------------------------------------

/** CSPRNG del navegador. `Math.random()` no sirve para nada criptografico. */
export function randomBytes(length: number): Uint8Array {
  if (length < 0 || length > 65_536) throw new RangeError('longitud invalida');
  return crypto.getRandomValues(new Uint8Array(length));
}

export function toB64(bytes: Uint8Array): string {
  let binary = '';
  // Por bloques: `String.fromCharCode(...bytes)` revienta la pila con
  // volumenes grandes y nunca es mas rapido que esto.
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export function fromB64(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Copia exacta a un ArrayBuffer. `subarray` comparte el `ArrayBuffer`
 * subyacente, y pasar un buffer con bytes de mas a WebCrypto seria un fallo
 * de memoria silencioso.
 */
function exact(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', exact(data)));
}

export function wipe(bytes: Uint8Array | null | undefined): void {
  if (bytes) bytes.fill(0);
}

// ---------------------------------------------------------------------------
// Derivacion
// ---------------------------------------------------------------------------

/**
 * Salt determinista derivado del email normalizado.
 *
 * No es aleatorio a proposito: el servidor lo necesita para devolver los
 * MISMOS parametros KDF en cada prelogin, y el usuario necesita que la misma
 * contrasena-maestra + email produzcan siempre la misma clave. La aleatoriedad
 * ya la aporta Argon2id, cuyo salt se usa ademas como "semilla" del HKDF.
 */
async function kdfSalt(email: string): Promise<Uint8Array> {
  return sha256(te.encode(email.trim().toLowerCase()));
}

export async function deriveMasterKey(
  password: string,
  email: string,
  kdf: KdfParams,
): Promise<Uint8Array> {
  // NFC: dos tecleados visualmente identicos desde moviles distintos pueden
  // llegar en NFC o NFD. Normalizamos para que la clave sea siempre la misma.
  const normalized = password.normalize('NFC');
  if (normalized.length === 0) throw new Error('La contrasena maestra no puede estar vacia');

  const raw = await argon2id({
    password: te.encode(normalized),
    salt: await kdfSalt(email),
    parallelism: kdf.p,
    iterations: kdf.t,
    memorySize: kdf.m,
    hashLength: PROTOCOL.KEY_BYTES,
    outputType: 'binary',
  });
  return new Uint8Array(raw);
}

/** Deriva HKDF-SHA256 -> clave AES-256-GCM. */
async function hkdfAesKey(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', exact(ikm), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: exact(salt), info: te.encode(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

async function hkdfBits(ikm: Uint8Array, salt: Uint8Array, info: string, bytes: number) {
  const base = await crypto.subtle.importKey('raw', exact(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: exact(salt), info: te.encode(info) },
    base,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

export type AccountKeys = {
  /** Clave que envuelve la clave de boveda. */
  kek: CryptoKey;
  /** Verificador que viaja al servidor. */
  authKey: Uint8Array;
  kekInfo: string;
};

export async function deriveAccountKeys(masterKey: Uint8Array, email: string): Promise<AccountKeys> {
  const salt = await kdfSalt(email);
  const kek = await hkdfAesKey(masterKey, salt, PROTOCOL.KEK_INFO, ['encrypt', 'decrypt']);
  const authKey = await hkdfBits(masterKey, salt, PROTOCOL.AUTH_INFO, PROTOCOL.KEY_BYTES);
  return { kek, authKey, kekInfo: PROTOCOL.KEK_INFO };
}

// ---------------------------------------------------------------------------
// Envelope de la boveda
// ---------------------------------------------------------------------------

/** Datos autenticados: atan el ciphertext a la cuenta y a la version. */
function vaultAad(email: string, keyVersion: number): Uint8Array {
  return te.encode(`securekey/v${PROTOCOL.version}:vault:${email.trim().toLowerCase()}:key:${keyVersion}`);
}

export function generateVaultKey(): Uint8Array {
  return randomBytes(PROTOCOL.KEY_BYTES);
}

export async function wrapVaultKey(
  vaultKey: Uint8Array,
  kek: CryptoKey,
  email: string,
  keyVersion: number,
): Promise<WrappedKey> {
  const nonce = randomBytes(PROTOCOL.NONCE_BYTES);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: exact(nonce),
      additionalData: exact(vaultAad(email, keyVersion)),
      tagLength: 128,
    },
    kek,
    exact(vaultKey),
  );
  return {
    alg: 'AES-256-GCM',
    nonce: toB64(nonce),
    ciphertext: toB64(new Uint8Array(ciphertext)),
  };
}

export async function unwrapVaultKey(
  wrapped: WrappedKey,
  kek: CryptoKey,
  email: string,
  keyVersion: number,
): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: exact(fromB64(wrapped.nonce)),
      additionalData: exact(vaultAad(email, keyVersion)),
      tagLength: 128,
    },
    kek,
    exact(fromB64(wrapped.ciphertext)),
  );
  const key = new Uint8Array(plaintext);
  if (key.length !== PROTOCOL.KEY_BYTES) {
    wipe(key);
    throw new Error('La clave de boveda tiene un tamano inesperado');
  }
  return key;
}

// ---------------------------------------------------------------------------
// Items de la boveda
// ---------------------------------------------------------------------------

/** Contenido en claro de un item. Nunca sale de esta funcion. */
export type ItemPlain = {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  favorite: boolean;
  /** Score 0-4 calculado en el cliente, para la vista de salud. */
  strength: number;
  updatedAt: string;
};

export function emptyItem(): ItemPlain {
  return {
    title: '',
    username: '',
    password: '',
    url: '',
    notes: '',
    favorite: false,
    strength: -1,
    updatedAt: new Date().toISOString(),
  };
}

/** AAD por item: ata el ciphertext a su id y a la version de la boveda. */
function itemAad(itemId: string, keyVersion: number): Uint8Array {
  return te.encode(`securekey/v${PROTOCOL.version}:item:${itemId}:key:${keyVersion}`);
}

function itemInfo(keyVersion: number): string {
  return `${PROTOCOL.ITEM_INFO_PREFIX}${keyVersion}`;
}

/** El blob viene de la base de datos: su `info` debe ser el que esperamos. */
function assertItemKdf(kdf: ItemKdf, keyVersion: number): void {
  if (kdf.alg !== 'HKDF-SHA256') throw new Error(`Algoritmo de derivacion no soportado: ${kdf.alg}`);
  if (!kdf.info.startsWith(PROTOCOL.ITEM_INFO_PREFIX)) {
    throw new Error('Origen de derivacion de clave no reconocido');
  }
  const fromBlob = kdf.info.slice(PROTOCOL.ITEM_INFO_PREFIX.length);
  if (fromBlob !== String(keyVersion)) {
    throw new Error('El item fue cifrado con otra version de clave');
  }
}

export async function encryptItem(
  vaultKey: Uint8Array,
  itemId: string,
  keyVersion: number,
  plain: ItemPlain,
): Promise<ItemBlob> {
  const salt = randomBytes(PROTOCOL.ITEM_SALT_BYTES);
  const info = itemInfo(keyVersion);
  const itemKey = await hkdfAesKey(vaultKey, salt, info, ['encrypt']);
  const nonce = randomBytes(PROTOCOL.NONCE_BYTES);

  const plaintext = te.encode(
    JSON.stringify({ ...plain, updatedAt: new Date().toISOString() }),
  );
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: exact(nonce),
      additionalData: exact(itemAad(itemId, keyVersion)),
      tagLength: 128,
    },
    itemKey,
    plaintext,
  );

  return {
    alg: 'AES-256-GCM',
    kdf: { alg: 'HKDF-SHA256', salt: toB64(salt), info },
    nonce: toB64(nonce),
    ciphertext: toB64(new Uint8Array(ciphertext)),
  };
}

export async function decryptItem(
  vaultKey: Uint8Array,
  itemId: string,
  keyVersion: number,
  blob: ItemBlob,
): Promise<ItemPlain> {
  assertItemKdf(blob.kdf, keyVersion);
  const itemKey = await hkdfAesKey(vaultKey, fromB64(blob.kdf.salt), blob.kdf.info, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: exact(fromB64(blob.nonce)),
      additionalData: exact(itemAad(itemId, keyVersion)),
      tagLength: 128,
    },
    itemKey,
    exact(fromB64(blob.ciphertext)),
  );

  const parsed: unknown = JSON.parse(td.decode(plaintext));
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('El contenido descifrado no tiene el formato esperado');
  }
  const value = parsed as Record<string, unknown>;
  const str = (key: string, fallback = ''): string =>
    typeof value[key] === 'string' ? (value[key] as string) : fallback;

  return {
    title: str('title'),
    username: str('username'),
    password: str('password'),
    url: str('url'),
    notes: str('notes'),
    favorite: value['favorite'] === true,
    strength: typeof value['strength'] === 'number' ? (value['strength'] as number) : -1,
    updatedAt: str('updatedAt'),
  };
}

// ---------------------------------------------------------------------------
// Verificacion de disponibilidad de WebCrypto
// ---------------------------------------------------------------------------

/**
 * `crypto.subtle` solo existe en un contexto seguro (HTTPS o localhost).
 * Sin esto, la app fallaria con un error incomprensible en redes distintas.
 */
export function cryptoAvailable(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
}
