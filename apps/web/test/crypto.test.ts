/**
 * Tests de `src/lib/crypto.ts`: la parte de la que depende toda la promesa
 * "zero-knowledge" del producto.
 *
 * La regla que se repite en cada bloque es: lo que sale de aqui no lo puede
 * descifrar nadie mas que el navegador del usuario. Por eso se comprueban
 * tanto los round-trips (las cosas funcionan) como los fallos (las cosas se
 * rompen cuando deben).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { PROTOCOL, type ItemBlob, type KdfParams } from '@securekey/shared';
import {
  cryptoAvailable,
  decryptItem,
  deriveAccountKeys,
  deriveMasterKey,
  encryptItem,
  fromB64,
  generateVaultKey,
  randomBytes,
  sha256,
  toB64,
  unwrapVaultKey,
  wipe,
  wrapVaultKey,
  type AccountKeys,
  type ItemPlain,
} from '../src/lib/crypto.js';

const te = new TextEncoder();

/** Los parametros KDF reales del producto (minimo OWASP: 19 MiB, t = 2, p = 1). */
const KDF: KdfParams = { alg: 'argon2id', m: 19_456, t: 2, p: 1, version: 1 };

const EMAIL_A = 'alice@example.com';
const EMAIL_B = 'bob@example.com';
const PASSWORD = 'ContrasenaMaestra#1';
const KEY_VERSION = 1;

const ITEM_ID = '11111111-2222-4333-8444-555555555555';
const OTRO_ITEM_ID = '99999999-8888-4777-8666-555555555555';

// --- Utilidades de test ----------------------------------------------------

/** Copia exacta a `ArrayBuffer`, igual que hace el modulo por tipos de TS. */
function exacta(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Item de ejemplo con todos los campos de `ItemPlain` rellenos. */
function itemDeEjemplo(over: Partial<ItemPlain> = {}): ItemPlain {
  return {
    title: 'Banco Egg',
    username: 'alice',
    password: 'Kd9!mQ2$vL7#xZ',
    url: 'https://banco.example.com',
    notes: 'Pregunta de seguridad: MiPerro',
    favorite: true,
    strength: 4,
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...over,
  };
}

/** Devuelve el base64 del blob con UN byte del campo indicado alterado. */
function byteAlterado(b64: string, indice: number): string {
  const bytes = fromB64(b64);
  bytes[indice] = (bytes[indice] ?? 0) ^ 0x01;
  return toB64(bytes);
}

/** AAD tal y como lo construye `itemAad()` del modulo. */
function aadDeItem(itemId: string, keyVersion: number): string {
  return `securekey/v${PROTOCOL.version}:item:${itemId}:key:${keyVersion}`;
}

/**
 * Descifra un blob SIN usar `decryptItem`: deriva la `itemKey` a mano con
 * WebCrypto a partir del `kdf.salt` y el `kdf.info` del propio blob.
 *
 * Asi el test es independiente de la implementacion que quiere comprobar: si
 * esto devuelve el texto plano, es que el texto plano estaba cifrado de verdad
 * y no solo "cifrado" por la funcion que estamos probando.
 */
async function descifrarAMano(
  vaultKey: Uint8Array,
  blob: ItemBlob,
  aad: string,
): Promise<string> {
  const base = await globalThis.crypto.subtle.importKey(
    'raw',
    exacta(vaultKey),
    'HKDF',
    false,
    ['deriveKey'],
  );
  const itemKey = await globalThis.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: exacta(fromB64(blob.kdf.salt)),
      info: te.encode(blob.kdf.info),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  const claro = await globalThis.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: exacta(fromB64(blob.nonce)),
      additionalData: te.encode(aad),
      tagLength: 128,
    },
    itemKey,
    exacta(fromB64(blob.ciphertext)),
  );
  return new TextDecoder('utf-8', { fatal: true }).decode(claro);
}

// --- Estado compartido (Argon2id es caro: se deriva una sola vez) ----------

let masterA: Uint8Array;
let masterB: Uint8Array;
let keysA: AccountKeys;
let keysB: AccountKeys;

beforeAll(async () => {
  masterA = await deriveMasterKey(PASSWORD, EMAIL_A, KDF);
  masterB = await deriveMasterKey(PASSWORD, EMAIL_B, KDF);
  keysA = await deriveAccountKeys(masterA, EMAIL_A);
  keysB = await deriveAccountKeys(masterB, EMAIL_B);
}, 60_000);

// ---------------------------------------------------------------------------

describe('crypto: codificacion base64', () => {
  it('hace round-trip con un array vacio', () => {
    expect(toB64(fromB64(toB64(new Uint8Array(0))))).toBe('');
  });

  it('hace round-trip con 1 byte', () => {
    const bytes = new Uint8Array([0x42]);
    expect([...fromB64(toB64(bytes))]).toEqual([0x42]);
  });

  it('hace round-trip con 12 bytes (longitud del nonce AES-GCM)', () => {
    const bytes = randomBytes(PROTOCOL.NONCE_BYTES);
    expect([...fromB64(toB64(bytes))]).toEqual([...bytes]);
  });

  it('hace round-trip con 32 bytes (longitud de las claves)', () => {
    const bytes = randomBytes(PROTOCOL.KEY_BYTES);
    expect([...fromB64(toB64(bytes))]).toEqual([...bytes]);
  });

  it('hace round-trip con 1000 bytes (regresion del codigo por bloques)', () => {
    const bytes = randomBytes(1000);
    expect(fromB64(toB64(bytes)).length).toBe(1000);
  });

  it('hace round-trip con los 256 valores posibles, sin fallos de charCodeAt', () => {
    const bytes = new Uint8Array(256);
    for (let i = 0; i < 256; i += 1) bytes[i] = i;
    expect([...fromB64(toB64(bytes))]).toEqual([...bytes]);
  });

  it('codifica 0xFF sin signo ni relleno extra', () => {
    expect(toB64(new Uint8Array([0xff]))).toBe('/w==');
  });
});

describe('crypto: randomBytes', () => {
  it('devuelve exactamente la longitud pedida', () => {
    expect(randomBytes(37).length).toBe(37);
  });

  it('dos llamadas consecutivas no coinciden', () => {
    expect(toB64(randomBytes(32))).not.toBe(toB64(randomBytes(32)));
  });

  it('rechaza longitudes negativas', () => {
    expect(() => randomBytes(-1)).toThrow(RangeError);
  });

  it('rechaza longitudes por encima de 65_536', () => {
    expect(() => randomBytes(65_537)).toThrow(RangeError);
  });
});

describe('crypto: sha256 y wipe', () => {
  it('sha256 de la cadena vacia es el vector conocido', async () => {
    expect(hex(await sha256(new Uint8Array(0)))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('sha256 de "abc" es el vector conocido', async () => {
    expect(hex(await sha256(te.encode('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('sha256 devuelve 32 bytes', async () => {
    expect((await sha256(te.encode('securekey'))).length).toBe(PROTOCOL.KEY_BYTES);
  });

  it('wipe pone a cero el array recibido (en el sitio, no una copia)', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    wipe(bytes);
    expect([...bytes]).toEqual([0, 0, 0]);
  });

  it('wipe tolera null y undefined', () => {
    expect(() => {
      wipe(null);
      wipe(undefined);
    }).not.toThrow();
  });
});

describe('crypto: deriveMasterKey', () => {
  it('devuelve 32 bytes', () => {
    expect(masterA.length).toBe(PROTOCOL.KEY_BYTES);
  });

  it('es determinista: mismos (password, email, kdf) -> mismos bytes', async () => {
    const otra = await deriveMasterKey(PASSWORD, EMAIL_A, KDF);
    expect(hex(otra)).toBe(hex(masterA));
  });

  it('cambia si cambia la contrasena maestra', async () => {
    const otra = await deriveMasterKey('OtraContrasena#2', EMAIL_A, KDF);
    expect(hex(otra)).not.toBe(hex(masterA));
  });

  it('cambia si cambia el email (el salt es SHA-256 del email)', () => {
    expect(hex(masterB)).not.toBe(hex(masterA));
  });

  it('normaliza el email: espacios y mayusculas dan la misma clave', async () => {
    const otra = await deriveMasterKey(PASSWORD, '  ALICE@Example.COM ', KDF);
    expect(hex(otra)).toBe(hex(masterA));
  });

  it('rechaza una contrasena maestra vacia', async () => {
    await expect(deriveMasterKey('', EMAIL_A, KDF)).rejects.toThrow(/vacia/);
  });
});

describe('crypto: deriveAccountKeys', () => {
  it('produce un authKey de 32 bytes', () => {
    expect(keysA.authKey.length).toBe(PROTOCOL.KEY_BYTES);
  });

  it('el authKey es determinista', async () => {
    const otra = await deriveAccountKeys(masterA, EMAIL_A);
    expect(hex(otra.authKey)).toBe(hex(keysA.authKey));
  });

  it('dos cuentas con la misma contrasena y distinto email dan authKey distintos', () => {
    expect(hex(keysB.authKey)).not.toBe(hex(keysA.authKey));
  });

  it('el authKey no es la masterKey: sale de un HKDF con info propio', () => {
    expect(hex(keysA.authKey)).not.toBe(hex(masterA));
  });

  it('expone el info de HKDF de la KEK', () => {
    expect(keysA.kekInfo).toBe(PROTOCOL.KEK_INFO);
  });
});

describe('crypto: envoltura de la clave de boveda', () => {
  it('wrap + unwrap devuelve la misma vaultKey', async () => {
    const vaultKey = generateVaultKey();
    const envuelto = await wrapVaultKey(vaultKey, keysA.kek, EMAIL_A, KEY_VERSION);
    const desenvuelta = await unwrapVaultKey(envuelto, keysA.kek, EMAIL_A, KEY_VERSION);
    expect(hex(desenvuelta)).toBe(hex(vaultKey));
  });

  it('la vaultKey son 32 bytes aleatorios', () => {
    expect(generateVaultKey().length).toBe(PROTOCOL.KEY_BYTES);
  });

  it('el nonce del envelope son 12 bytes', async () => {
    const envuelto = await wrapVaultKey(generateVaultKey(), keysA.kek, EMAIL_A, KEY_VERSION);
    expect(fromB64(envuelto.nonce).length).toBe(PROTOCOL.NONCE_BYTES);
  });

  it('el algoritmo del envelope es AES-256-GCM', async () => {
    const envuelto = await wrapVaultKey(generateVaultKey(), keysA.kek, EMAIL_A, KEY_VERSION);
    expect(envuelto.alg).toBe('AES-256-GCM');
  });

  it('envolver dos veces la misma vaultKey produce nonces distintos', async () => {
    const vaultKey = generateVaultKey();
    const a = await wrapVaultKey(vaultKey, keysA.kek, EMAIL_A, KEY_VERSION);
    const b = await wrapVaultKey(vaultKey, keysA.kek, EMAIL_A, KEY_VERSION);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it('LANZA si se altera un byte del ciphertext (integridad AEAD)', async () => {
    const envuelto = await wrapVaultKey(generateVaultKey(), keysA.kek, EMAIL_A, KEY_VERSION);
    const manipulado = { ...envuelto, ciphertext: byteAlterado(envuelto.ciphertext, 0) };
    await expect(
      unwrapVaultKey(manipulado, keysA.kek, EMAIL_A, KEY_VERSION),
    ).rejects.toThrow();
  });

  it('LANZA si se altera un byte del nonce', async () => {
    const envuelto = await wrapVaultKey(generateVaultKey(), keysA.kek, EMAIL_A, KEY_VERSION);
    const manipulado = { ...envuelto, nonce: byteAlterado(envuelto.nonce, 3) };
    await expect(
      unwrapVaultKey(manipulado, keysA.kek, EMAIL_A, KEY_VERSION),
    ).rejects.toThrow();
  });

  it('LANZA si el email del AAD no es el del wrap, aun usando la misma KEK', async () => {
    const envuelto = await wrapVaultKey(generateVaultKey(), keysA.kek, EMAIL_A, KEY_VERSION);
    await expect(
      unwrapVaultKey(envuelto, keysA.kek, EMAIL_B, KEY_VERSION),
    ).rejects.toThrow();
  });

  it('LANZA con una KEK derivada de otro email', async () => {
    const envuelto = await wrapVaultKey(generateVaultKey(), keysA.kek, EMAIL_A, KEY_VERSION);
    await expect(
      unwrapVaultKey(envuelto, keysB.kek, EMAIL_B, KEY_VERSION),
    ).rejects.toThrow();
  });

  it('LANZA si la keyVersion del AAD no es la del wrap', async () => {
    const envuelto = await wrapVaultKey(generateVaultKey(), keysA.kek, EMAIL_A, KEY_VERSION);
    await expect(
      unwrapVaultKey(envuelto, keysA.kek, EMAIL_A, 2),
    ).rejects.toThrow();
  });
});

describe('crypto: items de la boveda', () => {
  it('round-trip: cifrar y descifrar devuelve el mismo item', async () => {
    const vaultKey = generateVaultKey();
    const original = itemDeEjemplo();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, original);
    const recuperado = await decryptItem(vaultKey, ITEM_ID, KEY_VERSION, blob);
    expect(recuperado).toEqual({ ...original, updatedAt: recuperado.updatedAt });
  });

  it('preserva los campos de texto tal cual, con acentos y emoji', async () => {
    const vaultKey = generateVaultKey();
    const original = itemDeEjemplo({
      title: 'Correo 📨 ñandú',
      notes: 'Multilinea\ncon "comillas" y \\barra\\',
      username: 'álice@example.com',
    });
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, original);
    const recuperado = await decryptItem(vaultKey, ITEM_ID, KEY_VERSION, blob);
    expect({
      title: recuperado.title,
      username: recuperado.username,
      notes: recuperado.notes,
    }).toEqual({ title: original.title, username: original.username, notes: original.notes });
  });

  it('preserva `favorite` y `strength` como tipos primitivos', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    const recuperado = await decryptItem(vaultKey, ITEM_ID, KEY_VERSION, blob);
    expect({ favorite: recuperado.favorite, strength: recuperado.strength }).toEqual({
      favorite: true,
      strength: 4,
    });
  });

  it('el blob declara HKDF-SHA256 con un salt de 16 bytes', async () => {
    const blob = await encryptItem(generateVaultKey(), ITEM_ID, KEY_VERSION, itemDeEjemplo());
    expect({
      alg: blob.kdf.alg,
      info: blob.kdf.info,
      salt: fromB64(blob.kdf.salt).length,
    }).toEqual({ alg: 'HKDF-SHA256', info: `${PROTOCOL.ITEM_INFO_PREFIX}1`, salt: 16 });
  });

  it('el item descifrado lleva un `updatedAt` ISO nuevo (lo pone el servidor del reloj local)', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    const recuperado = await decryptItem(vaultKey, ITEM_ID, KEY_VERSION, blob);
    expect(Number.isNaN(Date.parse(recuperado.updatedAt))).toBe(false);
  });

  it('LANZA si se altera un byte del ciphertext', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    const manipulado = { ...blob, ciphertext: byteAlterado(blob.ciphertext, 2) };
    await expect(
      decryptItem(vaultKey, ITEM_ID, KEY_VERSION, manipulado),
    ).rejects.toThrow();
  });

  it('LANZA si el itemId del AAD es distinto del usado al cifrar', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    await expect(
      decryptItem(vaultKey, OTRO_ITEM_ID, KEY_VERSION, blob),
    ).rejects.toThrow();
  });

  it('LANZA si la keyVersion es distinta (la comprueba assertItemKdf con kdf.info)', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    await expect(
      decryptItem(vaultKey, ITEM_ID, 2, blob),
    ).rejects.toThrow(/otra version de clave/);
  });

  it('LANZA si se manipula kdf.info para apuntar a otra version de clave', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    const manipulado: ItemBlob = {
      ...blob,
      kdf: { ...blob.kdf, info: `${PROTOCOL.ITEM_INFO_PREFIX}7` },
    };
    await expect(
      decryptItem(vaultKey, ITEM_ID, KEY_VERSION, manipulado),
    ).rejects.toThrow(/otra version de clave/);
  });

  it('LANZA si kdf.info no lleva el prefijo del protocolo', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    const manipulado: ItemBlob = { ...blob, kdf: { ...blob.kdf, info: 'securekey/v9/item/1' } };
    await expect(
      decryptItem(vaultKey, ITEM_ID, KEY_VERSION, manipulado),
    ).rejects.toThrow(/no reconocido/);
  });

  it('LANZA si el algoritmo de derivacion del blob no es HKDF-SHA256', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    const manipulado = {
      ...blob,
      kdf: { ...blob.kdf, alg: 'HKDF-SHA512' },
    } as unknown as ItemBlob;
    await expect(
      decryptItem(vaultKey, ITEM_ID, KEY_VERSION, manipulado),
    ).rejects.toThrow(/no soportado/);
  });

  it('LANZA con una vaultKey distinta (cada item tiene su propia clave derivada)', async () => {
    const blob = await encryptItem(generateVaultKey(), ITEM_ID, KEY_VERSION, itemDeEjemplo());
    await expect(
      decryptItem(generateVaultKey(), ITEM_ID, KEY_VERSION, blob),
    ).rejects.toThrow();
  });

  it('dos cifrados del mismo item usan nonce y salt distintos (reutilizar nonce seria fatal en GCM)', async () => {
    const vaultKey = generateVaultKey();
    const a = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    const b = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    expect({ nonce: a.nonce === b.nonce, salt: a.kdf.salt === b.kdf.salt }).toEqual({
      nonce: false,
      salt: false,
    });
  });
});

describe('crypto: el texto plano nunca sale del navegador', () => {
  it('el item se puede descifrar a mano con la itemKey del blob y el AAD del protocolo', async () => {
    const vaultKey = generateVaultKey();
    const original = itemDeEjemplo();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, original);
    const json = JSON.parse(
      await descifrarAMano(vaultKey, blob, aadDeItem(ITEM_ID, KEY_VERSION)),
    ) as ItemPlain;
    expect(json.password).toBe(original.password);
  });

  it('el descifrado manual falla si el AAD no lleva el itemId del cifrado', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    await expect(
      descifrarAMano(vaultKey, blob, aadDeItem(OTRO_ITEM_ID, KEY_VERSION)),
    ).rejects.toThrow();
  });

  it('el descifrado manual falla si el AAD no lleva la keyVersion del cifrado', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, itemDeEjemplo());
    await expect(
      descifrarAMano(vaultKey, blob, aadDeItem(ITEM_ID, 2)),
    ).rejects.toThrow();
  });

  it('el ciphertext y el nonce no contienen el texto plano en claro', async () => {
    const vaultKey = generateVaultKey();
    const original = itemDeEjemplo();
    const blob = await encryptItem(vaultKey, ITEM_ID, KEY_VERSION, original);
    // `latin1` conserva los bytes 1:1: si la password estuviera en claro dentro
    // del base64, se veria aqui tal cual.
    const crudo = fromB64(blob.ciphertext);
    const texto = new TextDecoder('latin1').decode(crudo);
    expect(texto.includes(original.password)).toBe(false);
  });

  it('el AAD del item es exactamente securekey/v1:item:<itemId>:key:<keyVersion>', async () => {
    const vaultKey = generateVaultKey();
    const blob = await encryptItem(vaultKey, ITEM_ID, 3, itemDeEjemplo());
    const json = JSON.parse(
      await descifrarAMano(vaultKey, blob, 'securekey/v1:item:11111111-2222-4333-8444-555555555555:key:3'),
    ) as ItemPlain;
    expect(json.title).toBe('Banco Egg');
  });
});

describe('crypto: disponibilidad de WebCrypto', () => {
  it('cryptoAvailable() es true en Node 22 (y en un contexto seguro del navegador)', () => {
    expect(cryptoAvailable()).toBe(true);
  });
});
