/**
 * SecureKey - Protocolo compartido entre el cliente y el servidor.
 *
 * REGLA DE ORO: en ningun punto de este fichero viaja texto claro de una
 * credencial. El servidor solo manipula blobs cifrados con AEAD.
 */
import { z } from 'zod';

/** Base64 estandar (con relleno). Es lo que viaja por HTTP. */
const b64 = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/, 'Base64 invalido');
/** Base64url (sin relleno). Es lo que se usa en URLs y cookies. */
export const b64url = z.string().regex(/^[A-Za-z0-9_-]+$/, 'Base64url invalido');

/**
 * Parametros de derivacion de la clave maestra (Argon2id).
 * El `salt` NO viaja: se deriva de forma determinista como
 * SHA-256(email normalizado), de modo que el servidor no necesita
 * almacenarlo y puede subir los parametros sin romper clientes viejos.
 */
export const kdfParamsSchema = z.object({
  alg: z.literal('argon2id'),
  /** Memoria en KiB. */
  m: z.number().int().min(8192).max(1_048_576),
  /** Iteraciones. */
  t: z.number().int().min(1).max(32),
  /** Paralelismo. */
  p: z.number().int().min(1).max(16),
  /** Version del perfil de parametros; permite rotarlos. */
  version: z.number().int().min(1),
});
export type KdfParams = z.infer<typeof kdfParamsSchema>;

/** Limite duro de OWASP. El servidor rechaza registros por debajo de esto. */
export const MIN_KDF = { m: 19_456, t: 2, p: 1 } as const;

/**
 * Clave de bóveda envuelta con la KEK derivada de la contraseña maestra.
 * Es envelope encryption: `vaultKey` es aleatoria y no se deriva de la
 * contraseña, por lo que cambiar la contraseña maestra no re-cifra la bóveda.
 */
export const wrappedKeySchema = z.object({
  alg: z.literal('AES-256-GCM'),
  /** Nonce de 12 bytes. */
  nonce: b64,
  ciphertext: b64,
});
export type WrappedKey = z.infer<typeof wrappedKeySchema>;

/** Origen de la clave derivada para cada item (separacion de claves). */
export const itemKdfSchema = z.object({
  alg: z.literal('HKDF-SHA256'),
  /** Salt aleatorio de 16 bytes, distinto por item. */
  salt: b64,
  /**
   * Info que ata la derivacion a la version del formato: debe ser
   * `securekey/v1/item/<keyVersion>`.
   *
   * Se valida en el servidor y no solo en el cliente a proposito. Un `info`
   * equivocado no es un problema de seguridad (el AAD y la clave siguen
   * atando el ciphertext), pero produce un item que el cliente no puede
   * descifrar NUNCA mas, porque no hay forma de recalcular la clave. Aceptarlo
   * convertiria un 400 de las dos primeras lineas de la peticion en una fila
   * permanently lost que el usuario no puede ni ver ni borrar.
   */
  info: z
    .string()
    .max(128)
    .regex(/^securekey\/v\d+\/item\/[1-9]\d*$/, 'info de derivacion de item no reconocido'),
});
export type ItemKdf = z.infer<typeof itemKdfSchema>;

/** Blob cifrado de un item de la bóveda. */
export const itemBlobSchema = z.object({
  alg: z.literal('AES-256-GCM'),
  kdf: itemKdfSchema,
  nonce: b64,
  ciphertext: b64,
});
export type ItemBlob = z.infer<typeof itemBlobSchema>;

/** Item tal y como lo devuelve la API (metadatos + blob cifrado). */
export const itemDtoSchema = z.object({
  id: z.string().uuid(),
  version: z.number().int().min(1),
  blob: itemBlobSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type ItemDto = z.infer<typeof itemDtoSchema>;

// --------------------------------------------------------------------------
// Autenticacion
// --------------------------------------------------------------------------

/**
 * Email de la cuenta.
 *
 * `.trim()` va ANTES de `.email()` a proposito: pegar una direccion con un
 * espacio o un salto de linea al final es el error de tecleo mas comun, y sin
 * esto el usuario recibe un 400 de "formato invalido" en un campo que de hecho
 * es valido. El servidor normaliza a minusculas por su cuenta (`normalizeEmail`).
 */
const email = z.string().trim().email().max(254);

export const preloginRequestSchema = z.object({ email });
export type PreloginRequest = z.infer<typeof preloginRequestSchema>;

export const preloginResponseSchema = z.object({
  exists: z.boolean(),
  kdf: kdfParamsSchema,
  /** ISO date, presente si la cuenta esta bloqueada por intentos fallidos. */
  lockedUntil: z.string().nullable(),
});
export type PreloginResponse = z.infer<typeof preloginResponseSchema>;

export const registerRequestSchema = z.object({
  email,
  /** HKDF(masterKey, "auth") - 32 bytes. El servidor nunca ve la masterKey. */
  authKey: b64,
  vault: wrappedKeySchema,
  kdf: kdfParamsSchema,
  /** Solo obligatorio cuando REGISTRATION_MODE=invite. */
  inviteCode: z.string().max(256).optional(),
});
export type RegisterRequest = z.infer<typeof registerRequestSchema>;

export const loginRequestSchema = z.object({
  email,
  authKey: b64,
  kdfVersion: z.number().int().min(1),
});
export type LoginRequest = z.infer<typeof loginRequestSchema>;

/**
 * Borrado de la cuenta entera.
 *
 * Pide el `authKey` de nuevo a proposito, aunque la sesion ya este
 * autenticada. Es lo que impide que una cookie de sesion robada sirva para
 * destruir la boveda: con esto hace falta la contrasena maestra, que es
 * precisamente lo que un atacante con la sesion NO tiene.
 *
 * Sin esto, la cookie de sesion bastaria para destruir la boveda: eso ya no
 * seria robo, seria destruccion.
 */
export const deleteAccountRequestSchema = z.object({
  authKey: b64,
});
export type DeleteAccountRequest = z.infer<typeof deleteAccountRequestSchema>;

export const loginResponseSchema = z.object({
  user: z.object({ id: z.string().uuid(), email: z.string() }),
  /** Envuelve la clave de boveda. `null` solo en cuentas recien creadas. */
  vault: wrappedKeySchema.nullable(),
  /** El servidor subio los parametros KDF: hay que re-envolver el vault. */
  needsVaultRekey: z.boolean(),
  /**
   * Generacion de la clave de boveda. Solo cambia con una ROTACION real (que
   * obliga a re-cifrar la boveda entera). Re-envolver la misma clave con otra
   * contrasena maestra NO lo incrementa: va dentro del AAD de cada item, por lo
   * que alterarlo a la ligera dejaria la boveda entera sin descifrar.
   */
  keyVersion: z.number().int().min(1),
});
export type LoginResponse = z.infer<typeof loginResponseSchema>;

export const unlockRequestSchema = z.object({
  authKey: b64,
  kdfVersion: z.number().int().min(1),
});
export type UnlockRequest = z.infer<typeof unlockRequestSchema>;

export const unlockResponseSchema = z.object({
  vault: wrappedKeySchema,
  needsVaultRekey: z.boolean(),
  keyVersion: z.number().int().min(1),
});
export type UnlockResponse = z.infer<typeof unlockResponseSchema>;

/**
 * Re-envuelve la boveda con una KEK nueva (tras subir parametros KDF).
 * Exige probar de nuevo la contrasena maestra: una sesion robada por si sola
 * no debe poder inutilizar la boveda de un usuario.
 */
export const rekeyRequestSchema = z.object({
  authKey: b64,
  vault: wrappedKeySchema,
  kdfVersion: z.number().int().min(1),
});
export type RekeyRequest = z.infer<typeof rekeyRequestSchema>;

/**
 * Cambio de contraseña maestra. Se re-envuelve la MISMA vaultKey con una KEK
 * nueva, por lo que ningun item necesita re-cifrarse.
 */
export const changeMasterPasswordRequestSchema = z.object({
  currentAuthKey: b64,
  newAuthKey: b64,
  newVault: wrappedKeySchema,
  kdfVersion: z.number().int().min(1),
});
export type ChangeMasterPasswordRequest = z.infer<
  typeof changeMasterPasswordRequestSchema
>;

// --------------------------------------------------------------------------
// Sesion
// --------------------------------------------------------------------------

export const sessionResponseSchema = z.object({
  authenticated: z.boolean(),
  user: z.object({ id: z.string().uuid(), email: z.string() }).nullable(),
});
export type SessionResponse = z.infer<typeof sessionResponseSchema>;

// --------------------------------------------------------------------------
// Items
// --------------------------------------------------------------------------

export const createItemRequestSchema = z.object({
  /**
   * El cliente genera el UUID porque forma parte del AAD del cifrado: sin el,
   * un blob podria moverse de fila sin que el descifrado lo detecte.
   */
  id: z.string().uuid(),
  blob: itemBlobSchema,
});
export type CreateItemRequest = z.infer<typeof createItemRequestSchema>;

export const updateItemRequestSchema = z.object({
  blob: itemBlobSchema,
  /** Optimistic locking: debe coincidir con la version del servidor. */
  version: z.number().int().min(1),
});
export type UpdateItemRequest = z.infer<typeof updateItemRequestSchema>;

// --------------------------------------------------------------------------
// Constantes del protocolo (compartidas con el navegador)
// --------------------------------------------------------------------------

export const PROTOCOL = {
  /** `info` de HKDF para envolver la clave de boveda. */
  KEK_INFO: 'securekey/v1/kek',
  /** `info` de HKDF para derivar el verificador de autenticacion. */
  AUTH_INFO: 'securekey/v1/auth',
  /** Prefijo del `info` de HKDF para claves por item. */
  ITEM_INFO_PREFIX: 'securekey/v1/item/',
  /** Longitud de la masterKey / vaultKey / authKey. */
  KEY_BYTES: 32,
  /** Longitud de los nonces AEAD. */
  NONCE_BYTES: 12,
  /** Longitud del salt por item. */
  ITEM_SALT_BYTES: 16,
  version: 1,
} as const;

// --------------------------------------------------------------------------
// Validacion (la usara la API con fastify-type-provider-zod o manual)
// --------------------------------------------------------------------------

export const errorResponseSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    /** Detalle de validacion, presente solo en errores 400. */
    details: z.unknown().optional(),
  }),
});
export type ErrorResponse = z.infer<typeof errorResponseSchema>;

export const healthResponseSchema = z.object({
  status: z.literal('ok'),
  version: z.string(),
  uptimeSeconds: z.number(),
  database: z.literal('up'),
});
export type HealthResponse = z.infer<typeof healthResponseSchema>;
