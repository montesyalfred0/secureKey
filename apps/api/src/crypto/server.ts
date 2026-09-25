/**
 * Primitivas criptograficas del SERVIDOR.
 *
 * El servidor nunca cifra ni descifra credenciales. Solo necesita:
 *   - verificar el `authKey` derivado en el cliente (hash + pepper),
 *   - emitir tokens de sesion opacos,
 *   - generar auditorias de codigos de invitacion.
 *
 * Todo sale de `node:crypto`: cero modulos nativos que compilar en Alpine.
 */
import {
  createHmac,
  createHash,
  randomBytes,
  scrypt as scryptCb,
  timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb) as (
  password: Buffer | string,
  salt: Buffer | string,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

/** Bytes de sal para el hash del verificador de autenticacion. */
export const AUTH_SALT_BYTES = 16;
/** Bytes de token de sesion / CSRF. */
export const TOKEN_BYTES = 32;

/**
 * Coste de `scrypt` para el hash del verificador.
 *
 * NO es el control de coste real: la contrasena maestra nunca llega al
 * servidor, solo el `authKey` de 32 bytes que el cliente ya tuvo que obtener
 * pagando Argon2id. Este coste es defense in depth: evita que un atacante con
 * la base de datos use la tabla como un oraculo de verificacion barato.
 */
const SCRYPT_N = 1 << 14; // 16 MiB
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
const SCRYPT_KEYLEN = 64;

function scryptOptions() {
  return { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAXMEM };
}

/**
 * Calcula el hash del verificador de autenticacion.
 *
 *   peppered  = HMAC-SHA256(pepper, authKey)      <- pre-hash con el pepper
 *   authHash  = scrypt(peppered, salt, 64, N=2^14)
 *
 * El pepper vive fuera de la base de datos (variable de entorno / secreto
 * de Docker), por lo que un robo de la BD no permite verificar candidatos.
 */
export async function hashAuthKey(
  pepper: string,
  authKey: Uint8Array,
  salt: Uint8Array,
): Promise<Buffer> {
  const peppered = createHmac('sha256', Buffer.from(pepper, 'utf8'))
    .update(Buffer.from(authKey))
    .digest();
  return scrypt(peppered, Buffer.from(salt), SCRYPT_KEYLEN, scryptOptions());
}

export function generateSalt(): Buffer {
  return randomBytes(AUTH_SALT_BYTES);
}

/** Comparacion en tiempo constante que no filtra la longitud. */
export function safeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const bufA = Buffer.isBuffer(a) ? a : Buffer.from(a);
  const bufB = Buffer.isBuffer(b) ? b : Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Comparacion de longitud fija para no filtrar informacion por el tiempo.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

/** Token opaco en base64url. Viaja en la cookie, nunca se guarda en claro. */
export function generateToken(): string {
  return randomBytes(TOKEN_BYTES).toString('base64url');
}

export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

/**
 * Codigo de invitacion: `skinv_<base64url(payload)>.<base64url(HMAC)>`.
 * Firma con HMAC-SHA256 para que no necesite estado en el servidor.
 */
export function issueInviteCode(secret: string, email: string, days = 30): string {
  const payload = Buffer.from(
    JSON.stringify({ e: email.toLowerCase(), exp: Date.now() + days * 86_400_000 }),
    'utf8',
  ).toString('base64url');
  const sig = createHmac('sha256', secret).update(payload).digest('base64url').slice(0, 32);
  return `skinv_${payload}.${sig}`;
}

export function verifyInviteCode(
  secret: string,
  code: string,
  email: string,
  now = Date.now(),
): boolean {
  if (!code.startsWith('skinv_')) return false;
  const rest = code.slice('skinv_'.length);
  const dot = rest.lastIndexOf('.');
  if (dot <= 0) return false;
  const payload = rest.slice(0, dot);
  const sig = rest.slice(dot + 1);

  const expected = createHmac('sha256', secret).update(payload).digest('base64url').slice(0, 32);
  if (!safeEqual(Buffer.from(sig, 'utf8'), Buffer.from(expected, 'utf8'))) return false;

  let parsed: { e?: unknown; exp?: unknown };
  try {
    parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as typeof parsed;
  } catch {
    return false;
  }
  if (typeof parsed.exp !== 'number' || parsed.exp < now) return false;
  return parsed.e === email.toLowerCase();
}
