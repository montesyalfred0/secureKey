/**
 * Flujo de autenticacion zero-knowledge.
 *
 * El cliente deriva en su memoria:
 *     masterKey = Argon2id(password, salt = SHA-256(email))
 *     KEK       = HKDF(masterKey, "securekey/v1/kek")
 *     authKey   = HKDF(masterKey, "securekey/v1/auth")
 *     vaultKey  = 32 bytes aleatorios, envueltos con la KEK
 *
 * El servidor solo recibe `authKey` (para verificar) y la `vaultKey` ya
 * cifrada (para almacenarla). Nunca ve la contrasena maestra ni la KEK, por
 * lo que no puede recuperar ninguna credencial de la boveda.
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { z } from 'zod';
import {
  kdfParamsSchema,
  loginRequestSchema,
  preloginRequestSchema,
  rekeyRequestSchema,
  registerRequestSchema,
  deleteAccountRequestSchema,
  unlockRequestSchema,
  changeMasterPasswordRequestSchema,
  wrappedKeySchema,
  MIN_KDF,
  type KdfParams,
  type WrappedKey,
} from '@securekey/shared';
import type { Config } from '../config.js';
import { withSystem, withUser } from '../db/withUser.js';
import { generateSalt, hashAuthKey, safeEqual, verifyInviteCode } from '../crypto/server.js';
import { createSession, clearSessionCookies, destroySession } from '../auth/session.js';
import { audit } from '../auth/audit.js';
import { attachAuth, currentUser, requireAuth } from '../http/context.js';
import {
  badRequest,
  conflict,
  notFound,
  tooManyRequests,
  unauthorized,
} from '../http/errors.js';

type AuthUserRow = {
  id: string;
  email: string;
  auth_hash: Buffer;
  auth_salt: Buffer;
  vault_cipher: Buffer;
  vault_nonce: Buffer;
  key_version: number;
  kdf: unknown;
  failed_logins: number;
  locked_until: Date | null;
};

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function parse<S extends z.ZodTypeAny>(schema: S, request: FastifyRequest): z.infer<S> {
  const result = schema.safeParse(request.body);
  if (!result.success) {
    throw badRequest('Peticion invalida', result.error.flatten());
  }
  return result.data;
}

/**
 * Alta de cuenta.
 *
 * Va por una funcion `SECURITY DEFINER` y no por un INSERT directo porque el
 * registro ocurre antes de existir sesion: no hay `app.user_id` publicado, asi
 * que la RLS rechazaria la escritura. La funcion la ejecuta el propietario y
 * de paso convierte la violacion de clave unica en un NULL, que aqui se
 * traduce a 409.
 */
async function createUser(
  config: Config,
  params: {
    email: string;
    authHash: Buffer;
    salt: Buffer;
    vaultCipher: Buffer;
    vaultNonce: Buffer;
    kdf: unknown;
  },
): Promise<string | undefined> {
  return withSystem(config, async (tx) => {
    const res = await tx.query<{ auth_create_user: string | null }>(
      `SELECT auth_create_user($1, $2, $3, $4, $5, $6::jsonb) AS auth_create_user`,
      [
        params.email,
        params.authHash,
        params.salt,
        params.vaultCipher,
        params.vaultNonce,
        JSON.stringify(params.kdf),
      ],
    );
    return res.rows[0]?.auth_create_user ?? undefined;
  });
}

/** Perfil de KDF vigente. No toca `key_version` (ver el comentario del rekey). */
async function updateUserKdf(config: Config, userId: string, kdf: unknown): Promise<void> {
  await withSystem(config, async (tx) => {
    await tx.query('SELECT auth_update_user_kdf($1, $2::jsonb)', [userId, JSON.stringify(kdf)]);
  });
}

/** Re-envuelve la vaultKey. `key_version` NO se incrementa. */
async function updateUserVault(
  config: Config,
  userId: string,
  vault: WrappedKey,
  kdf: unknown,
): Promise<void> {
  await withSystem(config, async (tx) => {
    await tx.query('SELECT auth_update_user_vault($1, $2, $3, $4::jsonb)', [
      userId,
      Buffer.from(vault.ciphertext, 'base64'),
      Buffer.from(vault.nonce, 'base64'),
      JSON.stringify(kdf),
    ]);
  });
}

/** Cambio de contrasena maestra: verificador, sal, envoltura y contadores. */
async function updateUserCredentials(
  config: Config,
  userId: string,
  params: { authHash: Buffer; salt: Buffer; vault: WrappedKey; kdf: unknown },
): Promise<void> {
  await withSystem(config, async (tx) => {
    await tx.query(
      `SELECT auth_update_user_credentials($1, $2, $3, $4, $5, $6::jsonb)`,
      [
        userId,
        params.authHash,
        params.salt,
        Buffer.from(params.vault.ciphertext, 'base64'),
        Buffer.from(params.vault.nonce, 'base64'),
        JSON.stringify(params.kdf),
      ],
    );
  });
}

/** Parametros KDF vigentes segun el estado de la fila o del servidor. */
function kdfFrom(row: AuthUserRow | undefined, config: Config): KdfParams {
  if (!row) return config.kdf;
  const parsed = kdfParamsSchema.safeParse(row.kdf);
  return parsed.success ? parsed.data : config.kdf;
}

function toWrappedKey(cipher: Buffer, nonce: Buffer): WrappedKey {
  return wrappedKeySchema.parse({
    alg: 'AES-256-GCM',
    nonce: nonce.toString('base64'),
    ciphertext: cipher.toString('base64'),
  });
}

async function findUser(config: Config, email: string): Promise<AuthUserRow | undefined> {
  return withSystem(config, async (tx) => {
    const res = await tx.query<AuthUserRow>('SELECT * FROM auth_lookup($1)', [email]);
    return res.rows[0];
  });
}

/**
 * Iguala el coste cuando el email no existe, para que el tiempo de respuesta
 * no revele que cuentas estan registradas.
 */
async function dummyAuthHash(config: Config): Promise<void> {
  const fake = Buffer.alloc(32, 7);
  await hashAuthKey(config.authPepper, fake, generateSalt());
}

async function verifyAuthKey(
  config: Config,
  user: AuthUserRow,
  authKeyB64: string,
): Promise<boolean> {
  const candidate = Buffer.from(authKeyB64, 'base64');
  if (candidate.length !== 32) return false;
  const hash = await hashAuthKey(config.authPepper, candidate, user.auth_salt);
  return safeEqual(hash, user.auth_hash);
}

function lockedUntilFuture(user: AuthUserRow, now = Date.now()): Date | null {
  if (!user.locked_until) return null;
  return user.locked_until.getTime() > now ? user.locked_until : null;
}

/** Sincroniza los parametros KDF del servidor si el cliente va por detras. */
async function syncKdfVersion(
  config: Config,
  user: AuthUserRow,
  clientKdfVersion: number,
): Promise<{ current: KdfParams; needsVaultRekey: boolean }> {
  const current = kdfFrom(user, config);
  const needsVaultRekey = clientKdfVersion !== current.version;
  if (needsVaultRekey) {
    await updateUserKdf(config, user.id, current);
  }
  return { current, needsVaultRekey };
}

export async function authRoutes(app: FastifyInstance, opts: { config: Config }): Promise<void> {
  const { config } = opts;

  // ---------------------------------------------------------------------
  // 1. Prelogin: el cliente necesita los parametros KDF antes de derivar nada.
  // ---------------------------------------------------------------------
  app.post(
    '/auth/prelogin',
    { config: { rateLimit: { max: config.rateLimits.prelogin, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const { email } = parse(preloginRequestSchema, request);
      const user = await findUser(config, normalizeEmail(email));

      return reply.send({
        exists: user !== undefined,
        kdf: kdfFrom(user, config),
        lockedUntil: user ? (lockedUntilFuture(user)?.toISOString() ?? null) : null,
      });
    },
  );

  // ---------------------------------------------------------------------
  // 2. Registro. El servidor no puede verificar el email: en zero-knowledge
  //    eso es inherente. Se compensa con rate limiting y, si se desea, con
  //    codigos de invitacion firmados (sin estado en el servidor).
  // ---------------------------------------------------------------------
  app.post(
    '/auth/register',
    { config: { rateLimit: { max: config.rateLimits.register, timeWindow: '1 hour' } } },
    async (request, reply) => {
      const body = parse(registerRequestSchema, request);
      const email = normalizeEmail(body.email);

      if (body.kdf.m < MIN_KDF.m || body.kdf.t < MIN_KDF.t || body.kdf.p < MIN_KDF.p) {
        throw badRequest(
          `Parametros KDF por debajo del minimo de OWASP (m>=${MIN_KDF.m} KiB, t>=${MIN_KDF.t}, p>=${MIN_KDF.p})`,
        );
      }

      if (config.registrationMode === 'invite') {
        const ok =
          config.inviteSecret !== undefined &&
          body.inviteCode !== undefined &&
          verifyInviteCode(config.inviteSecret, body.inviteCode, email);
        if (!ok) throw unauthorized('Codigo de invitacion invalido o caducado');
      }

      const authKey = Buffer.from(body.authKey, 'base64');
      if (authKey.length !== 32) throw badRequest('authKey debe tener 32 bytes');
      const vault = wrappedKeySchema.parse(body.vault);

      // El salt se genera una sola vez y se usa tanto para el hash como para
      // la fila, de modo que la verificacion posterior use exactamente el mismo.
      const salt = generateSalt();
      const authHash = await hashAuthKey(config.authPepper, authKey, salt);

      const userId = await createUser(config, {
        email,
        authHash,
        salt,
        vaultCipher: Buffer.from(vault.ciphertext, 'base64'),
        vaultNonce: Buffer.from(vault.nonce, 'base64'),
        kdf: body.kdf,
      });

      if (userId === undefined) throw conflict('No se ha podido completar el registro');

      await audit(config, { userId, action: 'auth.register', request });
      await createSession(config, reply, userId, request);

      return reply.code(201).send({
        user: { id: userId, email },
        vault: toWrappedKey(Buffer.from(vault.ciphertext, 'base64'), Buffer.from(vault.nonce, 'base64')),
        needsVaultRekey: false,
        keyVersion: 1,
      });
    },
  );

  // ---------------------------------------------------------------------
  // 3. Login. Crea sesion nueva.
  // ---------------------------------------------------------------------
  app.post(
    '/auth/login',
    { config: { rateLimit: { max: config.rateLimits.login, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const body = parse(loginRequestSchema, request);
      const email = normalizeEmail(body.email);
      const user = await findUser(config, email);

      if (!user) {
        await dummyAuthHash(config);
        await audit(config, { userId: null, action: 'auth.login.fail', request });
        throw unauthorized('Credenciales invalidas');
      }

      const locked = lockedUntilFuture(user);
      if (locked) {
        await audit(config, { userId: user.id, action: 'auth.login.locked', request });
        throw tooManyRequests(`Cuenta bloqueada hasta las ${locked.toISOString()}`);
      }

      if (!(await verifyAuthKey(config, user, body.authKey))) {
        await withSystem(config, async (tx) => {
          await tx.query('SELECT auth_register_failure($1, $2, $3)', [
            user.id,
            config.loginMaxAttempts,
            Math.ceil(config.loginLockMs / 60_000),
          ]);
        });
        await audit(config, { userId: user.id, action: 'auth.login.fail', request });
        throw unauthorized('Credenciales invalidas');
      }

      await withSystem(config, async (tx) => {
        await tx.query('SELECT auth_register_success($1)', [user.id]);
      });

      const { needsVaultRekey } = await syncKdfVersion(config, user, body.kdfVersion);

      await audit(config, { userId: user.id, action: 'auth.login.ok', request });
      await createSession(config, reply, user.id, request);

      return reply.send({
        user: { id: user.id, email: user.email },
        vault: toWrappedKey(user.vault_cipher, user.vault_nonce),
        needsVaultRekey,
        keyVersion: user.key_version,
      });
    },
  );

  // ---------------------------------------------------------------------
  // 4. Unlock: la sesion sobrevive a un recargado de pagina, la clave no.
  // ---------------------------------------------------------------------
  app.post(
    '/auth/unlock',
    { preHandler: requireAuth(config), config: { rateLimit: { max: config.rateLimits.unlock, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const body = parse(unlockRequestSchema, request);
      const user = await findUser(config, normalizeEmail(currentUser(request).email));
      if (!user) throw unauthorized('Sesion no valida');

      const locked = lockedUntilFuture(user);
      if (locked) throw tooManyRequests('Cuenta bloqueada temporalmente');

      if (!(await verifyAuthKey(config, user, body.authKey))) {
        await audit(config, { userId: user.id, action: 'auth.unlock.fail', request });
        throw unauthorized('Contrasena maestra incorrecta');
      }

      const { needsVaultRekey } = await syncKdfVersion(config, user, body.kdfVersion);
      await audit(config, { userId: user.id, action: 'auth.unlock.ok', request });

      return reply.send({
        vault: toWrappedKey(user.vault_cipher, user.vault_nonce),
        needsVaultRekey,
        keyVersion: user.key_version,
      });
    },
  );

  // ---------------------------------------------------------------------
  // 5. Rekey: re-envuelve la boveda. Exige contrasena maestra, no solo sesion,
  //    para que una sesion robada no pueda inutilizar la boveda.
  // ---------------------------------------------------------------------
  app.post('/auth/rekey', { preHandler: requireAuth(config) }, async (request, reply) => {
    const body = parse(rekeyRequestSchema, request);
    const auth = currentUser(request);
    const user = await findUser(config, normalizeEmail(auth.email));
    if (!user || user.id !== auth.userId) throw unauthorized('Sesion no valida');
    if (!(await verifyAuthKey(config, user, body.authKey))) {
      throw unauthorized('Contrasena maestra incorrecta');
    }

    const vault = wrappedKeySchema.parse(body.vault);
    // OJO: `key_version` NO se incrementa. Es la generacion de la clave de
    // boveda, y va dentro del AAD de cada item. Subirla al re-envolver la misma
    // vaultKey dejaria TODOS los items sin descifrar. Rotar de verdad (cambiar
    // la vaultKey) exige re-cifrar la boveda entera y solo tiene sentido como
    // operacion planificada.
    await updateUserVault(config, user.id, vault, {
      ...kdfFrom(user, config),
      version: body.kdfVersion,
    });

    await audit(config, { userId: user.id, action: 'auth.rekey', request });
    return reply.send({ ok: true });
  });

  // ---------------------------------------------------------------------
  // 6. Cambio de contrasena maestra. Se re-envuelve la MISMA vaultKey, asi
  //    que ningun item de la boveda necesita re-cifrarse.
  // ---------------------------------------------------------------------
  app.post('/auth/master-password', { preHandler: requireAuth(config) }, async (request, reply) => {
    const body = parse(changeMasterPasswordRequestSchema, request);
    const auth = currentUser(request);
    const user = await findUser(config, normalizeEmail(auth.email));
    if (!user || user.id !== auth.userId) throw unauthorized('Sesion no valida');

    if (!(await verifyAuthKey(config, user, body.currentAuthKey))) {
      await audit(config, { userId: user.id, action: 'auth.unlock.fail', request });
      throw unauthorized('Contrasena maestra actual incorrecta');
    }

    const newAuthKey = Buffer.from(body.newAuthKey, 'base64');
    if (newAuthKey.length !== 32) throw badRequest('newAuthKey debe tener 32 bytes');
    const vault = wrappedKeySchema.parse(body.newVault);

    const salt = generateSalt();
    const authHash = await hashAuthKey(config.authPepper, newAuthKey, salt);

    // `key_version` se mantiene: la vaultKey no cambia, solo su envoltorio.
    await updateUserCredentials(config, user.id, {
      authHash,
      salt,
      vault,
      kdf: { ...kdfFrom(user, config), version: body.kdfVersion },
    });

    await audit(config, { userId: user.id, action: 'auth.master_password.changed', request });
    return reply.send({ ok: true });
  });

  // ---------------------------------------------------------------------
  // 7. Borrado de la cuenta.
  // ---------------------------------------------------------------------
  //   Sin esto, un registro de porfolio se llena de cuentas que nadie puede
  //   quitar, y el usuario que se registra y se arrepiente no tiene forma de
  //   borrar lo suyo. Es tambien el derecho de supresion: en mucho de Europa es
  //   una obligacion legal, y en un gestor de contrasenas tiene una consecuencia
  //   incomoda: hay que poder BORRAR credenciales ajenas sin poder LEERLAS.
  //   Aqui es trivial por construccion, porque el servidor nunca las leyo.
  //
  //   SIN limite de tasa a proposito, y conviene entender por que: el unico que
  //   puede borrarla es el dueno de la sesion, y solo puede borrar SU cuenta, una
  //   vez en su vida. Un limite por IP aqui no protege nada que la contrasena
  //   maestra no proteja ya, y estorba en cuanto alguien prueba el flujo. La
  //   barrera que importa es la reautenticacion de mas abajo.
  app.post(
    '/auth/delete-account',
    { preHandler: requireAuth(config) },
    async (request, reply) => {
      const body = parse(deleteAccountRequestSchema, request);
      const auth = currentUser(request);
      const user = await findUser(config, normalizeEmail(auth.email));
      if (!user || user.id !== auth.userId) throw unauthorized('Sesion no valida');

      // Reautenticacion. Una sesion robada no basta para destruir la boveda.
      if (!(await verifyAuthKey(config, user, body.authKey))) {
        await audit(config, { userId: user.id, action: 'auth.delete.fail', request });
        throw unauthorized('Contrasena maestra incorrecta');
      }

      // `items` y `sessions` cuelgan de `users` con ON DELETE CASCADE, asi que
      // una sola fila se lleva la cuenta entera. Y va dentro de `withUser` a
      // proposito: la politica RLS de `users` es FOR ALL sobre
      // `id = app_user_id()`, asi que el borrado solo es posible sobre la
      // propia fila. No hace falta una funcion SECURITY DEFINER nueva, que es
      // siempre lo que se quiere.
      const borrado = await withUser(config, auth.userId, async (tx) => {
        const res = await tx.query('DELETE FROM users WHERE id = $1 RETURNING id', [auth.userId]);
        return res.rowCount ?? 0;
      });
      if (borrado === 0) throw notFound('Cuenta no encontrada');

      // La bitacora sobrevive: `audit_log` no cuelga de `users` a proposito,
      // para que quede constancia de que existio la cuenta. Es la unica parte
      // que se conserva, y no contiene ninguna credencial.
      await audit(config, { userId: null, action: 'auth.account.deleted', request });
      clearSessionCookies(reply);
      return reply.send({ ok: true });
    },
  );

  // ---------------------------------------------------------------------
  // 8. Logout.
  // ---------------------------------------------------------------------
  app.post('/auth/logout', { preHandler: requireAuth(config) }, async (request, reply) => {
    const auth = currentUser(request);
    await destroySession(config, auth.sessionId, auth.userId);
    await audit(config, { userId: auth.userId, action: 'auth.logout', request });
    clearSessionCookies(reply);
    return reply.send({ ok: true });
  });

  // ---------------------------------------------------------------------
  // 9. Sesion actual. En el arranque sirve para saber si hay que desbloquear:
  //    las cookies sobreviven a un recargado, la clave de boveda no.
  // ---------------------------------------------------------------------
  app.get('/session', async (request, reply) => {
    await attachAuth(config, request, reply);
    if (!request.auth) return reply.send({ authenticated: false, user: null });
    return reply.send({
      authenticated: true,
      user: { id: request.auth.userId, email: request.auth.email },
    });
  });
}
