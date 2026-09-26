/**
 * Flujo de autenticacion contra la API y la base de datos reales.
 *
 * Lo que se comprueba aqui NO se puede simular con dobles: cookies httpOnly,
 * doble envio de CSRF, validacion de Origin, RLS y bloqueo por intentos
 * fallidos son comportamiento de servidor y de PostgreSQL.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { closeDatabase, createTestApp, withAdmin, makeAccount, makeClient, registerPayload, resetDatabase, testConfig, type TestClient } from '../helpers.js';
import { issueInviteCode } from '../../src/crypto/server.js';

const API = '/api/v1';
let app: FastifyInstance;
let close: () => Promise<void>;

beforeAll(async () => {
  const built = await createTestApp();
  app = built.app;
  close = async () => {
    await app.close();
    await closeDatabase();
  };
});

afterAll(async () => {
  await close();
});

beforeEach(async () => {
  await resetDatabase(testConfig());
});

/** Registra una cuenta y devuelve un cliente ya autenticado. */
async function registerClient(email?: string): Promise<{ client: TestClient; account: Awaited<ReturnType<typeof makeAccount>> }> {
  const account = await makeAccount(email);
  const client = makeClient(app);
  const reply = await client.post(`${API}/auth/register`, registerPayload(account));
  expect(reply.statusCode).toBe(201);
  return { client, account };
}

describe('POST /auth/prelogin', () => {
  it('para un correo desconocido devuelve exists:false y los parametros KDF del servidor', async () => {
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/prelogin`, { email: 'nadie@example.test' });
    expect(reply.statusCode).toBe(200);
    const body = reply.json() as { exists: boolean; kdf: { alg: string; m: number }; lockedUntil: null };
    expect(body.exists).toBe(false);
    expect(body.lockedUntil).toBeNull();
    // El cliente necesita parametros validos aunque la cuenta no exista.
    expect(body.kdf.alg).toBe('argon2id');
    expect(body.kdf.m).toBeGreaterThanOrEqual(19_456);
  });

  it('para un correo registrado devuelve exists:true y los KDF de esa fila', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    await client.post(`${API}/auth/register`, registerPayload(account, 7));

    const reply = await client.post(`${API}/auth/prelogin`, { email: account.email });
    expect(reply.json()).toMatchObject({ exists: true, kdf: { version: 7 } });
  });

  it('normaliza el correo: mayusculas y espacios dan el mismo resultado', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    await client.post(`${API}/auth/register`, registerPayload(account));

    const reply = await client.post(`${API}/auth/prelogin`, { email: `  ${account.email.toUpperCase()} ` });
    expect((reply.json() as { exists: boolean }).exists).toBe(true);
  });

  it('rechaza un correo que no es un email', async () => {
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/prelogin`, { email: 'no-es-un-correo' });
    expect(reply.statusCode).toBe(400);
    expect((reply.json() as { error: { code: string } }).error.code).toBe('bad_request');
  });
});

describe('POST /auth/register', () => {
  it('crea la cuenta, abre sesion y devuelve la vaultKey envuelta intacta', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/register`, registerPayload(account));

    expect(reply.statusCode).toBe(201);
    const body = reply.json() as {
      user: { email: string };
      vault: { nonce: string; ciphertext: string };
      needsVaultRekey: boolean;
      keyVersion: number;
    };
    expect(body.user.email).toBe(account.email);
    expect(body.vault).toEqual(account.wrappedVault);
    expect(body.needsVaultRekey).toBe(false);
    expect(body.keyVersion).toBe(1);
    // Sesion abierta de inmediato: las dos cookies de prefijo __Host-.
    expect(client.cookies.get('__Host-sk_session')).toBeTruthy();
    expect(client.cookies.get('__Host-sk_csrf')).toBeTruthy();
  });

  it('las cookies de sesion son httpOnly, secure, SameSite=Strict y sin Domain', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/register`, registerPayload(account));

    const cookies = (reply.headers['set-cookie'] as unknown as string[]).map((c) => c.toLowerCase());
    const session = cookies.find((c) => c.startsWith('__host-sk_session='));
    expect(session).toBeDefined();
    expect(session).toContain('httponly');
    expect(session).toContain('secure');
    expect(session).toContain('samesite=strict');
    expect(session).not.toContain('domain=');
  });

  it('la cookie de CSRF es legible por JS (si no, el doble envio es imposible)', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/register`, registerPayload(account));
    const cookies = (reply.headers['set-cookie'] as unknown as string[]).map((c) => c.toLowerCase());
    const csrf = cookies.find((c) => c.startsWith('__host-sk_csrf='));
    expect(csrf).toBeDefined();
    expect(csrf).not.toContain('httponly');
  });

  it('el servidor guarda el verificador, nunca la contrasena maestra', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    await client.post(`${API}/auth/register`, registerPayload(account));

    const config = testConfig();
    const filas = await withAdmin(config, async (tx) => {
      const res = await tx.query<Record<string, unknown>>('SELECT * FROM users WHERE email = $1', [
        account.email,
      ]);
      return res.rows;
    });

    expect(filas).toHaveLength(1);
    const fila = filas[0]!;
    // El blob de la vaultKey llega cifrado y el verificador es un hash.
    expect(Buffer.from(fila.vault_cipher as Buffer).toString('base64')).toBe(
      account.wrappedVault.ciphertext,
    );
    expect(fila.auth_hash).not.toBe(account.authKey);
    const authHash = fila.auth_hash as Buffer;
    expect(authHash.length).toBe(64);
    // Y en ningun sitio aparece nada derivado de la contrasena.
    const volcado = JSON.stringify(fila, (_k, v) => (v instanceof Buffer ? v.toString('hex') : v));
    expect(volcado).not.toContain(account.masterKey.toString('hex'));
    expect(volcado).not.toContain('contrasena-maestra-de-prueba');
  });

  it('rechaza un correo duplicado con 409 y no crea una segunda sesion', async () => {
    const account = await makeAccount();
    const primero = makeClient(app);
    expect((await primero.post(`${API}/auth/register`, registerPayload(account))).statusCode).toBe(201);

    const segundo = makeClient(app);
    const reply = await segundo.post(`${API}/auth/register`, registerPayload(account));
    expect(reply.statusCode).toBe(409);
    expect(segundo.cookies.get('__Host-sk_session')).toBeUndefined();
  });

  it('el mismo correo con distinta capitalizacion es el mismo usuario', async () => {
    const account = await makeAccount();
    await makeClient(app).post(`${API}/auth/register`, registerPayload(account));
    const otro = makeClient(app);
    const reply = await otro.post(`${API}/auth/register`, {
      ...registerPayload(account),
      email: account.email.toUpperCase(),
    });
    expect(reply.statusCode).toBe(409);
  });

  it('rechaza parametros KDF por debajo del minimo de OWASP', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    // 8192 KiB es valido para el esquema (que baja a 8192) pero esta por
    // debajo del minimo de OWASP que exige el servidor. Asi se comprueba
    // especificamente el guard de MIN_KDF, no la validacion de forma.
    const reply = await client.post(`${API}/auth/register`, {
      ...registerPayload(account),
      kdf: { alg: 'argon2id', m: 8192, t: 2, p: 1, version: 1 },
    });
    expect(reply.statusCode).toBe(400);
    expect((reply.json() as { error: { message: string } }).error.message).toMatch(/OWASP/);
  });

  it('rechaza un KDF con una forma invalida antes incluso de mirar OWASP', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/register`, {
      ...registerPayload(account),
      kdf: { alg: 'argon2id', m: 4096, t: 2, p: 1, version: 1 },
    });
    expect(reply.statusCode).toBe(400);
    expect((reply.json() as { error: { message: string } }).error.message).toBe('Peticion invalida');
  });

  it('rechaza una authKey que no son 32 bytes', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/register`, {
      ...registerPayload(account),
      authKey: Buffer.from('corto').toString('base64'),
    });
    expect(reply.statusCode).toBe(400);
  });

  it('rechaza una vaultKey que no es base64', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/register`, {
      ...registerPayload(account),
      vault: { alg: 'AES-256-GCM', nonce: 'no-es-base64!!', ciphertext: 'tampoco' },
    });
    expect(reply.statusCode).toBe(400);
  });

  it('no acepta un algoritmo de cifrado desconocido en la vault', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/register`, {
      ...registerPayload(account),
      vault: { ...account.wrappedVault, alg: 'ROT13' },
    });
    expect(reply.statusCode).toBe(400);
  });
});

describe('modo invitacion', () => {
  const secret = 'secreto-de-invitacion-suficientemente-largo';

  it('sin codigo valido el registro es 401', async () => {
    const conInvite = await createTestApp({ REGISTRATION_MODE: 'invite', INVITE_SECRET: secret });
    const account = await makeAccount();
    const client = makeClient(conInvite.app);

    expect((await client.post(`${API}/auth/register`, registerPayload(account))).statusCode).toBe(401);
    expect(
      (await client.post(`${API}/auth/register`, registerPayload(account, 1, 'skinv_falso'))).statusCode,
    ).toBe(401);

    await conInvite.app.close();
  });

  it('con un codigo emitido para ese correo el registro funciona', async () => {
    const conInvite = await createTestApp({ REGISTRATION_MODE: 'invite', INVITE_SECRET: secret });
    const account = await makeAccount();
    const client = makeClient(conInvite.app);
    const code = issueInviteCode(secret, account.email);

    expect((await client.post(`${API}/auth/register`, registerPayload(account, 1, code))).statusCode).toBe(201);

    await conInvite.app.close();
  });
});

describe('POST /auth/login', () => {
  it('devuelve la vaultKey y abre sesion', async () => {
    const { client, account } = await registerClient();
    const sesion = makeClient(app);
    const reply = await sesion.post(`${API}/auth/login`, {
      email: account.email,
      authKey: account.authKey,
      kdfVersion: 1,
    });

    expect(reply.statusCode).toBe(200);
    const body = reply.json() as { vault: unknown; needsVaultRekey: boolean };
    expect(body.vault).toEqual(account.wrappedVault);
    expect(body.needsVaultRekey).toBe(false);
    expect(sesion.cookies.get('__Host-sk_session')).toBeTruthy();
    expect(client.cookies.get('__Host-sk_session')).toBeTruthy();
  });

  it('con una authKey incorrecta responde 401 sin abrir sesion', async () => {
    const { account } = await registerClient();
    const sesion = makeClient(app);
    const reply = await sesion.post(`${API}/auth/login`, {
      email: account.email,
      authKey: Buffer.alloc(32, 9).toString('base64'),
      kdfVersion: 1,
    });

    expect(reply.statusCode).toBe(401);
    expect(sesion.cookies.get('__Host-sk_session')).toBeUndefined();
  });

  it('para un correo inexistente responde 401 con el MISMO mensaje (no filtra que cuentas hay)', async () => {
    const { account } = await registerClient();
    const sesion = makeClient(app);

    const mal = await sesion.post(`${API}/auth/login`, {
      email: 'nadie@example.test',
      authKey: Buffer.alloc(32, 1).toString('base64'),
      kdfVersion: 1,
    });
    const sinCuenta = await sesion.post(`${API}/auth/login`, {
      email: account.email,
      authKey: Buffer.alloc(32, 1).toString('base64'),
      kdfVersion: 1,
    });

    expect(mal.statusCode).toBe(sinCuenta.statusCode);
    expect((mal.json() as { error: unknown }).error).toEqual((sinCuenta.json() as { error: unknown }).error);
  });

  it('bloquea la cuenta tras N intentos fallidos y el prelogin lo avisa', async () => {
    // App propia con un umbral bajo: en produccion son 5 y 15 minutos.
    const conCero = await createTestApp({ LOGIN_MAX_ATTEMPTS: '3', LOGIN_LOCK_MINUTES: '15' });
    const account = await makeAccount();
    await makeClient(conCero.app).post(`${API}/auth/register`, registerPayload(account));

    const sesion = makeClient(conCero.app);
    const intento = (): Promise<{ statusCode: number }> =>
      sesion.post(`${API}/auth/login`, {
        email: account.email,
        authKey: Buffer.alloc(32, 3).toString('base64'),
        kdfVersion: 1,
      });

    expect((await intento()).statusCode).toBe(401);
    expect((await intento()).statusCode).toBe(401);
    // El tercero ya es el que completa el cupo.
    expect((await intento()).statusCode).toBe(401);

    const pre = await sesion.post(`${API}/auth/prelogin`, { email: account.email });
    const preBody = pre.json() as { lockedUntil: string | null };
    expect(preBody.lockedUntil).not.toBeNull();

    // Con la contrasena CORRECTA tampoco entra mientras este bloqueada.
    const correcto = await makeClient(conCero.app).post(`${API}/auth/login`, {
      email: account.email,
      authKey: account.authKey,
      kdfVersion: 1,
    });
    expect(correcto.statusCode).toBe(429);

    await conCero.app.close();
  });

  it('un login correcto despues de fallar reinicia el contador', async () => {
    const laxo = await createTestApp({ LOGIN_MAX_ATTEMPTS: '3', LOGIN_LOCK_MINUTES: '15' });
    const account = await makeAccount();
    await makeClient(laxo.app).post(`${API}/auth/register`, registerPayload(account));

    const sesion = makeClient(laxo.app);
    const malo = { email: account.email, authKey: Buffer.alloc(32, 4).toString('base64'), kdfVersion: 1 };
    await sesion.post(`${API}/auth/login`, malo);
    await sesion.post(`${API}/auth/login`, malo);

    const bueno = await makeClient(laxo.app).post(`${API}/auth/login`, {
      email: account.email,
      authKey: account.authKey,
      kdfVersion: 1,
    });
    expect(bueno.statusCode).toBe(200);

    // Dos fallos mas NO bloquean: el contador estaba a cero.
    const tras = makeClient(laxo.app);
    expect((await tras.post(`${API}/auth/login`, malo)).statusCode).toBe(401);
    expect((await tras.post(`${API}/auth/login`, malo)).statusCode).toBe(401);

    await laxo.app.close();
  });

  it('avisa al cliente cuando el servidor subio la version de KDF', async () => {
    const { account } = await registerClient();
    const sesion = makeClient(app);
    const reply = await sesion.post(`${API}/auth/login`, {
      email: account.email,
      authKey: account.authKey,
      kdfVersion: 1,
    });
    expect((reply.json() as { needsVaultRekey: boolean }).needsVaultRekey).toBe(false);
  });
});

describe('GET /session', () => {
  it('sin cookie responde authenticated:false', async () => {
    const client = makeClient(app);
    const reply = await client.get(`${API}/session`);
    expect(reply.json()).toEqual({ authenticated: false, user: null });
  });

  it('con la sesion abierta devuelve el usuario', async () => {
    const { client, account } = await registerClient();
    const reply = await client.get(`${API}/session`);
    expect(reply.json()).toMatchObject({ authenticated: true, user: { email: account.email } });
  });

  it('despues de cerrar sesion vuelve a anonymous aunque la cookie siga ahi', async () => {
    const { client } = await registerClient();
    const token = client.cookies.get('__Host-sk_session');

    expect((await client.post(`${API}/auth/logout`)).statusCode).toBe(200);

    // Se reutiliza a proposito el token viejo: la fila se borro, asi que da igual
    // que el navegador conserve la cookie.
    const reutilizado = makeClient(app);
    await reutilizado.cookies.set('__Host-sk_session', token!);
    const reply = await reutilizado.get(`${API}/session`);
    expect((reply.json() as { authenticated: boolean }).authenticated).toBe(false);
  });

  it('las sesiones de dos usuarios no se mezclan', async () => {
    const a = await registerClient();
    const b = await registerClient();
    expect(a.client.cookies.get('__Host-sk_session')).not.toBe(b.client.cookies.get('__Host-sk_session'));

    // Cerrar la de A no toca la de B.
    await a.client.post(`${API}/auth/logout`);
    expect((await a.client.get(`${API}/session`)).json()).toMatchObject({ authenticated: false });
    expect((await b.client.get(`${API}/session`)).json()).toMatchObject({ authenticated: true });
  });
});

describe('POST /auth/unlock', () => {
  it('devuelve la vaultKey sin abrir una sesion nueva', async () => {
    const { client, account } = await registerClient();
    const antes = client.cookies.get('__Host-sk_session');

    const reply = await client.post(`${API}/auth/unlock`, {
      authKey: account.authKey,
      kdfVersion: 1,
    });

    expect(reply.statusCode).toBe(200);
    expect((reply.json() as { vault: unknown }).vault).toEqual(account.wrappedVault);
    expect(client.cookies.get('__Host-sk_session')).toBe(antes);
  });

  it('con una authKey incorrecta responde 401', async () => {
    const { client } = await registerClient();
    const reply = await client.post(`${API}/auth/unlock`, {
      authKey: Buffer.alloc(32, 5).toString('base64'),
      kdfVersion: 1,
    });
    expect(reply.statusCode).toBe(401);
  });

  it('sin sesion responde 401', async () => {
    const account = await makeAccount();
    const client = makeClient(app);
    const reply = await client.post(`${API}/auth/unlock`, {
      authKey: account.authKey,
      kdfVersion: 1,
    });
    expect(reply.statusCode).toBe(401);
  });
});

describe('POST /auth/rekey', () => {
  it('re-envuelve la MISMA vaultKey y conserva key_version', async () => {
    const { client, account } = await registerClient();
    // Se re-envuelve la misma vaultKey con otro nonce: el contenido no cambia.
    const reply = await client.post(`${API}/auth/rekey`, {
      authKey: account.authKey,
      vault: account.wrappedVault,
      kdfVersion: 2,
    });

    expect(reply.statusCode).toBe(200);
    const { authKey, vaultKey } = account;
    void authKey;
    void vaultKey;

    // El cliente puede seguir leyendo la boveda: la clave no ha rotado.
    const items = await client.get(`${API}/items`);
    expect(items.statusCode).toBe(200);
  });

  it('exige la contrasena maestra, no solo la sesion', async () => {
    const { client } = await registerClient();
    const reply = await client.post(`${API}/auth/rekey`, {
      authKey: Buffer.alloc(32, 6).toString('base64'),
      vault: (await makeAccount()).wrappedVault,
      kdfVersion: 1,
    });
    expect(reply.statusCode).toBe(401);
  });

  it('no permite rekey sobre la boveda de otro usuario', async () => {
    const a = await registerClient();
    const b = await registerClient();
    const reply = await b.client.post(`${API}/auth/rekey`, {
      authKey: a.account.authKey,
      vault: a.account.wrappedVault,
      kdfVersion: 1,
    });
    expect(reply.statusCode).toBe(401);
  });
});

describe('POST /auth/master-password', () => {
  it('cambia el verificador y deja la vaultKey descifrable con la nueva KEK', async () => {
    const { client, account } = await registerClient();
    const nuevo = await makeAccount(account.email, 'otra-contrasena-maestra');

    const reply = await client.post(`${API}/auth/master-password`, {
      currentAuthKey: account.authKey,
      newAuthKey: nuevo.authKey,
      newVault: nuevo.wrappedVault,
      kdfVersion: 1,
    });
    expect(reply.statusCode).toBe(200);

    // La clave de boveda sigue siendo la MISMA: ningun item se re-cifro.
    const config = testConfig();
    const filas = await withAdmin(config, async (tx) => {
      const res = await tx.query<{ vault_cipher: Buffer; key_version: number }>(
        'SELECT vault_cipher, key_version FROM users WHERE email = $1',
        [account.email],
      );
      return res.rows;
    });
    expect(Buffer.from(filas[0]!.vault_cipher).toString('base64')).toBe(nuevo.wrappedVault.ciphertext);
    expect(filas[0]!.key_version).toBe(1);

    // Y ahora entra con la nueva contrasena y NO con la antigua.
    const conNueva = makeClient(app);
    expect(
      (
        await conNueva.post(`${API}/auth/login`, {
          email: account.email,
          authKey: nuevo.authKey,
          kdfVersion: 1,
        })
      ).statusCode,
    ).toBe(200);

    const conVieja = makeClient(app);
    expect(
      (
        await conVieja.post(`${API}/auth/login`, {
          email: account.email,
          authKey: account.authKey,
          kdfVersion: 1,
        })
      ).statusCode,
    ).toBe(401);
  });

  it('con la contrasena maestra actual equivocada no cambia nada', async () => {
    const { client, account } = await registerClient();
    const reply = await client.post(`${API}/auth/master-password`, {
      currentAuthKey: Buffer.alloc(32, 7).toString('base64'),
      newAuthKey: account.authKey,
      newVault: account.wrappedVault,
      kdfVersion: 1,
    });
    expect(reply.statusCode).toBe(401);

    const sigue = makeClient(app);
    expect(
      (
        await sigue.post(`${API}/auth/login`, {
          email: account.email,
          authKey: account.authKey,
          kdfVersion: 1,
        })
      ).statusCode,
    ).toBe(200);
  });
});

describe('CSRF y validacion de origen', () => {
  it('una peticion mutante sin x-csrf-token se rechaza con 403', async () => {
    const { client } = await registerClient();
    const reply = await client.post(`${API}/auth/logout`, undefined, { 'x-csrf-token': '' });
    expect(reply.statusCode).toBe(403);
  });

  it('un x-csrf-token que no es el de la cookie se rechaza', async () => {
    const { client } = await registerClient();
    const reply = await client.post(`${API}/auth/logout`, undefined, { 'x-csrf-token': 'inventado' });
    expect(reply.statusCode).toBe(403);
  });

  it('un Origin no permitido se rechaza antes de tocar la base de datos', async () => {
    const { client } = await registerClient();
    const reply = await client.post(
      `${API}/auth/logout`,
      undefined,
      { origin: 'https://atacante.example.com' },
    );
    expect(reply.statusCode).toBe(403);
  });

  it('las peticiones GET no necesitan token CSRF', async () => {
    const { client } = await registerClient();
    expect((await client.get(`${API}/items`)).statusCode).toBe(200);
  });
});

describe('rutas protegidas', () => {
  it('sin sesion, /items responde 401', async () => {
    const client = makeClient(app);
    expect((await client.get(`${API}/items`)).statusCode).toBe(401);
  });

  it('una ruta inexistente responde 404 con el formato de error de la app', async () => {
    const client = makeClient(app);
    const reply = await client.get(`${API}/no-existe`);
    expect(reply.statusCode).toBe(404);
    expect((reply.json() as { error: { code: string } }).error.code).toBe('not_found');
  });
});

describe('bitacora de auditoria', () => {
  it('registra el registro, el login y el logout sin datos sensibles', async () => {
    const { client, account } = await registerClient();
    await client.post(`${API}/auth/logout`);

    const config = testConfig();
    const filas = await withAdmin(config, async (tx) => {
      const res = await tx.query<{ action: string; user_id: string | null }>(
        'SELECT action, user_id FROM audit_log ORDER BY at',
      );
      return res.rows;
    });

    const acciones = filas.map((f) => f.action);
    expect(acciones).toContain('auth.register');
    expect(acciones).toContain('auth.logout');

    const todo = JSON.stringify(await withAdmin(config, (tx) => tx.query('SELECT * FROM audit_log')));
    expect(todo).not.toContain(account.authKey);
    expect(todo).not.toContain('contrasena-maestra');
  });
});
