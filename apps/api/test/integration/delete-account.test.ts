/**
 * Borrado de la cuenta.
 *
 * Es la unica operacion de la aplicacion que destruye datos de forma
 * irreversible, y por eso tiene su propio fichero. Lo que importa fijar:
 *
 *   1. Que NO se pueda sin la contrasena maestra. Con la sesion abierta
 *      bastaria, y entonces una cookie robada permitiria borrar la boveda de
 *      cualquiera. Eso ya no seria robo, seria destruccion.
 *   2. Que se lleve TODO: usuario, items y sesiones. Una fila que se queda
 *      colgando es justo el tipo de basura que despues no sabes de donde salio.
 *   3. Que no pueda borrar la cuenta de otro. Aqui es donde RLS hace su trabajo:
 *      el `user_id` sale de la sesion, no del cuerpo de la peticion, y la
 *      politica de `users` es FOR ALL sobre `id = app_user_id()`.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  closeDatabase,
  createTestApp,
  makeAccount,
  makeClient,
  makeItemBlob,
  registerPayload,
  resetDatabase,
  testConfig,
  withAdmin,
  type TestClient,
} from '../helpers.js';

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

/** Registra, deja una credencial guardada y entra en sesion. */
async function conBovedaPoblada(email?: string): Promise<{
  client: TestClient;
  account: Awaited<ReturnType<typeof makeAccount>>;
  itemId: string;
}> {
  const account = await makeAccount(email);
  const client = makeClient(app);
  const alta = await client.post(`${API}/auth/register`, registerPayload(account));
  expect(alta.statusCode).toBe(201);

  const login = await client.post(`${API}/auth/login`, {
    email: account.email,
    authKey: account.authKey,
    kdfVersion: 1,
  });
  expect(login.statusCode).toBe(200);

  const itemId = crypto.randomUUID();
  const blob = await makeItemBlob(account.vaultKey, itemId, 1, {
    title: 'Credencial que debe desaparecer',
    username: 'alguien',
    password: 'esto-es-una-contrasena-ficticia',
    url: 'https://ejemplo.test',
    notes: '',
    favorite: false,
    strength: -1,
    updatedAt: new Date().toISOString(),
  });
  const guardado = await client.post(`${API}/items`, { id: itemId, blob });
  expect(guardado.statusCode).toBe(201);

  return { client, account, itemId };
}

const csrf = (client: TestClient): string => client.cookies.get('__Host-sk_csrf') ?? '';

const contar = async (tabla: 'users' | 'items' | 'sessions', pred?: string): Promise<number> => {
  const filas = await withAdmin(testConfig(), async (tx) => {
    const res = await tx.query<{ n: string }>(`SELECT count(*) AS n FROM ${tabla}${pred ? ` WHERE ${pred}` : ''}`);
    return res.rows;
  });
  return Number(filas[0]?.n ?? 0);
};

describe('POST /auth/delete-account — lo que no debe pasar', () => {
  it('sin sesion responde 401', async () => {
    const anonimo = makeClient(app);
    const res = await anonimo.post(`${API}/auth/delete-account`, { authKey: 'AAAA' });
    expect(res.statusCode).toBe(401);
  });

  it('con la contrasena maestra incorrecta NO borra nada', async () => {
    const { client, account } = await conBovedaPoblada();
    const antes = await contar('users');

    const res = await client.post(
      `${API}/auth/delete-account`,
      { authKey: Buffer.alloc(32, 9).toString('base64') },
      { 'x-csrf-token': csrf(client) },
    );

    expect(res.statusCode).toBe(401);
    expect(await contar('users')).toBe(antes);
    // Y la sesion sigue viva: un fallo aqui no invalida nada.
    expect((await client.get(`${API}/items`)).statusCode).toBe(200);
    void account;
  });

  it('sin token CSRF responde 403', async () => {
    const { client, account } = await conBovedaPoblada();
    // `makeClient` inyecta el `x-csrf-token` por su cuenta en cualquier metodo
    // que no sea GET, asi que probar "sin CSRF" con `post()` no probaria nada:
    // la cabecera estaria ahi igual. Hay que usar `raw()`, que es el metodo
    // que el helper deja justamente para romper el contrato a proposito.
    const res = await client.raw({
      method: 'POST',
      url: `${API}/auth/delete-account`,
      headers: { cookie: [...client.cookies].map(([k, v]) => `${k}=${v}`).join('; ') },
      payload: { authKey: account.authKey },
    });
    expect(res.statusCode).toBe(403);
    expect(await contar('users')).toBe(1);
  });
});

describe('POST /auth/delete-account — lo que si debe pasar', () => {
  it('con la contrasena correcta borra usuario, items y sesiones', async () => {
    const { client, account, itemId } = await conBovedaPoblada();

    // Punto de partida: hay una fila de cada cosa.
    //
    // DOS sesiones, no una: el registro abre sesion por su cuenta (el cliente
    // entra directo a la boveda sin segundo login) y despues este helper hace
    // login otra vez. El numero exacto se fija aqui a proposito, porque si
    // alguien cambia ese comportamiento el CASCADE de abajo dejaria una sesion
    // colgando y este test lo diria.
    expect(await contar('users')).toBe(1);
    expect(await contar('items')).toBe(1);
    expect(await contar('sessions')).toBe(2);

    const res = await client.post(
      `${API}/auth/delete-account`,
      { authKey: account.authKey },
      { 'x-csrf-token': csrf(client) },
    );

    expect(res.statusCode).toBe(200);

    // El CASCADE tiene que llevarse items y sessions. Si algum dia
    // se quita, estos tres numeros son los que avisan.
    expect(await contar('users')).toBe(0);
    expect(await contar('items')).toBe(0);
    expect(await contar('sessions')).toBe(0);
    expect(await contar('items', `id = '${itemId}'`)).toBe(0);
  });

  it('la sesion deja de valer despues del borrado', async () => {
    const { client, account } = await conBovedaPoblada();
    await client.post(
      `${API}/auth/delete-account`,
      { authKey: account.authKey },
      { 'x-csrf-token': csrf(client) },
    );
    // La cookie sigue en el jar del cliente, pero la fila ya no existe.
    expect((await client.get(`${API}/items`)).statusCode).toBe(401);
  });

  it('ya no se puede entrar con esa cuenta', async () => {
    const { client, account } = await conBovedaPoblada();
    await client.post(
      `${API}/auth/delete-account`,
      { authKey: account.authKey },
      { 'x-csrf-token': csrf(client) },
    );

    const otro = makeClient(app);
    const login = await otro.post(`${API}/auth/login`, {
      email: account.email,
      authKey: account.authKey,
      kdfVersion: 1,
    });
    expect(login.statusCode).toBe(401);
  });

  it('el correo queda libre para volver a registrarse', async () => {
    // Consecuencia de que la fila desaparezca de verdad, y no de que se marque
    // como borrada. Importa para el derecho de supresion: si el correo se
    // quedara ocupado, el usuario no podria dejar de existir del todo.
    const { client, account } = await conBovedaPoblada();
    await client.post(
      `${API}/auth/delete-account`,
      { authKey: account.authKey },
      { 'x-csrf-token': csrf(client) },
    );

    const otro = makeClient(app);
    const nuevo = await makeAccount(account.email);
    const alta = await otro.post(`${API}/auth/register`, registerPayload(nuevo));
    expect(alta.statusCode).toBe(201);
  });

  it('no toca las cuentas de los demas', async () => {
    // La RLS es la barrera: el `user_id` sale de la sesion, no del cuerpo, y la
    // politica de `users` solo deja borrar la propia fila.
    const mia = await conBovedaPoblada('mia@example.test');
    const suya = await conBovedaPoblada('suya@example.test');
    expect(await contar('users')).toBe(2);

    await mia.client.post(
      `${API}/auth/delete-account`,
      { authKey: mia.account.authKey },
      { 'x-csrf-token': csrf(mia.client) },
    );

    expect(await contar('users')).toBe(1);
    expect(await contar('users', `email = 'suya@example.test'`)).toBe(1);
    // La otra sesion sigue viva.
    expect((await suya.client.get(`${API}/items`)).statusCode).toBe(200);
  });
});

describe('la bitacora sobrevive al borrado', () => {
  it('queda constancia de que existio la cuenta, sin nada suyo', async () => {
    // `audit_log` NO cuelga de `users`, a proposito. Es lo unico que queda
    // tras el borrado, y conviene que sea una linea de "se elimino una cuenta"
    // y nada mas: ningun correo, ninguna credencial, ningun titulo.
    const { client, account } = await conBovedaPoblada();

    const res = await client.post(
      `${API}/auth/delete-account`,
      { authKey: account.authKey },
      { 'x-csrf-token': csrf(client) },
    );
    expect(res.statusCode).toBe(200);

    const trazas = await withAdmin(testConfig(), async (tx) => {
      const res2 = await tx.query<{ n: string }>(
        `SELECT count(*) AS n FROM audit_log WHERE action = 'auth.account.deleted'`,
      );
      return res2.rows;
    });
    expect(Number(trazas[0]?.n ?? 0)).toBe(1);

    // Y la linea no puede contener nada del usuario, por construccion.
    //
    // Aqui se intento comprobar que `items.title` no aparecia en la bitacora, y
    // la consulta fallo con "column does not exist": la tabla `items` no TIENE
    // columna `title`. El servidor no sabe como se llama una credencial, que es
    // justo lo que hay que demostrar. Asi que se comprueba la forma de la tabla
    // entera, que es un invariante mas fuerte.
    const columnas = await withAdmin(testConfig(), async (tx) => {
      const res = await tx.query<{ nombre: string }>(
        `SELECT column_name AS nombre FROM information_schema.columns
          WHERE table_name = 'audit_log'`,
      );
      return res.rows.map((r) => r.nombre);
    });
    for (const prohibido of ['title', 'username', 'password', 'notes', 'ciphertext', 'auth_hash']) {
      expect(columnas).not.toContain(prohibido);
    }
    // Y la traza queda sin usuario, porque la fila ya no existe.
    const traza = await withAdmin(testConfig(), async (tx) => {
      const res = await tx.query<{ user_id: string | null }>(
        `SELECT user_id::text AS user_id FROM audit_log WHERE action = 'auth.account.deleted'`,
      );
      return res.rows;
    });
    expect(traza[0]?.user_id).toBeNull();
  });
});
