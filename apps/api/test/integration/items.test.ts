/**
 * CRUD de la boveda contra la API y la base de datos reales.
 *
 * El foco de este fichero es el aislamiento. El servidor filtra por `user_id`
 * en todas las consultas, pero la garantia de verdad la da la RLS de
 * PostgreSQL: si alguien dejara de filtrar, estas pruebas tienen que ponerse
 * rojas. Por eso se comprueba tambien que la fila ajena es INACCESIBLE, no
 * simplemente invisible.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import {
  closeDatabase,
  createTestApp,
  makeAccount,
  makeClient,
  makeItemBlob,
  openItemBlob,
  registerPayload,
  resetDatabase,
  testConfig,
  type TestAccount,
  type TestClient,
  withAdmin,
} from '../helpers.js';

const API = '/api/v1';

let app: FastifyInstance;
let base: Awaited<ReturnType<typeof createTestApp>>;

beforeAll(async () => {
  base = await createTestApp();
  app = base.app;
});

afterAll(async () => {
  await app.close();
  await closeDatabase();
});

beforeEach(async () => {
  await resetDatabase(testConfig());
});

type Registered = { client: TestClient; account: TestAccount };

async function register(email?: string): Promise<Registered> {
  const account = await makeAccount(email);
  const client = makeClient(app);
  const reply = await client.post(`${API}/auth/register`, registerPayload(account));
  expect(reply.statusCode).toBe(201);
  return { client, account };
}

async function createItem(
  user: Registered,
  plain: Record<string, unknown> = { title: 'GitHub', password: 'secreto' },
): Promise<{ id: string; version: number }> {
  const id = randomUUID();
  const blob = await makeItemBlob(user.account.vaultKey, id, 1, plain);
  const reply = await user.client.post(`${API}/items`, { id, blob });
  expect(reply.statusCode).toBe(201);
  const body = reply.json() as { id: string; version: number };
  return { id: body.id, version: body.version };
}

describe('POST /items', () => {
  it('crea el item y devuelve el blob tal cual, sin tocar un byte', async () => {
    const user = await register();
    const id = randomUUID();
    const blob = await makeItemBlob(user.account.vaultKey, id, 1, {
      title: 'Banco',
      username: 'yo',
      password: 'muy-secreto',
    });

    const reply = await user.client.post(`${API}/items`, { id, blob });
    expect(reply.statusCode).toBe(201);

    const body = reply.json() as { id: string; version: number; blob: typeof blob };
    expect(body.id).toBe(id);
    expect(body.version).toBe(1);
    // El servidor es un almacen opaco: si modificase un byte, el descifrado
    // del cliente reventaria. La igualdad exacta lo deja demostrado.
    expect(body.blob).toEqual(blob);
  });

  it('el blob sigue descifrando con la vaultKey del cliente', async () => {
    const user = await register();
    const id = randomUUID();
    const plain = { title: 'Correo', password: 'clave-de-prueba' };
    const blob = await makeItemBlob(user.account.vaultKey, id, 1, plain);

    await user.client.post(`${API}/items`, { id, blob });

    const guardado = await withAdmin(testConfig(), async (tx) => {
      const res = await tx.query<{ id: string; version: number; kdf: unknown; nonce: Buffer; ciphertext: Buffer }>(
        'SELECT id, version, kdf, nonce, ciphertext FROM items WHERE id = $1',
        [id],
      );
      return res.rows[0]!;
    });

    const abierto = await openItemBlob(user.account.vaultKey, id, 1, {
      alg: 'AES-256-GCM',
      kdf: guardado.kdf as TestItemKdf,
      nonce: guardado.nonce.toString('base64'),
      ciphertext: guardado.ciphertext.toString('base64'),
    });
    expect(abierto).toEqual(plain);
  });

  it('la base de datos NO contiene nada en claro', async () => {
    const user = await register();
    await createItem(user, { title: 'Secreto-Corporativo', password: 'P4ssw0rd-del-banco' });

    const volcado = await withAdmin(testConfig(), async (tx) => {
      const res = await tx.query<Record<string, unknown>>('SELECT * FROM items');
      return JSON.stringify(res.rows, (_k, v) => (v instanceof Buffer ? v.toString('utf8') : v));
    });

    expect(volcado).not.toContain('Secreto-Corporativo');
    expect(volcado).not.toContain('P4ssw0rd-del-banco');
  });

  it('rechaza un id que no es un UUID', async () => {
    const user = await register();
    const blob = await makeItemBlob(user.account.vaultKey, randomUUID(), 1);
    const reply = await user.client.post(`${API}/items`, { id: 'no-es-uuid', blob });
    expect(reply.statusCode).toBe(400);
  });

  it('rechaza un blob sin nonce o sin ciphertext', async () => {
    const user = await register();
    const blob = await makeItemBlob(user.account.vaultKey, randomUUID(), 1);
    const reply = await user.client.post(`${API}/items`, {
      id: randomUUID(),
      blob: { ...blob, ciphertext: '' },
    });
    expect(reply.statusCode).toBe(400);
  });

  it('rechaza un KDF de item con un `info` desconocido', async () => {
    const user = await register();
    const id = randomUUID();
    const blob = await makeItemBlob(user.account.vaultKey, id, 1);
    const reply = await user.client.post(`${API}/items`, {
      id,
      blob: { ...blob, kdf: { ...blob.kdf, info: 'otra-cosa' } },
    });
    expect(reply.statusCode).toBe(400);
  });

  it('rechaza un id repetido con 409', async () => {
    const user = await register();
    const id = randomUUID();
    const blob = await makeItemBlob(user.account.vaultKey, id, 1);
    await user.client.post(`${API}/items`, { id, blob });

    const otra = await makeItemBlob(user.account.vaultKey, id, 1);
    const reply = await user.client.post(`${API}/items`, { id, blob: otra });
    expect(reply.statusCode).toBe(409);
  });

  it('sin sesion responde 401', async () => {
    const anonimo = makeClient(app);
    const blob = await makeItemBlob((await makeAccount()).vaultKey, randomUUID(), 1);
    const reply = await anonimo.post(`${API}/items`, { id: randomUUID(), blob });
    expect(reply.statusCode).toBe(401);
  });
});

describe('GET /items', () => {
  it('lista solo los items del usuario, del mas reciente al mas antiguo', async () => {
    const user = await register();
    const primero = await createItem(user, { title: 'Uno' });
    const segundo = await createItem(user, { title: 'Dos' });

    const reply = await user.client.get(`${API}/items`);
    expect(reply.statusCode).toBe(200);
    const body = reply.json() as { items: { id: string }[] };
    expect(body.items.map((i) => i.id)).toEqual([segundo.id, primero.id]);
  });

  it('la boveda de un usuario es vacia para el otro', async () => {
    const a = await register();
    const b = await register();
    await createItem(a, { title: 'Secreto-de-A' });

    const reply = await b.client.get(`${API}/items`);
    expect((reply.json() as { items: unknown[] }).items).toEqual([]);
  });

  it('devuelve los blobs descifrables por el propietario', async () => {
    const user = await register();
    const id = randomUUID();
    const blob = await makeItemBlob(user.account.vaultKey, id, 1, { title: 'Legible', password: 'x' });
    await user.client.post(`${API}/items`, { id, blob });

    const reply = await user.client.get(`${API}/items`);
    const body = reply.json() as { items: { id: string; blob: Parameters<typeof openItemBlob>[3] }[] };
    const item = body.items[0]!;
    expect(item.id).toBe(id);
    expect((await openItemBlob(user.account.vaultKey, id, 1, item.blob)).title).toBe('Legible');
  });
});

describe('GET /items/:id', () => {
  it('devuelve el item propio', async () => {
    const user = await register();
    const creado = await createItem(user);
    const reply = await user.client.get(`${API}/items/${creado.id}`);
    expect(reply.statusCode).toBe(200);
    expect((reply.json() as { id: string }).id).toBe(creado.id);
  });

  it('un item de otro usuario responde 404, no 403: no se confirma que exista', async () => {
    const a = await register();
    const b = await register();
    const creado = await createItem(a);

    const reply = await b.client.get(`${API}/items/${creado.id}`);
    expect(reply.statusCode).toBe(404);
  });

  it('un id que no es un UUID responde 404 sin tocar la base de datos', async () => {
    const user = await register();
    expect((await user.client.get(`${API}/items/12345`)).statusCode).toBe(404);
  });

  it('un UUID que no existe responde 404', async () => {
    const user = await register();
    expect((await user.client.get(`${API}/items/${randomUUID()}`)).statusCode).toBe(404);
  });
});

describe('PUT /items/:id (optimistic locking)', () => {
  it('actualiza y sube la version', async () => {
    const user = await register();
    const creado = await createItem(user, { title: 'Antiguo' });

    const blob = await makeItemBlob(user.account.vaultKey, creado.id, 1, { title: 'Nuevo' });
    const reply = await user.client.put(`${API}/items/${creado.id}`, { blob, version: creado.version });

    expect(reply.statusCode).toBe(200);
    expect((reply.json() as { version: number }).version).toBe(creado.version + 1);

    const leido = await user.client.get(`${API}/items/${creado.id}`);
    const body = leido.json() as { version: number; blob: Parameters<typeof openItemBlob>[3] };
    // OJO: para descifrar va la keyVersion (1), NO `body.version`, que ahora
    // vale 2. Son dos contadores distintos: `version` es el cerrojo de
    // optimistic locking y sube en cada escritura; `keyVersion` es la
    // generacion de la vaultKey y solo cambia en una rotacion real.
    expect((await openItemBlob(user.account.vaultKey, creado.id, 1, body.blob)).title).toBe('Nuevo');
  });

  it('el contador de version NO es la keyVersion: subirlo rompe el descifrado', async () => {
    // Documenta la trampa de forma explicita, porque es silenciosa: el AAD
    // lleva la keyVersion, asi que escribir el numero de version del item en
    // su lugar produce "unsupported state or unable to authenticate data" sin
    // ninguna pista sobre el motivo real.
    const user = await register();
    const creado = await createItem(user, { title: 'V1' });

    const blob = await makeItemBlob(user.account.vaultKey, creado.id, 1, { title: 'V2' });
    await user.client.put(`${API}/items/${creado.id}`, { blob, version: creado.version });

    const leido = await user.client.get(`${API}/items/${creado.id}`);
    const body = leido.json() as { version: number; blob: Parameters<typeof openItemBlob>[3] };

    expect(body.version).toBe(2); // el item va por su segunda version
    await expect(openItemBlob(user.account.vaultKey, creado.id, body.version, body.blob)).rejects.toThrow();
    expect((await openItemBlob(user.account.vaultKey, creado.id, 1, body.blob)).title).toBe('V2');
  });

  it('un item borrado en otra pestana responde 404', async () => {
    const user = await register();
    const creado = await createItem(user);
    const blob = await makeItemBlob(user.account.vaultKey, creado.id, 1, { title: 'Zombie' });

    await user.client.delete(`${API}/items/${creado.id}`);
    const reply = await user.client.put(`${API}/items/${creado.id}`, { blob, version: creado.version });
    expect(reply.statusCode).toBe(404);
  });

  it('CON LA MISMA VERSION devuelve 409 y NO pisa el cambio del otro dispositivo', async () => {
    const user = await register();
    const creado = await createItem(user, { title: 'Original' });

    // El otro dispositivo escribe primero.
    const suyo = await makeItemBlob(user.account.vaultKey, creado.id, 1, { title: 'Del otro' });
    const ok = await user.client.put(`${API}/items/${creado.id}`, {
      blob: suyo,
      version: creado.version,
    });
    expect(ok.statusCode).toBe(200);

    // Esta pestana sigue con la version vieja: el cambio se rechaza.
    const mio = await makeItemBlob(user.account.vaultKey, creado.id, 1, { title: 'Mio' });
    const choque = await user.client.put(`${API}/items/${creado.id}`, {
      blob: mio,
      version: creado.version,
    });
    expect(choque.statusCode).toBe(409);

    // Y el contenido que gana es el del otro, no el nuestro.
    const leido = await user.client.get(`${API}/items/${creado.id}`);
    const body = leido.json() as { version: number; blob: Parameters<typeof openItemBlob>[3] };
    // keyVersion 1, no `body.version` (que ya va por 3): son contadores
    // distintos, ver el test explicito de mas arriba.
    expect((await openItemBlob(user.account.vaultKey, creado.id, 1, body.blob)).title).toBe('Del otro');
  });

  it('con la version correcta tras un 409 se puede reintentar', async () => {
    const user = await register();
    const creado = await createItem(user);
    const otro = await makeItemBlob(user.account.vaultKey, creado.id, 1, { title: 'A' });
    await user.client.put(`${API}/items/${creado.id}`, { blob: otro, version: creado.version });

    const mio = await makeItemBlob(user.account.vaultKey, creado.id, 1, { title: 'B' });
    const reintento = await user.client.put(`${API}/items/${creado.id}`, {
      blob: mio,
      version: creado.version + 1,
    });
    expect(reintento.statusCode).toBe(200);
  });

  it('no permite actualizar el item de otro usuario', async () => {
    const a = await register();
    const b = await register();
    const creado = await createItem(a);
    const blob = await makeItemBlob(b.account.vaultKey, creado.id, 1, { title: 'Intruso' });

    const reply = await b.client.put(`${API}/items/${creado.id}`, { blob, version: creado.version });
    expect(reply.statusCode).toBe(404);
  });
});

describe('DELETE /items/:id', () => {
  it('responde 204 y el item desaparece del listado', async () => {
    const user = await register();
    const creado = await createItem(user);

    expect((await user.client.delete(`${API}/items/${creado.id}`)).statusCode).toBe(204);
    expect((await user.client.get(`${API}/items/${creado.id}`)).statusCode).toBe(404);

    const listado = await user.client.get(`${API}/items`);
    expect((listado.json() as { items: unknown[] }).items).toEqual([]);
  });

  it('es borrado logico: la fila sigue en la base de datos con deleted_at', async () => {
    const user = await register();
    const creado = await createItem(user);
    await user.client.delete(`${API}/items/${creado.id}`);

    // Borrado logico y no fisico es lo que permite sincronizar borrados entre
    // dispositivos sin que una operacion concurrente lo "resucite".
    const filas = await withAdmin(testConfig(), async (tx) => {
      const res = await tx.query<{ deleted_at: Date | null }>('SELECT deleted_at FROM items WHERE id = $1', [
        creado.id,
      ]);
      return res.rows;
    });
    expect(filas).toHaveLength(1);
    expect(filas[0]!.deleted_at).toBeInstanceOf(Date);
  });

  it('borrar dos veces el mismo item da 404 la segunda', async () => {
    const user = await register();
    const creado = await createItem(user);
    expect((await user.client.delete(`${API}/items/${creado.id}`)).statusCode).toBe(204);
    expect((await user.client.delete(`${API}/items/${creado.id}`)).statusCode).toBe(404);
  });

  it('no permite borrar el item de otro usuario', async () => {
    const a = await register();
    const b = await register();
    const creado = await createItem(a);

    expect((await b.client.delete(`${API}/items/${creado.id}`)).statusCode).toBe(404);

    // El item del otro sigue intacto.
    expect((await a.client.get(`${API}/items/${creado.id}`)).statusCode).toBe(200);
  });
});

describe('aislamiento de la sesion (RLS en la practica)', () => {
  it('el id de un item ajeno no se puede reutilizar para colarse en otra boveda', async () => {
    const a = await register();
    const b = await register();
    const deA = await createItem(a);

    // B intenta crear un item con el id que ya existe en la boveda de A.
    // El id es la clave primaria global, asi que la RLS lo bloquea: B no puede
    // ni escribir encima ni leer lo que hay.
    const blob = await makeItemBlob(b.account.vaultKey, deA.id, 1, { title: 'Colado' });
    const reply = await b.client.post(`${API}/items`, { id: deA.id, blob });
    expect(reply.statusCode).toBe(409);

    // El item de A no se ha visto afectado.
    const leido = await a.client.get(`${API}/items/${deA.id}`);
    expect(leido.statusCode).toBe(200);
  });

  it('cerrar sesion deja de dar acceso a los items', async () => {
    const user = await register();
    await createItem(user);

    expect((await user.client.get(`${API}/items`)).statusCode).toBe(200);
    await user.client.post(`${API}/auth/logout`);
    expect((await user.client.get(`${API}/items`)).statusCode).toBe(401);
  });

  it('con la cookie de sesion de A, el endpoint de items no devuelve nada de B', async () => {
    const a = await register();
    const b = await register();
    await createItem(b, { title: 'Privado-de-B' });

    // Cliente con la sesion de A pero querying el id de B.
    const suplantado = makeClient(app);
    await suplantado.cookies.set('__Host-sk_session', a.client.cookies.get('__Host-sk_session')!);
    await suplantado.cookies.set('__Host-sk_csrf', a.client.cookies.get('__Host-sk_csrf')!);

    const listado = await suplantado.get(`${API}/items`);
    expect((listado.json() as { items: unknown[] }).items).toEqual([]);
  });
});

// Tipos locales usados solo para castear la fila de la base de datos.
type TestItemKdf = { alg: 'HKDF-SHA256'; salt: string; info: string };
