/**
 * Limite de tasa.
 *
 * Este fichero verifica un comportamiento que ya estuvo roto: cuando se
 * supera el limite, `@fastify/rate-limit` hace `throw errorResponseBuilder(...)`,
 * es decir lanza LITERALMENTE el valor devuelto. Si ese valor es un objeto
 * plano, Fastify lo ve como un error sin `statusCode` y responde 500, asi que
 * el cliente recibia "error del servidor" en lugar de "demasiadas peticiones".
 *
 * Cada test crea su PROPIA app con su PROPRIO umbral en vez de compartir una.
 * Depender del estado acumulado de la cuota haria que el resultado dependiera
 * del orden de ejecucion, que es la forma mas habitual de tener tests que
 * pasan en local y fallan en CI.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { closeDatabase, createTestApp, makeClient, resetDatabase, testConfig } from '../helpers.js';

const API = '/api/v1';

/** App propia con un limite global de `max` peticiones por minuto. */
async function appWithLimit(max: number): Promise<FastifyInstance> {
  const built = await createTestApp({ RATE_LIMIT_GLOBAL_MAX: String(max) });
  return built.app;
}

let shared: FastifyInstance;

beforeAll(async () => {
  shared = await appWithLimit(1000);
});

afterAll(async () => {
  await shared.close();
  await closeDatabase();
});

beforeEach(async () => {
  await resetDatabase(testConfig());
});

describe('limite de tasa global', () => {
  it('deja pasar las peticiones por debajo del limite', async () => {
    const app = await appWithLimit(3);
    const client = makeClient(app);
    for (let i = 0; i < 3; i += 1) {
      expect((await client.get(`${API}/health`)).statusCode).toBe(200);
    }
    await app.close();
  });

  it('al superarlo responde 429, NO 500', async () => {
    const app = await appWithLimit(3);
    const client = makeClient(app);
    for (let i = 0; i < 3; i += 1) await client.get(`${API}/health`);

    const reply = await client.get(`${API}/health`);
    expect(reply.statusCode).toBe(429);

    const body = reply.json() as { error: { code: string; message: string } };
    expect(body.error.code).toBe('rate_limited');
    // El mensaje es el de la app, no "Error interno del servidor": eso es
    // justamente lo que se rompia antes.
    expect(body.error.message).toBe('Demasiadas peticiones, intentalo mas tarde');
    await app.close();
  });

  it('el 429 no es un 5xx y no filtra detalles internos', async () => {
    const app = await appWithLimit(1);
    const client = makeClient(app);
    await client.get(`${API}/health`);

    const reply = await client.get(`${API}/health`);
    expect(reply.statusCode).toBe(429);
    expect(reply.statusCode).toBeLessThan(500);
    expect(reply.body).not.toContain('Error interno del servidor');
    expect(reply.body).not.toContain('node_modules');
    await app.close();
  });

  it('expone las cabeceras de limite de tasa con el remanente a cero', async () => {
    const app = await appWithLimit(2);
    const client = makeClient(app);
    await client.get(`${API}/health`);

    const reply = await client.get(`${API}/health`);
    expect(reply.headers['x-ratelimit-limit']).toBe('2');
    expect(reply.headers['x-ratelimit-remaining']).toBe('0');
    await app.close();
  });

  it('el limite por ruta de prelogin se puede ajustar por configuracion', async () => {
    const app = (
      await createTestApp({
        RATE_LIMIT_GLOBAL_MAX: '1000000',
        RATE_LIMIT_PRELOGIN_MAX: '2',
      })
    ).app;
    const client = makeClient(app);

    expect((await client.post(`${API}/auth/prelogin`, { email: 'a@example.test' })).statusCode).toBe(200);
    expect((await client.post(`${API}/auth/prelogin`, { email: 'b@example.test' })).statusCode).toBe(200);
    // El tercero agota el cupo de prelogin, aunque el global sea enorme.
    expect((await client.post(`${API}/auth/prelogin`, { email: 'c@example.test' })).statusCode).toBe(429);

    await app.close();
  });

  it('el limite global no se aplica a rutas con su propio limite mas alto', async () => {
    // El global es 1, pero prelogin tiene 100: manda el especifico.
    const app = (
      await createTestApp({
        RATE_LIMIT_GLOBAL_MAX: '1',
        RATE_LIMIT_PRELOGIN_MAX: '100',
      })
    ).app;
    const client = makeClient(app);

    expect((await client.post(`${API}/auth/prelogin`, { email: 'a@example.test' })).statusCode).toBe(200);
    expect((await client.post(`${API}/auth/prelogin`, { email: 'b@example.test' })).statusCode).toBe(200);
    // Una ruta sin limite especifico (`/session`) si obeyece el global.
    expect((await client.get(`${API}/session`)).statusCode).toBe(200);
    expect((await client.get(`${API}/session`)).statusCode).toBe(429);

    await app.close();
  });
});
