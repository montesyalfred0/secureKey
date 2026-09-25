import type { FastifyInstance } from 'fastify';
import type { Config } from '../config.js';
import { withSystem } from '../db/withUser.js';

const startedAt = Date.now();

export async function healthRoutes(app: FastifyInstance, opts: { config: Config }): Promise<void> {
  const { config } = opts;

  app.get('/health', async (_request, reply) => {
    try {
      await withSystem(config, async (tx) => {
        await tx.query('SELECT 1');
      });
      return reply.send({
        status: 'ok',
        version: config.version,
        uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
        database: 'up',
      });
    } catch {
      return reply.code(503).send({
        error: { code: 'unhealthy', message: 'Base de datos no disponible' },
      });
    }
  });
}
