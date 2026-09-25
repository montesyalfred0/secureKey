import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import type { Config } from './config.js';
import { securityPlugin } from './plugins/security.js';
import { AppError } from './http/errors.js';
import { authRoutes } from './routes/auth.js';
import { itemRoutes } from './routes/items.js';
import { healthRoutes } from './routes/health.js';

export const API_PREFIX = '/api/v1';

export async function buildApp(config: Config): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      // Nunca registramos cuerpos ni cabeceras de autorizacion/cookies:
      // `redact` es la red de seguridad ante un descuido futuro.
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'req.headers["x-csrf-token"]',
          'req.body',
          'res.headers["set-cookie"]',
        ],
        censor: '[redactado]',
      },
    },
    // Detras de Caddy: sin esto `request.ip` seria siempre la IP del proxy y
    // el rate limiting seria inutil.
    trustProxy: true,
    bodyLimit: 256 * 1024,
    disableRequestLogging: config.isProduction,
    ajv: { customOptions: { removeAdditional: false, coerceTypes: false } },
  });

  await app.register(cookie, { parseOptions: { path: '/' } });
  await app.register(securityPlugin, { config });

  app.setErrorHandler((error: FastifyError, request, reply) => {
    if (error instanceof AppError) {
      if (error.statusCode >= 500) {
        request.log.error({ err: error, code: error.code }, 'error de aplicacion');
      }
      return reply.code(error.statusCode).send({
        error: {
          code: error.code,
          message: error.message,
          ...(error.details === undefined ? {} : { details: error.details }),
        },
      });
    }

    // Todo lo que no sea un `AppError` lo tratamos como fallo nuestro y nunca
    // devolvemos su mensaje interno: puede filtrar nombres de tabla, rutas o
    // valores de entorno. El rate limiting tambien llega aqui, pero como
    // `AppError` (lo lanza `errorResponseBuilder`), asi que conserva su 429.
    const status = error.statusCode ?? 500;
    if (status >= 500) {
      request.log.error({ err: error }, 'error no controlado');
    }
    return reply.code(status).send({
      error: {
        code: 'internal_error',
        message: status >= 500 ? 'Error interno del servidor' : error.message,
      },
    });
  });

  app.setNotFoundHandler((_request, reply) => {
    reply.code(404).send({ error: { code: 'not_found', message: 'Ruta no encontrada' } });
  });

  await app.register(
    async (api) => {
      await healthRoutes(api, { config });
      await authRoutes(api, { config });
      await itemRoutes(api, { config });
    },
    { prefix: API_PREFIX },
  );

  return app;
}
