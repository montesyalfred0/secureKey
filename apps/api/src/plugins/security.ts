/**
 * Cabeceras de seguridad, limite de tasa y validacion de origen.
 *
 * No hay CORS: el SPA y la API se sirven desde el MISMO origen a traves de
 * Caddy, asi que no hace falta. Lo que si hacemos es rechazar cualquier
 * peticion mutante cuyo `Origin` no este permitido, que es la mitad server-side
 * de la defensa CSRF (la otra mitad es SameSite=Strict + doble envio).
 */
import fp from 'fastify-plugin';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import { AppError, forbidden } from '../http/errors.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export const securityPlugin = fp(
  async (app: FastifyInstance, opts: { config: Config }) => {
    const { config } = opts;
    const allowed = new Set(config.allowedOrigins);

    await app.register(helmet, {
      // El HTML lo sirve `web`; aqui solo hay JSON.
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: true,
      crossOriginResourcePolicy: { policy: 'same-site' },
      referrerPolicy: { policy: 'no-referrer' },
      // NoRelevantHeaderOptionSent ya no es necesario en helmet 13.
      hsts: config.isProduction
        ? { maxAge: 31_536_000, includeSubDomains: true, preload: false }
        : false,
    });

    // Limite global. Los limites finos por ruta se aplican donde hace falta
    // (prelogin/login), que son las unicas operaciones craving CPU.
    await app.register(rateLimit, {
      global: true,
      max: config.rateLimits.global,
      timeWindow: '1 minute',
      // Detras de Caddy: usar X-Forwarded-For (trustedProxy = true en app.ts).
      keyGenerator: (request: FastifyRequest) => request.ip,
      addHeadersOnExceeding: { 'x-ratelimit-limit': true, 'x-ratelimit-remaining': true },
      // OJO: el plugin hace `throw errorResponseBuilder(req, ctx)`, es decir,
      // lanza LITERALMENTE lo que devolvamos aqui. Si devolvemos un objeto
      // plano, Fastify lo trata como un error sin `statusCode` y responde 500:
      // el cliente veria "error del servidor" donde deberia ver "demasiadas
      // peticiones". Devolviendo un `AppError` el statusCode y el cuerpo
      // pasan intactos por el manejador de errores de la app.
      errorResponseBuilder: (_request, context) =>
        new AppError(
          context.statusCode,
          'rate_limited',
          'Demasiadas peticiones, intentalo mas tarde',
        ),
    });

    app.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
      // Estado por peticion: garantiza que `request.auth` siempre exista.
      request.auth = null;

      if (SAFE_METHODS.has(request.method)) return;

      const origin = request.headers.origin;
      if (origin !== undefined && !allowed.has(origin)) {
        throw forbidden('Origen no permitido');
      }
    });
  },
  { name: 'securekey-security' },
);
