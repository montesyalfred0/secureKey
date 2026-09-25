import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import { hashToken, safeEqual } from '../crypto/server.js';
import { clearSessionCookies, resolveSession, SESSION_COOKIE } from '../auth/session.js';
import { audit } from '../auth/audit.js';
import { unauthorized, forbidden } from '../http/errors.js';
import { AppError } from '../http/errors.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Resuelve la sesion de la peticion y la adjunta a `request.auth`.
 * Nunca lanza: devuelve `null` para que cada ruta decida que hacer.
 */
export async function attachAuth(
  config: Config,
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const token = request.cookies[SESSION_COOKIE];
  const session = await resolveSession(config, token);

  if (!session) {
    if (token) clearSessionCookies(reply);
    return;
  }

  // Doble envio de CSRF: la cookie legible por JS debe coincidir con el hash
  // almacenado. SameSite=Strict ya bloquea la mayoría, esto es defensa extra.
  if (!SAFE_METHODS.has(request.method)) {
    const header = request.headers['x-csrf-token'];
    const presented = typeof header === 'string' ? header : '';
    if (!presented || !safeEqual(hashToken(presented), session.csrfHash)) {
      await audit(config, {
        userId: session.userId,
        action: 'security.csrf_rejected',
        request,
      }).catch(() => undefined);
      clearSessionCookies(reply);
      throw forbidden('Token CSRF ausente o invalido');
    }
  }

  request.auth = {
    sessionId: session.sessionId,
    userId: session.userId,
    email: session.email,
  };
}

/** `preHandler` que exige sesion valida. */
export function requireAuth(config: Config) {
  return async function authGuard(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    await attachAuth(config, request, reply);
    if (!request.auth) {
      throw unauthorized('Sesion no valida o expirada');
    }
  };
}

export function currentUser(request: FastifyRequest): NonNullable<FastifyRequest['auth']> {
  const auth = request.auth;
  if (!auth) {
    throw new AppError(401, 'unauthorized', 'Sesion no valida o expirada');
  }
  return auth;
}
