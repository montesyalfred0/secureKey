import 'fastify';
import type { SessionRow } from '../auth/session.js';

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * Sesion resuelta por `attachAuth`. Es `null` (no `undefined`) cuando la
     * peticion no lleva sesion, para que los type guards sean explicitos.
     */
    auth: {
      sessionId: string;
      userId: string;
      email: string;
    } | null;
  }
}

export type { SessionRow };
