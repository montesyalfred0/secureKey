/**
 * Bitacora de seguridad. Solo metadatos: jamas una contrasena, un titulo ni un
 * texto descifrado. Un atacante con acceso a la BD no obtiene nada util.
 */
import type { FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import { withUser } from '../db/withUser.js';
import { clientIp, userAgent } from './session.js';

const NIL_UUID = '00000000-0000-0000-0000-000000000000';

export type AuditAction =
  | 'auth.register'
  | 'auth.login.ok'
  | 'auth.login.fail'
  | 'auth.login.locked'
  | 'auth.unlock.ok'
  | 'auth.unlock.fail'
  | 'auth.logout'
  | 'auth.rekey'
  | 'auth.master_password.changed'
  // Borrado de la cuenta. `deleted` es la unica accion que sobrevive a la
  // cuenta: `audit_log` no cuelga de `users`, asi que queda constancia de que
  // existio sin conservar nada suyo. `fail` es el intento con contrasena
  // maestra incorrecta, que es justamente el caso que de verdad avisa.
  | 'auth.account.deleted'
  | 'auth.delete.fail'
  | 'items.create'
  | 'items.read'
  | 'items.update'
  | 'items.delete'
  | 'session.idle_timeout'
  | 'security.csrf_rejected';

export async function audit(
  config: Config,
  params: {
    userId: string | null;
    action: AuditAction;
    itemId?: string | null;
    request?: FastifyRequest;
  },
): Promise<void> {
  const scope = params.userId ?? NIL_UUID;
  await withUser(config, scope, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log (user_id, action, item_id, ip, user_agent)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        params.userId,
        params.action,
        params.itemId ?? null,
        params.request ? clientIp(params.request) : null,
        params.request ? userAgent(params.request) : null,
      ],
    );
  });
}
