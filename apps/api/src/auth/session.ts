/**
 * Sesiones opacas sin estado visible para el cliente.
 *
 * El token viaja en una cookie httpOnly y en la base de datos solo se guarda
 * su SHA-256. El doble envio de CSRF usa una segunda cookie legible por JS que
 * se compara (hasheada) con la almacenada.
 */
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import { withSystem, withUser } from '../db/withUser.js';
import { generateToken, hashToken } from '../crypto/server.js';

export const SESSION_COOKIE = '__Host-sk_session';
export const CSRF_COOKIE = '__Host-sk_csrf';

const BASE_COOKIE = {
  path: '/',
  sameSite: 'strict',
  secure: true,
  // Sin `domain`: el prefijo __Host- lo exige y asi la cookie no puede ser
  // fijada desde un subdominio atacante.
} as const;

export type SessionRow = {
  id: string;
  user_id: string;
  csrf_hash: Buffer;
  created_at: Date;
  last_seen_at: Date;
  expires_at: Date;
  ip: string | null;
  user_agent: string | null;
};

export type ResolvedSession = {
  sessionId: string;
  userId: string;
  email: string;
  csrfHash: Buffer;
};

type SessionLookupRow = Omit<SessionRow, 'token_hash'>;

export async function createSession(
  config: Config,
  reply: FastifyReply,
  userId: string,
  request: FastifyRequest,
): Promise<void> {
  const token = generateToken();
  const csrf = generateToken();
  const now = Date.now();

  await withUser(config, userId, async (tx) => {
    await tx.query(
      `INSERT INTO sessions (user_id, token_hash, csrf_hash, created_at, last_seen_at, expires_at, ip, user_agent)
       VALUES ($1, $2, $3, to_timestamp($4/1000.0), to_timestamp($4/1000.0), to_timestamp($5/1000.0), $6, $7)`,
      [
        userId,
        hashToken(token),
        hashToken(csrf),
        now,
        now + config.sessionTtlMs,
        clientIp(request),
        userAgent(request),
      ],
    );
  });

  const maxAge = Math.floor(config.sessionTtlMs / 1000);
  reply.setCookie(SESSION_COOKIE, token, { ...BASE_COOKIE, httpOnly: true, maxAge });
  reply.setCookie(CSRF_COOKIE, csrf, { ...BASE_COOKIE, httpOnly: false, maxAge });
}

export async function resolveSession(
  config: Config,
  token: string | undefined,
): Promise<ResolvedSession | null> {
  if (!token || token.length < 32) return null;

  const tokenHash = hashToken(token);
  const rows = await withSystemLookup(config, tokenHash);
  const row = rows[0];
  if (!row) return null;

  const now = Date.now();
  if (row.expires_at.getTime() <= now) {
    await destroySession(config, row.id, row.user_id);
    return null;
  }
  if (now - row.last_seen_at.getTime() > config.sessionIdleMs) {
    await destroySession(config, row.id, row.user_id);
    return null;
  }

  // Renovacion deslizante de la marca de actividad.
  await withUser(config, row.user_id, async (tx) => {
    await tx.query(`UPDATE sessions SET last_seen_at = now() WHERE id = $1`, [row.id]);
  });

  const emailRows = await withUser(config, row.user_id, async (tx) => {
    const res = await tx.query<{ email: string }>('SELECT email FROM users WHERE id = $1', [
      row.user_id,
    ]);
    return res.rows;
  });
  const email = emailRows[0]?.email;
  if (!email) return null;

  return {
    sessionId: row.id,
    userId: row.user_id,
    email,
    csrfHash: row.csrf_hash,
  };
}

async function withSystemLookup(
  config: Config,
  tokenHash: Buffer,
): Promise<SessionLookupRow[]> {
  return withSystem(config, async (tx) => {
    const res = await tx.query<SessionLookupRow>(
      `SELECT id, user_id, csrf_hash, created_at, last_seen_at, expires_at, ip, user_agent
         FROM session_lookup($1)`,
      [tokenHash],
    );
    return res.rows;
  });
}

export async function destroySession(
  config: Config,
  sessionId: string,
  userId: string,
): Promise<void> {
  await withUser(config, userId, async (tx) => {
    await tx.query('DELETE FROM sessions WHERE id = $1', [sessionId]);
  });
}

/** Borra la cookie de sesion y la de CSRF. */
export function clearSessionCookies(reply: FastifyReply): void {
  reply.clearCookie(SESSION_COOKIE, { ...BASE_COOKIE, httpOnly: true });
  reply.clearCookie(CSRF_COOKIE, { ...BASE_COOKIE, httpOnly: false });
}

export function clientIp(request: FastifyRequest): string | null {
  return request.ip ?? null;
}

export function userAgent(request: FastifyRequest): string | null {
  const ua = request.headers['user-agent'];
  return typeof ua === 'string' ? ua.slice(0, 512) : null;
}
