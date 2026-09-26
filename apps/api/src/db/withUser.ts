/**
 * Contexto de usuario con RLS (Row Level Security) de PostgreSQL.
 *
 * Cada peticion autenticada corre dentro de una transaccion en la que:
 *   1. Se cambia el rol efectivo al rol restringido `securekey_app`
 *      (sin privilegios de DDL y sujeto a las politicas RLS).
 *   2. Se publica `app.user_id`, que es lo que leen las politicas.
 *
 * `SET LOCAL` y `set_config(..., is_local => true)` hacen que ambos cambios
 * desaparezcan al hacer COMMIT/ROLLBACK, de modo que una conexion devuelta al
 * pool nunca puede arrastrar el contexto de otro usuario.
 */
import type { PoolClient, QueryResultRow } from 'pg';
import type { Config } from '../config.js';
import { getPool } from './pool.js';

export class DatabaseError extends Error {
  constructor(
    message: string,
    readonly code?: string,
  ) {
    super(message);
    this.name = 'DatabaseError';
  }
}

function codeOf(error: unknown): string | undefined {
  if (typeof error === 'object' && error !== null) {
    const code = (error as { code?: unknown }).code;
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}

/** Errores tras los cuales el estado de la transaccion es desconocido. */
const FATAL_CODES = new Set([
  'ECONNRESET',
  'EPIPE',
  'ETIMEDOUT',
  'ECONNREFUSED',
  '57P01', // admin_shutdown
  '57P02', // crash_shutdown
  '57P03', // cannot_connect_now
  '08000',
  '08003',
  '08006',
  '08P01',
]);

const DESTROY_REASON = 'securekey: estado de conexion desconocido';

function isFatal(error: unknown): boolean {
  const code = codeOf(error);
  return code !== undefined && FATAL_CODES.has(code);
}

/**
 * Envoltura de una transaccion.
 *
 * La liberacion del cliente ocurre EXACTAMENTE una vez, y en todas las rutas:
 * exito, error con ROLLBACK correcto y error con ROLLBACK fallido (en ese
 * ultimo caso se destruye la conexion en lugar de devolverla al pool).
 *
 * Omitir la liberacion en el camino feliz no es un detalle menor: el pool
 * tiene 10 conexiones y cada peticion que se Saltase la liberacion quemaria
 * una de forma permanente, hasta agotarlo.
 */
async function inTransaction<T>(
  config: Config,
  begin: (client: PoolClient) => Promise<void>,
  fn: (tx: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await getPool(config.databaseUrl).connect();
  let released = false;

  try {
    await client.query('BEGIN');
    await begin(client);
    const result = await fn(client);
    await client.query('COMMIT');
    client.release();
    released = true;
    return result;
  } catch (error) {
    let destroy = isFatal(error);
    try {
      await client.query('ROLLBACK');
    } catch {
      destroy = true;
    }
    client.release(destroy ? new Error(DESTROY_REASON) : undefined);
    released = true;
    throw new DatabaseError(
      error instanceof Error ? error.message : 'Error de base de datos',
      codeOf(error),
    );
  } finally {
    // Si hemos llegado aqui sin liberar, la transicion no se pudo cerrar y la
    // conexion no es reutilizable: se destruye en lugar de filtrarla.
    if (!released) client.release(new Error(DESTROY_REASON));
  }
}

/**
 * Ejecuta `fn` en una transaccion aislada, con RLS activada para `userId`.
 */
export function withUser<T>(
  config: Config,
  userId: string,
  fn: (tx: PoolClient) => Promise<T>,
): Promise<T> {
  return inTransaction(
    config,
    async (client) => {
      await client.query('SET LOCAL ROLE securekey_app');
      await client.query(`SELECT set_config('app.user_id', $1, true)`, [userId]);
    },
    fn,
  );
}

/**
 * Consulta fuera del contexto de usuario. Reservada a las funciones
 * SECURITY DEFINER que necesita el flujo de autenticacion, y para las
 * migraciones.
 *
 * Conecta con `config.databaseUrl`, que es el rol RESTRINGIDO. Las migraciones
 * necesitan superusuario y por eso usan `withSystemAdmin`: conectan con
 * `config.databaseAdminUrl`, que el servicio de migraciones tiene y la API no.
 */
export function withSystem<T>(
  config: Config,
  fn: (tx: PoolClient) => Promise<T>,
): Promise<T> {
  return inTransaction(config, async () => {}, fn);
}

/**
 * Igual que `withSystem`, pero por el canal de superusuario.
 *
 * Solo debe usarse en migraciones y en la creacion del rol de la API. Que exista
 * una via separada es lo que hace explicito que la API no la tiene: si las
 * migraciones usaran `withSystem`, el servicio `migrate` tendria que llevar el
 * rol restringido, que no puede hacer `CREATE ROLE`.
 */
export function withSystemAdmin<T>(
  config: Config,
  fn: (tx: PoolClient) => Promise<T>,
): Promise<T> {
  return inTransaction({ ...config, databaseUrl: config.databaseAdminUrl }, async () => {}, fn);
}

export function firstRow<T extends QueryResultRow>(rows: readonly T[]): T | undefined {
  return rows[0];
}
