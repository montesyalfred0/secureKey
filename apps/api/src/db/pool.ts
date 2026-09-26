import { Pool } from 'pg';

let pool: Pool | undefined;

/**
 * Recibe la cadena de conexion y no el `Config` entero a proposito.
 *
 * El podador de la bitacora (`prune-audit.js`) solo necesita la base de
 * datos, y si tomara el `Config` completo habria que darle el `AUTH_PEPPER`
 * para que pasara la validacion. Un contenedor que no toca la tabla de
 * usuarios no deberia poder ni leer el pepper.
 */
export function createPool(databaseUrl: string): Pool {
  return new Pool({
    connectionString: databaseUrl,
    application_name: 'securekey-api',
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    // Cinturon de seguridad: ninguna consulta puede retener recursos indefinidamente.
    statement_timeout: 10_000,
    query_timeout: 10_000,
  });
}

export function getPool(databaseUrl: string): Pool {
  pool ??= createPool(databaseUrl);
  return pool;
}

export async function closePool(): Promise<void> {
  if (pool) {
    const p = pool;
    pool = undefined;
    await p.end();
  }
}
