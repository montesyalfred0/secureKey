import { Pool } from 'pg';
import type { Config } from '../config.js';

let pool: Pool | undefined;

export function createPool(config: Config): Pool {
  return new Pool({
    connectionString: config.databaseUrl,
    application_name: 'securekey-api',
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    // Cinturon de seguridad: ninguna consulta puede retener recursos indefinidamente.
    statement_timeout: 10_000,
    query_timeout: 10_000,
  });
}

export function getPool(config: Config): Pool {
  pool ??= createPool(config);
  return pool;
}

export async function closePool(): Promise<void> {
  if (pool) {
    const p = pool;
    pool = undefined;
    await p.end();
  }
}
