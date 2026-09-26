import { Pool } from 'pg';

/**
 * Pools indexados por cadena de conexion.
 *
 * Antes esto era un unico singleton. Con el rol restringido hacen falta DOS
 * conexiones distintas en el mismo proceso: la de la API (rol sin superusuario)
 * y la de las migraciones (superusuario). Con un singleton, la primera que se
 * creaba ganaba para siempre y el resto del proceso acababa con el rol
 * equivocado: en los tests eso hacia que la app bajo prueba se ejecutara con
 * superusuario y no detectara consultas que ya no tenian permisos.
 */
const pools = new Map<string, Pool>();

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
  const existing = pools.get(databaseUrl);
  if (existing) return existing;

  const created = createPool(databaseUrl);
  pools.set(databaseUrl, created);
  return created;
}

/** Cierra el pool de una URL concreta. */
export async function closePool(databaseUrl: string): Promise<void> {
  const pool = pools.get(databaseUrl);
  if (pool === undefined) return;
  pools.delete(databaseUrl);
  await pool.end();
}

/**
 * Cierra TODOS los pools. Es lo que necesitan los tests, que mueven las URLs
 * entre rol de aplicación y de administración dentro del mismo proceso.
 */
export async function closeAllPools(): Promise<void> {
  const todos = [...pools.values()];
  pools.clear();
  await Promise.all(todos.map((pool) => pool.end()));
}
