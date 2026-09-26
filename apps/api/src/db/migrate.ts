/**
 * Ejecutor de migraciones. Se invoca como servicio one-shot en `docker compose`
 * antes de que levante la API.
 */
import { loadConfig } from '../config.js';
import { runMigrations } from './migrations.js';
import { closePool, getPool } from './pool.js';

async function main(): Promise<void> {
  const config = loadConfig();

  for (let attempt = 1; attempt <= 30; attempt += 1) {
    try {
      await getPool(config.databaseUrl).query('SELECT 1');
      break;
    } catch (error) {
      if (attempt === 30) throw error;
      process.stdout.write(`Base de datos no disponible, reintento ${attempt}/30\n`);
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }

  const results = await runMigrations(config);
  for (const result of results) {
    process.stdout.write(`${result.applied ? 'aplicada  ' : 'omitida   '} ${result.id}\n`);
  }

  await closePool();

  // Salida explicita: los timers internos del pool de `pg` pueden mantener el
  // event loop vivo, y un servicio one-shot que no termina bloquea para
  // siempre el `depends_on: service_completed_successfully` de la API.
  process.exit(0);
}

main().catch((error: unknown) => {
  process.stderr.write(
    `Error en las migraciones: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
});
