/**
 * Podador de la bitacora de seguridad.
 *
 * Se ejecuta como servicio one-shot periodico (ver `prune` en
 * docker-compose.yml). Existe porque `audit_log` se rellena desde la red sin
 * autenticar: cada login fallido inserta una fila, y cada fila cuesta el heap
 * mas tres indices. Sin esto, el disco se llena solo y es una denegacion de
 * servicio gratuita para cualquiera que sepa la URL.
 *
 * Usa dos topes a la vez, porque cada uno cubre un fallo del otro:
 *   - antiguedad maxima: la que manda en el uso diario.
 *   - numero maximo de filas: cota dura si un ataque dispara el caudal entre
 *     dos pasada, mas rapido de lo que la poda puede seguir.
 */
import { closeAllPools, getPool } from './pool.js';

/** Dias que se conservan. Ajuste de despliegue, no de codigo. */
const KEEP_DAYS = Number(process.env['AUDIT_KEEP_DAYS'] ?? 30);

/** Cota dura de filas. ~50 MB con los indices actuales. */
const MAX_ROWS = Number(process.env['AUDIT_MAX_ROWS'] ?? 500_000);

/** Espera maxima a que la base de datos este lista. */
const WAIT_ATTEMPTS = 30;

// Solo se lee `DATABASE_URL`, no el `Config` completo. Asi este contenedor no
// necesita el `AUTH_PEPPER` para arrancar: no toca la tabla de usuarios, y no
// deberia poder ni leer ese secreto. Es la unica excepcion al arranque
// tranquilo del resto de la API, y esta justificada.
const databaseUrlRaw = process.env['DATABASE_URL'];
if (databaseUrlRaw === undefined || databaseUrlRaw.length === 0) {
  process.stderr.write('DATABASE_URL no esta definido. No se puede podar.\n');
  process.exit(1);
}
const databaseUrl: string = databaseUrlRaw;

async function waitForDatabase(): Promise<void> {
  for (let attempt = 1; attempt <= WAIT_ATTEMPTS; attempt += 1) {
    try {
      await getPool(databaseUrl).query('SELECT 1');
      return;
    } catch (error) {
      if (attempt === WAIT_ATTEMPTS) throw error;
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
}

let removed: bigint;

try {
  await waitForDatabase();
  const result = await getPool(databaseUrl).query<{ audit_prune: bigint }>(
    'SELECT audit_prune($1::integer, $2::bigint)',
    [KEEP_DAYS, MAX_ROWS],
  );
  removed = result.rows[0]?.audit_prune ?? 0n;
  process.stdout.write(
    `audit_log: ${removed} fila(s) borrada(s) (conservando ${KEEP_DAYS} dias, max ${MAX_ROWS} filas)\n`,
  );
} catch (error) {
  // Un fallo aqui NO debe tumbar el servicio ni el API: solo se queda sin
  // podar esta pasada. Se avisa por stderr y se sale con codigo 0 para que el
  // orquestador no entre en bucle de reinicios.
  process.stderr.write(`No se pudo podar audit_log: ${error instanceof Error ? error.message : String(error)}\n`);
} finally {
  await closeAllPools();
}

process.exit(0);
