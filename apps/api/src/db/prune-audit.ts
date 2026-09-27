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

/**
 * Lee un entero del entorno con defecto, sin caer en la trampa de `Number('')`.
 *
 * `AUDIT_KEEP_DAYS=` en el `.env` NO es lo mismo que no poner la variable: con
 * `??`, el texto vacio pasa de largo y `Number('')` es `0`. Con 0 dias y 0
 * filas, la primera pasada se lleva la bitacora entera. Comprobado: asi
 * borraba las 60 filas que habia.
 *
 * Ademas, un valor absurdo (negativo o NaN) es un fallo de configuracion que no
 * debe convertirse en "borra todo". Se cae al defecto y se avisa por stderr.
 *
 * Defectos: `AUDIT_KEEP_DAYS=7` (una semana basta para ver un ataque entero en
 * una instancia de porfolio) y `AUDIT_MAX_ROWS=20000`.
 *
 * El tope de filas viene de una MEDIDA, no de una suposicion: 128 bytes por
 * fila contando sus tres indices, o sea ~2,5 MB. Con el valor anterior de
 * 500 000 eran ~64 MB. Al ritmo que impone el limite de tasa por IP, llegar a
 * 20 000 filas lleva meses, asi que la cota dura solo entra en juego cuando
 * alguien dispara el caudal, que es justo para lo que existe.
 */
function enteroDelEntorno(nombre: string, defecto: number): number {
  const bruto = process.env[nombre];
  if (bruto === undefined || bruto.trim() === '') return defecto;
  const valor = Number(bruto);
  if (!Number.isFinite(valor) || valor < 0) {
    process.stderr.write(
      `${nombre}="${bruto}" no es un numero valido; se usa el valor por defecto ${defecto}.\n`,
    );
    return defecto;
  }
  return valor;
}

const KEEP_DAYS = enteroDelEntorno('AUDIT_KEEP_DAYS', 7);
const MAX_ROWS = enteroDelEntorno('AUDIT_MAX_ROWS', 20_000);

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
let fallo: string | null = null;

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
  // Un fallo aqui no debe tumbar el API, y el script se ejecuta dentro de un
  // bucle, asi que salir con exito evita un bucle de reinicios. Pero callarse
  // sale mas caro: asi un `permission denied` permanente dejo meses la defensa
  // muerta y el contenedor en "healthy", con una sola linea de log como unico
  // rastro.
  //
  // Por eso se sale con codigo 1. En un `while true` el bucle sigue igual, pero
  // el fallo queda a la vista en el log y en cualquier monitor que mire el
  // codigo de salida. El coste de un reinicio era cero; el beneficio era
  // invisible.
  fallo = error instanceof Error ? error.message : String(error);
  process.stderr.write(`No se pudo podar audit_log: ${fallo}\n`);
} finally {
  await closeAllPools();
}

process.exit(fallo === null ? 0 : 1);
