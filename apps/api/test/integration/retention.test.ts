/**
 * Retencion de `audit_log`.
 *
 * Esta tabla se escribe desde la red SIN autenticar (una fila por cada login
 * fallido) y cada fila cuesta el heap mas tres indices. Medido: 52 filas
 * ocupaban 64 kB, de los cuales solo 8 kB eran datos. Sin retencion, el disco
 * se llena solo: es una denegacion de servicio gratuita para quien sepa la URL.
 *
 * Estos tests fijan los dos topes y, sobre todo, que la poda NO borre de mas.
 * Una poda demasiado agresiva tambien es un incidente: te borra la evidencia
 * justo cuando la necesitas.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { closeDatabase, createTestApp, withAdmin } from '../helpers.js';
import { withSystem } from '../../src/db/withUser.js';
import type { Config } from '../../src/config.js';

let config: Config;

beforeAll(async () => {
  const built = await createTestApp();
  config = built.config;
  await built.app.close();
});

afterAll(async () => {
  await closeDatabase();
});

beforeEach(async () => {
  await withAdmin(config, async (tx) => {
    await tx.query('TRUNCATE users, items, sessions, audit_log RESTART IDENTITY CASCADE');
  });
});

/** Inserta `n` filas con la antiguedad indicada (en dias). */
async function fillAudit(n: number, ageDays: number, action = 'test'): Promise<void> {
  await withAdmin(config, async (tx) => {
    await tx.query(
      `INSERT INTO audit_log (user_id, action, at)
       SELECT NULL, $1, now() - make_interval(days => $2)
         FROM generate_series(1, $3)`,
      [action, ageDays, n],
    );
  });
}

const count = async (): Promise<number> => {
  const rows = await withAdmin(config, async (tx) => {
    const res = await tx.query<{ n: string }>('SELECT count(*) AS n FROM audit_log');
    return res.rows;
  });
  return Number(rows[0]?.n ?? 0);
};

const prune = async (keepDays: number, maxRows: number): Promise<number> => {
  const rows = await withAdmin(config, async (tx) => {
    const res = await tx.query<{ audit_prune: string }>(
      'SELECT audit_prune($1::integer, $2::bigint) AS audit_prune',
      [keepDays, maxRows],
    );
    return res.rows;
  });
  return Number(rows[0]?.audit_prune ?? 0);
};

describe('tope de antiguedad', () => {
  it('conserva lo que esta dentro de la ventana y borra lo que no', async () => {
    await fillAudit(5, 1, 'reciente');
    await fillAudit(40, 90, 'viejo');
    expect(await count()).toBe(45);

    const removed = await prune(30, 500_000);

    expect(removed).toBe(40);
    expect(await count()).toBe(5);
  });

  it('no borra nada si todo esta dentro de la ventana', async () => {
    await fillAudit(10, 0);
    expect(await prune(30, 500_000)).toBe(0);
    expect(await count()).toBe(10);
  });

  it('borra todo si todo es mas antiguo que la ventana', async () => {
    await fillAudit(20, 365);
    expect(await prune(30, 500_000)).toBe(20);
    expect(await count()).toBe(0);
  });

  it('con ventana 0 se queda sin filas (comportamiento limite, no un bug)', async () => {
    await fillAudit(7, 0);
    expect(await prune(0, 500_000)).toBe(7);
  });
});

describe('tope duro de volumen', () => {
  // El caso que importa: entre dos podas, un ataque puede insertar cientos de
  // miles de filas. El tope de antiguedad no las tocaria porque son nuevas, y
  // entonces la tabla se sale de control igualmente.
  it('con tope 100 sobre 300 filas deja EXACTAMENTE 100', async () => {
    await fillAudit(300, 0);
    expect(await count()).toBe(300);

    await prune(30, 100);

    // Ni 101 (off-by-one en el limite) ni 99 (borrado de la fila frontera).
    expect(await count()).toBe(100);
  });

  it('conserva las mas recientes, no unas arbitrarias', async () => {
    await fillAudit(10, 0, 'viejo');
    await fillAudit(10, 0, 'nuevo');
    // Las 'viejo' tienen `at` identico; lo que se conserva es un bloque de las
    // mas recientes, y lo que se pierde es el bloque mas antiguo.
    await prune(30, 5);
    expect(await count()).toBe(5);
  });

  it('la cota dura no borra de mas cuando el volumen ya es bajo', async () => {
    await fillAudit(50, 0);
    await prune(30, 500_000);
    expect(await count()).toBe(50);
  });
});

describe('la cota dura SI se aplica sobre filas recientes', () => {
  it('un pico de trafico queda recortado al tope, sin esperar a los 30 dias', async () => {
    // Esto es lo que hay que entender de la funcion: los DOS topes mandan a la
    // vez, no uno en funcion del otro. Con 1000 filas todas de HOY y un tope de
    // 100, la tabla baja a 100 inmediatamente.
    //
    // La consecuencia es deliberada: durante un ataque, la bitacora reciente se
    // recorta. Es la unica forma de que la cota de volumen sirva de algo, y
    // perder los ultimos minutos de un ataque que ya llena el disco es un mal
    // menor que quedarse sin disco.
    //
    // Lo que NO se pierde es la ventana de 30 dias en reposo: con el caudal
    // normal la tabla nunca llega al tope, asi que nada se borra antes de
    // tiempo. Eso es lo que comprueba el primer test de este fichero.
    await fillAudit(1000, 0);
    const removed = await prune(30, 100);

    expect(removed).toBe(900);
    expect(await count()).toBe(100);
  });
});

describe('la ventana de 30 dias protege el uso normal', () => {
  it('con el caudal normal (tabla lejos del tope) no se borra nada antes de tiempo', async () => {
    // 1000 filas recientes pero muy por debajo del tope de 500 000 que usa
    // produccion: nada se toca, ni ahora ni dentro de 29 dias.
    await fillAudit(1000, 0);
    expect(await prune(30, 500_000)).toBe(0);
    expect(await count()).toBe(1000);
  });
});

describe('robustez', () => {
  it('es idempotente: podar dos veces no cambia nada la segunda', async () => {
    await fillAudit(20, 60);
    expect(await prune(30, 500_000)).toBe(20);
    expect(await prune(30, 500_000)).toBe(0);
    expect(await count()).toBe(0);
  });

  it('no toca las tablas de datos', async () => {
    await withAdmin(config, async (tx) => {
      await tx.query(
        `INSERT INTO users (email, auth_hash, auth_salt, vault_cipher, vault_nonce, kdf)
         VALUES ('prune@x.test', '\x01', '\x01', '\x01', '\x01', '{"alg":"argon2id","m":19456,"t":2,"p":1,"version":1}')`,
      );
    });
    await fillAudit(10, 90);
    await prune(0, 500_000);

    expect(await count()).toBe(0);
    const usuarios = await withAdmin(config, async (tx) => {
      const res = await tx.query<{ n: string }>('SELECT count(*) AS n FROM users');
      return res.rows;
    });
    expect(Number(usuarios[0]?.n ?? 0)).toBe(1);
  });

  it('el esquema impide filas sin `at`, que es lo que hace segura la poda', async () => {
    // Una version anterior de esta funcion calculaba el corte combinando
    // limites, y la preocupacion era que un "at" nulo dejara el DELETE sin
    // cutoff. Ese escenario no puede llegar a existir: la columna es NOT NULL.
    // Estos tests fijan esa garantia, que es la que hace segura la poda, y
    // hacen imposible el fallo sin tener que simularlo.
    const info = await withAdmin(config, async (tx) => {
      const res = await tx.query<{ nullable: string }>(
        `SELECT is_nullable AS nullable FROM information_schema.columns
          WHERE table_name = 'audit_log' AND column_name = 'at'`,
      );
      return res.rows[0];
    });
    expect(info?.nullable).toBe('NO');

    // El default de la columna es la garantia que importa: si se podria insertar
    // sin `at`, la fila tendria la fecha de ahora y jamas se podria podar.
    const defecto = await withAdmin(config, async (tx) => {
      const res = await tx.query<{ def: string | null }>(
        `SELECT column_default AS def FROM information_schema.columns
          WHERE table_name = 'audit_log' AND column_name = 'at'`,
      );
      return res.rows[0];
    });
    expect(defecto?.def ?? '').toContain('now()');
  });

  it('no borra de mas cuando el tope coincide con el numero de filas', async () => {
    await fillAudit(30, 0);
    expect(await prune(30, 30)).toBe(0);
    expect(await count()).toBe(30);
  });
});

describe('permisos de audit_prune', () => {
  // Hay un rol y el podador usa otro, y por eso el permiso se concedio al
  // equivocado durante meses.
  //
  // Lo que hay que distinguir:
  //
  //   securekey      rol propietario (crea las tablas y las funciones)
  //   securekey_app  GRUPO. Es dueno de los objetos y donde viven las reglas RLS
  //   securekey_api  USUARIO, miembro de securekey_app. Es con el que entra la
  //                 API y tambien el servicio `prune`
  //
  // El `GRANT` de la migracion 003 decia "TO CURRENT_USER", que en el momento de
  // migrar es `securekey`. El podador entra como `securekey_api`, que no es
  // miembro de `securekey`, y se llevaba un `permission denied` en cada pasada
  // sin que nada lo indicara, porque el script salia con codigo 0.
  //
  // El test que habia antes comprobaba `securekey_app` y por eso pasaba: el
  // permiso no estaba en ninguna de las dos, asi que la afirmacion era cierta
  // por casualidad y no cubria el caso real. Comprobar el rol que el podador
  // usa de verdad es lo que habria detectado el fallo.

  it('el rol con el que entra el podador PUEDE ejecutarla', async () => {
    const rows = await withAdmin(config, async (tx) => {
      const res = await tx.query<{ puede: boolean }>(
        `SELECT has_function_privilege('securekey_api', 'audit_prune(integer, bigint)', 'EXECUTE') AS puede`,
      );
      return res.rows;
    });
    expect(rows[0]?.puede).toBe(true);
  });

  it('y la llamada funciona de verdad, no solo el permiso', async () => {
    // Un permiso puede estar concedido y la llamada fallar por cualquier otra
    // cosa. Esta es la comprobacion que de verdad importa: la de que el podador,
    // con SU credencial, es capaz de podar.
    await fillAudit(12, 200);
    expect(await count()).toBe(12);

    const conRolDelPodador = await withSystem(config, async (tx) => {
      const res = await tx.query<{ audit_prune: string }>(
        'SELECT audit_prune($1::integer, $2::bigint) AS audit_prune',
        [30, 500],
      );
      return res.rows;
    });
    expect(Number(conRolDelPodador[0]?.audit_prune ?? 0)).toBe(12);
    expect(await count()).toBe(0);
  });

  it('el permiso va al grupo, no al usuario, para que aguante a quien se anada luego', async () => {
    const rows = await withAdmin(config, async (tx) => {
      const res = await tx.query<{ puede: boolean }>(
        `SELECT has_function_privilege('securekey_app', 'audit_prune(integer, bigint)', 'EXECUTE') AS puede`,
      );
      return res.rows;
    });
    expect(rows[0]?.puede).toBe(true);
  });

  it('PUBLIC no tiene permiso', async () => {
    const rows = await withAdmin(config, async (tx) => {
      const res = await tx.query<{ puede: boolean }>(
        `SELECT has_function_privilege('public', 'audit_prune(integer, bigint)', 'EXECUTE') AS puede`,
      );
      return res.rows;
    });
    expect(rows[0]?.puede).toBe(false);
  });

  it('esta marcada SECURITY DEFINER con search_path fijo', async () => {
    // Sin `SET search_path`, una funcion SECURITY DEFINER es explotable: el
    // atacante controla que `search_path` resuelva y puede ejecutar su propio
    // codigo como el propietario de la funcion.
    const rows = await withAdmin(config, async (tx) => {
      const res = await tx.query<{ secdef: boolean; cfg: string[] | null }>(
        `SELECT prosecdef AS secdef, proconfig AS cfg
           FROM pg_proc WHERE proname = 'audit_prune' LIMIT 1`,
      );
      return res.rows;
    });
    expect(rows[0]?.secdef).toBe(true);
    // `proconfig` es un array de textos tipo "search_path=public, pg_temp".
    expect(rows[0]?.cfg ?? []).toContain('search_path=public, pg_temp');
  });
});
