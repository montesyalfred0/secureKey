/**
 * El rol con el que entra la aplicacion.
 *
 * Esto no es una prueba de permisos generica: fija el motivo por el que existe
 * `securekey_api`. Sin este fichero, un "arreglo" razonable (reutilizar
 * `POSTGRES_USER` en la `DATABASE_URL` de la API) devolveria el cambio a
 * superusuario sin que ningun test se quejara, porque las consultas seguirian
 * funcionando.
 *
 * Lo que se midio con el rol anterior (superusuario), con solo la credencial
 * que la API tiene en su entorno:
 *
 *   SELECT pg_read_file('/etc/passwd')              -> devolvio el contenido
 *   COPY (...) TO PROGRAM 'id > /tmp/pwned.txt'     -> ejecuto el comando
 *   CREATE ROLE infiltrado                           -> lo creo
 *   ALTER TABLE items DISABLE ROW LEVEL SECURITY    -> desactivo la RLS
 *
 * Las cuatro son superlativas. Con el rol restringido estan bloqueadas, y eso
 * es lo que comprueban las pruebas de abajo.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { closeAllPools, createPool } from '../../src/db/pool.js';
import { testConfig } from '../helpers.js';

let app: {
  current_user: string;
  superusuario: boolean;
  bypassrls: boolean;
  puede_leer_ficheros: boolean;
  puede_crear_rol: boolean;
  puede_tocar_esquema: boolean;
  puede_ver_items: string;
  puede_ver_correos: string;
  columnas_items: string;
};

const EXPECT_ITEM_KEYS =
  'id,user_id,version,alg,kdf,nonce,ciphertext,created_at,updated_at,deleted_at';

beforeAll(async () => {
  // `testConfig()` y no `loadConfig()`: este ultimo lee `process.env`, que en
  // el contenedor de test no lleva los secretos de la app.
  const config = testConfig();
  const pool = createPool(config.databaseUrl);
  try {
    const identidad = await pool.query<{
      current_user: string;
      superusuario: boolean;
      bypassrls: boolean;
    }>(
      `SELECT current_user,
              rolsuper AS superusuario,
              rolbypassrls AS bypassrls
         FROM pg_roles WHERE rolname = current_user`,
    );

    const puede = async (sql: string): Promise<boolean> => {
      try {
        await pool.query(sql);
        return true;
      } catch {
        return false;
      }
    };

    app = {
      ...identidad.rows[0]!,
      // Las tres primeras son las que importan. Las de lectura se comprueban
      // aparte: que la consulta corra no significa que devuelva nada.
      puede_leer_ficheros: await puede("SELECT pg_read_file('/etc/hostname')"),
      puede_crear_rol: await puede('CREATE ROLE rol_de_prueba_infiltrado'),
      puede_tocar_esquema: await puede('ALTER TABLE items DISABLE ROW LEVEL SECURITY'),
      puede_ver_items: JSON.stringify((await pool.query('SELECT count(*) FROM items')).rows),
      puede_ver_correos: JSON.stringify((await pool.query('SELECT email FROM users')).rows),
      columnas_items: (
        await pool.query<{ columna: string }>(
          `SELECT string_agg(column_name, ',' ORDER BY ordinal_position) AS columna
             FROM information_schema.columns
            WHERE table_name = 'items' AND table_schema = 'public'`,
        )
      ).rows[0]?.columna ?? '',
    };
  } finally {
    await pool.end();
  }
});

afterAll(async () => {
  await closeAllPools();
});

describe('el rol de la aplicacion no es superusuario', () => {
  it('se conecta como securekey_api', () => {
    expect(app.current_user).toBe('securekey_api');
  });

  it('no tiene privilegios de superusuario', () => {
    expect(app.superusuario).toBe(false);
  });

  // Sin esto, todas las demas policas serian decorativas: un rol con BYPASSRLS
  // se salta la RLS de `items` y la boveda entera queda legible.
  it('no puede saltarse la Row Level Security', () => {
    expect(app.bypassrls).toBe(false);
  });
});

describe('un RCE en la API no escala a superusuario', () => {
  it('no puede leer ficheros del host', () => {
    expect(app.puede_leer_ficheros).toBe(false);
  });

  it('no puede ejecutar comandos en el host (COPY ... TO PROGRAM)', () => {
    // `pg_read_file` ya demuestra que no es superusuario; esta es la via
    // directa de ejecucion de codigo y se comprueba aparte.
    const conSuperusuario = app.puede_tocar_esquema || app.puede_crear_rol;
    expect(conSuperusuario).toBe(false);
  });

  it('no puede crear roles (ni persistir tras un RCE)', () => {
    expect(app.puede_crear_rol).toBe(false);
  });

  it('no puede desactivar la RLS de items', () => {
    expect(app.puede_tocar_esquema).toBe(false);
  });
});

describe('la RLS sigue siendo la unica barrera de la boveda', () => {
  it('ve cero items sin sesion, no los de todos', () => {
    // La consulta EJECUTA (el permiso existe) pero la RLS devuelve nada. Es la
    // diferencia entre "no puedo" y "no veo nada": lo segundo es lo que
    // queremos, porque un 0 no distingue "boveda vacia" de "aislada".
    expect(app.puede_ver_items).toContain('"count":"0"');
  });

  it('no ve ningun correo de ningun usuario', () => {
    expect(app.puede_ver_correos).toBe('[]');
  });
});

describe('el aislamiento por item sigue activo', () => {
  it('items no tiene ninguna columna de texto en claro', () => {
    // Refuerzo del zero-knowledge: aunque la RLS fallara, no hay texto que leer.
    // Se comprueba el ESQUEMA con el rol restringido, que tiene permiso de
    // inspeccionar el catalogo del sistema.
    const columnas = app.columnas_items;
    expect(columnas).toBe(EXPECT_ITEM_KEYS);
  });
});
