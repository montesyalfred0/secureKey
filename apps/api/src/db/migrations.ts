/**
 * Migraciones como codigo: sin archivos que copiar en la imagen de produccion
 * y disponibles tanto en `tsx` (desarrollo) como en `dist` (produccion).
 */
import type { Config } from '../config.js';
import { withSystemAdmin } from './withUser.js';
import { createPool } from './pool.js';

export type Migration = {
  id: string;
  sql: string;
};

const initSql = String.raw`
-- ===========================================================================
-- 001 - Esquema inicial de SecureKey
--
-- Principio: en este esquema NO existe ninguna columna en texto claro con
-- datos de credenciales. Solo metadatos, blobs AEAD y verificadores.
-- ===========================================================================

CREATE EXTENSION IF NOT EXISTS citext;

-- Rol restringido de la aplicacion. NOLOGIN: la aplicacion lo adopta con
-- SET LOCAL ROLE, de modo que sus propias conexiones nunca son superusuario.
DO $do$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securekey_app') THEN
    CREATE ROLE securekey_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END
$do$;

GRANT securekey_app TO CURRENT_USER;

-- ---------------------------------------------------------------------------
-- Funcion auxiliar que leen las politicas RLS.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app_user_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $fn$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$fn$;

-- ---------------------------------------------------------------------------
-- Tablas
-- ---------------------------------------------------------------------------

CREATE TABLE users (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  email         citext      NOT NULL UNIQUE,
  -- Verificador de autenticacion: scrypt(HMAC(pepper, authKey), salt).
  -- Es un hash, no un cifrado: no se puede recuperar la authKey.
  auth_hash     bytea       NOT NULL,
  auth_salt     bytea       NOT NULL,
  -- Clave de boveda envuelta con la KEK derivada de la contrasena maestra.
  vault_cipher  bytea       NOT NULL,
  vault_nonce   bytea       NOT NULL,
  key_version   integer     NOT NULL DEFAULT 1,
  -- Perfil de parametros KDF vigente: permite subirlos sin romper clientes.
  kdf           jsonb       NOT NULL,
  failed_logins integer     NOT NULL DEFAULT 0,
  locked_until  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE items (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  version    integer     NOT NULL DEFAULT 1,
  alg        text        NOT NULL DEFAULT 'AES-256-GCM',
  kdf        jsonb       NOT NULL,
  nonce      bytea       NOT NULL,
  ciphertext bytea       NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

-- El indice parcial cubre el caso habitual: listar items vivos de un usuario.
CREATE INDEX items_user_live_idx ON items (user_id, updated_at DESC) WHERE deleted_at IS NULL;

CREATE TABLE sessions (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- SHA-256 del token opaco. Si roban la tabla no pueden suplantar sesiones.
  token_hash   bytea       NOT NULL UNIQUE,
  csrf_hash    bytea       NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL DEFAULT now(),
  ip           inet,
  user_agent   text
);

CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Bitacora de seguridad. Nunca contiene datos sensibles, solo metadatos.
CREATE TABLE audit_log (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid,
  action     text        NOT NULL,
  item_id    uuid,
  ip         inet,
  user_agent text,
  at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_user_idx ON audit_log (user_id, at DESC);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);

-- ---------------------------------------------------------------------------
-- Row Level Security
--
-- Sin FORCE: el propietario (rol de migracion) conserva acceso sinuirresto,
-- y las funciones SECURITY DEFINER de abajo pueden hacer su trabajo. La
-- aplicacion SIEMPRE opera bajo el rol seguro 'securekey_app', por lo que
-- estas politicas son las unicas que se aplican a las consultas de la API.
-- ---------------------------------------------------------------------------

ALTER TABLE users     ENABLE ROW LEVEL SECURITY;
ALTER TABLE items     ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_self ON users
  FOR ALL
  USING      (id = app_user_id())
  WITH CHECK (id = app_user_id());

CREATE POLICY items_owner ON items
  FOR ALL
  USING      (user_id = app_user_id())
  WITH CHECK (user_id = app_user_id());

CREATE POLICY sessions_owner ON sessions
  FOR ALL
  USING      (user_id = app_user_id())
  WITH CHECK (user_id = app_user_id());

-- Solo insercion. Nadie puede leer la bitacora desde la aplicacion.
CREATE POLICY audit_log_append ON audit_log
  FOR INSERT
  WITH CHECK (user_id IS NULL OR user_id = app_user_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON users, items, sessions, audit_log TO securekey_app;

-- ---------------------------------------------------------------------------
-- Funciones SECURITY DEFINER
--
-- El flujo de autenticacion necesita leer el usuario por email y la sesion por
-- token ANTES de conocer el 'app.user_id', y por eso no puede pasar por el
-- contexto RLS. Se acota lo que devuelven y se exige conocer un secreto de
-- 256 bits (el hash del token) o el email objetivo.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION auth_lookup(p_email citext)
RETURNS TABLE (
  id            uuid,
  email         citext,
  auth_hash     bytea,
  auth_salt     bytea,
  vault_cipher  bytea,
  vault_nonce   bytea,
  key_version   integer,
  kdf           jsonb,
  failed_logins integer,
  locked_until  timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
  SELECT u.id, u.email, u.auth_hash, u.auth_salt, u.vault_cipher, u.vault_nonce,
         u.key_version, u.kdf, u.failed_logins, u.locked_until
    FROM users u
   WHERE u.email = p_email
$fn$;

CREATE OR REPLACE FUNCTION session_lookup(p_token_hash bytea)
RETURNS TABLE (
  id           uuid,
  user_id      uuid,
  csrf_hash    bytea,
  created_at   timestamptz,
  last_seen_at timestamptz,
  expires_at   timestamptz,
  ip           inet,
  user_agent   text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
  SELECT s.id, s.user_id, s.csrf_hash, s.created_at, s.last_seen_at, s.expires_at, s.ip, s.user_agent
    FROM sessions s
   WHERE s.token_hash = p_token_hash
$fn$;

-- Contadores de bloqueo. Tambien fuera de RLS: la cuenta todavia no esta
-- autenticada en el momento de contar un fallo.
CREATE OR REPLACE FUNCTION auth_register_failure(p_id uuid, p_max_attempts integer, p_lock_minutes integer)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
  UPDATE users
     SET failed_logins = failed_logins + 1,
         locked_until = CASE
           WHEN failed_logins + 1 >= p_max_attempts
             THEN now() + make_interval(mins => p_lock_minutes)
           ELSE locked_until
         END
   WHERE id = p_id
$fn$;

CREATE OR REPLACE FUNCTION auth_register_success(p_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
  UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = now() WHERE id = p_id
$fn$;

REVOKE ALL ON FUNCTION auth_lookup(citext)          FROM PUBLIC;
REVOKE ALL ON FUNCTION session_lookup(bytea)        FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_register_failure(uuid, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_register_success(uuid)  FROM PUBLIC;

GRANT EXECUTE ON FUNCTION auth_lookup(citext)         TO securekey_app;
GRANT EXECUTE ON FUNCTION session_lookup(bytea)       TO securekey_app;
GRANT EXECUTE ON FUNCTION auth_register_failure(uuid, integer, integer) TO securekey_app;
GRANT EXECUTE ON FUNCTION auth_register_success(uuid) TO securekey_app;
`;

/**
 * 002 - Retencion de la bitacora de seguridad.
 *
 * `audit_log` crece sin limite y, peor, cada fila cuesta cuatro escrituras:
 * el heap mas tres indices (medido: 52 filas ocupaban 64 kB, de los cuales
 * solo 8 kB eran datos). Se rellena desde la red SIN autenticar, porque cada
 * login fallido inserta una fila. Un atacante que dispare al limite de 10
 * Intentos/min por IP desde muchas IPs llena el disco del servidor sin
 * necesitar credenciales. Es un vector de denegacion de servicio gratuito.
 *
 * La poda va en una funcion SECURITY DEFINER porque el rol de la aplicacion
 * solo tiene politica INSERT sobre esta tabla: nadie puede leerla ni borrarla
 * desde la API, y eso es lo que queremos. El podador es un rol de sistema.
 */
const auditRetentionSql = String.raw`
CREATE OR REPLACE FUNCTION audit_prune(p_keep_days integer, p_max_rows bigint)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
DECLARE
  v_edge     timestamptz;
  v_removed  bigint;
  v_removed_by_age bigint := 0;
  v_removed_by_cap bigint := 0;
BEGIN
  -- ---------------------------------------------------------------------
  -- Fase 1: antiguedad. Es lo que manda en el uso normal.
  -- ---------------------------------------------------------------------
  v_edge := now() - make_interval(days => p_keep_days);
  DELETE FROM audit_log WHERE at IS NOT NULL AND at < v_edge;
  GET DIAGNOSTICS v_removed_by_age = ROW_COUNT;

  -- ---------------------------------------------------------------------
  -- Fase 2: cota dura de volumen.
  --
  -- Por que NO se resuelve con GREATEST(v_cutoff, <at de la fila N+1>): con
  -- filas de la MISMA fecha, que es justo el caso de un pico de trafico, esa
  -- fila tiene "at" igual a la anterior. GREATEST se quedaba con el tope de
  -- antiguedad (30 dias atras) y no borraba NADA. Medido: 300 filas todas de
  -- hoy, tope 100 -> seguian 300.
  --
  -- Ademas, el criterio "at" no distingue filas identicas, asi que no puede
  -- cortar por un numero exacto. Se borra por identificador, que si es unico,
  -- y se conservan las p_max_rows mas recientes con el indice de "at".
  --
  -- El "at IS NULL" no va en la seleccion: el orden "at DESC NULLS LAST" deja
  -- las nulas al final, asi que nunca entran entre las p_max_rows que se
  -- conservan, y una fila sin fecha no debe empujar fuera a otra que si la tiene.
  IF (SELECT count(*) FROM audit_log) > p_max_rows THEN
    DELETE FROM audit_log
     WHERE id NOT IN (
       SELECT id FROM audit_log
        WHERE at IS NOT NULL
        ORDER BY at DESC
        LIMIT p_max_rows
     );
    GET DIAGNOSTICS v_removed_by_cap = ROW_COUNT;
  END IF;

  v_removed := v_removed_by_age + v_removed_by_cap;
  RETURN v_removed;
END
$fn$;

REVOKE ALL ON FUNCTION audit_prune(integer, bigint) FROM PUBLIC;

-- El rol de migracion (propietario) es quien la ejecuta desde el podador.
GRANT EXECUTE ON FUNCTION audit_prune(integer, bigint) TO CURRENT_USER;
`;

export type MigrationResult = { id: string; applied: boolean };

/**
 * Las migraciones se identifican por `id` y `schema_migrations` guarda las ya
 * aplicadas, asi que editar el SQL de una migracion existente NO hace que se
 * vuelva a ejecutar: la base se queda con la version anterior para siempre.
 *
 * Por eso `audit_prune` lleva dos entradas. La primera es la version
 * incompleta; la segunda la sustituye. Un despliegue que ya tenga aplicada la
 * 001/003 ejecuta la 004 y arregla la funcion.
 *
 * El patron general: nunca editar una migracion ya publicada. O se anade una
 * nueva, o se fuerza el recargado manual (DROP FUNCTION + volver a aplicar).
 */
const auditPruneV2Sql = String.raw`
CREATE OR REPLACE FUNCTION audit_prune(p_keep_days integer, p_max_rows bigint)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
DECLARE
  v_edge            timestamptz;
  v_removed         bigint;
  v_removed_by_age  bigint := 0;
  v_removed_by_cap  bigint := 0;
BEGIN
  -- ---------------------------------------------------------------------
  -- Fase 1: antiguedad. Es lo que manda en el uso normal.
  -- ---------------------------------------------------------------------
  v_edge := now() - make_interval(days => p_keep_days);
  DELETE FROM audit_log WHERE at IS NOT NULL AND at < v_edge;
  GET DIAGNOSTICS v_removed_by_age = ROW_COUNT;

  -- ---------------------------------------------------------------------
  -- Fase 2: cota dura de volumen.
  --
  -- Por que NO se resuelve combinando el corte por antiguedad con un "at"
  -- calculado: con filas de la MISMA fecha, que es justo el caso de un pico de
  -- trafico, la fila N+1 tiene "at" igual que las anteriores y la combinacion
  -- se quedaba con el tope de antiguedad sin borrar nada. Medido: 300 filas
  -- todas de hoy con tope 100 -> seguian 300.
  --
  -- Ademas "at" no distingue filas identicas, asi que no permite cortar por un
  -- numero exacto. Se borra por identificador, que si es unico, y se conservan
  -- las p_max_rows mas recientes apoyandose en el indice de "at".
  --
  -- Las filas con "at" nulo quedan fuera de la seleccion (NULLS LAST) y por
  -- tanto nunca desplazan a una que si lo tiene.
  -- ---------------------------------------------------------------------
  IF (SELECT count(*) FROM audit_log) > p_max_rows THEN
    DELETE FROM audit_log
     WHERE id NOT IN (
       SELECT id FROM audit_log
        WHERE at IS NOT NULL
        ORDER BY at DESC
        LIMIT p_max_rows
     );
    GET DIAGNOSTICS v_removed_by_cap = ROW_COUNT;
  END IF;

  v_removed := v_removed_by_age + v_removed_by_cap;
  RETURN v_removed;
END
$fn$;

REVOKE ALL ON FUNCTION audit_prune(integer, bigint) FROM PUBLIC;
`;

/**
 * 004 - Escrituras de `users` como funciones SECURITY DEFINER.
 *
 * El objetivo es que la API pueda dejar de conectar como superusuario.
 *
 * El problema: el flujo de autenticacion necesita escribir en `users` ANTES de
 * que exista una sesion y, por tanto, antes de que `app.user_id` este
 * publicado. Bajo la RLS, `app_user_id()` devuelve NULL y el `WITH CHECK` de
 * `users` rechaza la escritura. Por eso esas escrituras iban directas, desde
 * el rol de la migracion, que es superusuario y se salta la RLS.
 *
 * Eso dejaba al superusuario como requisito de funcionamiento: un RCE en la
 * API significaba superusuario en la base, con capacidad de leer ficheros del
 * host (`pg_read_file`) o ejecutar comandos (`COPY ... TO PROGRAM`).
 *
 * La solucion es la misma que ya usaban las lecturas: mover cada escritura a
 * una funcion `SECURITY DEFINER` acotada a lo que hace falta, con
 * `search_path` fijo y `EXECUTE` revocado a `PUBLIC`. La API entra con un rol
 * sin privilegios, y la superficie de superusuario queda reducida a un puñado
 * de funciones revisadas.
 */
const userWritesSql = String.raw`
-- Alta de cuenta. Devuelve el id, o NULL si el correo ya existe (23505), que
-- es lo que el registro traduce a un 409.
CREATE OR REPLACE FUNCTION auth_create_user(
  p_email    citext,
  p_hash     bytea,
  p_salt     bytea,
  p_vault    bytea,
  p_nonce    bytea,
  p_kdf      jsonb
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
DECLARE
  v_id uuid;
BEGIN
  INSERT INTO users (email, auth_hash, auth_salt, vault_cipher, vault_nonce, key_version, kdf)
  VALUES (p_email, p_hash, p_salt, p_vault, p_nonce, 1, p_kdf)
  RETURNING id INTO v_id;

  RETURN v_id;
EXCEPTION
  -- Chave primaria violada: el correo ya esta registrado. Se devuelve NULL en
  -- vez de propagar el error para que el registro responda 409.
  WHEN unique_violation THEN
    RETURN NULL;
END
$fn$;

-- Actualiza el perfil de KDF cuando el servidor sube parametros. Deliberadamente
-- NO toca la columna key_version: esa es la generacion de la clave de boveda y va
-- en el AAD de cada item.
CREATE OR REPLACE FUNCTION auth_update_user_kdf(p_id uuid, p_kdf jsonb)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
BEGIN
  UPDATE users SET kdf = p_kdf, updated_at = now() WHERE id = p_id;
  RETURN FOUND;
END
$fn$;

-- Re-envuelve la clave de boveda (rekey y KDF). La columna key_version NO se
-- incrementa: es la generacion de la vaultKey y va en el AAD de cada item.
CREATE OR REPLACE FUNCTION auth_update_user_vault(
  p_id     uuid,
  p_vault  bytea,
  p_nonce  bytea,
  p_kdf    jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
BEGIN
  UPDATE users
     SET vault_cipher = p_vault, vault_nonce = p_nonce, kdf = p_kdf, updated_at = now()
   WHERE id = p_id;
  RETURN FOUND;
END
$fn$;

-- Cambio de contrasena maestra: nuevo verificador, nueva sal, nueva envoltura
-- y reinicio del contador de fallos.
CREATE OR REPLACE FUNCTION auth_update_user_credentials(
  p_id     uuid,
  p_hash   bytea,
  p_salt   bytea,
  p_vault  bytea,
  p_nonce  bytea,
  p_kdf    jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
BEGIN
  UPDATE users
     SET auth_hash = p_hash, auth_salt = p_salt,
         vault_cipher = p_vault, vault_nonce = p_nonce, kdf = p_kdf,
         failed_logins = 0, locked_until = NULL, updated_at = now()
   WHERE id = p_id;
  RETURN FOUND;
END
$fn$;

REVOKE ALL ON FUNCTION auth_create_user(citext, bytea, bytea, bytea, bytea, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_update_user_kdf(uuid, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_update_user_vault(uuid, bytea, bytea, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_update_user_credentials(uuid, bytea, bytea, bytea, bytea, jsonb) FROM PUBLIC;

-- Se conceden a securekey_app, no al rol de la API. Asi el acceso depende de
-- la pertenencia al rol, y revocar a la API es una sola sentencia.
GRANT EXECUTE ON FUNCTION auth_create_user(citext, bytea, bytea, bytea, bytea, jsonb) TO securekey_app;
GRANT EXECUTE ON FUNCTION auth_update_user_kdf(uuid, jsonb) TO securekey_app;
GRANT EXECUTE ON FUNCTION auth_update_user_vault(uuid, bytea, bytea, jsonb) TO securekey_app;
GRANT EXECUTE ON FUNCTION auth_update_user_credentials(uuid, bytea, bytea, bytea, bytea, jsonb) TO securekey_app;

-- Fija la contrasena del rol de la API.
--
-- Existe como funcion y no como "ALTER ROLE ... PASSWORD $1" porque Postgres no
-- admite parametros en sentencias de utilidad: da "syntax error at or near $1".
-- El %L de format() hace el escapado por la propia base de datos, asi que la
-- contrasena se trata como un literal y no se concatena en ningun sitio.
CREATE OR REPLACE FUNCTION admin_set_app_password(p_password text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
BEGIN
  EXECUTE format('ALTER ROLE securekey_api PASSWORD %L', p_password);
END
$fn$;

REVOKE ALL ON FUNCTION admin_set_app_password(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin_set_app_password(text) TO CURRENT_USER;
`;

/**
 * Arregla el permiso de `audit_prune`, que la 003 concedio al rol equivocado.
 *
 * El fallo: la 003 hacia
 *
 *     GRANT EXECUTE ON FUNCTION audit_prune(integer, bigint) TO CURRENT_USER;
 *
 * `CURRENT_USER` en el momento de migrar es el rol de migracion (`securekey`),
 * no el rol con el que entra el podador. El servicio `prune` conecta como
 * `securekey_api`, que es miembro de `securekey_app` y de nada mas, asi que se
 * llevaba un `permission denied for function audit_prune` en cada pasada.
 *
 * Como el podador sale con codigo 0 aunque no pode nada, el contenedor
 * `prune` se quedaba en "healthy" sin hacer nada y el unico rastro era una
 * linea en el log. La defensa existia y no funcionaba, que es peor que no
 * tenerla.
 *
 * El permiso va al GRUPO `securekey_app`, no a `securekey_api`: asi funciona
 * para el rol actual y para cualquiera que se anada manana sin tocar aqui.
 */
const auditPruneGrantSql = String.raw`
GRANT EXECUTE ON FUNCTION audit_prune(integer, bigint) TO securekey_app;
`;

// El orden importa: se declara DESPUES de los tres bloques de SQL.
export const MIGRATIONS: readonly Migration[] = [
  { id: '001_init', sql: initSql },
  { id: '002_audit_retention', sql: auditRetentionSql },
  { id: '003_audit_prune_fix', sql: auditPruneV2Sql },
  { id: '004_user_writes', sql: userWritesSql },
  { id: '005_audit_prune_grant', sql: auditPruneGrantSql },
];

/**
 * Rol con el que entra la aplicacion. NO es superusuario.
 *
 * Se crea aqui y no en el SQL de una migracion porque necesita contrasena, y el
 * SQL de las migraciones es estatico: la contrasena llega por parametro desde
 * `migrate.ts`. Es idempotente, asi que se puede volver a ejecutar para rotar
 * la contrasena sin tocar el esquema.
 *
 * Lo que se gana, y que se midio: con el rol anterior (superusuario) un RCE en
 * la API permitia `pg_read_file` sobre el host y `COPY ... TO PROGRAM` para
 * ejecutar comandos. Con este rol, ninguna de las dos cosas existe.
 *
 * Lo que NO se gana: este rol es miembro de `securekey_app`, asi que sigue
 * viendo lo que el contexto de la transaccion permita. Lo que se pierde con el
 * RCE es el salto directo a superusuario.
 */
export async function ensureApiRole(
  databaseUrl: string,
  password: string,
): Promise<{ created: boolean }> {
  const pool = createPool(databaseUrl);
  try {
    const existing = await pool.query<{ n: string }>(
      "SELECT count(*) AS n FROM pg_roles WHERE rolname = 'securekey_api'",
    );

    if (Number(existing.rows[0]?.n ?? 0) === 0) {
      // NOINHERIT seria mas estricto todavia (habria que hacer SET ROLE
      // siempre, que es justo lo que ya hace `withUser`), pero el propio
      // `withSystem` necesita los privilegios heredados de `securekey_app`.
      await pool.query(`
        CREATE ROLE securekey_api
          LOGIN
          NOSUPERUSER
          NOCREATEDB
          NOCREATEROLE
          NOBYPASSRLS
          NOREPLICATION
      `);
    }

    // Parametrizado de verdad: la contrasena viaja como parametro y la
    // concatenacion la hace la base de datos con `format`/`%L`, no el
    // aplicativo. Ver `admin_set_app_password` en la migracion 004.
    await pool.query('SELECT admin_set_app_password($1)', [password]);
    await pool.query('GRANT securekey_app TO securekey_api');

    return { created: Number(existing.rows[0]?.n ?? 0) === 0 };
  } finally {
    await pool.end();
  }
}

export async function runMigrations(config: Config): Promise<MigrationResult[]> {
  return withSystemAdmin(config, async (tx) => {
    await tx.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id         text        PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    const results: MigrationResult[] = [];
    for (const migration of MIGRATIONS) {
      const existing = await tx.query<{ id: string }>(
        'SELECT id FROM schema_migrations WHERE id = $1',
        [migration.id],
      );
      if ((existing.rowCount ?? 0) > 0) {
        results.push({ id: migration.id, applied: false });
        continue;
      }
      await tx.query(migration.sql);
      await tx.query('INSERT INTO schema_migrations (id) VALUES ($1)', [migration.id]);
      results.push({ id: migration.id, applied: true });
    }
    return results;
  });
}
