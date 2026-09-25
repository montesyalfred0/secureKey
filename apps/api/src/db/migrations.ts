/**
 * Migraciones como codigo: sin archivos que copiar en la imagen de produccion
 * y disponibles tanto en `tsx` (desarrollo) como en `dist` (produccion).
 */
import type { Config } from '../config.js';
import { withSystem } from './withUser.js';

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

export const MIGRATIONS: readonly Migration[] = [{ id: '001_init', sql: initSql }];

export type MigrationResult = { id: string; applied: boolean };

export async function runMigrations(config: Config): Promise<MigrationResult[]> {
  return withSystem(config, async (tx) => {
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
