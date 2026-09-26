#!/usr/bin/env bash
# ===========================================================================
# Backup de SecureKey.
#
# Que se copia y por que es aceptable:
#
#   - `pg_dump -Fc` (formato custom comprimido) de la base de datos.
#   - `pg_dumpall --globals-only` para los roles, que incluye `securekey_app`.
#     Sin esto, restaurar el dump en un Postgres nuevo fallaria al aplicar las
#     politicas RLS, porque el rol no existiria.
#
# Es SEGURO almacenar: la tabla `items` solo contiene blobs AEAD y el hash
# scrypt del verificador. No hay texto en claro que exfiltrar. Lo que si es
# sensible, y por eso el dump no debe subirse a un repositorio ni a un bucket
# publico tal cual:
#
#   - correos electronicos
#   - `auth_hash` (verificadores; con el pepper NO se pueden verificar, pero
#     son datos derivados de la contrasena maestra)
#   - IPs y user agents del `audit_log`
#
# Si el destino no es de fiar, cifra el dump:
#     age -r <tu-clave> -o backup.dump.age backup.dump
#
# Uso:
#   scripts/backup.sh                          -> backup en ./backups
#   BACKUP_DIR=/mnt/nas scripts/backup.sh
# ===========================================================================
set -Eeuo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
# Cuantas copias se guardan. Sin esto, "backup" es solo otra cosa que llena
# el disco: un backup diario sin retencion acaba siendo la causa del mismo
# incidente que pretendia prevenir.
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DUMP="${BACKUP_DIR}/securekey-${STAMP}.dump"
GLOBALS="${BACKUP_DIR}/globals-${STAMP}.sql"

# Dos usuarios distintos y confundirlos rompe el script:
#
#   -U  = rol de la BASE DE DATOS. Es el POSTGRES_USER de la imagen
#         (`securekey` por defecto). NO es `postgres`: ese rol no existe aqui.
#   -u  = usuario del SISTEMA OPERATIVO dentro del contenedor. Solo existe
#         `postgres`; pasar `-u securekey` falla con "no matching entries in
#         passwd file", que parece un fallo de la base y no lo es.
DB_USER="${POSTGRES_USER:-securekey}"
DB_NAME="${POSTGRES_DB:-securekey}"

# `pg_dump`/`pg_dumpall` heredan POSTGRES_USER del entorno del contenedor, asi
# que `-U` explicito es solo por clarity; lo que importa es no usar `-u`.
pg() { docker exec -u postgres -e PGPASSWORD="${POSTGRES_PASSWORD:-}" "$DB" "$@" -U "$DB_USER"; }

mkdir -p "$BACKUP_DIR"

DB="$(docker compose ps -q db)"
if [ -z "$DB" ]; then
  echo "ERROR: el contenedor de la base de datos no esta en marcha" >&2
  exit 1
fi

# `.env` no lo lee `docker exec`. Sin esto, PGPASSWORD llega vacio y un
# `pg_dump` con password required falla con un error que no dice "contrasena".
if [ -z "${POSTGRES_PASSWORD:-}" ] && [ -f .env ]; then
  POSTGRES_PASSWORD="$(grep -E '^POSTGRES_PASSWORD=' .env | head -1 | cut -d= -f2-)"
  export POSTGRES_PASSWORD
fi

echo "Base de datos: $DB (rol=$DB_USER db=$DB_NAME)"
echo "Destino:       $BACKUP_DIR"

# Se vuelca DENTRO del contenedor y se copia fuera: asi se usa exactamente la
# version de servidor que esta corriendo y no hace falta cliente en el host.
# `pg_dump -Fc` escribe en stdout, que es lo que permite redirigir.
pg pg_dump -Fc -d "$DB_NAME" > "$DUMP.tmp"
pg pg_dumpall --globals-only > "$GLOBALS.tmp"

# El dump contiene correos y verificadores: no debe quedar legible para otros
# usuarios del host ni aparecer en un listado de directorio.
mv "$DUMP.tmp" "$DUMP"
mv "$GLOBALS.tmp" "$GLOBALS"
chmod 600 "$DUMP" "$GLOBALS"

echo "OK  $DUMP ($(du -h "$DUMP" | cut -f1))"
echo "OK  $GLOBALS"

# ---- Verificacion: un backup que no se ha restaurado no es un backup ----
# Un volcado corrupto se detecta aqui, no el dia que haya que usarlo.
if docker exec -i -u postgres -e PGPASSWORD="${POSTGRES_PASSWORD:-}" "$DB" pg_restore --list -U "$DB_USER" < "$DUMP" > /dev/null 2>&1; then
  ENTRIES="$(docker exec -i -u postgres -e PGPASSWORD="${POSTGRES_PASSWORD:-}" "$DB" pg_restore --list -U "$DB_USER" < "$DUMP" 2>/dev/null | wc -l)"
  echo "OK  el volcado se lee correctamente ($ENTRIES entradas en pg_restore --list)"
else
  echo "ERROR: el volcado esta corrupto" >&2
  rm -f "$DUMP" "$GLOBALS"
  exit 1
fi

# El rol `securekey_app` sin el cual la restauracion no deja la RLS activa.
if grep -q 'securekey_app' "$GLOBALS"; then
  echo "OK  los globals incluyen el rol securekey_app (imprescindible para la RLS)"
else
  echo "AVISO: los globals NO incluyen securekey_app. La restauracion dejaria la"
  echo "      base sin RLS. Revisa POSTGRES_USER antes de confiar en este backup."
fi

# ---- Retencion ------------------------------------------------------------
find "$BACKUP_DIR" -name 'securekey-*.dump' -type f -mtime "+${KEEP_DAYS}" -delete
find "$BACKUP_DIR" -name 'globals-*.sql'    -type f -mtime "+${KEEP_DAYS}" -delete
echo "Retencion: se conservan ${KEEP_DAYS} dias"

ls -1t "$BACKUP_DIR" 2>/dev/null | head -4
