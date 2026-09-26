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
#   BACKUP_KEEP_DAYS=30 scripts/backup.sh
# ===========================================================================
set -Eeuo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
# Cuantas copias se guardan. Sin esto, "backup" es solo otra cosa que llena
# el disco: un backup diario sin retencion acaba siendo la causa del mismo
# incidente que pretendia prevenir.
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
# Numero minimo de filas que debe contener el volcado. Ver la comprobacion de
# abajo: sin esto, un volcado vacio pasaria por bueno.
MIN_ROWS="${BACKUP_MIN_ROWS:-1}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DUMP="${BACKUP_DIR}/securekey-${STAMP}.dump"
GLOBALS="${BACKUP_DIR}/globals-${STAMP}.sql"

cleanup() {
  # Si algo falla a mitad, no se deja un `.tmp` que el siguiente run confunda con
  # un volcado bueno, ni un dump a medias que `backup-verify.sh` daria por valido.
  rm -f "$DUMP.tmp" "$GLOBALS.tmp"
}
trap cleanup EXIT

fallar() {
  echo "ERROR: $*" >&2
  cleanup
  exit 1
}

fallar_vacio() {
  echo "ERROR: el volcado no contiene datos (${TABLAS_CON_DATOS:-0} tablas, minimo ${MIN_ROWS})." >&2
  echo "       Un backup vacio es PEOR que no tener backup: parece correcto y" >&2
  echo "       solo se descubre el dia que hay que restaurar. NO se guarda." >&2
  echo "       Causa habitual: un rol con RLS en vez del de administracion." >&2
  cleanup
  exit 1
}

# Dos usuarios distintos y confundirlos rompe el script:
#
#   -U  = rol de la BASE DE DATOS. Es el POSTGRES_USER de la imagen
#         (`securekey` por defecto). NO es `postgres`: ese rol no existe aqui.
#   -u  = usuario del SISTEMA OPERATIVO dentro del contenedor. Solo existe
#         `postgres`; pasar `-u securekey` falla con "no matching entries in
#         passwd file", que parece un fallo de la base y no lo es.
DB_USER="${POSTGRES_USER:-securekey}"
DB_NAME="${POSTGRES_DB:-securekey}"

mkdir -p "$BACKUP_DIR"

DB="$(docker compose ps -q db 2>/dev/null || true)"
[ -n "$DB" ] || fallar "el contenedor de la base de datos no esta en marcha"

# `.env` no lo lee `docker exec`. Sin esto, PGPASSWORD llega vacio y un
# `pg_dump` con password required falla con un error que no dice "contrasena".
if [ -z "${POSTGRES_PASSWORD:-}" ] && [ -f .env ]; then
  POSTGRES_PASSWORD="$(grep -E '^POSTGRES_PASSWORD=' .env | head -1 | cut -d= -f2-)"
  export POSTGRES_PASSWORD
fi
[ -n "${POSTGRES_PASSWORD:-}" ] || fallar "no se encuentra POSTGRES_PASSWORD (ni en el entorno ni en el .env)"

# Se vuelca DENTRO del contenedor y se copia fuera: asi se usa exactamente la
# version de servidor que esta corriendo y no hace falta cliente en el host.
# `pg_dump -Fc` escribe en stdout, que es lo que permite redirigir.
#
# `-i` NO es opcional: sin el, `pg_restore --list < fichero` no recibe el
# volcado por stdin, lee vacio y devuelve cero entradas. Parecia un volcado
# corrupto cuando en realidad estaba entero. Se perdio al reescribir la funcion
# y solo se detecto porque la base de pruebas TIENE datos.
pg() { docker exec -i -u postgres -e PGPASSWORD="$POSTGRES_PASSWORD" "$DB" "$@" -U "$DB_USER"; }

echo "Base de datos: $DB (rol=$DB_USER db=$DB_NAME)"
echo "Destino:       $BACKUP_DIR"

pg pg_dump -Fc -d "$DB_NAME" > "$DUMP.tmp" || fallar "pg_dump no pudo volcar la base"
pg pg_dumpall --globals-only > "$GLOBALS.tmp" || fallar "pg_dumpall no pudo volcar los roles"

# ---- El volcado no puede estar vacio ---------------------------------------
#
# Un backup vacio que parece correcto es peor que no tener backup: da falsa
# confianza y solo se descubre el dia que hay que restaurar.
#
# Con el rol de la API (`securekey_api`) el volcado completo FALLA con
# "permission denied for table schema_migrations" (pg_dump necesita LOCK TABLE),
# asi que en ese camino el error es ruidoso. Pero el modo `--data-only` sale con
# codigo 0 y CERO filas, porque la RLS simplemente no le muestra nada. Ambos
# comprobados.
#
# Por eso la comprobacion no es "pg_dump no fallo", sino "el volcado TIENE
# datos": cubre el camino ruidoso y el silencioso con la misma linea.
#
# `pg_restore --list` lista, entre otras cosas, una entrada `TABLE DATA` por
# cada tabla volcada CON contenido. Un volcado de datos vacio no las tiene.
#
# Se consulta el `.tmp` a proposito: si el volcado no sirve, todavia no se ha
# movido a su nombre final y no queda un backup inutil en el directorio.
TABLAS_CON_DATOS="$(
  pg pg_restore --list < "$DUMP.tmp" 2>/dev/null \
    | grep -c 'TABLE DATA' \
    || true
)"

if [ "${TABLAS_CON_DATOS:-0}" -lt "$MIN_ROWS" ]; then
  fallar_vacio
fi

echo "OK  el volcado contiene datos ($TABLAS_CON_DATOS tablas con contenido)"

# El volcado contiene correos y verificadores: no debe quedar legible para otros
# usuarios del host ni aparecer en un listado de directorio.
mv "$DUMP.tmp" "$DUMP"
mv "$GLOBALS.tmp" "$GLOBALS"
chmod 600 "$DUMP" "$GLOBALS"

echo "OK  $DUMP ($(du -h "$DUMP" | cut -f1))"
echo "OK  $GLOBALS"

# ---- Verificacion: un backup que no se ha restaurado no es un backup ----
# Un volcado corrupto se detecta aqui, no el dia que haya que usarlo.
if ! pg pg_restore --list < "$DUMP" > /dev/null 2>&1; then
  echo "ERROR: el volcado esta corrupto; se descarta" >&2
  rm -f "$DUMP" "$GLOBALS"
  exit 1
fi
echo "OK  el volcado se lee correctamente (pg_restore --list)"

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
