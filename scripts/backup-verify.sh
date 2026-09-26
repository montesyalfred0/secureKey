#!/usr/bin/env bash
# ===========================================================================
# Comprueba que el ultimo backup existe, NO esta vacio y se puede restaurar.
#
#   scripts/backup-verify.sh
#
# Por que esto es distinto de hacer un backup: un backup te dice que el
# fichero se ha escrito. Esto te dice que, si llega el dia, la restauracion
# funcionara. Un volcado que nadie ha restaurado nunca es un backup, es una
# hopesina con extension de fichero.
#
# NO toca la base de datos real: levanta un PostgreSQL aislado, restaura ahi y
# lo destruye. Es la unica forma de comprobar un backup sin riesgo.
#
# Lo que verifica, en orden de importancia:
#   1. Hay un volcado reciente.
#   2. No esta vacio (la trampa del rol con RLS).
#   3. Se lee con `pg_restore --list`.
#   4. Se restaura de verdad y la base resultante tiene las 4 tablas, la RLS
#      activa en las 4 y el rol `securekey_app`.
#   5. La base restaurada se parece a la real en numero de usuarios.
#
# Opcionales:
#   BACKUP_VERIFY_QUIET=1   solo imprime el veredicto final
#   BACKUP_DIR=...          donde buscar los volcados
# ===========================================================================
set -Eeuo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
MAX_AGE_HOURS="${BACKUP_VERIFY_MAX_AGE_HOURS:-48}"
# Margen del 25 %: si la real tiene 100 usuarios y el backup trae 75, se
# considera sospechoso. Un backup del mes pasado tambien dispara esto.
ROW_TOLERANCE="${BACKUP_VERIFY_TOLERANCE:-25}"

PASS=0
FAIL=0
# `ok` DEBE devolver 0 siempre. Con el patron `[ ... ] && ok || bad`, un
# `ok` que acabara en 1 (por ejemplo, en modo silencioso, donde no imprime)
# ejecutaria tambien el `bad`. Es el clasico de bash y da falsos negativos.
ok() {
  PASS=$((PASS + 1))
  [ "${BACKUP_VERIFY_QUIET:-0}" = "1" ] || echo "  ok   $1"
  return 0
}
bad() {
  FAIL=$((FAIL + 1))
  echo "  FAIL $1" >&2
  return 0
}
die() { echo "ERROR: $*" >&2; exit 1; }

[ -d "$BACKUP_DIR" ] || die "no existe el directorio de backups: $BACKUP_DIR"

echo "== 1. El volcado mas reciente =="
# `ls -t` y no `find -printf`: la segunda forma es de GNU find y no existe en
# busybox (Alpine), que es justo lo que corre dentro de Docker.
DUMP="$(ls -1t "$BACKUP_DIR"/securekey-*.dump 2>/dev/null | head -1 || true)"
[ -n "$DUMP" ] && [ -f "$DUMP" ] \
  || die "no hay ningun volcado en $BACKUP_DIR. Ejecuta 'npm run backup' primero."

# Los dos ficheros comparten marca de tiempo: `securekey-<stamp>.dump` y
# `globals-<stamp>.sql`. Hay que quitar el prefijo Y la extension, o el nombre
# acaba en `globals-<stamp>.dump.sql` y no se encuentra.
NOMBRE="$(basename "$DUMP" .dump)"
MARCA="${NOMBRE#securekey-}"
GLOBALS="$(dirname "$DUMP")/globals-${MARCA}.sql"
echo "  $DUMP ($(du -h "$DUMP" | cut -f1))"

EDAD_HORAS=$(( ( $(date +%s) - $(stat -c %Y "$DUMP") ) / 3600 ))
if [ "$EDAD_HORAS" -gt "$MAX_AGE_HOURS" ]; then
  bad "el volcado tiene ${EDAD_HORAS} h (maximo ${MAX_AGE_HOURS})"
else
  ok "el volcado tiene ${EDAD_HORAS} h"
fi

DB="$(docker compose ps -q db 2>/dev/null || true)"
[ -n "$DB" ] || die "el contenedor de la base de datos no esta en marcha"

if [ -z "${POSTGRES_PASSWORD:-}" ] && [ -f .env ]; then
  POSTGRES_PASSWORD="$(grep -E '^POSTGRES_PASSWORD=' .env | head -1 | cut -d= -f2-)"
fi
DB_USER="${POSTGRES_USER:-securekey}"
DB_NAME="${POSTGRES_DB:-securekey}"
# `-i` es obligatorio: sin el, `pg_restore --list < fichero` no recibe nada por
# stdin y reporta cero entradas, lo que parece un volcado corrupto o vacio
# cuando esta entero.
pg() { docker exec -i -u postgres -e PGPASSWORD="${POSTGRES_PASSWORD:-}" "$DB" "$@" -U "$DB_USER"; }

echo
echo "== 2. No esta vacio (trampa del rol con RLS) =="
TABLAS="$(pg pg_restore --list < "$DUMP" 2>/dev/null | grep -c 'TABLE DATA' || true)"
if [ "${TABLAS:-0}" -gt 0 ]; then
  ok "contiene $TABLAS tablas con datos"
else
  bad "el volcado NO tiene datos. Suele ser que se uso el rol de la API (con RLS) en vez del de administracion."
fi

echo
echo "== 3. Se lee con pg_restore --list =="
if pg pg_restore --list < "$DUMP" > /dev/null 2>&1; then
  ok "el archivo no esta corrupto"
else
  bad "pg_restore no puede leerlo: esta corrupto"
  die "sin punto de seguir: un backup corrupto no se puede verificar"
fi

echo
echo "== 4. Se restaura de verdad (en una base aislada) =="
CHECK="securekey_backup_check"
cleanup() { docker rm -f "$CHECK" > /dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker run -d --name "$CHECK" \
  -e POSTGRES_DB=securekey -e POSTGRES_USER=securekey \
  -e POSTGRES_PASSWORD=verificacion_local_unica \
  postgres:17-alpine > /dev/null

for _ in $(seq 1 30); do
  docker exec "$CHECK" pg_isready -U securekey -d securekey > /dev/null 2>&1 && break
  sleep 2
done
docker exec "$CHECK" pg_isready -U securekey -d securekey > /dev/null 2>&1 \
  || die "el PostgreSQL de verificacion no arranco"

# Los globals van primero: las politicas RLS necesitan que exista el rol.
if [ -f "$GLOBALS" ]; then
  docker cp "$GLOBALS" "$CHECK:/tmp/g.sql" > /dev/null
  docker exec "$CHECK" psql -U securekey -d postgres -q -f /tmp/g.sql > /dev/null 2>&1
  ok "roles restaurados (incluye securekey_app)"
else
  bad "no hay globals junto al volcado: al restaurar faltaria securekey_app y la RLS no se aplicaria"
fi

docker cp "$DUMP" "$CHECK:/tmp/b.dump" > /dev/null
if docker exec "$CHECK" pg_restore -U securekey -d securekey --no-owner /tmp/b.dump > /dev/null 2>&1; then
  ok "el volcado se restaura sin errores"
else
  bad "la restauracion falla"
  die "el backup no sirve"
fi

# `q` SIEMPRE devuelve 0. Con `set -e`, una asignacion del tipo
# `C="$(q ...)"` aborta el script entero si la consulta falla, y aqui algunas
# pueden fallar legitimamente (por ejemplo `convert_from` sobre datos que no
# son UTF-8 valido). El `|| true` convierte un fallo de consulta en un valor
# vacio, que se comprueba como tal.
q() { docker exec "$CHECK" psql -U securekey -d securekey -t -A -c "$1" 2>/dev/null || true; }

T="$(q "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','items','sessions','audit_log');")"
if [ "$T" = "4" ]; then
  ok "las 4 tablas existen"
else
  bad "faltan tablas (hay $T de 4)"
fi

# Lo critico: sin RLS activa, la base restaurada deja de proteger la boveda
# y no da ningun error visible al operar.
R="$(q "SELECT count(*) FROM pg_class WHERE relname IN ('users','items','sessions','audit_log') AND relrowsecurity;")"
if [ "$R" = "4" ]; then
  ok "RLS activa en las 4 tablas"
else
  bad "RLS activa en solo $R/4. NO publiques esta copia."
fi

A="$(q "SELECT count(*) FROM pg_roles WHERE rolname='securekey_app';")"
if [ "$A" = "1" ]; then
  ok "existe el rol securekey_app"
else
  bad "falta securekey_app: la restauracion no tendria RLS"
fi

# El cifrado sigue siendo opaco. Si una fila tuviera texto en claro, el backup
# seria un problema en si mismo y no solo una wasted space.
# Se comprueba sobre la representacion hexadecimal, no sobre `convert_from`:
# el ciphertext es binario y `convert_from(..., 'UTF8')` lanza error si no es
# UTF-8 valido, lo que daria un falso negativo en toda fila legitima.
C="$(q "SELECT count(*) FROM items WHERE encode(ciphertext,'hex') ~ '([4-7][1-9a-f]){6}';")"
if [ "$C" = "0" ]; then
  ok "los items siguen siendo binario, no texto"
elif [ -z "$C" ]; then
  ok "no se pudo comprobar el cifrado (sin filas que comprobar)"
else
  bad "hay $C filas cuyo ciphertext parece texto. NO publiques este backup."
fi

echo
echo "== 5. Se parece a la base real =="
# `tr -cd '0-9'` y no `tr -d '[:space:]'`: `psql` puede devolver CRLF y un
# `\r` suelto haria que la comparacion de cadenas fallara sin motivo aparente.
REAL="$(pg psql -d "$DB_NAME" -t -A -c 'SELECT count(*) FROM users;' 2>/dev/null | tr -cd '0-9' || true)"
COPIADA="$(q 'SELECT count(*) FROM users;' | tr -cd '0-9')"
echo "  usuarios: real=${REAL:-?} copia=${COPIADA:-?}"
if [ -n "${REAL:-}" ] && [ -n "${COPIADA:-}" ]; then
  MIN_ESPERADOS=$(( REAL * (100 - ROW_TOLERANCE) / 100 ))
  if [ "$COPIADA" -ge "$MIN_ESPERADOS" ]; then
    ok "la copia tiene un numero de usuarios creible"
  else
    bad "la copia tiene $COPIADA usuarios y la real tiene $REAL: parece ANTIGUA"
  fi
else
  ok "comparacion de usuarios omitida (no se pudo leer el numero)"
fi

echo
echo "=============================================================="
if [ "$FAIL" -eq 0 ]; then
  echo " VEREDICTO: el backup es RESTAURABLE"
else
  echo " VEREDICTO: $FAIL comprobacion(es) fallida(s). No confies en este backup."
fi
echo "=============================================================="
[ "$FAIL" -eq 0 ]
