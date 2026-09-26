#!/usr/bin/env bash
# ===========================================================================
# Restauracion de SecureKey. Pensado para el peor dia.
#
#   scripts/restore.sh backups/securekey-20260925T101500Z.dump
#
# Levanta un PostgreSQL AISLADO, restaura ahi y verifica que el resultado es
# una boveda usable. Solo cuando todo cuadra se ofrece tocar el real.
#
# Por que NO restaura directamente sobre la base viva: un restore a medias
# deja la produccion en un estado que antes no existia, y en un gestor de
# contrasenas eso puede significar credenciales irrecuperables. El dump# sobrescribe tablas enteras; no hay "deshacer".
# ===========================================================================
set -Eeuo pipefail

DUMP="${1:-}"
if [ -z "$DUMP" ] || [ ! -f "$DUMP" ]; then
  echo "Uso: $0 <ruta/al/dump.dump>" >&2
  exit 1
fi

GLOBALS="$(dirname "$DUMP")/globals-$(basename "$DUMP" | sed 's/^securekey-//').sql"
VERIFY_DB="securekey_restore_check"
VERIFY_PASS="verificacion-local-unica"

echo "=============================================================="
echo " 1/4  Levanto un Postgres aislado para verificar"
echo "=============================================================="
docker rm -f "$VERIFY_DB" > /dev/null 2>&1 || true
docker run -d --name "$VERIFY_DB" \
  -e POSTGRES_DB=securekey \
  -e POSTGRES_USER=securekey \
  -e POSTGRES_PASSWORD="$VERIFY_PASS" \
  postgres:17-alpine > /dev/null

for _ in $(seq 1 30); do
  if docker exec "$VERIFY_DB" pg_isready -U securekey -d securekey > /dev/null 2>&1; then break; fi
  sleep 2
done

cleanup() { docker rm -f "$VERIFY_DB" > /dev/null 2>&1 || true; }
trap cleanup EXIT

echo "=============================================================="
echo " 2/4  Restauro el volcado"
echo "=============================================================="
# Los globals primero: las politicas RLS necesitan que exista `securekey_app`.
if [ -f "$GLOBALS" ]; then
  docker cp "$GLOBALS" "$VERIFY_DB:/tmp/globals.sql"
  docker exec "$VERIFY_DB" psql -U securekey -d postgres -v ON_ERROR_STOP=1 -f /tmp/globals.sql > /dev/null
  echo "OK  roles restaurados (incluye securekey_app)"
else
  echo "AVISO: no hay globals junto al dump; las politicas RLS no se aplicaran"
fi

docker cp "$DUMP" "$VERIFY_DB:/tmp/backup.dump"
docker exec "$VERIFY_DB" pg_restore -U securekey -d securekey --no-owner < /dev/null 2>/dev/null || true
docker exec "$VERIFY_DB" pg_restore -U securekey -d securekey --no-owner /tmp/backup.dump
echo "OK  datos restaurados"

echo "=============================================================="
echo " 3/4  Verifico que la base restaurada es coherente"
echo "=============================================================="
q() { docker exec "$VERIFY_DB" psql -U securekey -d securekey -t -A -c "$1"; }

TABLAS="$(q "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','items','sessions','audit_log');")"
if [ "$TABLAS" != "4" ]; then
  echo "ERROR: faltan tablas (esperadas 4, hay $TABLAS). El dump no es de esta app." >&2
  exit 1
fi
echo "OK  las 4 tablas existen"

USERS="$(q 'SELECT count(*) FROM users;')"
ITEMS="$(q 'SELECT count(*) FROM items;')"
echo "OK  $USERS usuario(s), $ITEMS item(s)"

# Lo importante: que la RLS este ACTIVA. Un restore que se trae las tablas pero
# sin los ENABLE ROW LEVEL SECURITY deja la base en un estado donde la API
# opera sin aislamiento, sin ningun error visible. Esto es lo que hay que
# comprobar.
RLS="$(q "SELECT count(*) FROM pg_class WHERE relname IN ('users','items','sessions','audit_log') AND relrowsecurity;")"
if [ "$RLS" != "4" ]; then
  echo "ERROR: RLS activa en solo $RLS/4 tablas. NO publiques esto." >&2
  exit 1
fi
echo "OK  RLS activa en las 4 tablas"

ROL="$(q "SELECT count(*) FROM pg_roles WHERE rolname='securekey_app';")"
if [ "$ROL" != "1" ]; then
  echo "ERROR: falta el rol securekey_app; la API no podria funcionar." >&2
  exit 1
fi
echo "OK  existe el rol securekey_app"

# Y que el cifrado sigue siendo opaco: si una fila de items tuviera texto
# claro, el backup seria un problema en si mismo.
CLARO="$(q "SELECT count(*) FROM items WHERE convert_from(ciphertext,'UTF8') ~ '[A-Za-z]{6}';")"
if [ "$CLARO" != "0" ]; then
  echo "ERROR: hay ciphertext que parece texto claro. NO publiques este backup." >&2
  exit 1
fi
echo "OK  los items siguen siendo binario, no texto"

echo "=============================================================="
echo " 4/4  Resultado"
echo "=============================================================="
echo "El volcado RESTAURA bien y es coherente."
echo
echo "Para aplicarlo de verdad sobre la base en produccion:"
echo "  1. docker compose stop api web caddy"
echo "  2. docker exec -u postgres \$(docker compose ps -q db) \\"
echo "       pg_restore -U securekey -d securekey --clean --if-exists < <tu-dump>"
echo "  3. docker compose up -d"
echo
echo "El Postgres de verificacion se ha eliminado. Nada se ha tocado."
