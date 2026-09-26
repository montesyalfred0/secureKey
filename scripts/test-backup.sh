#!/usr/bin/env bash
# Ejecuta la MISMA logica de scripts/backup.sh, pero dentro de un contenedor
# con el CLI de Docker. Existe para poder probar el backup en Windows con
# Docker Desktop, donde no hay bash ni cliente postgres en el host.
#
#   docker run --rm -v "$PWD:/w" -v /var/run/docker.sock:/var/run/docker.sock \
#     -w /w docker:27-cli sh scripts/test-backup.sh
set -Eeuo pipefail

DB="$(docker ps --filter "name=securekey-db" --format '{{.ID}}' | head -1)"
[ -n "$DB" ] || { echo "ERROR: securekey-db no esta en marcha" >&2; exit 1; }

# `-u postgres` es el USUARIO DEL SISTEMA (unico que existe en el contenedor).
# `-U` es el ROL DE LA BASE DE DATOS (`securekey`; el rol `postgres` no existe).
# Confundirlos da "no matching entries in passwd file" o "role does not exist".
DB_ROLE="${POSTGRES_USER:-securekey}"
DB_NAME="${POSTGRES_DB:-securekey}"
PW="${POSTGRES_PASSWORD:-}"
CHECK="securekey_restore_check"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p /w/backups
DUMP="/w/backups/securekey-${STAMP}.dump"
GLOBALS="/w/backups/globals-${STAMP}.sql"

echo "== volcado (rol=$DB_ROLE db=$DB_NAME) =="
docker exec -u postgres -e PGPASSWORD="$PW" "$DB" pg_dump -Fc -d "$DB_NAME" -U "$DB_ROLE" > "$DUMP"
docker exec -u postgres -e PGPASSWORD="$PW" "$DB" pg_dumpall --globals-only -U "$DB_ROLE" > "$GLOBALS"
chmod 600 "$DUMP" "$GLOBALS"
ls -l "$DUMP" "$GLOBALS"

echo
echo "== integridad: pg_restore --list =="
docker exec -i -u postgres -e PGPASSWORD="$PW" "$DB" pg_restore --list -U "$DB_ROLE" < "$DUMP" | head -3
echo "  entradas: $(docker exec -i -u postgres -e PGPASSWORD="$PW" "$DB" pg_restore --list -U "$DB_ROLE" < "$DUMP" | wc -l)"

echo
echo "== los globals traen el rol de la RLS? =="
grep -q securekey_app "$GLOBALS" && echo "  OK  securekey_app presente" || echo "  FALLO: falta securekey_app"

echo
echo "== restauracion real en un Postgres aislado =="
docker rm -f "$CHECK" > /dev/null 2>&1 || true
docker run -d --name "$CHECK" -e POSTGRES_DB=securekey -e POSTGRES_USER=securekey \
  -e POSTGRES_PASSWORD=verificacion_local postgres:17-alpine > /dev/null
for _ in $(seq 1 30); do
  docker exec "$CHECK" pg_isready -U securekey -d securekey > /dev/null 2>&1 && break
  sleep 2
done

docker cp "$GLOBALS" "$CHECK:/tmp/g.sql"
docker exec "$CHECK" psql -U securekey -d postgres -q -f /tmp/g.sql > /dev/null 2>&1
docker cp "$DUMP" "$CHECK:/tmp/b.dump"
docker exec "$CHECK" pg_restore -U securekey -d securekey --no-owner /tmp/b.dump

q() { docker exec "$CHECK" psql -U securekey -d securekey -t -A -c "$1"; }
echo "  tablas:      $(q "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','items','sessions','audit_log');")/4"
echo "  RLS activas: $(q "SELECT count(*) FROM pg_class WHERE relname IN ('users','items','sessions','audit_log') AND relrowsecurity;")/4"
echo "  rol app:     $(q "SELECT count(*) FROM pg_roles WHERE rolname='securekey_app';")/1"
echo "  usuarios:    $(q 'SELECT count(*) FROM users;')"
echo "  items:       $(q 'SELECT count(*) FROM items;')"
docker rm -f "$CHECK" > /dev/null
echo
echo "RESTAURACION VERIFICADA. Nada se ha tocado en la base real."
