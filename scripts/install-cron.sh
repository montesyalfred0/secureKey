#!/usr/bin/env bash
# ===========================================================================
# Instala (o desinstala) el backup automatico en el cron del host.
#
#   scripts/install-cron.sh            -> instala
#   scripts/install-cron.sh --remove   -> desinstala
#   scripts/install-cron.sh --show     -> muestra la linea actual
#
# Por que cron del host y no un contenedor mas: un servicio mas que corre
# para siempre es otro proceso que mantener, que monitorizar y que puede
# quedarse sin hacer nada sin que nadie se entere. El cron deja rastro en
# `/var/log/syslog` y seFailure al reiniciar cron, no al reiniciar Docker.
#
# OJO: cron NO tiene entorno. Un `npm run backup` a pelo fallaria con
# "POSTGRES_PASSWORD no encontrado", asi que la linea generated lleva
# `cd` al proyecto y el propio script lee el `.env`.
# ===========================================================================
set -Eeuo pipefail

PROYECTO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LINE="17 4 * * * cd $PROYECTO && ./scripts/backup.sh >> $PROYECTO/backups/cron.log 2>&1"
TAG="# securekey-backup"

case "${1:-}" in
  --remove)
    crontab -l 2>/dev/null | grep -v "$TAG" | crontab - || true
    echo "Backup automatico desinstalado."
    exit 0
    ;;
  --show)
    crontab -l 2>/dev/null | grep "$TAG" || echo "No hay backup automatico instalado."
    exit 0
    ;;
  "") ;;
  *)
    echo "Uso: $0 [--remove|--show]" >&2
    exit 1
    ;;
esac

command -v crontab > /dev/null || {
  echo "ERROR: no hay 'crontab' en este sistema." >&2
  echo "       En Ubuntu/Debian: apt install cron" >&2
  exit 1
}

# 04:17 y no 04:00 a proposito: a las en punto se disparan a la vez todos los
# cron del mundo, incluidos los de otros servicios del mismo servidor.
[ -f "$PROYECTO/.env" ] || {
  echo "ERROR: no hay .env en $PROYECTO. Ejecuta 'npm run secrets' antes." >&2
  exit 1
}
mkdir -p "$PROYECTO/backups"

# No se duplica si se ejecuta dos veces.
ACTUAL="$(crontab -l 2>/dev/null | grep -v "$TAG" || true)"

printf '%s\n%s %s\n' "$ACTUAL" "$LINE" "$TAG" | sed '/^$/d' | crontab -

echo "Backup automatico instalado:"
echo "  $LINE"
echo
echo "Se ejecutara cada dia a las 04:17. Se conservan"
grep -m1 '^BACKUP_KEEP_DAYS=' "$PROYECTO/.env" 2>/dev/null || echo "  14 dias (BACKUP_KEEP_DAYS por defecto)"
echo "dias de copias."
echo
echo "Comprobaciones:"
echo "  ./scripts/install-cron.sh --show     ver la linea"
echo "  tail -f $PROYECTO/backups/cron.log     ver la salida"
echo "  npm run backup:verify                 comprobar que el ultimo backup"
echo "                                         se puede restaurar de verdad"
echo
echo "Y aun asi: revisa el log de vez en cuando. Un backup del que nadie se"
echo "cuenta no protege de nada."
