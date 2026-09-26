# Ejecuta backup.sh dentro de un contenedor, porque el host (Windows) no tiene
# bash. Monta el socket de Docker y el proyecto, para que el script vea el
# repositorio tal cual lo vera en la VPS.
#
#   docker run --rm -v "$PWD:/w" -v /var/run/docker.sock:/var/run/docker.sock \
#     -w /w docker:27-cli sh scripts/backup.sh
set -Eeuo pipefail

# El script llama a `docker compose`, que necesita el socket y el contexto del
# proyecto. Montar el socket es el precio de probarlo desde Windows.
export DOCKER_HOST=unix:///var/run/docker.sock
cd /w
exec sh scripts/backup.sh
