#!/bin/sh
# Informe del tamano del bundle: lo que descarga el navegador.
set -e
DIR=/usr/share/nginx/html/assets
echo "--- assets ---"
ls -l "$DIR" | awk 'NR>1 {printf "%10d  %s\n", $5, $9}'
echo ""
echo "--- comprimido (gzip), que es lo que viaja por la red ---"
total=0
for f in "$DIR"/*.js "$DIR"/*.css; do
  [ -e "$f" ] || continue
  size=$(gzip -c "$f" | wc -c)
  total=$((total + size))
  printf "%10d  %s\n" "$size" "$(basename "$f")"
done
printf "%10d  TOTAL\n" "$total"
