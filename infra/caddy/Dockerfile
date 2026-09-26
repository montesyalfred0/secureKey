# ===========================================================================
# Caddy con el modulo de DNS de Cloudflare.
#
#   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
#
# Por que una imagen propia y no `caddy:2-alpine`:
#
# El certificado de Let's Encrypt se pide con el desafio DNS-01, y para eso
# Caddy necesita hablar con la API de Cloudflare. Eso lo aporta el modulo
# `caddy-dns/cloudflare`, que **no viene en la imagen oficial**: la imagen
# `caddy:2-alpine` solo incluye los modulos estandar de Caddy.
#
# Por que DNS-01 y no el de HTTP:
#
# El desafio HTTP-01 necesita el puerto 80, y en esta VPS el 80 ya lo ocupa el
# nginx que sirve las otras aplicaciones. Un solo servicio puede escuchar en un
# puerto. Con DNS-01 a Caddy no le hace falta ningun puerto para el desafio:
# solo para resolver un nombre. Por eso SecureKey funciona con el 443 libre y
# sin tocar el nginx de los demas.
#
# `v0.2.4` esta fijada a proposito. Sin fijar, `xcaddy build` traeria la ultima
# version publicada el dia de la construccion: dos VPS montadas con semanas de
# diferencia podrian acabar con binarios distintos, y una actualizacion
# automatica de una dependencia no es una mejora que se acepte sola. Para
# actualizar: cambia la etiqueta, construye y comprueba que el certificado se
# emite y se renueva.
# ===========================================================================
FROM caddy:2-builder-alpine AS builder

RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare@v0.2.4

FROM caddy:2-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
