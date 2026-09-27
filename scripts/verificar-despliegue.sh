#!/usr/bin/env bash
# ===========================================================================
# Comprueba que lo que esta CORRIENDO es lo que esta en el REPOSITORIO.
#
#   bash scripts/verificar-despliegue.sh
#
# Por que existe esto
#
# Tres veces seguidas, un despliegue quedo a medias sin decir nada:
#
#   - se reconstruyo `api` pero no `web`, y el boton de borrar cuenta no llego
#   - se reconstruyo `migrate` con imagen vieja, y una migracion no se aplico
#   - falto el `git pull`, y se reconstruyo el mismo binario de antes
#
# En los tres casos: el comando termino en verde, el sitio respondio 200, y
# `docker compose ps` enseño todo en verde. El sintoma unico era que el cambio
# no estaba. Eso es lo peor que puede pasar con un despliegue: no se ve.
#
# Que compara
#
#   ESPERADO  el commit que dice el repositorio
#   ACTUAL    el commit con el que se construyo la imagen que esta corriendo
#
# El commit va GRABADO en la imagen, no exposed por HTTP a proposito: publicar
# el hash exacto le dice a quien lo rastree que vulnerabilidades concretas
# aplican a esta instalacion. El log de arranque lo tiene y el script lo lee
# desde el servidor, que es donde hace falta.
# ===========================================================================
set -Eeuo pipefail

# Un script cuya funcion es decirte si algo va mal NO PUEDE morir en silencio.
# Esta trampa convierte cualquier salida inesperada en un mensaje con el motivo
# y un codigo de error, en vez de dejar la pantalla vacia.
trap 'echo ""; echo "ERROR: el script ha salido en la linea $LINENO sin avisar." >&2; exit 3' ERR

PROYECTO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROYECTO"

C="docker compose -f docker-compose.yml -f docker-compose.prod.yml"

ok()   { echo "  ok   $1"; }
aviso(){ echo "  AVISO $1"; }
mal()  { FALLOS=$((FALLOS + 1)); echo "  FALLA $1"; }

FALLOS=0
fallar() { trap - ERR; echo "ERROR: $*" >&2; exit 1; }

# --- 1. Que commit hay en el repositorio -----------------------------------

[ -d .git ] || fallar "esto no parece un clon de git (falta .git)"
ESPERADO="$(git rev-parse --short HEAD)"

# `grep -v '^??'` sale con CODIGO 1 cuando el arbol esta limpio, porque no
# encuentra ninguna linea que conservar. Con `set -e` y `pipefail` eso aborta
# el script entero ANTES del primer `echo`, y el script entero se queda en
# blanco: sin un solo sintoma de nada. Es exactamente lo que pasó la primera
# vez que se ejecutó, con el arbol recien hecho `git pull`.
CAMBIOS_SIN_SUBIR="$(git status --porcelain | grep -v '^??' | wc -l | tr -d ' ' || true)"
[ -z "$CAMBIOS_SIN_SUBIR" ] && CAMBIOS_SIN_SUBIR=0
SIN_SUBIR="$(git log --oneline 'origin/main..HEAD' 2>/dev/null | wc -l | tr -d ' ' || true)"
[ -z "$SIN_SUBIR" ] && SIN_SUBIR=0

echo "Repositorio: $(pwd)"
echo "  ESPERADO: $ESPERADO"
echo

# --- 2. Que commit dice la imagen que esta corriendo ------------------------

ACTUAL="$($C logs api 2>/dev/null \
  | grep -o '"commit":"[^"]*"' \
  | tail -1 \
  | cut -d'"' -f4 || true)"

if [ -z "${ACTUAL:-}" ]; then
  aviso "la API no ha registrado ningun commit todavia."
  aviso "puede que acabe de arrancar: espera unos segundos y vuelve a lanzarlo."
  echo
  echo "=== VEREDICTO: NO SE PUEDE COMPROBAR ==="
  exit 2
fi

echo "  ACTUAL:   $ACTUAL"
echo

# Dice si un fichero cambia lo que ESTA CORRIENDO o no.
#
# Existe por un caso que se vio el mismo dia que se escribio este script: entre
# el commit que corria y el que habia en el repositorio solo cambiaba este
# script. La app era identica y aun asi el veredicto era "DESPLIEGUE
# INCOMPLETO", porque solo comparaba hashes.
#
# Eso es un fallo de diseno, y de los que mas caros salen: una comprobacion que
# se queja de mas acaba ignorandose, y el dia que avise de algo de verdad ya no
# la lee nadie. Peor que no tenerla.
#
# FALLA EN CERRADO a proposito: lo que no aparece en ninguna de las dos listas
# cuenta como codigo que SI despliega. Un fichero desconocido podria ser
# importante, y ante la duda se avisa.
afecta_a_lo_que_corre() {
  case "$1" in
    # Cambia el binario, la imagen o el servidor. Grito.
    apps/*|packages/*|infra/*|package.json|package-lock.json) return 0 ;;
    docker-compose.yml|docker-compose.*.yml|Dockerfile|*/Dockerfile) return 0 ;;
    # Documentacion, utilidades y ejemplos. No cambia nada de lo que sirve.
    scripts/*|docs/*|*.md|.env.example|.gitignore|.gitattributes|LICENSE) return 1 ;;
    # Desconocido: se asume que importa.
    *) return 0 ;;
  esac
}

# --- 3. El veredicto -------------------------------------------------------

if [ "$ACTUAL" = "desconocido" ]; then
  mal "la imagen se construyo SIN el argumento APP_COMMIT"
  echo
  echo "  Eso significa que nadie puede saber que version esta corriendo, y"
  echo "  este script no te lo va a poder decir nunca."
  echo
  echo "  Se arregla desplegando asi:"
  echo "    APP_COMMIT=\$(git rev-parse --short HEAD) \\"
  echo "    docker compose -f docker-compose.yml -f docker-compose.prod.yml build"
  echo
  echo "=== VEREDICTO: NO SE PUEDE COMPROBAR ==="
  exit 2
fi

if [ "$ACTUAL" != "$ESPERADO" ]; then
  # Que cambio entre el commit que corre y el que hay aqui. Si el commit que
  # corre no esta en el repositorio (por ejemplo tras un force-push, o una
  # rama reescrita), `git diff` falla y no se puede saber: se avisa entero.
  CAMBIAN=()
  while IFS= read -r linea; do
    [ -n "$linea" ] && CAMBIAN+=("$linea")
  done < <(git diff --name-only "$ACTUAL" "$ESPERADO" 2>/dev/null || true)

  RELEVANTES=()
  COSMETICOS=()
  for f in ${CAMBIAN[@]+"${CAMBIAN[@]}"}; do
    if afecta_a_lo_que_corre "$f"; then RELEVANTES+=("$f"); else COSMETICOS+=("$f"); fi
  done

  if [ "${#RELEVANTES[@]}" -eq 0 ] && [ "${#COSMETICOS[@]}" -gt 0 ]; then
    # CASO BUENO: los commits difieren, pero lo que corre es correcto.
    ok "la aplicacion esta al dia"
    aviso "lo que corre es $ACTUAL y el repositorio esta en $ESPERADO,"
    aviso "pero entre los dos SOLO cambian ficheros que no se despliegan:"
    for f in ${COSMETICOS[@]+"${COSMETICOS[@]}"}; do aviso "    $f"; done
    aviso "no hace falta reconstruir. Cuando quieras igualarlos, un rebuild."
    echo
  else
    mal "LO QUE CORRE NO ES LO QUE HAY EN EL REPOSITORIO"
    echo
    echo "  corre    $ACTUAL"
    echo "  hay      $ESPERADO"
    if [ "${#RELEVANTES[@]}" -gt 0 ]; then
      echo
      echo "  Estos ficheros SI cambian lo que se sirve:"
      for f in ${RELEVANTES[@]+"${RELEVANTES[@]}"}; do echo "    $f"; done
    elif [ "${#CAMBIAN[@]}" -eq 0 ]; then
      echo
      echo "  No se ha podido comparar que cambio entre los dos commits."
      echo "  Puede que el commit que corre no este en este repositorio."
    fi
    echo
    echo "  O no reconstruiste despues del ultimo commit, o reconstruiste solo"
    echo "  una parte. Lo habitual es esto ultimo: hay varios servicios que"
    echo "  salen del mismo codigo y 'build <servicio>' solo rehace ese."
    echo
    echo "  Se arregla reconstruyendolo TODO, sin nombre de servicio:"
    echo "    APP_COMMIT=\$(git rev-parse --short HEAD) \\"
    echo "    docker compose -f docker-compose.yml -f docker-compose.prod.yml build"
    echo "    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
    echo
    echo "=== VEREDICTO: DESPLIEGUE INCOMPLETO ==="
    exit 1
  fi
else
  ok "lo que corre es exactamente el commit del repositorio ($ESPERADO)"
fi

# --- 4. Avisos que no rompen nada pero sehzan de ver -----------------------

if [ "$CAMBIOS_SIN_SUBIR" != "0" ]; then
  aviso "$CAMBIOS_SIN_SUBIR fichero(s) modificado(s) sin commitear."
  aviso "  lo que corre se construyo desde el ULTIMO commit, no de lo que"
  aviso "  tienes ahora en el disco. Si editaste algo, no esta desplegado."
  echo
fi

if [ "$SIN_SUBIR" != "0" ]; then
  aviso "$SIN_SUBIR commit(s) sin subir a origin/main."
  echo
fi

# --- 5. Que el sitio responde ---------------------------------------------

SITIO="${APP_URL:-https://securekey.yal99.com}"

# `curl` ya imprime su propio "000" cuando no puede conectar, asi que un
# `|| echo 000` de respaldo produce "000000". Solo se usa si curl no devolvio
# NADA, que es cuando ni siquiera llego a ejecutarse.
CODIGO="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$SITIO" 2>/dev/null)" || true
[ -z "$CODIGO" ] && CODIGO="sin respuesta"

if [ "$CODIGO" = "200" ]; then
  ok "$SITIO responde 200"
else
  mal "$SITIO responde $CODIGO"
fi

SALUD="$(curl -s --max-time 15 "$SITIO/api/v1/health" 2>/dev/null)" || true
case "$SALUD" in
  *'"database":"up"'*)
    ok "la API responde y la base de datos esta arriba" ;;
  *)
    mal "la API no responde bien: ${SALUD:-sin respuesta}" ;;
esac

echo
if [ "$FALLOS" -eq 0 ]; then
  echo "=== VEREDICTO: DESPLIEGUE CORRECTO ==="
  exit 0
fi
echo "=== VEREDICTO: $FALLOS COMPROBACION(ES) FALLIDA(S) ==="
exit 1
