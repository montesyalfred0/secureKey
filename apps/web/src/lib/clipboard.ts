/**
 * Portapapeles con borrado automatico.
 *
 * Un gestor de contrasenas que copia y deja la contrasena en el portapapeles
 * para siempre se vacia de su valor: cualquier aplicacion puede leerlo. Por eso
 * hacemos borrado automatico, y solo si el contenido sigue siendo el nuestro
 * (para no destruir lo que el usuario haya copiado despues).
 */
const CLEANUP_MS = 20_000;

let pending: { timer: number } | undefined;

export type CopyResult = 'copied' | 'failed';

/**
 * ¿Esta concedido el permiso de LECTURA del portapapeles?
 *
 * Se consulta antes de leer en lugar de leer y pillar el error despues, porque
 * `readText()` dispara un prompt de permisos en el navegador. Preguntar veinte
 * segundos despues de copiar, sin que el usuario este haciendo nada en ese
 * instante, es exactamente el tipo de susto que hace que alguien pulse
 * "Bloquear" y no vuelva a mirar la pagina.
 */
async function canReadClipboard(): Promise<boolean> {
  try {
    const status = await navigator.permissions.query({
      // El DOM lib de TypeScript no lista todavia los permisos de
      // portapapeles, pero Chrome, Firefox y Safari los implementan. El
      // `catch` de abajo cubre ademas el caso de un navegador que no conozca
      // el nombre y rechace la consulta.
      name: 'clipboard-read' as PermissionName,
    });
    return status.state === 'granted';
  } catch {
    // Sin Permissions API, o con un nombre de permiso que el navegador no
    // reconoce. En ambos casos se asume que no se puede leer: asi no se
    // pregunta nunca y el borrado sigue haciendo su trabajo.
    return false;
  }
}

/**
 * Vacia el portapapeles cuando ya ha pasado la ventana.
 *
 * Con permiso de lectura se comprueba antes de tocar nada, para no pisar lo
 * que el usuario haya copiado despues. Sin permiso NO se pregunta: se vacia
 * directamente.
 *
 * Ese es el intercambio que se acepta aqui, y es deliberado. La alternativa
 * (pedir el permiso de lectura) significa que el borrado no ocurre si el
 * usuario lo deniega, y entonces la contrasena se queda en el portapapeles
 * para siempre: la proteccion falla en silencio justo en el caso en que mas
 * importa. Veinte segundos de una contrasena en un portapapeles del sistema es
 * un riesgo mayor que comerse lo que el usuario copio en medio.
 */
async function clearAfterWindow(value: string): Promise<void> {
  try {
    if (await canReadClipboard()) {
      const current = await navigator.clipboard.readText();
      if (current !== value) return; // el usuario copio otra cosa: no se toca
    }
    await navigator.clipboard.writeText('');
  } catch {
    // El portapapeles no esta disponible (contexto no seguro, permiso
    // denegado, pestana cerrada). No hay nada que limpiar.
  }
}

export async function copySensitive(value: string, autoClear = true): Promise<CopyResult> {
  if (value.length === 0) return 'failed';
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    return 'failed';
  }

  // Copiar dos veces seguidas solo deja vivo el temporizador de la ultima: si no,
  // el primero vaciaria un portapapeles que ya no es suyo.
  if (pending !== undefined) {
    clearTimeout(pending.timer);
    pending = undefined;
  }

  if (autoClear) {
    pending = {
      timer: window.setTimeout(() => {
        pending = undefined;
        void clearAfterWindow(value);
      }, CLEANUP_MS),
    };
  }

  return 'copied';
}

/** Cancela el borrado pendiente (p. ej. al bloquear la boveda). */
export function cancelAutoClear(): void {
  if (pending !== undefined) {
    clearTimeout(pending.timer);
    pending = undefined;
  }
}

export const CLEANUP_SECONDS = CLEANUP_MS / 1000;
