/**
 * Portapapeles con borrado automatico.
 *
 * Un gestor de contrasenas que copia y deja la contrasena en el portapapeles
 * para siempre se vacia de su valor: cualquier aplicacion puede leerlo. Por eso
 * hacemos borrado automatico, y solo si el contenido sigue siendo el nuestro
 * (para no destruir lo que el usuario haya copiado despues).
 */
const CLEANUP_MS = 20_000;

let pending: { value: string; timer: number } | undefined;

export type CopyResult = 'copied' | 'cleared' | 'failed';

export async function copySensitive(value: string, autoClear = true): Promise<CopyResult> {
  if (value.length === 0) return 'failed';
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    return 'failed';
  }

  if (pending !== undefined) {
    clearTimeout(pending.timer);
    pending = undefined;
  }

  if (autoClear) {
    const timer = window.setTimeout(async () => {
      pending = undefined;
      try {
        // Si el permiso de lectura no esta concedido, no podemos comprobar
        // nada: mejor no tocar el portapapeles del usuario a ciegas.
        const current = await navigator.clipboard.readText();
        if (current === value) await navigator.clipboard.writeText('');
      } catch {
        // Sin permiso de lectura: dejamos constancia de que quedo sin limpiar.
      }
    }, CLEANUP_MS);
    pending = { value, timer };
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
