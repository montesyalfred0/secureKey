/**
 * Portapapeles con borrado automatico.
 *
 * Aqui vive la logica de seguridad de copiar una credencial, y hasta ahora no
 * tenia ni un test. El caso que mas importa es el que reporto un usuario: sin
 * permiso de lectura, el navegador AVISABA de que la pagina queria leer el
 * portapapeles veinte segundos despues de copiar, sin que estuviera haciendo
 * nada. Y si ademas se denegaba el permiso, el borrado no ocurria y la
 * contrasena se quedaba ahi para siempre.
 *
 * Estos tests fijan que el aviso no aparece y que el borrado siempre ocurre.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cancelAutoClear, copySensitive, CLEANUP_SECONDS } from '../src/lib/clipboard.js';

type ClipboardState = {
  /** Lo que hay ahora en el portapapeles. */
  value: string;
  writes: string[];
  reads: number;
  writeThrows?: boolean;
};

function install(clipboard: Partial<ClipboardState> = {}, readState: PermissionState | null = null) {
  const state: ClipboardState = {
    value: '',
    writes: [],
    reads: 0,
    ...clipboard,
  };

  const navigatorMock = {
    clipboard: {
      writeText: vi.fn(async (text: string) => {
        if (state.writeThrows === true) throw new Error('sin permiso');
        state.value = text;
        state.writes.push(text);
      }),
      readText: vi.fn(async () => {
        state.reads += 1;
        return state.value;
      }),
    },
    permissions: {
      query: vi.fn(async () => ({ state: readState })),
    },
  };

  vi.stubGlobal('navigator', navigatorMock);
  // `clipboard.ts` usa `window.setTimeout`: en el entorno de tests (node) no
  // existe `window`, asi que se expone con los temporizadores globales.
  vi.stubGlobal('window', { setTimeout, clearTimeout });

  return state;
}

const clearAt = (): void => {
  vi.advanceTimersByTime(CLEANUP_SECONDS * 1000);
};

/** Avanza el reloj y deja que se vacien las microtareas de la promesa. */
async function clearAtAsync(): Promise<void> {
  await vi.advanceTimersByTimeAsync(CLEANUP_SECONDS * 1000);
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cancelAutoClear();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('copySensitive', () => {
  it('escribe el valor y devuelve "copied"', async () => {
    const state = install();
    expect(await copySensitive('mi-contrasena')).toBe('copied');
    expect(state.value).toBe('mi-contrasena');
  });

  it('no hace nada con una cadena vacia', async () => {
    const state = install();
    expect(await copySensitive('')).toBe('failed');
    expect(state.writes).toEqual([]);
  });

  it('devuelve "failed" si el navegador rechaza la escritura', async () => {
    install({ writeThrows: true });
    expect(await copySensitive('mi-contrasena')).toBe('failed');
  });

  it('con autoClear = false no programa ningun borrado', async () => {
    const state = install();
    await copySensitive('mi-contrasena', false);
    await clearAtAsync();
    expect(state.value).toBe('mi-contrasena');
  });
});

describe('borrado automatico con permiso de lectura concedido', () => {
  it('vacia el portapapeles si sigue conteniendo la contrasena', async () => {
    const state = install({}, 'granted');
    await copySensitive('mi-contrasena');
    expect(state.value).toBe('mi-contrasena');

    await clearAtAsync();
    expect(state.reads).toBe(1);
    expect(state.value).toBe('');
  });

  it('NO vacia si el usuario copio otra cosa en medio', async () => {
    const state = install({}, 'granted');
    await copySensitive('mi-contrasena');
    // El usuario copia un enlace mientras corre el reloj.
    await navigator.clipboard.writeText('https://ejemplo.test');
    state.writes = [];

    await clearAtAsync();
    expect(state.value).toBe('https://ejemplo.test');
    expect(state.writes).toEqual([]);
  });
});

describe('borrado automatico SIN permiso de lectura', () => {
  // Este es el caso que se reporto: el navegador pedia permiso de lectura
  // veinte segundos despues de copiar, sin que el usuario hiciera nada.
  //
  // Ojo a la distincion, que es el fondo del asunto: consultar
  // `permissions.query` NO muestra ningun aviso (solo pregunta el estado), y es
  // lo que permite saber si hay que leer. Lo que dispara el aviso de permisos
  // es `clipboard.readText()`. Ese es el que no debe ocurrir nunca sin permiso.
  it('NUNCA lee el portapapeles, para no provocar el aviso de permisos', async () => {
    const state = install({}, 'prompt');
    await copySensitive('mi-contrasena');
    await clearAtAsync();

    expect(navigator.clipboard.readText).not.toHaveBeenCalled();
    expect(state.reads).toBe(0);
  });

  it('pero si consulta el estado del permiso, que es inocuo', async () => {
    install({}, 'prompt');
    await copySensitive('mi-contrasena');
    await clearAtAsync();

    expect(navigator.permissions.query).toHaveBeenCalledWith({ name: 'clipboard-read' });
  });

  it('vacia igualmente: el borrado no puede fallar en silencio', async () => {
    const state = install({}, 'prompt');
    await copySensitive('mi-contrasena');
    expect(state.value).toBe('mi-contrasena');

    await clearAtAsync();
    expect(state.value).toBe('');
  });

  it('también vacia si el permiso esta denegado de forma permanente', async () => {
    const state = install({}, 'denied');
    await copySensitive('mi-contrasena');
    await clearAtAsync();

    expect(state.reads).toBe(0);
    expect(state.value).toBe('');
  });

  it('tambien vacia si el navegador no tiene Permissions API', async () => {
    const state = install();
    vi.stubGlobal('navigator', {
      clipboard: {
        writeText: vi.fn(async (text: string) => {
          state.value = text;
        }),
        readText: vi.fn(async () => {
          state.reads += 1;
          return state.value;
        }),
      },
      // Sin `permissions`: `query` revienta y hay que aguantarlo.
    });

    await copySensitive('mi-contrasena');
    await clearAtAsync();

    expect(state.reads).toBe(0);
    expect(state.value).toBe('');
  });
});

describe('varias copias seguidas', () => {
  it('si la primera no limpia porque el usuario copio otra cosa, no reintenta', async () => {
    const state = install({}, 'granted');
    await copySensitive('primera');
    await copySensitive('segunda');

    // El usuario copia un enlace mientras corre el reloj.
    await navigator.clipboard.writeText('https://ejemplo.test');
    state.writes = [];

    // Pasa la ventana de la segunda: comprueba, ve que no es suya y no toca.
    await clearAtAsync();
    expect(state.value).toBe('https://ejemplo.test');
    expect(state.writes).toEqual([]);

    // No queda ningun temporizador vivo, asi que un segundo intento en la
    // ventana siguiente no debe ocurrir: si ocurriera, borraria el enlace.
    await clearAtAsync();
    expect(state.value).toBe('https://ejemplo.test');
  });

  it('la primera copia no programa un borrado propio', async () => {
    const state = install({}, 'granted');
    await copySensitive('primera');
    await copySensitive('segunda');

    // La ventana de la segunda: solo se limpia una vez, con el valor de la
    // ultima, no con el de la primera.
    await clearAtAsync();
    expect(state.writes.filter((w) => w === '')).toHaveLength(1);
  });

  it('copiar dos veces no vacia antes de tiempo', async () => {
    const state = install({}, 'granted');
    await copySensitive('primera');
    await copySensitive('segunda');
    expect(state.value).toBe('segunda');
  });
});

describe('cancelAutoClear', () => {
  it('anula el borrado pendiente', async () => {
    const state = install({}, 'granted');
    await copySensitive('mi-contrasena');
    cancelAutoClear();
    await clearAtAsync();

    expect(state.value).toBe('mi-contrasena');
  });

  it('se puede llamar sin ningun temporizador vivo', () => {
    expect(() => cancelAutoClear()).not.toThrow();
  });
});

describe('CLEANUP_SECONDS', () => {
  it('es la ventana que anuncia la interfaz', () => {
    expect(CLEANUP_SECONDS).toBe(20);
  });
});
