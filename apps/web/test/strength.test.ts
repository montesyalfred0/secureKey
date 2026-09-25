/**
 * Tests de `src/lib/strength.ts`.
 *
 * Dos cosas se comprueban aqui:
 *
 *  1. Que la evaluacion sea coherente consigo misma (score, etiqueta y tiempo
 *     de descifrado cuentan lo mismo).
 *  2. Que la carga diferida de `@zxcvbn-ts/core` funcione de verdad. Es la
 *     parte que mas facil se rompe: si el `import()` falla, o si se leen campos
 *     que la version instalada no expone, el `catch` del modulo cae en
 *     `quickScore()` en silencio y la UI sigue mintiendo con la heuristica.
 *
 * Quedan dos BUG CONOCIDOS, cada uno en su propio bloque:
 * `humanizeSeconds` (tabla de unidades desplazada) y `@zxcvbn-ts/core` sin los
 * diccionarios de idioma, que puntua "password123" como excelente.
 */
import { describe, expect, it } from 'vitest';
import {
  commonPasswordWarning,
  estimateCrackTime,
  evaluatePassword,
  humanizeSeconds,
  isCommonPassword,
  quickScore,
  vaultHealth,
} from '../src/lib/strength.js';
import type { ItemPlain } from '../src/lib/crypto.js';

/** 32 chars de 4 clases, sin patrones: el caso "bueno" de la app. */
const ALEATORIA = 'vQ7#mZ2!xL9@pR4$kT6&nB8*wJ3%hD5';
/** Misma mezcla de clases que `ALEATORIA`, pero mucho mas corta. */
const CORTA_MISMAS_CLASES = 'vQm7!xZ2';

function item(over: Partial<ItemPlain> = {}): ItemPlain {
  return {
    title: 'Sitio',
    username: 'usuario',
    password: 'Unica1#Segura',
    url: '',
    notes: '',
    favorite: false,
    strength: 3,
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...over,
  };
}

// ---------------------------------------------------------------------------

describe('strength: isCommonPassword', () => {
  it('detecta "password"', () => {
    expect(isCommonPassword('password')).toBe(true);
  });

  it('detecta "Contrasena1" normalizado a minusculas', () => {
    expect(isCommonPassword('Contrasena1')).toBe(true);
  });

  it('ignora espacios y mayusculas alrededor', () => {
    expect(isCommonPassword('  PASSWORD  ')).toBe(true);
  });

  it('una contrasena generada no esta en la lista', () => {
    expect(isCommonPassword('xK9#mQ2$vL')).toBe(false);
  });

  it('la cadena vacia no esta en la lista', () => {
    expect(isCommonPassword('')).toBe(false);
  });
});

describe('strength: commonPasswordWarning', () => {
  it('devuelve un aviso para una contrasena habitual', () => {
    expect(commonPasswordWarning('123456')).toMatch(/filtradas/);
  });

  it('no devuelve nada para una contrasena generada', () => {
    expect(commonPasswordWarning(ALEATORIA)).toBeNull();
  });

  it('no devuelve nada para la cadena vacia (no hay que avisar de nada)', () => {
    expect(commonPasswordWarning('')).toBeNull();
  });
});

describe('strength: quickScore', () => {
  it('la cadena vacia puntua 0 sin romperse', () => {
    expect(quickScore('').score).toBe(0);
  });

  it('la cadena vacia deja feedback al usuario', () => {
    expect(quickScore('').feedback.length).toBeGreaterThan(0);
  });

  it('la cadena vacia no inventa tiempo de descifrado', () => {
    expect(quickScore('').crackTime).toBe('-');
  });

  it('"123456" puntua 0', () => {
    expect(quickScore('123456').score).toBe(0);
  });

  it('"123456" genera avisos de longitud, lista y secuencia', () => {
    expect(quickScore('123456').warnings.length).toBeGreaterThanOrEqual(3);
  });

  it('una cadena larga y aleatoria puntua alto', () => {
    expect(quickScore(ALEATORIA).score).toBe(4);
  });

  it('la longitud domina: 40 chars de las mismas clases puntua mas que 8', () => {
    const larga = 'vQm7!xZ2Rk9#mN3$wP6&tB4*hD8yG1%jS5+fL0(uK2)';
    expect(quickScore(larga).score).toBeGreaterThan(quickScore(CORTA_MISMAS_CLASES).score);
  });

  it('la etiqueta corresponde al score', () => {
    expect(quickScore(ALEATORIA).label).toBe('Excelente');
  });

  it('un unico caracter repetido genera aviso', () => {
    expect(quickScore('aaaaaaaaaaaa').warnings).toContain('Un solo caracter repetido');
  });

  it('el patron palabra+numero genera aviso', () => {
    expect(quickScore('Juanito23').warnings).toContain(
      'Sigue el patron palabra+numero: facil de adivinar con un diccionario',
    );
  });
});

describe('strength: humanizeSeconds', () => {
  it('menos de un segundo se dice literalmente', () => {
    expect(humanizeSeconds(0.5)).toBe('menos de 1 segundo');
  });

  it('1 segundo va en singular', () => {
    expect(humanizeSeconds(1)).toBe('1 segundo');
  });

  it('45 segundos van en plural', () => {
    expect(humanizeSeconds(45)).toBe('45 segundos');
  });

  // La tabla de unidades estaba desplazada una posicion: al dividir, la
  // etiqueta destino se aplicaba tarde y 3600 s acababan en "1 minuto".
  // Estos tests son la red de seguridad del arreglo.
  it('120 s son 2 minutos', () => {
    expect(humanizeSeconds(120)).toBe('2 minutos');
  });

  it('3600 s son 1 hora', () => {
    expect(humanizeSeconds(3600)).toBe('1 hora');
  });

  it('86 400 s son 1 dia', () => {
    expect(humanizeSeconds(86_400)).toBe('1 dia');
  });

  it('400 dias son 1.1 anos', () => {
    expect(humanizeSeconds(86_400 * 400)).toBe('1.1 anos');
  });
});

describe('strength: estimateCrackTime', () => {
  it('0 bits no se traducen a un tiempo concreto', () => {
    expect(estimateCrackTime(0)).toBe('-');
  });

  it('40 bits salen en segundos', () => {
    expect(estimateCrackTime(40)).toBe('55 segundos');
  });

  it('un numero no finito es "eternamente"', () => {
    expect(estimateCrackTime(Number.POSITIVE_INFINITY)).toBe('eternamente');
  });
});

describe('strength: evaluatePassword (con carga diferida de zxcvbn)', () => {
  it('es una promesa', () => {
    expect(evaluatePassword('xK9#mQ2$vL')).toBeInstanceOf(Promise);
  });

  it('devuelve un score entero entre 0 y 4', async () => {
    const resultado = await evaluatePassword(ALEATORIA);
    expect(Number.isInteger(resultado.score)).toBe(true);
  });

  it('mantiene el score dentro de [0, 4] para cualquier entrada', async () => {
    const casos = ['', 'a', '123456', ALEATORIA, 'contrasena1'];
    const scores = await Promise.all(casos.map(async (c) => (await evaluatePassword(c)).score));
    expect(scores.every((s) => s >= 0 && s <= 4)).toBe(true);
  });

  it('una contrasena larga y aleatoria puntua alto', async () => {
    const resultado = await evaluatePassword(ALEATORIA);
    expect(resultado.score).toBeGreaterThanOrEqual(3);
  });

  it('devuelve una etiqueta y un tiempo de descifrado no vacios', async () => {
    const resultado = await evaluatePassword(ALEATORIA);
    expect({ etiqueta: resultado.label, crackTime: resultado.crackTime }).toEqual({
      etiqueta: expect.any(String),
      crackTime: expect.stringMatching(/\S/),
    });
  });

  it('feedback y warnings son arrays', async () => {
    const resultado = await evaluatePassword('123456');
    expect(Array.isArray(resultado.feedback)).toBe(true);
  });

  it('warnings es un array', async () => {
    const resultado = await evaluatePassword('123456');
    expect(Array.isArray(resultado.warnings)).toBe(true);
  });

  it('"123456" llega con avisos', async () => {
    const resultado = await evaluatePassword('123456');
    expect(resultado.warnings.length).toBeGreaterThan(0);
  });

  it('la cadena vacia se resuelve por la heuristica local, sin cargar zxcvbn', async () => {
    const resultado = await evaluatePassword('');
    expect(resultado.score).toBe(0);
  });

  it('el numero de intentos estimados es positivo', async () => {
    const resultado = await evaluatePassword(ALEATORIA);
    expect(resultado.guessesLog10).toBeGreaterThan(0);
  });

  it('"123456" llega con el aviso propio de contrasenas filtradas', async () => {
    const resultado = await evaluatePassword('123456');
    expect(resultado.warnings.join(' ')).toMatch(/filtradas/);
  });

  it('"aaaaaaaaaaaaaaaa" puntua como muy debil (zxcvbn le da 0)', async () => {
    const resultado = await evaluatePassword('aaaaaaaaaaaaaaaa');
    expect(resultado.score).toBeLessThanOrEqual(1);
  });

  it('el feedback llega en espanol desde las traducciones registradas', async () => {
    const resultado = await evaluatePassword('aaaaaaaaaaaaaaaa');
    expect(resultado.feedback.length).toBeGreaterThan(0);
    // Ni una sola palabra en ingles: las traducciones propias estan cargadas.
    const todo = [...resultado.feedback, ...resultado.warnings, resultado.crackTime].join(' | ');
    for (const inglesa of ['easy to guess', 'Avoid', 'Use ', 'less than a second', 'repeated']) {
      expect(todo).not.toContain(inglesa);
    }
    // Y debe aportar algo concreto que se pueda leer en la interfaz.
    expect(resultado.feedback.some((linea) => linea.trim().length > 0)).toBe(true);
  });

  it('una contrasena repetida dispara el aviso de la traduccion de zxcvbn', async () => {
    const resultado = await evaluatePassword('aaaaaaaaaaaaaaaa');
    expect(resultado.warnings.join(' ')).toMatch(/repetid/i);
  });

  it('el resultado viene de zxcvbn y no de la heuristica local', async () => {
    const conZxcvbn = await evaluatePassword(ALEATORIA);
    expect(conZxcvbn).not.toEqual(quickScore(ALEATORIA));
  });

  it('el tiempo de descifrado sale de crackTimesDisplay, no de estimateCrackTime', async () => {
    const resultado = await evaluatePassword('aaaaaaaaaaaaaaaa');
    expect(resultado.crackTime).not.toBe(quickScore('aaaaaaaaaaaaaaaa').crackTime);
  });

  // Sin `@zxcvbn-ts/language-common` y `@zxcvbn-ts/language-en` registrados,
  // zxcvbn solo puede hacer fuerza bruta y puntuaba "password123" con un 4 y
  // la etiqueta "Excelente": el indicador affirmaba justo lo contrario.
  // Este test es la red de seguridad de esa carga.
  it('"password123" no puede puntuar como excelente', async () => {
    const resultado = await evaluatePassword('password123');
    expect(resultado.score).toBeLessThanOrEqual(2);
  });

  it('"password123" no se etiqueta como Excelente', async () => {
    const resultado = await evaluatePassword('password123');
    expect(resultado.label).not.toBe('Excelente');
  });

  it('"password123" recibe igual el aviso de la lista local de filtradas', async () => {
    const resultado = await evaluatePassword('password123');
    expect(resultado.warnings.join(' ')).toMatch(/filtradas/);
  });

  // REGRESION (strength.ts:226-227): `evaluatePassword` leia la API de zxcvbn
  // v1 en snake_case (`crack_times_display`, `guesses_log10`) mientras que la
  // dependencia instalada es la v3, que la expone en camelCase
  // (`crackTimesDisplay`, `guessesLog10`). La lectura de `crack_times_display`
  // devolvia `undefined`, reventaba con TypeError y el `catch` sin argumentos
  // (strength.ts:231) se lo comia: TODA llamada caia en `quickScore()` y el
  // indicador que veia el usuario era siempre la heuristica local.
  // Los cuatro tests de arriba son la red que avisa si alguien vuelve a leer
  // los campos antiguos: son los que saltaron cuando se corrigio el modulo.
});

describe('strength: vaultHealth', () => {
  it('una boveda vacia esta sana por definición', () => {
    expect(vaultHealth([])).toEqual({ total: 0, debiles: 0, reutilizadas: 0, sinUsuario: 0 });
  });

  it('cuenta total, debiles, reutilizadas y sin usuario', () => {
    const items: ItemPlain[] = [
      // Debil y sin usuario: cuenta una vez en `debiles` y una en `sinUsuario`.
      item({ title: 'A', username: '', password: 'Repetida1!', strength: 0 }),
      // Reutilizada: es la SEGUNDA aparicion de 'Repetida1!'.
      item({ title: 'B', username: 'bob', password: 'Repetida1!', strength: 4 }),
      item({ title: 'C', username: 'carol', password: 'Unica2#', strength: 3 }),
    ];
    expect(vaultHealth(items)).toEqual({ total: 3, debiles: 1, reutilizadas: 1, sinUsuario: 1 });
  });

  it('la primera aparicion de una contrasena NO cuenta como reutilizada', () => {
    expect(vaultHealth([item({ password: 'Unica3$', strength: 4 })]).reutilizadas).toBe(0);
  });

  it('tres veces la misma contrasena cuentan como dos reutilizaciones', () => {
    const items = [
      item({ password: 'Igual4#', strength: 4 }),
      item({ password: 'Igual4#', strength: 4 }),
      item({ password: 'Igual4#', strength: 4 }),
    ];
    expect(vaultHealth(items).reutilizadas).toBe(2);
  });

  it('un strength de -1 (sin medir todavia) no se cuenta como debil', () => {
    expect(vaultHealth([item({ strength: -1 })]).debiles).toBe(0);
  });

  it('un score de 1 si cuenta como debil', () => {
    expect(vaultHealth([item({ strength: 1 })]).debiles).toBe(1);
  });

  it('un usuario con solo espacios cuenta como ausente', () => {
    expect(vaultHealth([item({ username: '   ' })]).sinUsuario).toBe(1);
  });

  it('las contrasenas vacias no cuentan como reutilizadas entre si', () => {
    expect(vaultHealth([item({ password: '' }), item({ password: '' })]).reutilizadas).toBe(0);
  });
});
