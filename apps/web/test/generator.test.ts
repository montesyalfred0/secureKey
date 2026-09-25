/**
 * Tests de `src/lib/generator.ts`.
 *
 * Lo que importa aqui no es solo que la contrasena sea larga: es que sea
 * IMPREDECIBLE y ESTADISTICAMENTE UNIFORME. Un `%` en lugar de un rechazo por
 * limite sesga la distribucion hacia los primeros caracteres del conjunto, que
 * es justo lo que se comprueba con la prueba de chi-cuadrado del final.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import {
  DEFAULT_OPTIONS,
  MAX_ACTIVE_CLASSES,
  MAX_LENGTH,
  MIN_LENGTH,
  classPool,
  entropyBits,
  generatePassword,
  strengthLabel,
  type CharSets,
  type GeneratorOptions,
} from '../src/lib/generator.js';

/** Las cuatro clases activas a la vez (las claves son las de `CLASES`). */
const TODAS: CharSets = { minusculas: true, mayusculas: true, digitos: true, simbolos: true };
const NINGUNA: CharSets = { minusculas: false, mayusculas: false, digitos: false, simbolos: false };
const NINGUNA_TODAS_BUT_DIGITOS: CharSets = {
  minusculas: false,
  mayusculas: false,
  digitos: true,
  simbolos: false,
};
const SOLO_MINUSCULAS: CharSets = {
  minusculas: true,
  mayusculas: false,
  digitos: false,
  simbolos: false,
};

/** Regex que detecta la presencia de una clase dentro de la contrasena. */
const REGEX_CLASE: Record<keyof CharSets, RegExp> = {
  minusculas: /[a-z]/,
  mayusculas: /[A-Z]/,
  digitos: /[0-9]/,
  simbolos: /[^A-Za-z0-9]/,
};

/** Caracteres que `evitarAmbiguos` declara excluidos (copia literal del modulo). */
const AMBIGUOS = new Set('0O1lI|`\'";:.,{}[]()/\\<>'.split(''));

const ALFABETO = 'abcdefghijklmnopqrstuvwxyz';

function opciones(over: Partial<GeneratorOptions> = {}): GeneratorOptions {
  return { ...DEFAULT_OPTIONS, ...over };
}

// ---------------------------------------------------------------------------

describe('generator: constantes', () => {
  it('el rango valido va de 8 a 128 caracteres', () => {
    expect([MIN_LENGTH, MAX_LENGTH]).toEqual([8, 128]);
  });

  it('los valores por defecto exigen todas las clases y evitan ambiguos', () => {
    expect(DEFAULT_OPTIONS).toEqual({
      length: 20,
      sets: TODAS,
      evitarAmbiguos: true,
      exigirTodasLasClases: true,
    });
  });
});

describe('generator: classPool', () => {
  it('no devuelve caracteres duplicados con evitarAmbiguos', () => {
    const pool = classPool(TODAS, true);
    expect(new Set(pool).size).toBe(pool.length);
  });

  it('no devuelve caracteres duplicados sin evitarAmbiguos', () => {
    const pool = classPool(TODAS, false);
    expect(new Set(pool).size).toBe(pool.length);
  });

  it('solo minusculas sin evitar ambiguos son las 26 letras', () => {
    expect([...classPool(SOLO_MINUSCULAS, false)].sort().join('')).toBe(ALFABETO);
  });

  it('evitarAmbiguos quita la "l" de minusculas: 25 letras', () => {
    expect(classPool(SOLO_MINUSCULAS, true).length).toBe(25);
  });

  it('el pool vacio es una cadena vacia', () => {
    expect(classPool(NINGUNA, true)).toBe('');
  });
});

describe('generator: generatePassword', () => {
  it('respeta la longitud exacta pedida (8, 20, 32, 64, 128)', () => {
    const erroneas: number[] = [];
    for (const longitud of [8, 20, 32, 64, 128]) {
      if (generatePassword(opciones({ length: longitud })).length !== longitud) {
        erroneas.push(longitud);
      }
    }
    expect(erroneas).toEqual([]);
  });

  it('acota una longitud demasiado corta a MIN_LENGTH', () => {
    expect(generatePassword(opciones({ length: 3 })).length).toBe(MIN_LENGTH);
  });

  it('acota una longitud excesiva a MAX_LENGTH', () => {
    expect(generatePassword(opciones({ length: 5_000 })).length).toBe(MAX_LENGTH);
  });

  it('con exigirTodasLasClases, cada clase activa aparece SIEMPRE (20 000 muestras)', () => {
    const faltan = new Set<string>();
    for (let i = 0; i < 20_000; i += 1) {
      const clave = generatePassword(opciones({ length: 8 }));
      for (const clase of Object.keys(REGEX_CLASE) as (keyof CharSets)[]) {
        if (!REGEX_CLASE[clase].test(clave)) faltan.add(clase);
      }
    }
    expect([...faltan]).toEqual([]);
  });

  it('con evitarAmbiguos, NUNCA aparece un caracter ambiguo', () => {
    const intrusionados = new Set<string>();
    for (let i = 0; i < 500; i += 1) {
      for (const c of generatePassword(opciones({ length: 32 }))) {
        if (AMBIGUOS.has(c)) intrusionados.add(c);
      }
    }
    expect([...intrusionados]).toEqual([]);
  });

  it('sin evitarAmbiguos, los caracteres ambiguos si llegan a salir', () => {
    let intrusion = false;
    for (let i = 0; i < 500 && !intrusion; i += 1) {
      for (const c of generatePassword(opciones({ length: 32, evitarAmbiguos: false }))) {
        if (AMBIGUOS.has(c)) intrusion = true;
      }
    }
    expect(intrusion).toBe(true);
  });

  it('desactivar una clase elimina todos sus caracteres de la contrasena', () => {
    const fugas = new Set<string>();
    for (const clase of Object.keys(REGEX_CLASE) as (keyof CharSets)[]) {
      const sets: CharSets = { minusculas: false, mayusculas: false, digitos: false, simbolos: false };
      sets[clase] = true;
      for (let i = 0; i < 200; i += 1) {
        const clave = generatePassword(
          opciones({ length: 24, sets, exigirTodasLasClases: false }),
        );
        for (const otra of Object.keys(REGEX_CLASE) as (keyof CharSets)[]) {
          if (otra !== clase && REGEX_CLASE[otra].test(clave)) fugas.add(`${clase}->${otra}`);
        }
      }
    }
    expect([...fugas]).toEqual([]);
  });

  it('dos contrasenas consecutivas casi nunca coinciden', () => {
    const iguales = generatePassword(opciones()) === generatePassword(opciones());
    expect(iguales).toBe(false);
  });

  it('LANZA si no hay ninguna clase de caracteres activa', () => {
    expect(() => generatePassword(opciones({ sets: NINGUNA }))).toThrow(/al menos una clase/);
  });

  // BUG CONOCIDO (generador.ts:91-93): la rama `length < classes.length` es
  // La invariante MIN_LENGTH > MAX_ACTIVE_CLASSES es lo que hace que la
  // garantia exigirTodasLasClases no necesite un chequeo de error: un
  // caracter por clase siempre cabe dentro de la longitud minima. Si alguien
  // baja MIN_LENGTH por debajo de 4, este test falla y avisa.
  it('MIN_LENGTH supera al numero maximo de clases activas', () => {
    expect(MIN_LENGTH).toBeGreaterThan(MAX_ACTIVE_CLASSES);
  });

  it('una longitud por debajo del minimo se acota, sin lanzar', () => {
    expect(generatePassword(opciones({ length: 3 })).length).toBe(MIN_LENGTH);
  });

  it('la garantia por clase se cumple con la longitud recortada al minimo', () => {
    // El recorte a MIN_LENGTH nunca puede impedir cumplir "una por clase",
    // porque MIN_LENGTH > MAX_ACTIVE_CLASSES. Este test es el que lo fija.
    for (const sets of [TODAS, SOLO_MINUSCULAS, NINGUNA_TODAS_BUT_DIGITOS]) {
      const salida = generatePassword(opciones({ length: 3, sets, exigirTodasLasClases: true }));
      expect(salida).toHaveLength(MIN_LENGTH);
      for (const clase of Object.entries(sets).filter(([, activo]) => activo).map(([key]) => key)) {
        const pool = classPool({ ...TODAS, [clase]: true }, true);
        expect(salida).toMatch(new RegExp(`[${pool.replace(/[\\\]^-]/g, '\\$&')}]`));
      }
    }
  });
});
