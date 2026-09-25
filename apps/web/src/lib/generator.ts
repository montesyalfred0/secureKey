/**
 * Generador de contrasenas.
 *
 * Correctitud estadistica: se elige un indice con `crypto.getRandomValues` y
 * se RECHAZA si cae fuera del rango, en lugar de usar `% tamano` (que sesga
 * hacia los primeros indices cuando el tamano del conjunto no divide 256).
 * Sin esto, la entropia real por caracter es menor que la teorica.
 */
import { randomBytes } from './crypto.js';

export type CharSets = {
  minusculas: boolean;
  mayusculas: boolean;
  digitos: boolean;
  simbolos: boolean;
};

export type GeneratorOptions = {
  length: number;
  sets: CharSets;
  /** Excluye 0/O, 1/l/I, etc. Recomendado para evitar confusiones al leer. */
  evitarAmbiguos: boolean;
  /** Garantiza al menos un caracter de cada clase activa. */
  exigirTodasLasClases: boolean;
};

export const DEFAULT_OPTIONS: GeneratorOptions = {
  length: 20,
  sets: { minusculas: true, mayusculas: true, digitos: true, simbolos: true },
  evitarAmbiguos: true,
  exigirTodasLasClases: true,
};

const AMBIGUOS = new Set('0O1lI|`\'";:.,{}[]()/\\<>'.split(''));

const CLASES = {
  minusculas: 'abcdefghijklmnopqrstuvwxyz',
  mayusculas: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digitos: '0123456789',
  simbolos: '!@#$%^&*()-_=+[]{};:,.?/~',
} as const;

export function classPool(sets: CharSets, evitarAmbiguos: boolean): string {
  const chars = (Object.keys(CLASES) as (keyof typeof CLASES)[])
    .filter((key) => sets[key])
    .map((key) => (evitarAmbiguos ? CLASES[key].split('').filter((c) => !AMBIGUOS.has(c)).join('') : CLASES[key]))
    .join('');
  return [...new Set(chars)].join('');
}

export function activeClasses(sets: CharSets): (keyof typeof CLASES)[] {
  return (Object.keys(CLASES) as (keyof typeof CLASES)[]).filter((key) => sets[key]);
}

export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;

/**
 * Invariante del generador: `MIN_LENGTH` (8) es MAYOR que el numero maximo de
 * clases simultaneas (4), de modo que la garantia "un caracter de cada clase
 * activa" siempre cabe dentro del mínimo y no necesita un chequeo de error.
 *
 * Esta nota existe para que nadie reintroduzca un `length < classes.length`
 * evaluado sobre la longitud ya recortada: sería codigo muerto.
 */
export const MAX_ACTIVE_CLASSES = 4;
if (activeClasses(DEFAULT_OPTIONS.sets).length > MAX_ACTIVE_CLASSES) {
  throw new Error('MAX_ACTIVE_CLASSES esta desactualizada');
}

function secureIndex(poolSize: number): number {
  if (poolSize < 1) throw new RangeError('El conjunto de caracteres esta vacio');
  if (poolSize === 1) return 0;
  // Mayor multiplo de poolSize que cabe en 256. Los valores mayores o iguales
  // a ese limite se descartan -> distribucion uniforme exacta.
  const limit = Math.floor(256 / poolSize) * poolSize;
  for (;;) {
    const byte = randomBytes(1)[0]!;
    if (byte < limit) return byte % poolSize;
  }
}

function pick(pool: string): string {
  return pool[secureIndex(pool.length)]!;
}

/** Fisher-Yates con CSPRNG: barajar con `Math.random()` seria un fallo grave. */
function shuffle(chars: string[]): string[] {
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = secureIndex(i + 1);
    const tmp = chars[i]!;
    chars[i] = chars[j]!;
    chars[j] = tmp;
  }
  return chars;
}

export function generatePassword(options: GeneratorOptions): string {
  const classes = activeClasses(options.sets);
  if (classes.length === 0) {
    throw new Error('Activa al menos una clase de caracteres');
  }

  // Recortamos a los limites soportados. La longitud minima (8) siempre supera
  // el numero de clases activas (ver MAX_ACTIVE_CLASSES), asi que un caracter
  // por clase cabe con holgura y no hace falta validar mas.
  const length = Math.min(MAX_LENGTH, Math.max(MIN_LENGTH, Math.round(options.length)));

  const chars: string[] = [];
  if (options.exigirTodasLasClases) {
    for (const key of classes) {
      chars.push(pick(isolateClass(key, options.evitarAmbiguos)));
    }
  }

  const pool = classPool(options.sets, options.evitarAmbiguos);
  while (chars.length < length) chars.push(pick(pool));
  if (chars.length > length) chars.length = length;

  return shuffle(chars).join('');
}

function isolateClass(key: keyof typeof CLASES, evitarAmbiguos: boolean): string {
  const raw = CLASES[key];
  return evitarAmbiguos ? raw.split('').filter((c) => !AMBIGUOS.has(c)).join('') : raw;
}

/** Entropia estimada en bits: log2(|pool|^longitud). */
export function entropyBits(options: GeneratorOptions): number {
  const pool = classPool(options.sets, options.evitarAmbiguos);
  if (pool.length === 0) return 0;
  return Math.log2(pool.length) * Math.max(MIN_LENGTH, Math.min(MAX_LENGTH, options.length));
}

export function strengthLabel(bits: number): string {
  if (bits < 40) return 'Muy debil';
  if (bits < 60) return 'Debil';
  if (bits < 80) return 'Aceptable';
  if (bits < 110) return 'Fuerte';
  return 'Excelente';
}
