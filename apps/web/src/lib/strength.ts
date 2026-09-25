/**
 * Evaluacion de fortaleza de contrasenas.
 *
 * `zxcvbn` (~800 KB de diccionarios y patrones) se carga de forma diferida
 * con `import()`: solo se descarga cuando el usuario pide medir una
 * contrasena, nunca al arrancar la boveda.
 *
 * IMPORTANTE: la contrasena no sale de este modulo. No hay peticion a
 * Have I Been Pwned ni a ningun otro servicio, ni aunque el usuario lo pida.
 * Enviarla seria filtrar el secreto a un tercero.
 */
import type { ItemPlain } from './crypto.js';
import { zxcvbnEs } from './zxcvbn-es.js';

export type StrengthResult = {
  /** 0 (debil) a 4 (muy seguro), el mismo esquema de zxcvbn. */
  score: number;
  label: string;
  crackTime: string;
  /** Entropia estimada por zxcvbn, en bits. */
  guessesLog10: number;
  feedback: string[];
  warnings: string[];
};

const LABELS = ['Muy debil', 'Debil', 'Aceptable', 'Fuerte', 'Excelente'] as const;

/**
 * Traduccion del diagnostico de zxcvbn.
 *
 * Este modulo registra los DICCIONARIOS y las TABLAS DE ADYACENCIA. Sin ellos
 * zxcvbn solo dispone del motor de calculo: no sabe que "password123" es una
 * contrasena filtradísima y le da la maxima puntuacion, con lo que el
 * indicador afirmaria justo lo contrario de la realidad. Por eso la carga es
 * parte de la seguridad de la aplicacion, no un detalle cosmético.
 */
let configured: Promise<ZxcvbnApi> | undefined;

type ZxcvbnApi = {
  zxcvbn: (password: string) => ZxcvbnResult;
};

async function loadZxcvbn(): Promise<ZxcvbnApi> {
  configured ??= (async () => {
    const [core, common, english] = await Promise.all([
      import('@zxcvbn-ts/core'),
      import('@zxcvbn-ts/language-common'),
      import('@zxcvbn-ts/language-en'),
    ]);

    core.zxcvbnOptions.setOptions({
      // Diccionarios: el comun (contrasenas filtradas, diceware) mas el ingles
      // (palabras comunes, nombres, etc.).
      dictionary: { ...common.dictionary, ...english.dictionary },
      // Patrones de teclado (qwerty, dvorak, keypad...).
      graphs: common.adjacencyGraphs,
      // Textos en espanol, para que feedback y tiempos lleguen ya traducidos.
      translations: zxcvbnEs,
    });

    return { zxcvbn: core.zxcvbn };
  })();

  return configured;
}

/** Resultado de zxcvbn: solo los campos que SecureKey consume. */
type ZxcvbnResult = {
  score: number;
  guessesLog10: number;
  feedback: { warning: string | null; suggestions: string[] };
  crackTimesDisplay: { offlineSlowHashing1e4PerSecond: string };
};

/** Lista corta de contrasenas mas filtradas, para un aviso rapido y local. */
const TOP_COMMON = `123456 password 123456789 12345678 1234567890 qwerty 1234567 111111
abc123 password1 123123 1234 000000 iloveyou 1q2w3e4r qwerty123 zaq12wsx dragon
monkey letmein sunshine princess football shadow master jennifer hello charlie
superman michael jordan batman trustno1 hello123 whatever qazwsx access
baseball passw0rd starwars login ashley 696969 passw0rd master1
test test123 root toor secret admin welcome
contrasena contrasena1 password123 clave123`
  .split(/\s+/)
  .filter(Boolean);

export function isCommonPassword(password: string): boolean {
  const normalized = password.trim().toLowerCase();
  return TOP_COMMON.includes(normalized);
}

export function commonPasswordWarning(password: string): string | null {
  if (password.length === 0) return null;
  if (isCommonPassword(password)) {
    return 'Esta contrasena aparece en listas de contrasenas filtradas muy habituales.';
  }
  return null;
}

/**
 * Heuristicas propias, rapidas y sin dependencias. Se aplican siempre, incluso
 * sin zxcvbn cargado, para que el indicador de la lista nunca mienta.
 */
export function quickScore(password: string): StrengthResult {
  const warnings: string[] = [];
  const feedback: string[] = [];

  if (password.length === 0) {
    return {
      score: 0,
      label: LABELS[0],
      crackTime: '-',
      guessesLog10: 0,
      feedback: ['Escribe una contrasena para medirla'],
      warnings,
    };
  }

  if (password.length < 12) warnings.push('Menos de 12 caracteres: facil de atacar por fuerza bruta');
  if (isCommonPassword(password)) warnings.push('Aparece en la lista de contrasenas mas usadas');
  if (/^(.)\1+$/.test(password)) warnings.push('Un solo caracter repetido');
  if (/(1234|abcd|qwer|asdf|0000|1111|2222)/i.test(password)) warnings.push('Contiene secuencias predecibles');
  if (/^[A-Z][a-z]+[0-9]{1,4}[!?.]?$/.test(password)) {
    warnings.push('Sigue el patron palabra+numero: facil de adivinar con un diccionario');
  }

  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 33;
  const bits = Math.log2(Math.max(2, pool)) * password.length;

  const score = bits >= 100 ? 4 : bits >= 80 ? 3 : bits >= 60 ? 2 : bits >= 40 ? 1 : 0;
  if (score <= 1) feedback.push('Anade longitud: es lo que mas aporta');
  if (pool <= 26) feedback.push('Combina mayusculas, digitos y simbolos');

  return {
    score,
    label: LABELS[score] ?? LABELS[0],
    crackTime: estimateCrackTime(bits),
    guessesLog10: bits / Math.log2(10),
    feedback,
    warnings,
  };
}

/** Estimacion conservadora: 1e10 intentos/segundo (GPU modesto). */
export function estimateCrackTime(bits: number): string {
  if (bits <= 0) return '-';
  const seconds = Math.pow(2, bits - 1) / 1e10;
  return humanizeSeconds(seconds);
}

export function humanizeSeconds(seconds: number): string {
  if (!Number.isFinite(seconds)) return 'eternamente';
  if (seconds < 1) return 'menos de 1 segundo';

  // Cada par es [divisor, etiqueta del nivel AL QUE se entra al dividir].
  // El primer nivel (segundos) es el inicial, por eso no aparece en la tabla.
  const UNITS: readonly (readonly [number, string])[] = [
    [60, 'minuto'],
    [60, 'hora'],
    [24, 'dia'],
    [365, 'ano'],
  ];

  let value = seconds;
  let label = 'segundo';
  for (const [divisor, nextLabel] of UNITS) {
    if (value < divisor) break;
    value /= divisor;
    label = nextLabel;
  }

  const rounded = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${rounded} ${label}${rounded === 1 ? '' : 's'}`;
}

/**
 * Evaluacion completa con zxcvbn. Carga perezosa del modulo (unos cientos de
 * KB que solo hacen falta cuando el usuario pide medir una contrasena).
 * `password` solo se usa en memoria y se descarta al terminar.
 */
export async function evaluatePassword(password: string): Promise<StrengthResult> {
  if (password.length === 0) return quickScore(password);

  try {
    const { zxcvbn } = await loadZxcvbn();
    const result = zxcvbn(password);

    // El texto viene ya en espanol desde las traducciones registradas.
    const warnings = result.feedback.warning === null ? [] : [result.feedback.warning];
    const common = commonPasswordWarning(password);
    if (common !== null && !warnings.includes(common)) warnings.push(common);

    const score = Math.max(0, Math.min(4, Math.round(result.score)));
    return {
      score,
      label: LABELS[score] ?? LABELS[0],
      crackTime: result.crackTimesDisplay?.offlineSlowHashing1e4PerSecond ?? '-',
      guessesLog10: result.guessesLog10 ?? 0,
      feedback: [...result.feedback.suggestions, ...lengthAdvice(score)],
      warnings,
    };
  } catch {
    // Si el modulo no se puede cargar, la heuristica local sigue siendo util:
    // es peor que zxcvbn, pero nunca miente en la direccion peligrosa.
    return quickScore(password);
  }
}

/** Consejo de longitud, en espanol, anadido al feedback de zxcvbn. */
function lengthAdvice(score: number): string[] {
  if (score >= 4) return ['Excelente: no hace falta tocar nada.'];
  if (score === 3) return ['Buena. Con un par de caracteres mas es inmejorable.'];
  return ['Recomendado: 16 caracteres o mas.'];
}

/** Resumen de salud de una boveda, TODO en el cliente. */
export type VaultHealth = {
  total: number;
  debiles: number;
  reutilizadas: number;
  sinUsuario: number;
};

export function vaultHealth(items: ItemPlain[]): VaultHealth {
  const seen = new Map<string, number>();
  let debiles = 0;
  let reutilizadas = 0;
  let sinUsuario = 0;

  for (const item of items) {
    if (item.strength >= 0 && item.strength <= 1) debiles += 1;
    if (item.username.trim().length === 0) sinUsuario += 1;
    if (item.password.length > 0) {
      const previous = seen.get(item.password) ?? 0;
      if (previous > 0) reutilizadas += 1;
      seen.set(item.password, previous + 1);
    }
  }

  return { total: items.length, debiles, reutilizadas, sinUsuario };
}
