/**
 * Traducciones al espanol para zxcvbn.
 *
 * `@zxcvbn-ts/language-es` no esta publicado, pero zxcvbn acepta cualquier
 * objeto de traducciones en `zxcvbnOptions.setOptions({ translations })`, asi
 * que supplyamos el nuestro. Es la via soportada: los textos salen ya en
 * espanol de `result.feedback` y de `result.crackTimesDisplay`, sin traducir
 * cadenas literales despues (que es justo lo que se rompe cuando upstream
 * cambia un texto).
 *
 * Las claves son las de `@zxcvbn-ts/language-en`. Si upstream anade una clave
 * nueva, esta seguiria compilando y solo faltaria ese mensaje: por eso el
 * modulo se valida en los tests contra las claves inglesas.
 */
export const zxcvbnEs = {
  warnings: {
    straightRow: 'Las filas rectas del teclado son faciles de adivinar.',
    keyPattern: 'Los patrones cortos de teclado son faciles de adivinar.',
    simpleRepeat: 'Los caracteres repetidos como «aaa» son faciles de adivinar.',
    extendedRepeat: 'Los patrones repetidos como «abcabcabc» son faciles de adivinar.',
    sequences: 'Las secuencias como «abc» son faciles de adivinar.',
    recentYears: 'Los anos recientes son faciles de adivinar.',
    dates: 'Las fechas son faciles de adivinar.',
    topTen: 'Esta entre las contrasenas mas usadas del mundo.',
    topHundred: 'Esta entre las contrasenas mas frecuentes.',
    common: 'Esta entre las contrasenas mas comunes.',
    similarToCommon: 'Se parece a una de las contrasenas mas comunes.',
    wordByItself: 'Una sola palabra es facil de adivinar.',
    namesByThemselves: 'Un nombre o un apellido suelto es facil de adivinar.',
    commonNames: 'Los nombres y apellidos comunes son faciles de adivinar.',
    userInputs: 'No deberia contener datos personales ni del sitio.',
    pwned: 'Esta contrasena aparecio en alguna filtracion de datos de Internet.',
  },
  suggestions: {
    l33t: 'Evita sustituciones predecibles como «@» en lugar de «a».',
    reverseWords: 'Evita escribir palabras al reves.',
    allUppercase: 'No la escribas toda en mayusculas: pon mayusculas en algunos sitios.',
    capitalization: 'Capitaliza mas alla de la primera letra.',
    dates: 'Evita fechas y anos que te relacionen contigo.',
    recentYears: 'Evita los anos recientes.',
    associatedYears: 'Evita anos que te relacionen contigo.',
    sequences: 'Evita las secuencias de caracteres tipicas.',
    repeated: 'Evita repetir palabras o caracteres.',
    longerKeyboardPattern: 'Usa patrones de teclado mas largos y cambia de direccion.',
    anotherWord: 'Anade palabras menos comunes.',
    useWords: 'Combina varias palabras, pero evita frases conocidas.',
    noNeed:
      'Puedes crear una contrasena fuerte sin simbolos, numeros ni mayusculas: la longitud manda.',
    pwned: 'Si reutilizas esta contrasena en otro sitio, cambiala tambien alli.',
  },
  timeEstimation: {
    ltSecond: 'menos de 1 segundo',
    second: '{base} segundo',
    seconds: '{base} segundos',
    minute: '{base} minuto',
    minutes: '{base} minutos',
    hour: '{base} hora',
    hours: '{base} horas',
    day: '{base} dia',
    days: '{base} dias',
    month: '{base} mes',
    months: '{base} meses',
    year: '{base} ano',
    years: '{base} anos',
    centuries: 'siglos',
  },
} as const;
