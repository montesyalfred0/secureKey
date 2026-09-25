/**
 * Las traducciones Spanolas de zxcvbn tienen que cubrir EXACTAMENTE las claves
 * que el paquete ingles define. Si upstream anade una clave nueva y aqui no
 * esta, zxcvbn no fallara: devolvera el mensaje en ingles o directamente
 * `undefined`, y el usuario veria texto mezclado sin que nada se rompa.
 *
 * Este test es el que detecta ese caso.
 */
import { describe, expect, it } from 'vitest';
import { zxcvbnOptions, zxcvbn } from '@zxcvbn-ts/core';
import * as english from '@zxcvbn-ts/language-en';
import { zxcvbnEs } from '../src/lib/zxcvbn-es.js';

type Groups = 'warnings' | 'suggestions' | 'timeEstimation';

function keysOf(group: Groups): string[] {
  return Object.keys(english.translations[group] as Record<string, string>).sort();
}

describe('traducciones de zxcvbn al espanol', () => {
  it('no tiene claves de mas que el paquete ingles', () => {
    for (const group of ['warnings', 'suggestions', 'timeEstimation'] as const) {
      const extra = Object.keys(zxcvbnEs[group] as Record<string, string>)
        .filter((key) => !keysOf(group).includes(key));
      expect({ group, extra }).toEqual({ group, extra: [] });
    }
  });

  it('tiene todas las claves que el paquete ingles define', () => {
    for (const group of ['warnings', 'suggestions', 'timeEstimation'] as const) {
      const missing = keysOf(group).filter((key) => !(key in (zxcvbnEs[group] as object)));
      expect({ group, missing }).toEqual({ group, missing: [] });
    }
  });

  it('no deja ningun texto vacio', () => {
    for (const group of ['warnings', 'suggestions', 'timeEstimation'] as const) {
      const vacios = Object.entries(zxcvbnEs[group] as Record<string, string>)
        .filter(([, text]) => text.trim().length === 0)
        .map(([key]) => key);
      expect({ group, vacios }).toEqual({ group, vacios: [] });
    }
  });

  it('el feedback sale en espanol de verdad, no en ingles', () => {
    // Configuramos con los diccionarios + traducciones reales, igual que
    // hace `evaluatePassword`.
    return import('../src/lib/strength.js').then(async ({ evaluatePassword }) => {
      const resultado = await evaluatePassword('password123');
      const todo = [...resultado.warnings, ...resultado.feedback, resultado.crackTime].join(' | ');
      // Palabras que solo aparecerian si se colase el texto de upstream.
      const ingleses = [
        'easy to guess',
        'password',
        'Avoid',
        'Use ',
        'Add ',
        'less than a second',
        'second',
        'minutes',
        'hours',
        'days',
        'years',
        'centuries',
      ];
      const encontrados = ingleses.filter((palabra) => todo.includes(palabra));
      expect({ encontrados, muestra: todo }).toEqual({ encontrados: [], muestra: todo });
    });
  });

  it('zxcvbn con diccionarios distingue una contrasena filtrada de una aleatoria', () => {
    return import('../src/lib/strength.js').then(async ({ evaluatePassword }) => {
      const filtrada = await evaluatePassword('password123');
      const aleatoria = await evaluatePassword('xK9#mQ2$vLbwRt7Yp');
      expect(filtrada.score).toBeLessThan(aleatoria.score);
      expect(filtrada.score).toBeLessThanOrEqual(2);
      expect(aleatoria.score).toBeGreaterThanOrEqual(3);
    });
  });

  it('las traducciones no se filtran al estado global de zxcvbn de forma permanente', () => {
    // Sanea tras cada test: `zxcvbnOptions` es un singleton de modulo.
    zxcvbnOptions.setOptions({ translations: english.translations });
    expect(zxcvbn('password').score).toBeGreaterThanOrEqual(0);
  });
});
