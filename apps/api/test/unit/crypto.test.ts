/**
 * Primitivas criptograficas del servidor.
 *
 * Aqui se comprueba sobre todo lo que NO se puede ver en los tests de
 * integracion: que el pepper de verdad cambia el hash, que comparar longitudes
 * distintas no revienta, y que los codigos de invitacion no son falsificables.
 */
import { describe, expect, it } from 'vitest';
import {
  AUTH_SALT_BYTES,
  TOKEN_BYTES,
  generateSalt,
  generateToken,
  hashAuthKey,
  hashToken,
  issueInviteCode,
  safeEqual,
  verifyInviteCode,
} from '../../src/crypto/server.js';

const PEPPER = 'pepper-de-pruebas-securekey-0123456789abcdef';
const OTHER_PEPPER = 'otro-pepper-distinto-0123456789abcdefghijklmnop';
const key32 = (seed: number): Uint8Array => new Uint8Array(32).fill(seed);

describe('hashAuthKey', () => {
  it('es determinista con el mismo pepper, salt y authKey', async () => {
    const salt = generateSalt();
    const a = await hashAuthKey(PEPPER, key32(1), salt);
    const b = await hashAuthKey(PEPPER, key32(1), salt);
    expect(a.equals(b)).toBe(true);
  });

  it('cambia si cambia la authKey', async () => {
    const salt = generateSalt();
    const a = await hashAuthKey(PEPPER, key32(1), salt);
    const b = await hashAuthKey(PEPPER, key32(2), salt);
    expect(a.equals(b)).toBe(false);
  });

  it('cambia si cambia el salt: dos cuentas con la misma clave no colisionan', async () => {
    const a = await hashAuthKey(PEPPER, key32(7), generateSalt());
    const b = await hashAuthKey(PEPPER, key32(7), generateSalt());
    expect(a.equals(b)).toBe(false);
  });

  it('el pepper defense in depth: sin el, la tabla de la BD es un oraculo barato', async () => {
    const salt = generateSalt();
    const conPepper = await hashAuthKey(PEPPER, key32(9), salt);
    const sinPepper = await hashAuthKey(OTHER_PEPPER, key32(9), salt);
    expect(conPepper.equals(sinPepper)).toBe(false);
  });

  it('devuelve 64 bytes (hash largo, no un recorte de 32)', async () => {
    const hash = await hashAuthKey(PEPPER, key32(3), generateSalt());
    expect(hash.length).toBe(64);
  });
});

describe('generateSalt', () => {
  it(`produce ${AUTH_SALT_BYTES} bytes`, () => {
    expect(generateSalt().length).toBe(AUTH_SALT_BYTES);
  });

  it('no se repite', () => {
    const salts = new Set(Array.from({ length: 50 }, () => generateSalt().toString('base64')));
    expect(salts.size).toBe(50);
  });
});

describe('safeEqual', () => {
  it('acepta buffers identicos', () => {
    expect(safeEqual(Buffer.from('hola'), Buffer.from('hola'))).toBe(true);
  });

  it('rechaza buffers distintos del mismo tamano', () => {
    expect(safeEqual(Buffer.from('hola'), Buffer.from('holb'))).toBe(false);
  });

  it('no revienta con longitudes distintas', () => {
    // Un `timingSafeEqual` en crudo lanza here: la longitud es informacion
    // filtrada, asi que esta funcion tiene que decidir sola.
    expect(safeEqual(Buffer.alloc(1), Buffer.alloc(64))).toBe(false);
    expect(safeEqual(Buffer.alloc(0), Buffer.alloc(1))).toBe(false);
  });

  it('acepta Uint8Array ademas de Buffer', () => {
    expect(safeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });
});

describe('tokens de sesion', () => {
  it(`genera ${TOKEN_BYTES} bytes en base64url`, () => {
    const token = generateToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(token, 'base64url').length).toBe(TOKEN_BYTES);
  });

  it('son unicos', () => {
    const tokens = new Set(Array.from({ length: 200 }, generateToken));
    expect(tokens.size).toBe(200);
  });

  it('hashToken es un SHA-256 de 32 bytes y es estable', () => {
    const a = hashToken('abc');
    expect(a.length).toBe(32);
    expect(a.equals(hashToken('abc'))).toBe(true);
    expect(a.equals(hashToken('abd'))).toBe(false);
  });

  it('el token original no aparece en su hash', () => {
    const token = generateToken();
    expect(hashToken(token).toString('hex')).not.toContain(token);
  });
});

describe('codigos de invitacion', () => {
  const email = 'invitado@example.test';

  it('acepta un codigo recien emitido para ese correo', () => {
    expect(verifyInviteCode(PEPPER, issueInviteCode(PEPPER, email), email)).toBe(true);
  });

  it('el prefijo del formato es estable', () => {
    expect(issueInviteCode(PEPPER, email).startsWith('skinv_')).toBe(true);
  });

  it('rechaza otro correo', () => {
    const code = issueInviteCode(PEPPER, email);
    expect(verifyInviteCode(PEPPER, code, 'otro@example.test')).toBe(false);
  });

  it('el email no distingue mayusculas, como en el resto de la app', () => {
    const code = issueInviteCode(PEPPER, 'Invitado@Example.TEST');
    expect(verifyInviteCode(PEPPER, code, 'invitado@example.test')).toBe(true);
  });

  it('rechaza un codigo firmado con otra clave', () => {
    const code = issueInviteCode(OTHER_PEPPER, email);
    expect(verifyInviteCode(PEPPER, code, email)).toBe(false);
  });

  it('rechaza un payload manipulado con la firma intacta', () => {
    const code = issueInviteCode(PEPPER, email);
    const body = code.slice('skinv_'.length);
    const dot = body.lastIndexOf('.');
    const payload = body.slice(0, dot);
    const sig = body.slice(dot + 1);
    const forjado = Buffer.from(
      JSON.stringify({ e: 'attacker@example.test', exp: Date.now() + 86_400_000 }),
      'utf8',
    ).toString('base64url');
    expect(verifyInviteCode(PEPPER, `skinv_${forjado}.${sig}`, 'attacker@example.test')).toBe(false);
    // El codigo original sigue valiendo: el problema era el payload, no la firma.
    expect(verifyInviteCode(PEPPER, `skinv_${payload}.${sig}`, email)).toBe(true);
  });

  it('rechaza un codigo caducado', () => {
    const code = issueInviteCode(PEPPER, email, 0);
    // Con `days = 0` la expiracion cae en este mismo milisegundo, asi que
    // comprobamos desde un instante posterior: el borde es "exp < now".
    expect(verifyInviteCode(PEPPER, code, email, Date.now() + 1000)).toBe(false);
  });

  it('rechaza basura sin lanzar', () => {
    for (const bad of ['', 'skinv_', 'skinv_sinsigla', 'skinv_.', 'otra-cosa', 'skinv_a.b.c']) {
      expect(verifyInviteCode(PEPPER, bad, email)).toBe(false);
    }
  });
});
