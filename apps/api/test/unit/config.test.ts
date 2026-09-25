/**
 * Configuracion por entorno.
 *
 * El requisito de aqui no es "carga bien": es que falle rapido y sin filtrar
 * secretos. Un mensaje de error de arranque que imprime el valor de AUTH_PEPPER
 * acaba en un log, un ticket o una captura de pantalla.
 */
import { describe, expect, it } from 'vitest';
import { loadConfig, resetConfigCache } from '../../src/config.js';

const MINIMO = {
  NODE_ENV: 'production',
  APP_ORIGIN: 'https://boveda.example.com',
  DATABASE_URL: 'postgres://usuario:clave@db:5432/securekey',
  AUTH_PEPPER: 'pepper-de-pruebas-securekey-0123456789abcdef',
} as const;

const env = (extra: Record<string, string> = {}): NodeJS.ProcessEnv => ({
  ...MINIMO,
  ...extra,
});

describe('loadConfig', () => {
  it('aplica valores por defecto razonables en produccion', () => {
    const config = loadConfig(env());
    expect(config.isProduction).toBe(true);
    expect(config.port).toBe(3000);
    expect(config.sessionTtlMs).toBe(24 * 3_600_000);
    expect(config.sessionIdleMs).toBe(30 * 60_000);
    expect(config.loginMaxAttempts).toBe(5);
    expect(config.registrationMode).toBe('open');
    expect(config.logLevel).toBe('info');
  });

  it('convierte lasPoliticas numericas a milisegundos', () => {
    const config = loadConfig(
      env({ SESSION_TTL_HOURS: '2', SESSION_IDLE_MINUTES: '15', LOGIN_LOCK_MINUTES: '45' }),
    );
    expect(config.sessionTtlMs).toBe(7_200_000);
    expect(config.sessionIdleMs).toBe(900_000);
    expect(config.loginLockMs).toBe(2_700_000);
  });

  it('el pepper ausente o corto es un fallo de arranque, no un valor por defecto', () => {
    expect(() => loadConfig(env({ AUTH_PEPPER: '' }))).toThrow(/AUTH_PEPPER/);
    expect(() => loadConfig(env({ AUTH_PEPPER: 'corto' }))).toThrow(/AUTH_PEPPER/);
  });

  it('DATABASE_URL es obligatoria', () => {
    const sinDb = { ...MINIMO } as Record<string, string>;
    delete sinDb.DATABASE_URL;
    expect(() => loadConfig(sinDb as NodeJS.ProcessEnv)).toThrow(/DATABASE_URL/);
  });

  it('rechaza parametros KDF por debajo del minimo de OWASP', () => {
    expect(() => loadConfig(env({ ARGON2_MEMORY_KIB: '8192' }))).toThrow(/ARGON2_MEMORY_KIB/);
    expect(() => loadConfig(env({ ARGON2_ITERATIONS: '1' }))).toThrow(/ARGON2_ITERATIONS/);
  });

  it('REGISTRATION_MODE=invite sin INVITE_SECRET no arranca', () => {
    expect(() => loadConfig(env({ REGISTRATION_MODE: 'invite' }))).toThrow(/INVITE_SECRET/);
    // Con un INVITE_SECRET presente pero demasiado corto, el mensaje de Zod
    // tambien lo dice: minimo 16 caracteres.
    expect(() => loadConfig(env({ REGISTRATION_MODE: 'invite', INVITE_SECRET: 'corto' }))).toThrow(
      /INVITE_SECRET/,
    );
    const secreto = 'secreto-de-invitacion-suficientemente-largo';
    expect(loadConfig(env({ REGISTRATION_MODE: 'invite', INVITE_SECRET: secreto })).registrationMode).toBe(
      'invite',
    );
  });

  it('rechaza un REGISTRATION_MODE desconocido en vez de asumir "open"', () => {
    expect(() => loadConfig(env({ REGISTRATION_MODE: 'cualquiera' }))).toThrow(/REGISTRATION_MODE/);
  });

  it('APP_ORIGIN tiene que ser una URL', () => {
    expect(() => loadConfig(env({ APP_ORIGIN: 'no-es-una-url' }))).toThrow(/APP_ORIGIN/);
  });

  it('ALLOWED_ORIGINS se anade al origen de la app e ignora vacios y espacios', () => {
    const config = loadConfig(
      env({ ALLOWED_ORIGINS: ' https://a.example.com , ,https://b.example.com ' }),
    );
    expect(config.allowedOrigins).toEqual([
      'https://boveda.example.com',
      'https://a.example.com',
      'https://b.example.com',
    ]);
  });

  it('sin ALLOWED_ORIGINS solo queda el origen de la app', () => {
    expect(loadConfig(env()).allowedOrigins).toEqual(['https://boveda.example.com']);
  });

  it('DATABASE_APP_URL cae a DATABASE_URL si no se define', () => {
    expect(loadConfig(env()).databaseAppUrl).toBe(MINIMO.DATABASE_URL);
    const propia = 'postgres://app:clave@db:5432/securekey';
    expect(loadConfig(env({ DATABASE_APP_URL: propia })).databaseAppUrl).toBe(propia);
  });

  it('el mensaje de error NUNCA imprime el valor de una variable', () => {
    const secreto = 'pepper-que-no-debe-aparecer-jamas-0123456789';
    let mensaje = '';
    try {
      loadConfig({ ...MINIMO, AUTH_PEPPER: secreto, PORT: 'no-es-un-puerto' } as NodeJS.ProcessEnv);
    } catch (error) {
      mensaje = error instanceof Error ? error.message : String(error);
    }
    expect(mensaje).not.toContain(secreto);
    // Nombra las variables que fallan: eso si es util para operar.
    expect(mensaje).toContain('PORT');
  });

  it('no cachea cuando la fuente no es process.env', () => {
    const a = loadConfig(env({ SESSION_IDLE_MINUTES: '10' }));
    const b = loadConfig(env({ SESSION_IDLE_MINUTES: '20' }));
    expect(a.sessionIdleMs).toBe(600_000);
    expect(b.sessionIdleMs).toBe(1_200_000);
  });

  it('si la fuente es process.env, cachea; resetConfigCache lo fuerza a releer', () => {
    const previous = { ...process.env };
    try {
      process.env.DATABASE_URL = MINIMO.DATABASE_URL;
      process.env.AUTH_PEPPER = MINIMO.AUTH_PEPPER;
      process.env.APP_ORIGIN = MINIMO.APP_ORIGIN;
      process.env.SESSION_IDLE_MINUTES = '11';
      resetConfigCache();

      expect(loadConfig(process.env).sessionIdleMs).toBe(660_000);

      process.env.SESSION_IDLE_MINUTES = '22';
      // Sin reset, la cache devuelve el valor viejo.
      expect(loadConfig(process.env).sessionIdleMs).toBe(660_000);

      resetConfigCache();
      expect(loadConfig(process.env).sessionIdleMs).toBe(1_320_000);
    } finally {
      for (const key of ['DATABASE_URL', 'AUTH_PEPPER', 'APP_ORIGIN', 'SESSION_IDLE_MINUTES']) {
        if (previous[key] === undefined) delete process.env[key];
        else process.env[key] = previous[key];
      }
      resetConfigCache();
    }
  });
});
