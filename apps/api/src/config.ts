/**
 * Configuracion de la API. Falla rapido y sin secretos en los mensajes de error.
 */
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  /** Origen publico de la app. Se usa para CORS y validacion de Origin. */
  APP_ORIGIN: z.string().url().default('https://localhost:8443'),
  ALLOWED_ORIGINS: z.string().default(''),

  DATABASE_URL: z.string().min(1),
  /** Rol con permisos reducidos usado por la aplicacion (sujeta a RLS). */
  DATABASE_APP_URL: z.string().min(1).optional(),

  /**
   * Pepper del servidor para el verificador de autenticacion.
   * Defense in depth: sin el, un atacante con la base de datos tendria que
   * pagar Argon2id por cada intento offline.
   */
  AUTH_PEPPER: z.string().min(32),

  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(24 * 30).default(24),
  SESSION_IDLE_MINUTES: z.coerce.number().int().min(1).max(24 * 60).default(30),
  LOGIN_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(100).default(5),
  LOGIN_LOCK_MINUTES: z.coerce.number().int().min(1).max(24 * 60).default(15),

  /**
   * Limites de tasa. Configurables por entorno y no en el codigo por dos
   * motivos:
   *
   *   - "cuanto es mucho" depende de la instalacion: una instancia domestica y
   *     una corporativa no se parecen.
   *   - la suite de tests hace cientos de peticiones en segundos. Con los
   *     valores de produccion el rate limiting se comeria los tests, y un
   *     limite de infraestructura se confundiria con un fallo de seguridad.
   *
   * El tope alto existe para que los tests puedan subir el limite; en
   * produccion se deja el valor por defecto de cada uno.
   */
  RATE_LIMIT_GLOBAL_MAX: z.coerce.number().int().min(1).max(1_000_000).default(300),
  RATE_LIMIT_PRELOGIN_MAX: z.coerce.number().int().min(1).max(1_000_000).default(30),
  RATE_LIMIT_REGISTER_MAX: z.coerce.number().int().min(1).max(1_000_000).default(5),
  RATE_LIMIT_LOGIN_MAX: z.coerce.number().int().min(1).max(1_000_000).default(10),
  RATE_LIMIT_UNLOCK_MAX: z.coerce.number().int().min(1).max(1_000_000).default(10),

  ARGON2_MEMORY_KIB: z.coerce.number().int().min(19_456).default(19_456),
  ARGON2_ITERATIONS: z.coerce.number().int().min(2).default(2),
  ARGON2_PARALLELISM: z.coerce.number().int().min(1).default(1),
  ARGON2_KDF_VERSION: z.coerce.number().int().min(1).default(1),

  REGISTRATION_MODE: z.enum(['open', 'invite']).default('open'),
  INVITE_SECRET: z.string().min(16).optional(),

  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  VERSION: z.string().default('0.1.0'),
});

export type Config = {
  nodeEnv: 'development' | 'test' | 'production';
  isProduction: boolean;
  host: string;
  port: number;
  appOrigin: string;
  allowedOrigins: string[];
  databaseUrl: string;
  databaseAppUrl: string;
  authPepper: string;
  sessionTtlMs: number;
  sessionIdleMs: number;
  loginMaxAttempts: number;
  loginLockMs: number;
  rateLimits: {
    global: number;
    prelogin: number;
    register: number;
    login: number;
    unlock: number;
  };
  kdf: { alg: 'argon2id'; m: number; t: number; p: number; version: number };
  registrationMode: 'open' | 'invite';
  inviteSecret: string | undefined;
  logLevel: string;
  version: string;
};

let cached: Config | undefined;

export function loadConfig(source: NodeJS.ProcessEnv = process.env): Config {
  if (cached && source === process.env) return cached;

  const parsed = envSchema.safeParse(source);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((i) => `  - ${i.path.join('.') || '(raiz)'}: ${i.message}`)
      .join('\n');
    // Nunca imprimimos valores: solo nombres de variables y motivos.
    throw new Error(`Configuracion de entorno invalida:\n${detail}`);
  }

  const env = parsed.data;
  const allowedOrigins = new Set<string>([env.APP_ORIGIN]);
  for (const origin of env.ALLOWED_ORIGINS.split(',')) {
    const trimmed = origin.trim();
    if (trimmed.length > 0) allowedOrigins.add(trimmed);
  }

  if (env.REGISTRATION_MODE === 'invite' && !env.INVITE_SECRET) {
    throw new Error('REGISTRATION_MODE=invite requiere INVITE_SECRET');
  }

  const config: Config = {
    nodeEnv: env.NODE_ENV,
    isProduction: env.NODE_ENV === 'production',
    host: env.HOST,
    port: env.PORT,
    appOrigin: env.APP_ORIGIN,
    allowedOrigins: [...allowedOrigins],
    databaseUrl: env.DATABASE_URL,
    databaseAppUrl: env.DATABASE_APP_URL ?? env.DATABASE_URL,
    authPepper: env.AUTH_PEPPER,
    sessionTtlMs: env.SESSION_TTL_HOURS * 3_600_000,
    sessionIdleMs: env.SESSION_IDLE_MINUTES * 60_000,
    loginMaxAttempts: env.LOGIN_MAX_ATTEMPTS,
    loginLockMs: env.LOGIN_LOCK_MINUTES * 60_000,
    rateLimits: {
      global: env.RATE_LIMIT_GLOBAL_MAX,
      prelogin: env.RATE_LIMIT_PRELOGIN_MAX,
      register: env.RATE_LIMIT_REGISTER_MAX,
      login: env.RATE_LIMIT_LOGIN_MAX,
      unlock: env.RATE_LIMIT_UNLOCK_MAX,
    },
    kdf: {
      alg: 'argon2id',
      m: env.ARGON2_MEMORY_KIB,
      t: env.ARGON2_ITERATIONS,
      p: env.ARGON2_PARALLELISM,
      version: env.ARGON2_KDF_VERSION,
    },
    registrationMode: env.REGISTRATION_MODE,
    inviteSecret: env.INVITE_SECRET,
    logLevel: env.LOG_LEVEL,
    version: env.VERSION,
  };

  if (source === process.env) cached = config;
  return config;
}

export function resetConfigCache(): void {
  cached = undefined;
}
