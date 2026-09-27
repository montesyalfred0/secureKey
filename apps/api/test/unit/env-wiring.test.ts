/**
 * Que lo que dice el .env.example llegue de verdad al contenedor.
 *
 * Esto existe por un fallo concreto. `RATE_LIMIT_REGISTER_MAX` estaba
 * documentada en el .env.example, leida por la config del servidor y con
 * valor por defecto en el codigo: ponerla en el .env no hacia NADA, porque no
 * estaba en el `environment` de ningun servicio y nadie se la pasaba al
 * contenedor. El limite era siempre 2. Y era un limite de seguridad.
 *
 * Es la peor clase de fallo de configuracion, porque no falla: el despliegue
 * arranca, todo va bien, y el ajuste que creiste hacer no esta.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const RAIZ = '/app';
const COMPOSE = ['docker-compose.yml', 'docker-compose.prod.yml', 'docker-compose.test.yml'] as const;

const lineasDe = (fichero: string): string[] =>
  readFileSync(join(RAIZ, fichero), 'utf8').split('\n');

const sangriaDe = (linea: string): number => linea.length - linea.trimStart().length;

/** El mismo formato que acepta docker compose: LLAVE=valor */
function clavesDocumentadas(contenido: string): string[] {
  return [...contenido.matchAll(/^([A-Z][A-Z0-9_]*)=/gm)]
    .map((m) => m[1] ?? '')
    .filter(Boolean);
}

/**
 * Variables de un `environment:`, siguiendo los anchors YAML.
 *
 * Hace falta porque `api` no declara sus variables: hace
 * `environment: { <<: *admin_env }` y las toma del bloque anclado de
 * `migrate`. Un recorrido que se quedase en el servicio devolveria una lista
 * vacia y la prueba pasaria sin comprobar nada.
 *
 * Es un parser por indentacion, no un parser de YAML, y a proposito: meter una
 * dependencia en el proyecto solo para leer tres ficheros seria peor. Se apoya
 * en la convencion de estos compose (servicios a 2 espacios, claves a 4,
 * variables a 6) y, si alguien la cambia, esto falla con un aserto claro en
 * vez de volverse algo que no comprueba nada.
 */
function variablesDeEnvironment(bloque: string[], fichero: string[]): Set<string> {
  const salida = new Set<string>();

  const recoge = (desde: number, hasta: number): void => {
    for (let i = desde; i < hasta; i++) {
      const linea = bloque[i] ?? '';
      if (linea.trim() !== '' && sangriaDe(linea) <= 4) break;
      const clave = linea.match(/^ {6}([A-Z][A-Z0-9_]*):/);
      if (clave?.[1] !== undefined) salida.add(clave[1]);
      const ref = linea.match(/<<:\s*\*(\w+)/);
      // `<<: *admin_env` delega en el bloque anclado, que esta en el bloque de
      // OTRO servicio. Por eso se busca en el fichero entero y no en `bloque`:
      // buscarlo dentro del servicio no encuentra nada y la lista sale vacia.
      if (ref?.[1] !== undefined) {
        for (const k of variablesDeAncla(fichero, ref[1])) salida.add(k);
      }
    }
  };

  for (let i = 0; i < bloque.length; i++) {
    if (!/^ {4}environment:/.test(bloque[i] ?? '')) continue;
    recoge(i + 1, bloque.length);
    break;
  }
  return salida;
}

/** El bloque `environment: &nombre` donde se define un anchor. */
function variablesDeAncla(lineas: string[], ancla: string): Set<string> {
  const salida = new Set<string>();
  for (let i = 0; i < lineas.length; i++) {
    if (!new RegExp(`^ {4}environment:\\s*&${ancla}\\b`).test(lineas[i] ?? '')) continue;
    for (let j = i + 1; j < lineas.length; j++) {
      const linea = lineas[j] ?? '';
      if (linea.trim() !== '' && sangriaDe(linea) <= 4) break;
      const clave = linea.match(/^ {6}([A-Z][A-Z0-9_]*):/);
      if (clave?.[1] !== undefined) salida.add(clave[1]);
    }
    break;
  }
  return salida;
}

/** El bloque completo de un servicio, por indentacion. */
function bloqueDeServicio(lineas: string[], servicio: string): string[] {
  const inicio = lineas.findIndex((l) => l.startsWith(`  ${servicio}:`));
  if (inicio < 0) throw new Error(`el servicio "${servicio}" no aparece en el compose`);
  let fin = lineas.length;
  for (let i = inicio + 1; i < lineas.length; i++) {
    const linea = lineas[i] ?? '';
    if (linea.trim() !== '' && sangriaDe(linea) <= 2) {
      fin = i;
      break;
    }
  }
  return lineas.slice(inicio, fin);
}

describe('las variables documentadas llegan al contenedor', () => {
  const compose = lineasDe('docker-compose.yml');

  it('el .env.example documenta variables y todas estan en algun compose', () => {
    const claves = clavesDocumentadas(readFileSync(join(RAIZ, '.env.example'), 'utf8'));
    expect(claves.length).toBeGreaterThan(10);

    const todo = COMPOSE.map((f) => readFileSync(join(RAIZ, f), 'utf8')).join('\n');
    const huerfanas = claves.filter((clave) => !todo.includes(clave));
    // Asi fue el fallo de RATE_LIMIT_REGISTER_MAX: documentada, leida por el
    // codigo, y sin cablear en ningun compose.
    expect(huerfanas).toEqual([]);
  });

  it('los limites y politicas de la API estan en el environment del servicio api', () => {
    const api = variablesDeEnvironment(bloqueDeServicio(compose, 'api'), compose);
    // Esta es la que habria pillado el fallo. El cruce de arriba puede
    // conformarse con que la variable aparezca en cualquier parte del
    // fichero; aqui se exige que llegue al servicio que la lee.
    for (const clave of [
      'RATE_LIMIT_REGISTER_MAX',
      'LOGIN_MAX_ATTEMPTS',
      'LOGIN_LOCK_MINUTES',
      'REGISTRATION_MODE',
      'SESSION_TTL_HOURS',
      'SESSION_IDLE_MINUTES',
    ]) {
      expect(api, `falta ${clave} en el environment de api`).toContain(clave);
    }
  });

  it('los parametros KDF que valida OWASP llegan a la API', () => {
    const api = variablesDeEnvironment(bloqueDeServicio(compose, 'api'), compose);
    for (const clave of [
      'ARGON2_MEMORY_KIB',
      'ARGON2_ITERATIONS',
      'ARGON2_PARALLELISM',
      'ARGON2_KDF_VERSION',
    ]) {
      expect(api, `falta ${clave} en el environment de api`).toContain(clave);
    }
  });

  it('las credenciales y el origen llegan a la API', () => {
    const api = variablesDeEnvironment(bloqueDeServicio(compose, 'api'), compose);
    for (const clave of ['AUTH_PEPPER', 'DATABASE_APP_PASSWORD', 'APP_ORIGIN', 'ALLOWED_ORIGINS']) {
      expect(api, `falta ${clave} en el environment de api`).toContain(clave);
    }
  });

  it('la retencion de la bitacora llega al podador, que es quien la usa', () => {
    const prune = variablesDeEnvironment(bloqueDeServicio(compose, 'prune'), compose);
    for (const clave of ['AUDIT_KEEP_DAYS', 'AUDIT_MAX_ROWS', 'DATABASE_URL']) {
      expect(prune, `falta ${clave} en el environment de prune`).toContain(clave);
    }
  });

  it('el resolver no se queda vacio: si el compose cambia de forma, esto avisa', () => {
    // Guarda contra un parser que dejo de encontrar nada y convertia las
    // pruebas de arriba en un FORMULARIO que se rellena solo con "ok".
    const api = variablesDeEnvironment(bloqueDeServicio(compose, 'api'), compose);
    expect(api.size).toBeGreaterThan(10);
  });
});
