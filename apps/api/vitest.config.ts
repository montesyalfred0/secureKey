import { defineConfig } from 'vitest/config';

/**
 * Configuracion de los tests de la API.
 *
 * Dos suites con requisitos distintos:
 *
 *   test/unit        logica pura, sin base de datos (criptografia, config).
 *   test/integration la app real contra la base de datos real: RLS, cookies,
 *                    CSRF y optimistic locking solo se pueden comprobar de
 *                    verdad hablando con PostgreSQL.
 *
 * `globals: false` obliga a importar `describe`/`it`/`expect` de `vitest` en
 * cada fichero, igual que en el cliente: ningun test depende de un global.
 *
 * `fileParallelism: false` es obligatorio para la parte de integracion: las
 * pruebas vacian las tablas entre casos, asi que dos ficheros en paralelo se
 * pisarian. El coste es bajo porque el grueso del tiempo es el scrypt del
 * registro y el login, que es CPU-bound de todos modos.
 */
export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
    include: ['test/**/*.test.ts'],
    fileParallelism: false,
    // El hash del verificador usa scrypt(N=2^14) y las pruebas repiten
    // registro y login muchas veces.
    testTimeout: 30_000,
    hookTimeout: 60_000,
    // Si una suite de integracion no puede alcanzar la base de datos no tiene
    // sentido que las de unidad tambien frenen esperando.
    teardownTimeout: 30_000,
  },
});
