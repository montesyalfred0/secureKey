import { defineConfig } from 'vitest/config';

/**
 * Configuracion de los tests del cliente.
 *
 * Entorno `node`: los tests de `src/lib/crypto.ts` solo necesitan WebCrypto, y
 * Node 22 ya lo expone como `globalThis.crypto` (`crypto.subtle` incluido), que
 * es exactamente la misma implementacion que usa el navegador.
 *
 * `globals: false` obliga a importar `describe`/`it`/`expect` de `vitest` en cada
 * fichero: asi ningun test depende de un global magico.
 */
export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
    include: ['test/**/*.test.ts'],
    // Argon2id con 19 MiB (m = MIN_KDF.m) tarda cientos de ms en WASM, asi que
    // el limite por defecto de 5 s se queda corto en hardware lento.
    testTimeout: 30_000,
  },
});
