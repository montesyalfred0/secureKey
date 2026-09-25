import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

export default defineConfig({
  plugins: [preact()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    // En desarrollo el origen es https://localhost:8443 y Vite corre detras de
    // Caddy. `hmr` debe usar el mismo host que ve el navegador.
    hmr: { host: 'localhost', protocol: 'wss', clientPort: 8443 },
  },
  preview: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
  },
  build: {
    target: 'es2022',
    outDir: 'dist',
    sourcemap: false,
    // Una app de contrasenas no necesita sourcemaps en produccion: exponen el
    // codigo fuente a cualquiera que inspeccione las herramientas del navegador.
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        // `hash-wasm` (Argon2id) va en su propio chunk: se carga solo al
        // crear cuenta o al desbloquear, no al pintar la boveda.
        manualChunks: {
          argon2: ['hash-wasm'],
        },
      },
    },
  },
  esbuild: {
    legalComments: 'none',
  },
});
