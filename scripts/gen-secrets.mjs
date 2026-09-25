#!/usr/bin/env node
/**
 * Genera los secretos del `.env` y ejecuta DENTRO de un contenedor, para no
 * depender de nada instalado en el sistema:
 *
 *   npm run secrets
 *
 * Crea `.env` a partir de `.env.example` rellenando los valores vacios con
 * entropia criptografica. Es idempotente: no pisa un `.env` existente, solo
 * completa lo que falta, y avisa si hay que revisar algo a mano.
 */
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ENV_PATH = resolve(process.cwd(), '.env');
const EXAMPLE_PATH = resolve(process.cwd(), '.env.example');

function secret(bytes) {
  return randomBytes(bytes).toString('base64url');
}

const GENERATED = {
  POSTGRES_PASSWORD: () => secret(32),
  AUTH_PEPPER: () => secret(32),
  INVITE_SECRET: () => secret(32),
};

function main() {
  if (!existsSync(EXAMPLE_PATH)) {
    console.error('No se encuentra .env.example');
    process.exit(1);
  }

  const existed = existsSync(ENV_PATH);
  const source = existed ? readFileSync(ENV_PATH, 'utf8') : readFileSync(EXAMPLE_PATH, 'utf8');
  const lines = source.split(/\r?\n/);
  const filled = [];
  const generatedKeys = [];

  for (const line of lines) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line);
    if (!match) {
      filled.push(line);
      continue;
    }
    const [, key, value] = match;
    const factory = GENERATED[key];
    if (factory && value.trim() === '') {
      const produced = factory();
      filled.push(`${key}=${produced}`);
      generatedKeys.push(key);
    } else {
      filled.push(line);
    }
  }

  const content = `${filled.join('\n').replace(/\n{3,}/g, '\n\n')}\n`;
  writeFileSync(ENV_PATH, content, { encoding: 'utf8', mode: 0o600 });

  if (existed) {
    console.log('.env ya existia: se han rellenado solo los valores vacios.');
  } else {
    console.log('.env creado a partir de .env.example');
  }
  if (generatedKeys.length > 0) {
    console.log(`Secretos generados: ${generatedKeys.join(', ')}`);
  }
  console.log('\nSiguiente paso:  npm run up');
  console.log(' despues:         docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt');
}

main();
