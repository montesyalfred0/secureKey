/**
 * Comprobacion de lo que un navegador recibe de verdad por HTTPS: cabeceras de
 * seguridad, CSP, disponibilidad de los assets y console-criticos.
 *
 * Node ignora el certificado autofirmado de la CA interna de Caddy mediante
 * NODE_TLS_REJECT_UNAUTHORIZED=0: aqui no se valida nada porque el unico
 * cliente real es el navegador del usuario, y lo que nos interesa comprobar es
 * el STATUS, las CABECERAS y que los assets respondan.
 */
const BASE = process.env['APP_URL'] ?? 'https://localhost:8443';

let passed = 0;
let failed = 0;
const check = (name, ok, detail = '') => {
  if (ok) {
    passed += 1;
    console.log(`  ok   ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL ${name}${detail ? ` -> ${detail}` : ''}`);
  }
};

const res = await fetch(`${BASE}/`, { redirect: 'manual' });
const html = await res.text();

console.log('\n1. Documento');
check('GET / responde 200', res.status === 200, `status ${res.status}`);
check('es HTML', (res.headers.get('content-type') ?? '').includes('text/html'));
check('el documento no lleva scripts en linea', !/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?\S[\s\S]*?<\/script>/.test(html));
check('carga el entrypoint del bundle', /<script[^>]+src="\/assets\/index-[^"]+\.js"/.test(html), html.slice(0, 200));
check('el bundle tiene hash de contenido en el nombre', /\/assets\/index-[A-Za-z0-9_-]{8,}\.js/.test(html));
check('favicon referenciado', html.includes('favicon.svg'));
check('lang=es para lectores de pantalla y SEO', html.includes('lang="es"'));

console.log('\n2. Cabeceras de seguridad');
const h = (name) => res.headers.get(name) ?? '';
const csp = h('content-security-policy');

/**
 * Devuelve las fuentes de una directiva de la CSP como tokens exactos.
 *
 * Hace falta porque comparar con `includes` da falsos positivos: la cadena
 * 'wasm-unsafe-eval' CONTIENE la subcadena 'unsafe-eval', asi que un
 * `csp.includes('unsafe-eval')` no distingue "no hay eval" de "solo hay
 * compilacion WASM", que es justo la distincion que importa.
 */
const sourcesOf = (directive) => {
  const match = new RegExp(`${directive}\\s+([^;]+)`).exec(csp);
  return match ? match[1].trim().split(/\s+/) : [];
};
const scriptSrc = sourcesOf('script-src');
const styleSrc = sourcesOf('style-src');

check('CSP presente', csp.length > 0);
check('CSP sin unsafe-inline en script-src', !scriptSrc.includes("'unsafe-inline'"), scriptSrc.join(' '));
check('CSP sin unsafe-eval en script-src', !scriptSrc.includes("'unsafe-eval'"), scriptSrc.join(' '));
check('CSP sin unsafe-inline en style-src', !styleSrc.includes("'unsafe-inline'"), styleSrc.join(' '));
check('CSP sin blob: ni data: en script-src', !scriptSrc.includes('blob:') && !scriptSrc.includes('data:'), scriptSrc.join(' '));

// El Argon2id del cliente viene en WebAssembly y `WebAssembly.compile()` lo
// gobierna `script-src`. Sin 'wasm-unsafe-eval' el navegador rechaza el
// modulo: la pantalla de registro falla con un error de CSP que no explica que
// el problema es la derivacion de la clave maestra. Este check existe para que
// endurecer la CSP no rompa la app otra vez sin que nadie se entere.
check(
  "script-src incluye 'wasm-unsafe-eval' (Argon2id es WASM)",
  scriptSrc.includes("'wasm-unsafe-eval'"),
  `script-src = ${scriptSrc.join(' ')}`,
);

check("CSP con default-src 'self'", csp.includes("default-src 'self'"));
check("CSP con script-src 'self'", scriptSrc.includes("'self'"));
check("CSP con frame-ancestors 'none'", csp.includes("frame-ancestors 'none'"));
check('CSP con object-src none', csp.includes("object-src 'none'"));
check('X-Content-Type-Options: nosniff', h('x-content-type-options') === 'nosniff');
check('X-Frame-Options: DENY', h('x-frame-options') === 'DENY');
check('Referrer-Policy: no-referrer', h('referrer-policy') === 'no-referrer');
check('HSTS activo', h('strict-transport-security').includes('max-age=31536000'), h('strict-transport-security'));
check('Permissions-Policy restringida', h('permissions-policy').includes('geolocation=()'));
check('la cabecera Server no filtra la version', !/^Caddy/i.test(h('server')), h('server'));

console.log('\n3. Assets y cache');
const bundleMatch = /src="(\/assets\/index-[^"]+\.js)"/.exec(html);
const cssMatch = /href="(\/assets\/index-[^"]+\.css)"/.exec(html);

if (bundleMatch) {
  const assetRes = await fetch(`${BASE}${bundleMatch[1]}`);
  const body = await assetRes.text();
  check('el bundle JS responde 200', assetRes.status === 200);
  check('el bundle se cachea de forma inmutable', (assetRes.headers.get('cache-control') ?? '').includes('immutable'));
  check('el bundle no incluye //# sourceMappingURL', !body.includes('sourceMappingURL'));
  check('el bundle contiene el modulo de criptografia', body.includes('argon2') || body.includes('Argon2'));
  check('el bundle NO contiene patrones de contrasena de ejemplo en claro', !/Str0ng!Pass/.test(body));

  // El Argon2id va en un chunk aparte (`argon2-<hash>.js`) que se carga por
  // import dinamico: no aparece en el HTML, lo referencia el entry. Asi que
  // hay que recorrer el grafo de imports, no solo los <script> del documento.
  const direct = [...html.matchAll(/<script[^>]+src="([^"]+\.js)"/g)].map((m) => m[1]);
  const seen = new Set(direct);
  const queue = [...direct];
  const bodies = new Map();

  while (queue.length > 0) {
    const src = queue.shift();
    if (src === undefined || bodies.has(src)) continue;
    const text = await (await fetch(`${BASE}${src}`)).text();
    bodies.set(src, text);
    for (const [, imported] of text.matchAll(/["']\.\/([A-Za-z0-9_.-]+\.js)["']/g)) {
      const next = `/assets/${imported}`;
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }

  const todo = [...bodies.values()].join('\n');

  check(
    'el grafo de bundles incluye el chunk de Argon2id',
    [...bodies.keys()].some((s) => /argon2-/.test(s)),
    [...bodies.keys()].join(' '),
  );
  // El Argon2id viene en WebAssembly y `WebAssembly.compile()` lo gobierna la
  // directiva `script-src` de la CSP. Si esto falla, la CSP se ha endurecido de
  // mas y el registro deja de funcionar en el navegador: es el aviso temprano
  // de un fallo que si no aparece como un error de CSP desconcertante.
  check(
    'los bundles traen el modulo WASM de Argon2id',
    todo.includes('WebAssembly') || /\.wasm/.test(todo),
    'sin WebAssembly.compile en ningun bundle',
  );
} else {
  check('se encuentra el bundle JS', false, 'sin script src');
}

if (cssMatch) {
  const cssRes = await fetch(`${BASE}${cssMatch[1]}`);
  const css = await cssRes.text();
  check('la hoja de estilos responde 200', cssRes.status === 200);
  check('el CSS define los tokens de tema', css.includes('--accent') && css.includes('[data-theme='));
  check('el CSS tiene reglas responsive', css.includes('@media'));
  check('el CSS respeta prefers-reduced-motion', css.includes('prefers-reduced-motion'));
} else {
  check('se encuentra la hoja de estilos', false, 'sin link stylesheet');
}

const indexRes = await fetch(`${BASE}/index.html`);
check(
  'index.html NO se cachea (los hashes cambian en cada build)',
  (indexRes.headers.get('cache-control') ?? '').includes('no-store'),
  indexRes.headers.get('cache-control') ?? '(sin cabecera)',
);

const spaRes = await fetch(`${BASE}/ruta/inexistente`, { redirect: 'manual' });
check('las rutas del lado del cliente devuelven index.html (SPA fallback)', spaRes.status === 200);

console.log('\n4. API a traves del proxy');
const health = await fetch(`${BASE}/api/v1/health`);
const healthBody = await health.json();
check('GET /api/v1/health responde 200 a traves de Caddy y nginx', health.status === 200);
check('la API declara la base de datos operativa', healthBody.database === 'up');

const unknown = await fetch(`${BASE}/api/v1/no-existe`);
check('una ruta de API inexistente da 404 en JSON', unknown.status === 404);
check('el 404 de API no devuelve HTML de la SPA', (unknown.headers.get('content-type') ?? '').includes('application/json'));

const noOrigin = await fetch(`${BASE}/api/v1/auth/prelogin`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email: 'test@example.test' }),
});
check('prelogin responde sin cabecera Origin (mismo origen)', noOrigin.status === 200);

const badOrigin = await fetch(`${BASE}/api/v1/auth/prelogin`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', origin: 'https://atacante.example' },
  body: JSON.stringify({ email: 'test@example.test' }),
});
check('una peticion mutante de origen ajeno se rechaza (403)', badOrigin.status === 403, `status ${badOrigin.status}`);

console.log(`\n=== ${passed} correctos, ${failed} fallidos ===`);
process.exit(failed === 0 ? 0 : 1);
