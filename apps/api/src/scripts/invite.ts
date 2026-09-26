/**
 * Emision de codigos de invitacion.
 *
 *   npm run invite -- tu@correo.com
 *   npm run invite -- a@x.com b@y.com c@z.com
 *
 * Lee `INVITE_SECRET` del entorno. El codigo es
 * `skinv_<payload>.<HMAC-SHA256>`, con el correo y la caducidad dentro, asi
 * que no hay estado en el servidor: el mismo codigo siempre valida y caduca
 * solo, sin tabla donde consultar ni cuenta que usar.
 *
 * ADVERTENCIA, y conviene decirla antes que despues: no hay un solo uso ni
 * limite de emision. Quien tenga el `INVITE_SECRET` puede emitir los que
 * quiera, y los mismos codigos valen para siempre hasta que caduquen. Tratalo
 * como una credencial mas:
 *
 *   - guardalo fuera del repositorio, con permisos 600;
 *   - no lo compartas en un canal donde lo lean mas personas de las que
 *     deberian poder crear cuentas;
 *   - rotar el secreto invalida TODOS los codigos emitidos antes, incluidos los
 *     que aun no se han usado.
 *
 * En un servidor publico, `REGISTRATION_MODE=invite` es lo que cierra el grifo
 * de "cualquiera que conozca la URL puede crear una cuenta".
 */
import { issueInviteCode } from '../crypto/server.js';
import { loadConfig } from '../config.js';

const DAYS = Number(process.env['INVITE_DAYS'] ?? 30);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const emails = process.argv.slice(2).map((value) => value.trim().toLowerCase());

if (emails.length === 0) {
  process.stderr.write('Uso: npm run invite -- <correo> [<correo> ...]\n');
  process.exit(1);
}

const config = loadConfig();

if (config.inviteSecret === undefined) {
  process.stderr.write(
    'INVITE_SECRET no esta definido en el entorno.\n' +
      'Generalo con `npm run secrets` y assurelo en el .env de la VPS.\n',
  );
  process.exit(1);
}

if (config.registrationMode !== 'invite') {
  process.stderr.write(
    `AVISO: REGISTRATION_MODE es "${config.registrationMode}", no "invite".\n` +
      'Los codigos se emitiran, pero la API aceptara registros SIN codigo.\n',
  );
}

const invalidos = emails.filter((email) => !EMAIL_RE.test(email));
if (invalidos.length > 0) {
  process.stderr.write(`Correos con formato invalido: ${invalidos.join(', ')}\n`);
  process.exit(1);
}

for (const email of emails) {
  process.stdout.write(`${email}\t${issueInviteCode(config.inviteSecret, email, DAYS)}\n`);
}

process.stdout.write(
  `\nCaducan en ${DAYS} dias. Codigos atados a cada correo: no sirven para otro.\n`,
);
