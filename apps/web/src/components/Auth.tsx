/**
 * Pantallas de acceso: registro, inicio de sesion y desbloqueo de boveda.
 *
 * Todas comparten la misma mecánica criptográfica (derivar -> enviar authKey),
 * asi que la lógica vive en el componente y la UI se limita a recoger datos y
 * explicar con claridad qué está pasando en cada paso.
 */
import { useState } from 'preact/hooks';
import { Icon } from './Icon.js';
import { Alert, Button, Field, Spinner } from './ui.js';
import { cryptoAvailable } from '../lib/crypto.js';
import { SecureKeyError, type SecureKeyStore } from '../state/session.js';

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div class={['brand', compact ? 'brand--compact' : ''].filter(Boolean).join(' ')}>
      <span class="brand__mark">
        <Icon name="shield" size={compact ? 20 : 26} />
      </span>
      <div class="brand__text">
        <p class="brand__name">SecureKey</p>
        {!compact && <p class="brand__tag">Boveda de contrasenas cifrada en tu navegador</p>}
      </div>
    </div>
  );
}

/** Explica el modelo de confianza: es la primera duda de cualquiera. */
function TrustPanel() {
  return (
    <ul class="trust">
      <li>
        <Icon name="key" size={18} />
        <div>
          <p class="trust__title">Cifrado en el navegador</p>
          <p class="trust__text">
            Tus contrasenas se cifran con AES-256-GCM antes de salir del dispositivo. El servidor
            solo guarda texto ininteligible.
          </p>
        </div>
      </li>
      <li>
        <Icon name="lock" size={18} />
        <div>
          <p class="trust__title">Contrasena maestra con Argon2id</p>
          <p class="trust__text">
            Derivamos una clave resistente a fuerza bruta con 19 MiB de memoria. Aunque alguien tenga
            la base de datos, no puede deducir tu contrasena.
          </p>
        </div>
      </li>
      <li>
        <Icon name="server" size={18} />
        <div>
          <p class="trust__title">Sin recuperacion por correo</p>
          <p class="trust__text">
            No hay SMTP ni correos electronicos. Si olvidas la contrasena maestra, nadie puede
            recuperar tu boveda. Guárdala en un sitio seguro.
          </p>
        </div>
      </li>
    </ul>
  );
}

export function AuthScreen({ store }: { store: SecureKeyStore }) {
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [mail, setMail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [invite, setInvite] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const available = cryptoAvailable();
  const isSignup = mode === 'signup';

  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!available) return;

    setError(null);

    if (isSignup) {
      if (password.length < 12) {
        setError('La contrasena maestra debe tener al menos 12 caracteres.');
        return;
      }
      if (password !== confirm) {
        setError('Las contrasenas no coinciden.');
        return;
      }
    } else if (password.length === 0) {
      setError('Escribe tu contrasena maestra.');
      return;
    }

    setDone(true);
    try {
      if (isSignup) {
        await store.signUp(mail, password, invite);
      } else {
        await store.signIn(mail, password);
      }
    } catch (caught) {
      setError(caught instanceof SecureKeyError ? caught.message : 'No se pudo completar la operacion');
      setDone(false);
    }
  }

  return (
    <main class="auth">
      <section class="auth__pitch">
        <Brand />
        <h1 class="auth__headline">
          Tus contrasenas <span class="gradient-text">solo existen en tu dispositivo</span>.
        </h1>
        <p class="auth__lead">
          SecureKey cifra y descifra en el navegador. El servidor es un almacén de blobs
          indescifrables: ni sus administradores ni un robo de la base de datos pueden leer lo que
          guardas.
        </p>
        <TrustPanel />
      </section>

      <section class="auth__panel">
        <div class="auth__card">
          <div class="auth__card-head">
            <h2 class="auth__title">
              {isSignup ? 'Crea tu boveda' : 'Entra en tu boveda'}
            </h2>
            <p class="auth__subtitle">
              {isSignup
                ? 'Elige una contrasena maestra. Es la unica que tendras que recordar.'
                : 'Derivaremos la clave de tu boveda a partir de tu contrasena maestra.'}
            </p>
          </div>

          {!available && (
            <Alert tone="danger" title="Contexto no seguro">
              Tu navegador no expone WebCrypto fuera de HTTPS o <code>localhost</code>. Abre la
              aplicacion mediante <code>https://localhost:8443</code>.
            </Alert>
          )}

          <form class="auth__form" onSubmit={(event) => void submit(event)}>
            <Field
              label="Correo electronico"
              type="email"
              icon="user"
              placeholder="tu@correo.com"
              autoComplete="username"
              required
              value={mail}
              onInput={(event) => setMail((event.currentTarget as HTMLInputElement).value)}
            />

            <Field
              label="Contrasena maestra"
              type={isSignup ? 'password' : 'password'}
              icon="lock"
              placeholder={isSignup ? 'Minimo 12 caracteres' : '••••••••••••'}
              autoComplete={isSignup ? 'new-password' : 'current-password'}
              required
              revealable
              monospace
              hint={
                isSignup
                  ? 'Nada se guarda en texto claro. Si la pierdes, no hay forma de recuperarla.'
                  : undefined
              }
              value={password}
              onInput={(event) => setPassword((event.currentTarget as HTMLInputElement).value)}
            />

            {isSignup && (
              <>
                <Field
                  label="Repite la contrasena maestra"
                  type="password"
                  icon="lock"
                  placeholder="••••••••••••"
                  autoComplete="new-password"
                  required
                  revealable
                  monospace
                  value={confirm}
                  onInput={(event) => setConfirm((event.currentTarget as HTMLInputElement).value)}
                />
                <Field
                  label="Codigo de invitacion (opcional)"
                  type="text"
                  icon="wand"
                  placeholder="solo si el administrador lo exige"
                  monospace
                  value={invite}
                  onInput={(event) => setInvite((event.currentTarget as HTMLInputElement).value)}
                />
              </>
            )}

            {error !== null && <Alert tone="danger">{error}</Alert>}

            <Button type="submit" tone="primary" size="lg" block busy={done || store.busy}>
              {isSignup ? 'Crear boveda cifrada' : 'Desbloquear boveda'}
            </Button>
          </form>

          <p class="auth__switch">
            {isSignup ? '¿Ya tienes cuenta?' : '¿Todavía no tienes cuenta?'}{' '}
            <button
              type="button"
              class="link"
              onClick={() => {
                setMode(isSignup ? 'signin' : 'signup');
                setError(null);
                setDone(false);
              }}
            >
              {isSignup ? 'Iniciar sesion' : 'Crear una boveda'}
            </button>
          </p>
        </div>
      </section>
    </main>
  );
}

export function LockScreen({
  email,
  onUnlock,
  busy,
  onLogout,
}: {
  email: string;
  onUnlock: (password: string) => Promise<void>;
  busy: boolean;
  onLogout: () => Promise<void>;
}) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    setError(null);
    setDone(true);
    try {
      await onUnlock(password);
      setPassword('');
    } catch (caught) {
      setError(caught instanceof SecureKeyError ? caught.message : 'No se pudo desbloquear');
      setDone(false);
    }
  }

  return (
    <main class="lock">
      <div class="lock__card">
        <span class="lock__icon">
          <Icon name="lock" size={30} />
        </span>
        <p class="lock__eyebrow">Sesion activa</p>
        <h1 class="lock__title">Boveda bloqueada</h1>
        <p class="lock__lead">
          Tu sesion sigue abierta en <strong>{email}</strong>, pero la clave de la boveda solo
          vivia en la memoria de la pestana anterior. Vuelve a introducir tu contrasena maestra.
        </p>

        <form class="lock__form" onSubmit={(event) => void submit(event)}>
          <Field
            label="Contrasena maestra"
            type="password"
            icon="lock"
            placeholder="••••••••••••"
            autoComplete="current-password"
            required
            revealable
            monospace
            value={password}
            onInput={(event) => setPassword((event.currentTarget as HTMLInputElement).value)}
          />

          {error !== null && <Alert tone="danger">{error}</Alert>}

          <Button type="submit" tone="primary" size="lg" block busy={done || busy}>
            Desbloquear
          </Button>
        </form>

        <button type="button" class="link link--muted" onClick={() => void onLogout()}>
          Cerrar sesion por completo
        </button>
      </div>
    </main>
  );
}

export function BootScreen() {
  return (
    <main class="boot">
      <Spinner label="Preparando tu boveda cifrada" />
    </main>
  );
}
