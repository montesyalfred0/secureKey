/** Panel de ajustes: cambio de contrasena maestra, sesion y datos. */
import { useState } from 'preact/hooks';
import { Icon } from './Icon.js';
import { Alert, Button, Field, Modal } from './ui.js';
import { CLEANUP_SECONDS } from '../lib/clipboard.js';
import { SecureKeyError, type SecureKeyStore } from '../state/session.js';
import { toast } from '../state/toasts.js';

export function SettingsModal({
  open,
  store,
  onClose,
  onLogout,
}: {
  open: boolean;
  store: SecureKeyStore;
  onClose: () => void;
  onLogout: () => Promise<void>;
}) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = (): void => {
    setCurrent('');
    setNext('');
    setRepeat('');
    setError(null);
  };

  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    setError(null);

    if (next.length < 12) {
      setError('La nueva contrasena maestra debe tener al menos 12 caracteres.');
      return;
    }
    if (next !== repeat) {
      setError('Las contrasenas no coinciden.');
      return;
    }

    setBusy(true);
    try {
      await store.changeMasterPassword(current, next);
      toast.success('Contrasena maestra actualizada');
      reset();
    } catch (caught) {
      setError(caught instanceof SecureKeyError ? caught.message : 'No se pudo cambiar');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      title="Ajustes"
      onClose={() => {
        reset();
        onClose();
      }}
      width="md"
    >
      <section class="settings">
        <div class="settings__block">
          <h3 class="settings__title">
            <Icon name="key" size={16} />
            Cambiar contrasena maestra
          </h3>
          <p class="settings__text">
            Se re-cifra la clave de tu boveda con la nueva contrasena. Tus credenciales no se
            tocan: la clave de boveda es la misma, solo cambia su envoltorio.
          </p>

          <form class="settings__form" onSubmit={(event) => void submit(event)}>
            <Field
              label="Contrasena actual"
              type="password"
              icon="lock"
              autoComplete="current-password"
              revealable
              monospace
              value={current}
              onInput={(event) => setCurrent((event.currentTarget as HTMLInputElement).value)}
            />
            <Field
              label="Nueva contrasena maestra"
              type="password"
              icon="lock"
              autoComplete="new-password"
              hint="Minimo 12 caracteres"
              revealable
              monospace
              value={next}
              onInput={(event) => setNext((event.currentTarget as HTMLInputElement).value)}
            />
            <Field
              label="Repite la nueva"
              type="password"
              icon="lock"
              autoComplete="new-password"
              revealable
              monospace
              value={repeat}
              onInput={(event) => setRepeat((event.currentTarget as HTMLInputElement).value)}
            />

            {error !== null && <Alert tone="danger">{error}</Alert>}

            <Button type="submit" tone="primary" icon="check" busy={busy} disabled={current.length === 0}>
              Actualizar contrasena maestra
            </Button>
          </form>
        </div>

        <hr class="settings__rule" />

        <div class="settings__block">
          <h3 class="settings__title">
            <Icon name="shield" size={16} />
            Seguridad
          </h3>
          <ul class="settings__facts">
            <li>
              <Icon name="check" size={14} />
              Sesion en cookie httpOnly <code>SameSite=Strict</code> con CSRF de doble envio
            </li>
            <li>
              <Icon name="check" size={14} />
              Contrasenas derivadas con Argon2id (m={store.kdf?.m ?? 19_456} KiB, t={store.kdf?.t ?? 2})
            </li>
            <li>
              <Icon name="check" size={14} />
              Cifrado por item con AES-256-GCM y clave derivada por HKDF
            </li>
            <li>
              <Icon name="check" size={14} />
              El portapapeles se limpia a los {CLEANUP_SECONDS} segundos de copiar
            </li>
          </ul>
        </div>

        <hr class="settings__rule" />

        <div class="settings__block">
          <h3 class="settings__title">
            <Icon name="logout" size={16} />
            Sesion
          </h3>
          <p class="settings__text">
            Al cerrar sesion se destruyen la clave de boveda en memoria y el token de sesion en el
            servidor.
          </p>
          <Button
            tone="danger"
            icon="logout"
            onClick={() => {
              reset();
              void onLogout();
            }}
          >
            Cerrar sesion
          </Button>
        </div>
      </section>
    </Modal>
  );
}
