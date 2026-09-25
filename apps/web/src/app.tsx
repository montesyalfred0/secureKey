/**
 * Raiz de la aplicacion. Decide que pantalla mostrar y conecta el estado
 * global con la interfaz.
 */
import { useEffect, useState } from 'preact/hooks';
import { AuthScreen, BootScreen, LockScreen } from './components/Auth.js';
import { VaultScreen } from './components/Vault.js';
import { SettingsModal } from './components/Settings.js';
import { Toaster } from './components/Toaster.js';
import { useSecureKey } from './state/session.js';
import { useTheme } from './state/theme.js';

const IDLE_LOCK_MS = 5 * 60 * 1000;

export function App() {
  const store = useSecureKey();
  const { theme, toggle } = useTheme();
  const [settingsOpen, setSettingsOpen] = useState(false);

  // Bloqueo automatico por inactividad. En un gestor de contrasenas, dejar la
  // boveda abierta en un portatil desatendido es el riesgo mas habitual.
  useEffect(() => {
    if (store.phase !== 'vault') return undefined;

    let timer = window.setTimeout(() => store.lock(), IDLE_LOCK_MS);
    const reset = (): void => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => store.lock(), IDLE_LOCK_MS);
    };

    const events: (keyof WindowEventMap)[] = ['pointerdown', 'keydown', 'wheel', 'touchstart'];
    for (const event of events) window.addEventListener(event, reset, { passive: true });
    return () => {
      window.clearTimeout(timer);
      for (const event of events) window.removeEventListener(event, reset);
    };
  }, [store.phase, store.lock]);

  // Aviso antes de cerrar si la boveda esta abierta: evita perder el trabajo
  // en curso por un cierre accidental de pestana.
  useEffect(() => {
    if (store.phase !== 'vault') return undefined;
    const onBeforeUnload = (event: BeforeUnloadEvent): void => {
      event.preventDefault();
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [store.phase]);

  return (
    <>
      {store.phase === 'boot' && <BootScreen />}

      {store.phase === 'auth' && <AuthScreen store={store} />}

      {store.phase === 'locked' && (
        <LockScreen
          email={store.email}
          busy={store.busy}
          onUnlock={store.unlock}
          onLogout={store.logout}
        />
      )}

      {store.phase === 'vault' && (
        <VaultScreen
          store={store}
          onLock={store.lock}
          onSettings={() => setSettingsOpen(true)}
          theme={theme}
          onToggleTheme={toggle}
        />
      )}

      {store.phase === 'vault' && (
        <SettingsModal
          open={settingsOpen}
          store={store}
          onClose={() => setSettingsOpen(false)}
          onLogout={store.logout}
        />
      )}

      <Toaster />
    </>
  );
}
