/** Contenedor de avisos flotantes. */
import { Icon } from './Icon.js';
import { dismissToast, useToasts } from '../state/toasts.js';

export function Toaster() {
  const toasts = useToasts();
  if (toasts.length === 0) return null;

  return (
    <div class="toaster" role="region" aria-label="Avisos" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} class={`toast toast--${toast.tone}`} role="status">
          <Icon name={toast.icon ?? 'info'} size={17} class="toast__icon" />
          <p class="toast__message">{toast.message}</p>
          <button
            type="button"
            class="toast__close"
            aria-label="Cerrar aviso"
            onClick={() => dismissToast(toast.id)}
          >
            <Icon name="x" size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}
