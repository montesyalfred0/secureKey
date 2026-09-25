/**
 * Primitivas de interfaz. Sin librerias: botones, campos, modales y avisos
 * propios para mantener el bundle pequeno y el control del comportamiento
 * (teclado, foco, ARIA) en nuestras manos.
 */
import { useEffect, useId, useRef, useState } from 'preact/hooks';
import type { ComponentChildren, JSX } from 'preact';
import { Icon, type IconName } from './Icon.js';

/** Tipos de evento de formulario: sin esto Preact los deja en `any`. */
export type InputChangeEvent = JSX.TargetedEvent<HTMLInputElement, Event>;
export type TextAreaChangeEvent = JSX.TargetedEvent<HTMLTextAreaElement, Event>;
export type FormSubmitEvent = JSX.TargetedSubmitEvent<HTMLFormElement>;

/** Props comunes de un `<input>`, con los handlers bien tipados. */
type BaseInputProps = Omit<
  JSX.InputHTMLAttributes<HTMLInputElement>,
  'size' | 'onInput' | 'onChange'
> & {
  onInput?: (event: InputChangeEvent) => void;
  onChange?: (event: InputChangeEvent) => void;
};

// ---------------------------------------------------------------------------
// Boton
// ---------------------------------------------------------------------------

export type ButtonTone = 'primary' | 'secondary' | 'ghost' | 'danger' | 'success';
export type ButtonSize = 'sm' | 'md' | 'lg';

export type ButtonProps = Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, 'size'> & {
  tone?: ButtonTone;
  size?: ButtonSize;
  icon?: IconName;
  iconAfter?: IconName;
  busy?: boolean;
  block?: boolean;
};

export function Button({
  tone = 'secondary',
  size = 'md',
  icon,
  iconAfter,
  busy = false,
  block = false,
  class: className,
  children,
  disabled,
  ...rest
}: ButtonProps) {
  const classes = [
    'btn',
    `btn--${tone}`,
    `btn--${size}`,
    block ? 'btn--block' : '',
    busy ? 'is-busy' : '',
    className ?? '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <button type="button" class={classes} disabled={disabled === true || busy} {...rest}>
      {busy ? (
        <Icon name="spinner" class="btn__spinner" />
      ) : (
        icon !== undefined && <Icon name={icon} class="btn__icon" />
      )}
      {children !== undefined && children !== null && children !== false && (
        <span class="btn__label">{children}</span>
      )}
      {iconAfter !== undefined && !busy && <Icon name={iconAfter} class="btn__icon" />}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Boton de icono (acciones compacta)
// ---------------------------------------------------------------------------

export type IconButtonProps = Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, 'size'> & {
  icon: IconName;
  label: string;
  tone?: 'default' | 'danger' | 'accent';
  size?: number;
};

export function IconButton({
  icon,
  label,
  tone = 'default',
  size = 18,
  class: className,
  ...rest
}: IconButtonProps) {
  return (
    <button
      type="button"
      class={['icon-btn', `icon-btn--${tone}`, className ?? ''].filter(Boolean).join(' ')}
      title={label}
      aria-label={label}
      {...rest}
    >
      <Icon name={icon} size={size} />
    </button>
  );
}

// ---------------------------------------------------------------------------
// Campo de formulario
// ---------------------------------------------------------------------------

export type FieldProps = BaseInputProps & {
  label: string;
  hint?: string;
  error?: string;
  icon?: IconName;
  /** Anade revelar/copiar; solo para secretos. */
  revealable?: boolean;
  copyable?: boolean;
  monospace?: boolean;
  trailing?: JSX.Element | null;
  onCopy?: () => void;
};

export function Field({
  label,
  hint,
  error,
  icon,
  revealable = false,
  copyable = false,
  monospace = false,
  trailing,
  onCopy,
  class: className,
  ...rest
}: FieldProps) {
  const id = useId();
  const [revealed, setRevealed] = useState(false);
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;

  const describedBy = [hint !== undefined ? hintId : null, error !== undefined ? errorId : null]
    .filter(Boolean)
    .join(' ');

  return (
    <div class={['field', error !== undefined ? 'field--error' : '', className ?? ''].filter(Boolean).join(' ')}>
      <label class="field__label" htmlFor={id}>
        {label}
      </label>

      <div class="field__control">
        {icon !== undefined && <Icon name={icon} class="field__icon" size={18} />}
        <input
          id={id}
          class={['field__input', monospace ? 'is-mono' : '', icon === undefined ? 'is-plain' : '']
            .filter(Boolean)
            .join(' ')}
          aria-describedby={describedBy.length > 0 ? describedBy : undefined}
          aria-invalid={error !== undefined}
          {...rest}
        />

        <div class="field__actions">
          {trailing}
          {revealable && (
            <IconButton
              icon={revealed ? 'eyeOff' : 'eye'}
              label={revealed ? 'Ocultar' : 'Mostrar'}
              size={17}
              onClick={() => setRevealed((value) => !value)}
            />
          )}
          {copyable && (
            <IconButton
              icon="copy"
              label="Copiar"
              size={17}
              onClick={() => {
                onCopy?.();
              }}
            />
          )}
        </div>
      </div>

      {hint !== undefined && (
        <p class="field__hint" id={hintId}>
          {hint}
        </p>
      )}
      {error !== undefined && (
        <p class="field__error" id={errorId} role="alert">
          <Icon name="alert" size={14} />
          {error}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Area de texto
// ---------------------------------------------------------------------------

export type TextAreaProps = Omit<
  JSX.TextareaHTMLAttributes<HTMLTextAreaElement>,
  'onInput' | 'onChange'
> & {
  label: string;
  hint?: string;
  rows?: number;
  onInput?: (event: TextAreaChangeEvent) => void;
  onChange?: (event: TextAreaChangeEvent) => void;
};

export function TextArea({ label, hint, rows = 4, class: className, ...rest }: TextAreaProps) {
  const id = useId();
  return (
    <div class={['field', className ?? ''].filter(Boolean).join(' ')}>
      <label class="field__label" htmlFor={id}>
        {label}
      </label>
      <textarea id={id} class="field__input field__input--area" rows={rows} {...rest} />
      {hint !== undefined && <p class="field__hint">{hint}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Interruptor
// ---------------------------------------------------------------------------

export type ToggleProps = {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  hint?: string;
  disabled?: boolean;
};

export function Toggle({ checked, onChange, label, hint, disabled = false }: ToggleProps) {
  const id = useId();
  return (
    <div class="toggle">
      <button
        type="button"
        id={id}
        role="switch"
        aria-checked={checked}
        class={['toggle__track', checked ? 'is-on' : ''].filter(Boolean).join(' ')}
        disabled={disabled}
        onClick={() => onChange(!checked)}
      >
        <span class="toggle__thumb" />
      </button>
      <div class="toggle__text">
        <label class="toggle__label" htmlFor={id}>
          {label}
        </label>
        {hint !== undefined && <p class="toggle__hint">{hint}</p>}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Deslizador
// ---------------------------------------------------------------------------

export type SliderProps = {
  value: number;
  min: number;
  max: number;
  step?: number;
  onChange: (value: number) => void;
  label: string;
  suffix?: string;
};

export function Slider({ value, min, max, step = 1, onChange, label, suffix = '' }: SliderProps) {
  const id = useId();
  const percent = ((value - min) / (max - min)) * 100;
  return (
    <div class="slider">
      <div class="slider__head">
        <label class="slider__label" htmlFor={id}>
          {label}
        </label>
        <span class="slider__value">
          {value}
          {suffix}
        </span>
      </div>
      <input
        id={id}
        type="range"
        class="slider__input"
        min={min}
        max={max}
        step={step}
        value={value}
        style={`--fill: ${percent}%`}
        onInput={(event) => onChange(Number((event.currentTarget as HTMLInputElement).value))}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Segmentado
// ---------------------------------------------------------------------------

export type SegmentedProps<T extends string> = {
  value: T;
  options: { value: T; label: string; icon?: IconName }[];
  onChange: (value: T) => void;
  ariaLabel: string;
};

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
}: SegmentedProps<T>) {
  return (
    <div class="segmented" role="tablist" aria-label={ariaLabel}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="tab"
          aria-selected={value === option.value}
          class={['segmented__item', value === option.value ? 'is-active' : ''].filter(Boolean).join(' ')}
          onClick={() => onChange(option.value)}
        >
          {option.icon !== undefined && <Icon name={option.icon} size={16} />}
          {option.label}
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Modal
// ---------------------------------------------------------------------------

export type ModalProps = {
  open: boolean;
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: JSX.Element | JSX.Element[];
  footer?: JSX.Element | null;
  width?: 'sm' | 'md' | 'lg';
};

export function Modal({ open, title, subtitle, onClose, children, footer, width = 'md' }: ModalProps) {
  const panelRef = useRef<HTMLDivElement | null>(null);
  const titleId = useId();

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    // Bloquea el scroll del fondo sin desplazar la pagina (compensacion de
    // la barra de scroll, que en moviles produce un salto visible).
    const previousOverflow = document.body.style.overflow;
    const previousPadding = document.body.style.paddingRight;
    const gap = window.innerWidth - document.documentElement.clientWidth;
    document.body.style.overflow = 'hidden';
    if (gap > 0) document.body.style.paddingRight = `${gap}px`;

    const focusable = panelRef.current?.querySelector<HTMLElement>(
      'input:not([type="hidden"]), textarea, button:not([disabled])',
    );
    focusable?.focus();

    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = previousOverflow;
      document.body.style.paddingRight = previousPadding;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div class="modal-layer" role="presentation" onClick={onClose}>
      <div
        ref={panelRef}
        class={['modal', `modal--${width}`].join(' ')}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(event) => event.stopPropagation()}
      >
        <header class="modal__head">
          <div>
            <h2 class="modal__title" id={titleId}>
              {title}
            </h2>
            {subtitle !== undefined && <p class="modal__subtitle">{subtitle}</p>}
          </div>
          <IconButton icon="x" label="Cerrar" onClick={onClose} />
        </header>

        <div class="modal__body">{children}</div>

        {footer !== undefined && footer !== null && <footer class="modal__foot">{footer}</footer>}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Spinner y estados vacios
// ---------------------------------------------------------------------------

export function Spinner({ label }: { label?: string }) {
  return (
    <div class="spinner-block" role="status" aria-live="polite">
      <span class="spinner" />
      {label !== undefined && <p class="spinner__label">{label}</p>}
    </div>
  );
}

export type EmptyStateProps = {
  icon: IconName;
  title: string;
  description: string;
  action?: JSX.Element | null;
};

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div class="empty">
      <span class="empty__icon">
        <Icon name={icon} size={26} />
      </span>
      <h3 class="empty__title">{title}</h3>
      <p class="empty__text">{description}</p>
      {action !== undefined && action !== null && <div class="empty__action">{action}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Avisos
// ---------------------------------------------------------------------------

export type AlertProps = {
  tone: 'info' | 'warn' | 'danger' | 'success';
  children: ComponentChildren;
  title?: string;
};

const ALERT_ICON: Record<AlertProps['tone'], IconName> = {
  info: 'info',
  warn: 'alert',
  danger: 'alert',
  success: 'shield',
};

export function Alert({ tone, children, title }: AlertProps) {
  return (
    <div class={`alert alert--${tone}`} role={tone === 'danger' ? 'alert' : 'status'}>
      <Icon name={ALERT_ICON[tone]} size={18} class="alert__icon" />
      <div class="alert__body">
        {title !== undefined && <p class="alert__title">{title}</p>}
        <div class="alert__text">{children}</div>
      </div>
    </div>
  );
}
