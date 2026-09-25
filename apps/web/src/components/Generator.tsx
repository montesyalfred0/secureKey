/**
 * Generador de contrasenas y medidor de fortaleza.
 *
 * Ambos viven juntos porque comparten el ciclo de evaluacion: el generador
 * produce la contrasena y el medidor la juzga al instante, con la misma
 * logica que usara el usuario al escribirla a mano.
 */
import { useEffect, useRef, useState } from 'preact/hooks';
import { Icon } from './Icon.js';
import { Button, Field, IconButton, Slider, Toggle } from './ui.js';
import {
  DEFAULT_OPTIONS,
  entropyBits,
  generatePassword,
  strengthLabel,
  type GeneratorOptions,
} from '../lib/generator.js';
import { evaluatePassword, quickScore, type StrengthResult } from '../lib/strength.js';
import { copySensitive, CLEANUP_SECONDS } from '../lib/clipboard.js';
import { toast } from '../state/toasts.js';

const SCORE_COLORS = [
  'var(--strength-0)',
  'var(--strength-1)',
  'var(--strength-2)',
  'var(--strength-3)',
  'var(--strength-4)',
] as const;

const CRITERIA = [
  { key: 'minusculas', label: 'a-z', title: 'Minusculas' },
  { key: 'mayusculas', label: 'A-Z', title: 'Mayusculas' },
  { key: 'digitos', label: '0-9', title: 'Digitos' },
  { key: 'simbolos', label: '!@#', title: 'Simbolos' },
] as const;

/**
 * Evaluacion con rebote. La heuristica local es instantanea (feedback
 * inmediato al teclear) y zxcvbn se carga despues, en diferido, para dar el
 * veredicto preciso sin bloquear la escritura.
 */
export function useStrength(password: string): StrengthResult {
  const [result, setResult] = useState<StrengthResult>(() => quickScore(password));
  const sequence = useRef(0);

  useEffect(() => {
    const current = ++sequence.current;
    if (password.length === 0) {
      setResult(quickScore(''));
      return undefined;
    }

    setResult(quickScore(password));

    const timer = setTimeout(() => {
      void evaluatePassword(password).then((detailed) => {
        // Una evaluacion lenta de un valor antiguo no puede pisar a la nueva.
        if (current === sequence.current) setResult(detailed);
      });
    }, 350);

    return () => clearTimeout(timer);
  }, [password]);

  return result;
}

export function StrengthMeter({
  result,
  compact = false,
}: {
  result: StrengthResult;
  compact?: boolean;
}) {
  return (
    <div class={['meter', compact ? 'meter--compact' : ''].filter(Boolean).join(' ')}>
      <div class="meter__bar" role="presentation">
        {[0, 1, 2, 3, 4].map((step) => (
          <span
            key={step}
            class="meter__segment"
            style={
              step <= result.score
                ? `background:${SCORE_COLORS[result.score]};`
                : undefined
            }
          />
        ))}
      </div>

      <div class="meter__meta">
        <span class="meter__label" style={`color:${SCORE_COLORS[result.score]};`}>
          {result.label}
        </span>
        {result.crackTime !== '-' && (
          <span class="meter__time">
            <Icon name="clock" size={13} />
            {result.crackTime}
          </span>
        )}
      </div>

      {!compact && (result.warnings.length > 0 || result.feedback.length > 0) && (
        <ul class="meter__notes">
          {result.warnings.map((warning) => (
            <li key={warning} class="meter__note meter__note--warn">
              <Icon name="alert" size={13} />
              {warning}
            </li>
          ))}
          {result.feedback.map((tip) => (
            <li key={tip} class="meter__note">
              <Icon name="info" size={13} />
              {tip}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function PasswordGenerator({
  value,
  onChange,
  autoFocus = false,
}: {
  value: string;
  onChange: (value: string) => void;
  autoFocus?: boolean;
}) {
  const [options, setOptions] = useState<GeneratorOptions>(DEFAULT_OPTIONS);
  const [revealed, setRevealed] = useState(true);

  const bits = entropyBits(options);
  const generated = (): void => {
    try {
      onChange(generatePassword(options));
    } catch (error) {
      toast.warning(error instanceof Error ? error.message : 'No se pudo generar');
    }
  };

  const update = <K extends keyof GeneratorOptions>(key: K, next: GeneratorOptions[K]): void => {
    setOptions((current) => ({ ...current, [key]: next }));
  };

  const updateSet = (key: keyof GeneratorOptions['sets'], next: boolean): void => {
    setOptions((current) => {
      const sets = { ...current.sets, [key]: next };
      // Nunca dejamos la cesta vacia: sin clases no hay contrasena posible.
      if (!Object.values(sets).some(Boolean)) return current;
      return { ...current, sets };
    });
  };

  return (
    <div class="generator">
      <div class="generator__output">
        <input
          class="generator__value is-mono"
          type={revealed ? 'text' : 'password'}
          value={value}
          readOnly
          spellcheck={false}
          aria-label="Contrasena generada"
          autoFocus={autoFocus}
          onFocus={(event) => (event.currentTarget as HTMLInputElement).select()}
        />
        <div class="generator__actions">
          <IconButton
            icon={revealed ? 'eyeOff' : 'eye'}
            label={revealed ? 'Ocultar' : 'Mostrar'}
            size={17}
            onClick={() => setRevealed((current) => !current)}
          />
          <IconButton
            icon="copy"
            label="Copiar"
            size={17}
            onClick={() => {
              void copySensitive(value).then((result) => {
                if (result === 'copied') toast.success(`Copiado. Se borrara en ${CLEANUP_SECONDS}s`);
                else toast.error('El navegador ha bloqueado el portapapeles');
              });
            }}
          />
          <IconButton icon="refresh" label="Generar otra" tone="accent" size={17} onClick={generated} />
        </div>
      </div>

      <div class="generator__stats">
        <span class="chip">
          <strong>{value.length}</strong> caracteres
        </span>
        <span class="chip">
          <strong>{bits.toFixed(0)}</strong> bits de entropia
        </span>
        <span class="chip">{strengthLabel(bits)}</span>
      </div>

      <Slider
        label="Longitud"
        min={8}
        max={64}
        value={options.length}
        suffix=" caracteres"
        onChange={(next) => update('length', next)}
      />

      <div class="generator__sets">
        {CRITERIA.map((criterion) => {
          const active = options.sets[criterion.key];
          return (
            <button
              key={criterion.key}
              type="button"
              class={['set-chip', active ? 'is-on' : ''].filter(Boolean).join(' ')}
              aria-pressed={active}
              onClick={() => updateSet(criterion.key, !active)}
            >
              <span class="set-chip__check">{active && <Icon name="check" size={12} />}</span>
              <span class="set-chip__label" title={criterion.title}>
                {criterion.label}
              </span>
            </button>
          );
        })}
      </div>

      <Toggle
        checked={options.exigirTodasLasClases}
        onChange={(next) => update('exigirTodasLasClases', next)}
        label="Exigir una letra de cada clase"
        hint="Garantiza que la contrasena no sea solo minusculas, por ejemplo."
      />

      <Toggle
        checked={options.evitarAmbiguos}
        onChange={(next) => update('evitarAmbiguos', next)}
        label="Evitar caracteres ambiguos"
        hint="Excluye 0/O, 1/l/I y similares, que se confunden al teclear."
      />

      <Button tone="primary" icon="wand" block onClick={generated}>
        Generar contrasena
      </Button>
    </div>
  );
}

/**
 * Campo de contrasena con evaluacion en vivo. Es el componente que usan tanto
 * el alta de un item como el formulario de edicion.
 */
export function PasswordInputWithMeter({
  value,
  onChange,
  onCopy,
  autoGenerate,
}: {
  value: string;
  onChange: (value: string) => void;
  onCopy?: () => void;
  autoGenerate?: boolean;
}) {
  const result = useStrength(value);

  useEffect(() => {
    if (autoGenerate === true && value.length === 0) {
      onChange(generatePassword(DEFAULT_OPTIONS));
    }
    // Sugerencia puntual al montar, no un efecto continuo: las reglas de
    // reactivacion de hooks no aplican aqui porque el arbol es de una pantalla.
  }, []);

  return (
    <div class="password-field">
      <Field
        label="Contrasena"
        icon="key"
        type="password"
        placeholder="Escribe o genera una contrasena"
        monospace
        revealable
        copyable={value.length > 0}
        onCopy={onCopy}
        value={value}
        onInput={(event) => onChange((event.currentTarget as HTMLInputElement).value)}
      />
      <StrengthMeter result={result} />
    </div>
  );
}
