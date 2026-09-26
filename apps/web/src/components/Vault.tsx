/**
 * Pantalla principal de la boveda.
 *
 * Diseno responsive sin duplicar plantillas: en escritorio conviven lista y
 * detalle; en movil se muestra uno u otro segun `detailOpen`. La misma
 * informacion, dos distribuciones, cero ramificaciones en los componentes.
 */
import { useEffect, useMemo, useState } from 'preact/hooks';
import { Icon } from './Icon.js';
import {
  Alert,
  Button,
  ConfirmDialog,
  EmptyState,
  Field,
  IconButton,
  Modal,
  Segmented,
  Spinner,
  TextArea,
} from './ui.js';
import { PasswordGenerator, PasswordInputWithMeter } from './Generator.js';
import { copySensitive, CLEANUP_SECONDS } from '../lib/clipboard.js';
import { emptyItem, type ItemPlain } from '../lib/crypto.js';
import { avatarColor, displayUrl, initials, maskPassword, pluralize, relativeTime, safeHref } from '../lib/format.js';
import { vaultHealth } from '../lib/strength.js';
import { SecureKeyError, type DecryptedItem, type SecureKeyStore } from '../state/session.js';
import { toast } from '../state/toasts.js';

type FormMode = 'generate' | 'manual';

function ItemAvatar({ item, size = 40 }: { item: ItemPlain; size?: number }) {
  const seed = item.title || item.url || item.username || '?';
  const color = avatarColor(seed);
  return (
    <span
      class="avatar"
      style={`--avatar-bg:${color.bg};--avatar-fg:${color.fg};width:${size}px;height:${size}px;font-size:${Math.round(size * 0.38)}px;`}
      aria-hidden="true"
    >
      {initials(seed)}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Listado
// ---------------------------------------------------------------------------

function ItemList({
  items,
  selectedId,
  query,
  onSelect,
  onNew,
}: {
  items: DecryptedItem[];
  selectedId: string | null;
  query: string;
  onSelect: (id: string) => void;
  onNew: () => void;
}) {
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (needle.length === 0) return items;
    return items.filter((item) =>
      [item.plain.title, item.plain.username, item.plain.url, item.plain.notes]
        .join(' ')
        .toLowerCase()
        .includes(needle),
    );
  }, [items, query]);

  if (items.length === 0) {
    return (
      <div class="list list--empty">
        <EmptyState
          icon="shield"
          title="Tu boveda esta vacia"
          description="Guarda tu primer sitio: el titulo, el usuario y la contrasena salen cifrados de tu navegador."
          action={
            <Button tone="primary" icon="plus" onClick={onNew}>
              Anadir credencial
            </Button>
          }
        />
      </div>
    );
  }

  return (
    <div class="list">
      <p class="list__count">
        {filtered.length} {pluralize(filtered.length, 'credencial', 'credenciales')}
        {filtered.length !== items.length && ` de ${items.length}`}
      </p>

      <ul class="list__items">
        {filtered.map((item) => {
          const weak = item.plain.strength >= 0 && item.plain.strength <= 1;
          return (
            <li key={item.id}>
              <button
                type="button"
                class={['list__item', item.id === selectedId ? 'is-selected' : '']
                  .filter(Boolean)
                  .join(' ')}
                onClick={() => onSelect(item.id)}
                aria-current={item.id === selectedId}
              >
                <ItemAvatar item={item.plain} />
                <span class="list__text">
                  <span class="list__title">{item.plain.title || 'Sin titulo'}</span>
                  <span class="list__meta">
                    {item.plain.username || displayUrl(item.plain.url) || 'Sin usuario'}
                  </span>
                </span>
                {weak && (
                  <span class="list__flag" title="Contrasena debil">
                    <Icon name="alert" size={15} />
                  </span>
                )}
                {item.plain.favorite && (
                  <span class="list__flag list__flag--star" title="Favorita">
                    <Icon name="star" size={15} />
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ul>

      {filtered.length === 0 && (
        <p class="list__none">Ningun resultado para «{query}»</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Detalle
// ---------------------------------------------------------------------------

function ReadOnlyValue({
  label,
  value,
  secret = false,
  mono = false,
  onCopy,
  href,
}: {
  label: string;
  value: string;
  secret?: boolean;
  mono?: boolean;
  onCopy?: () => void;
  href?: string;
}) {
  const [revealed, setRevealed] = useState(false);
  const display = secret && !revealed ? maskPassword(value) : value;
  const empty = value.length === 0;

  return (
    <div class={['value', empty ? 'value--empty' : ''].filter(Boolean).join(' ')}>
      <span class="value__label">{label}</span>
      <div class="value__row">
        {empty ? (
          <span class="value__placeholder">No rellenado</span>
        ) : href !== undefined && href.length > 0 ? (
          <a
            class="value__text value__text--link"
            href={href}
            target="_blank"
            rel="noreferrer noopener"
          >
            {display}
            <Icon name="link" size={14} />
          </a>
        ) : (
          <span class={['value__text', mono ? 'is-mono' : ''].filter(Boolean).join(' ')}>
            {display}
          </span>
        )}

        <div class="value__actions">
          {secret && (
            <IconButton
              icon={revealed ? 'eyeOff' : 'eye'}
              label={revealed ? 'Ocultar' : 'Mostrar'}
              size={17}
              onClick={() => setRevealed((current) => !current)}
            />
          )}
          {!empty && onCopy !== undefined && (
            <IconButton icon="copy" label={`Copiar ${label.toLowerCase()}`} size={17} onClick={onCopy} />
          )}
        </div>
      </div>
    </div>
  );
}

function ItemDetail({
  item,
  onEdit,
  onDelete,
  onBack,
}: {
  item: DecryptedItem;
  onEdit: () => void;
  onDelete: () => void;
  onBack: () => void;
}) {
  const copy = (value: string, what: string) => {
    void copySensitive(value).then((result) => {
      if (result === 'copied') toast.success(`${what} copiado. Se borrara en ${CLEANUP_SECONDS}s`);
      else toast.error('El navegador ha bloqueado el portapapeles');
    });
  };

  const href = safeHref(item.plain.url);

  return (
    <article class="detail">
      <header class="detail__head">
        <div class="detail__identity">
          <IconButton icon="back" label="Volver al listado" class="detail__back" onClick={onBack} />
          <ItemAvatar item={item.plain} size={52} />
          <div class="detail__titles">
            <h2 class="detail__title">{item.plain.title || 'Sin titulo'}</h2>
            <p class="detail__sub">
              {item.plain.favorite && <Icon name="star" size={13} />}
              Modificado {relativeTime(item.updatedAt)}
            </p>
          </div>
        </div>

        <div class="detail__tools">
          <Button icon="edit" onClick={onEdit}>
            Editar
          </Button>
          <IconButton icon="trash" label="Eliminar" tone="danger" onClick={onDelete} />
        </div>
      </header>

      <div class="detail__grid">
        <ReadOnlyValue
          label="Usuario"
          value={item.plain.username}
          mono
          onCopy={() => copy(item.plain.username, 'Usuario')}
        />
        <ReadOnlyValue
          label="Contrasena"
          value={item.plain.password}
          secret
          mono
          onCopy={() => copy(item.plain.password, 'Contrasena')}
        />
        <ReadOnlyValue
          label="Sitio web"
          value={item.plain.url}
          href={href}
          onCopy={() => copy(item.plain.url, 'URL')}
        />
      </div>

      {item.plain.notes.length > 0 && (
        <div class="detail__notes">
          <span class="value__label">Notas</span>
          <p class="detail__notes-text">{item.plain.notes}</p>
          <div class="value__actions">
            <IconButton
              icon="copy"
              label="Copiar notas"
              size={17}
              onClick={() => copy(item.plain.notes, 'Notas')}
            />
          </div>
        </div>
      )}

      <footer class="detail__foot">
        <Icon name="lock" size={14} />
        Cifrado con AES-256-GCM en este navegador. El servidor solo almacena texto cifrado.
      </footer>
    </article>
  );
}

// ---------------------------------------------------------------------------
// Alta / edicion
// ---------------------------------------------------------------------------

function ItemForm({
  open,
  mode,
  initial,
  onClose,
  onSubmit,
  onDelete,
}: {
  open: boolean;
  mode: FormMode;
  initial: ItemPlain | null;
  onClose: () => void;
  onSubmit: (plain: ItemPlain) => Promise<void>;
  onDelete?: () => void;
}) {
  const [form, setForm] = useState<ItemPlain>(initial ?? emptyItem());
  const [tab, setTab] = useState<FormMode>(mode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setForm(initial ?? emptyItem());
      setTab(mode);
      setError(null);
    }
  }, [open, initial, mode]);

  const patch = <K extends keyof ItemPlain>(key: K, value: ItemPlain[K]): void => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const valid = form.title.trim().length > 0 && form.password.length > 0;

  async function save(): Promise<void> {
    if (!valid) {
      setError('El titulo y la contrasena son obligatorios.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSubmit({ ...form, updatedAt: new Date().toISOString() });
      onClose();
      toast.success('Guardado y cifrado en tu boveda');
    } catch (caught) {
      setError(caught instanceof SecureKeyError ? caught.message : 'No se pudo guardar');
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open={open}
      title={initial === null ? 'Nueva credencial' : 'Editar credencial'}
      subtitle="Se cifrara con una clave derivada de tu clave de boveda antes de salir del navegador."
      onClose={onClose}
      width="lg"
      footer={
        <>
          {onDelete !== undefined && (
            <Button tone="danger" icon="trash" onClick={onDelete}>
              Eliminar
            </Button>
          )}
          <div class="modal__spacer" />
          <Button onClick={onClose}>Cancelar</Button>
          <Button tone="primary" icon="check" busy={saving} disabled={!valid} onClick={() => void save()}>
            Guardar
          </Button>
        </>
      }
    >
      <div class="form">
        <div class="form__row">
          <Field
            label="Titulo"
            icon="star"
            placeholder="GitHub, Netflix, banco..."
            required
            value={form.title}
            onInput={(event) => patch('title', (event.currentTarget as HTMLInputElement).value)}
          />
          <Field
            label="Usuario o correo"
            icon="user"
            placeholder="tu@correo.com"
            monospace
            value={form.username}
            onInput={(event) => patch('username', (event.currentTarget as HTMLInputElement).value)}
          />
        </div>

        <Field
          label="Sitio web"
          icon="link"
          placeholder="github.com"
          value={form.url}
          onInput={(event) => patch('url', (event.currentTarget as HTMLInputElement).value)}
        />

        <div class="form__section">
          <Segmented
            ariaLabel="Como obtener la contrasena"
            value={tab}
            onChange={setTab}
            options={[
              { value: 'generate', label: 'Generar una fuerte', icon: 'wand' },
              { value: 'manual', label: 'Escribir y valorar', icon: 'edit' },
            ]}
          />

          {tab === 'generate' ? (
            <PasswordGenerator value={form.password} onChange={(value) => patch('password', value)} />
          ) : (
            <PasswordInputWithMeter
              value={form.password}
              onChange={(value) => patch('password', value)}
              onCopy={() => {
                void copySensitive(form.password).then(() =>
                  toast.success(`Contrasena copiada. Se borrara en ${CLEANUP_SECONDS}s`),
                );
              }}
            />
          )}
        </div>

        <TextArea
          label="Notas"
          rows={3}
          placeholder="Preguntas de seguridad, PIN, lugar de la tarjeta..."
          value={form.notes}
          onInput={(event) => patch('notes', (event.currentTarget as HTMLTextAreaElement).value)}
        />

        <label class="checkline">
          <input
            type="checkbox"
            checked={form.favorite}
            onChange={(event) => patch('favorite', (event.currentTarget as HTMLInputElement).checked)}
          />
          <Icon name="star" size={15} />
          Marcar como favorita
        </label>

        {error !== null && <Alert tone="danger">{error}</Alert>}
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Salud de la boveda
// ---------------------------------------------------------------------------

function HealthPanel({ items }: { items: DecryptedItem[] }) {
  const plains = items.map((item) => item.plain);
  const health = vaultHealth(plains);
  const flags = health.debiles + health.reutilizadas;

  return (
    <section class="health">
      <header class="health__head">
        <h3 class="health__title">
          <Icon name="chart" size={17} />
          Salud de tu boveda
        </h3>
        <span
          class={['badge', flags === 0 ? 'badge--ok' : health.debiles > 0 ? 'badge--danger' : 'badge--warn']
            .filter(Boolean)
            .join(' ')}
        >
          {flags === 0 ? 'Todo en orden' : `${flags} ${pluralize(flags, 'aviso', 'avisos')}`}
        </span>
      </header>

      <ul class="health__stats">
        <li>
          <span class="health__value">{health.total}</span>
          <span class="health__key">credenciales</span>
        </li>
        <li class={health.debiles > 0 ? 'is-bad' : ''}>
          <span class="health__value">{health.debiles}</span>
          <span class="health__key">debiles</span>
        </li>
        <li class={health.reutilizadas > 0 ? 'is-bad' : ''}>
          <span class="health__value">{health.reutilizadas}</span>
          <span class="health__key">reutilizadas</span>
        </li>
        <li class={health.sinUsuario > 0 ? 'is-warn' : ''}>
          <span class="health__value">{health.sinUsuario}</span>
          <span class="health__key">sin usuario</span>
        </li>
      </ul>

      <p class="health__note">
        Este analisis se ejecuta en tu navegador, con la boveda ya descifrada. Nada sale del
        dispositivo.
      </p>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Pantalla
// ---------------------------------------------------------------------------

export function VaultScreen({
  store,
  onLock,
  onSettings,
  theme,
  onToggleTheme,
}: {
  store: SecureKeyStore;
  onLock: () => void;
  onSettings: () => void;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}) {
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<DecryptedItem | null>(null);
  const [formMode, setFormMode] = useState<FormMode>('generate');

  useEffect(() => {
    void store.reload();
  }, [store.reload]);

  const selected = store.items.find((item) => item.id === selectedId) ?? null;

  const openNew = (mode: FormMode): void => {
    setEditing(null);
    setFormMode(mode);
    setFormOpen(true);
  };

  const openEdit = (item: DecryptedItem): void => {
    setEditing(item);
    setFormMode('manual');
    setFormOpen(true);
  };

  // Estado del dialogo de borrado. Antes era un `window.confirm()`; ahora es
  // un dialogo propio, asi que necesita saber que item es y si la peticion
  // sigue en vuelo.
  const [deleting, setDeleting] = useState<DecryptedItem | null>(null);
  const [deletingBusy, setDeletingBusy] = useState(false);

  const askDelete = (item: DecryptedItem): void => {
    setDeletingBusy(false);
    setDeleting(item);
  };

  const doDelete = async (): Promise<void> => {
    const item = deleting;
    if (item === null) return;

    setDeletingBusy(true);
    try {
      await store.removeItem(item.id);
      toast.success('Credencial eliminada');
      setDeleting(null);
      setSelectedId(null);
      setDetailOpen(false);
    } catch {
      // El dialogo se queda abierto a proposito: el usuario necesita ver WHY
      // no se borro, no un toast que se le va mientras mira otro sitio.
      toast.error('No se pudo eliminar. Revisa tu conexion e intentalo de nuevo.');
      setDeletingBusy(false);
    }
  };

  return (
    <div class={['vault', detailOpen ? 'is-detail-open' : ''].filter(Boolean).join(' ')}>
      <header class="topbar">
        <div class="topbar__brand">
          <span class="brand__mark brand__mark--sm">
            <Icon name="shield" size={19} />
          </span>
          <span class="topbar__name">SecureKey</span>
        </div>

        <div class="topbar__search">
          <Icon name="search" size={17} class="topbar__search-icon" />
          <input
            type="search"
            class="topbar__search-input"
            placeholder="Buscar en tu boveda cifrada"
            aria-label="Buscar credenciales"
            value={query}
            onInput={(event) => setQuery((event.currentTarget as HTMLInputElement).value)}
          />
          {query.length > 0 && (
            <IconButton icon="x" label="Limpiar busqueda" size={16} onClick={() => setQuery('')} />
          )}
        </div>

        <div class="topbar__actions">
          <Button tone="primary" icon="plus" class="topbar__new" onClick={() => openNew('generate')}>
            Nueva
          </Button>
          <IconButton
            icon={theme === 'dark' ? 'sun' : 'moon'}
            label={theme === 'dark' ? 'Tema claro' : 'Tema oscuro'}
            onClick={onToggleTheme}
          />
          <IconButton icon="settings" label="Ajustes" onClick={onSettings} />
          <IconButton icon="lock" label="Bloquear boveda" tone="accent" onClick={onLock} />
        </div>
      </header>

      <div class="vault__body">
        <aside class="vault__sidebar">
          <ItemList
            items={store.items}
            selectedId={selectedId}
            query={query}
            onSelect={(id) => {
              setSelectedId(id);
              setDetailOpen(true);
            }}
            onNew={() => openNew('generate')}
          />
          {store.items.length > 0 && <HealthPanel items={store.items} />}
        </aside>

        <main class="vault__main">
          {store.itemsError !== null ? (
            <div class="vault__state">
              <Alert tone="danger" title="No se pudo leer la boveda">
                {store.itemsError}
              </Alert>
              <Button icon="refresh" onClick={() => void store.reload()}>
                Reintentar
              </Button>
            </div>
          ) : store.itemsBusy && store.items.length === 0 ? (
            <div class="vault__state">
              <Spinner label="Descifrando tu boveda" />
            </div>
          ) : selected !== null ? (
            <ItemDetail
              item={selected}
              onEdit={() => openEdit(selected)}
              onDelete={() => askDelete(selected)}
              onBack={() => setDetailOpen(false)}
            />
          ) : (
            <div class="vault__state">
              <EmptyState
                icon="key"
                title="Selecciona una credencial"
                description="Elige una entrada de la lista para ver y copiar sus datos. Todo se descifra aqui, en memoria."
                action={
                  <div class="empty__buttons">
                    <Button tone="primary" icon="wand" onClick={() => openNew('generate')}>
                      Generar contrasena
                    </Button>
                    <Button icon="edit" onClick={() => openNew('manual')}>
                      Escribir la mia
                    </Button>
                  </div>
                }
              />
            </div>
          )}
        </main>
      </div>

      <ItemForm
        open={formOpen}
        mode={formMode}
        initial={editing?.plain ?? null}
        onClose={() => setFormOpen(false)}
        onSubmit={async (plain) => {
          if (editing === null) await store.createItem(plain);
          else await store.updateItem(editing.id, editing.version, plain);
        }}
        onDelete={
          editing === null ? undefined : () => {
            setFormOpen(false);
            askDelete(editing);
          }
        }
      />

      <ConfirmDialog
        open={deleting !== null}
        title="Eliminar credencial"
        subject={deleting?.plain.title || 'Sin titulo'}
        detail={
          deleting !== null && deleting.plain.username.length > 0
            ? `La cuenta ${deleting.plain.username} dejara de estar guardada aqui.`
            : undefined
        }
        busy={deletingBusy}
        onConfirm={() => void doDelete()}
        onCancel={() => setDeleting(null)}
      />
    </div>
  );
}
