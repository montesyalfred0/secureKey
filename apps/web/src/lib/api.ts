/**
 * Cliente HTTP. Origen unico: todo se sirve desde el mismo host a traves de
 * Caddy, asi que no hay CORS ni preflight. El token CSRF viaja en una
 * cabecera y se lee de la cookie legible por JS que el servidor expone.
 */
import {
  createItemRequestSchema,
  itemDtoSchema,
  loginRequestSchema,
  preloginRequestSchema,
  preloginResponseSchema,
  registerRequestSchema,
  sessionResponseSchema,
  unlockRequestSchema,
  updateItemRequestSchema,
  type ItemDto,
  type KdfParams,
  type LoginResponse,
  type PreloginResponse,
  type SessionResponse,
  type WrappedKey,
} from '@securekey/shared';

const API = '/api/v1';
const CSRF_COOKIE = '__Host-sk_csrf';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function readCookie(name: string): string {
  const match = document.cookie
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}

async function request<T>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  // El servidor exige doble envio: cookie legible + hash almacenado.
  if (method !== 'GET') headers['x-csrf-token'] = readCookie(CSRF_COOKIE);

  let response: Response;
  try {
    response = await fetch(`${API}${path}`, {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'network_error', 'No se pudo contactar con el servidor');
  }

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let payload: unknown = null;
  if (text.length > 0) {
    try {
      payload = JSON.parse(text);
    } catch {
      throw new ApiError(response.status, 'invalid_response', 'Respuesta inesperada del servidor');
    }
  }

  if (!response.ok) {
    const err = (payload as { error?: { code?: string; message?: string } } | null)?.error;
    throw new ApiError(
      response.status,
      err?.code ?? 'unknown',
      err?.message ?? 'Error inesperado del servidor',
    );
  }

  return payload as T;
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export async function prelogin(email: string): Promise<PreloginResponse> {
  const body = await request<unknown>('POST', '/auth/prelogin', preloginRequestSchema.parse({ email }));
  return preloginResponseSchema.parse(body);
}

export async function register(input: {
  email: string;
  authKey: string;
  vault: WrappedKey;
  kdf: KdfParams;
  inviteCode?: string;
}): Promise<LoginResponse> {
  const body = await request<unknown>('POST', '/auth/register', registerRequestSchema.parse(input));
  return body as LoginResponse;
}

export async function login(input: {
  email: string;
  authKey: string;
  kdfVersion: number;
}): Promise<LoginResponse> {
  const body = await request<unknown>('POST', '/auth/login', loginRequestSchema.parse(input));
  return body as LoginResponse;
}

export async function unlock(input: {
  authKey: string;
  kdfVersion: number;
}): Promise<{ vault: WrappedKey; needsVaultRekey: boolean; keyVersion: number }> {
  return request('POST', '/auth/unlock', unlockRequestSchema.parse(input));
}

export async function rekey(input: {
  authKey: string;
  vault: WrappedKey;
  kdfVersion: number;
}): Promise<void> {
  await request('POST', '/auth/rekey', input);
}

export async function changeMasterPassword(input: {
  currentAuthKey: string;
  newAuthKey: string;
  newVault: WrappedKey;
  kdfVersion: number;
}): Promise<void> {
  await request('POST', '/auth/master-password', input);
}

export async function logout(): Promise<void> {
  await request('POST', '/auth/logout');
}

export async function currentSession(): Promise<SessionResponse> {
  const body = await request<unknown>('GET', '/session');
  return sessionResponseSchema.parse(body);
}

export async function listItems(): Promise<ItemDto[]> {
  const body = await request<{ items: unknown[] }>('GET', '/items');
  return body.items.map((item) => itemDtoSchema.parse(item));
}

export async function createItem(id: string, blob: ItemDto['blob']): Promise<ItemDto> {
  const body = await request<unknown>(
    'POST',
    '/items',
    createItemRequestSchema.parse({ id, blob }),
  );
  return itemDtoSchema.parse(body);
}

export async function updateItem(
  id: string,
  blob: ItemDto['blob'],
  version: number,
): Promise<ItemDto> {
  const body = await request<unknown>(
    'PUT',
    `/items/${id}`,
    updateItemRequestSchema.parse({ blob, version }),
  );
  return itemDtoSchema.parse(body);
}

export async function deleteItem(id: string): Promise<void> {
  await request('DELETE', `/items/${id}`);
}
