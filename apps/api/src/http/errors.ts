/** Errores de aplicacion con codigo HTTP y codigo estable para el cliente. */
export class AppError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const badRequest = (message: string, details?: unknown): AppError =>
  new AppError(400, 'bad_request', message, details);

export const unauthorized = (message = 'No autenticado'): AppError =>
  new AppError(401, 'unauthorized', message);

export const forbidden = (message = 'Acceso denegado'): AppError =>
  new AppError(403, 'forbidden', message);

export const notFound = (message = 'Recurso no encontrado'): AppError =>
  new AppError(404, 'not_found', message);

/** 409: conflicto de version (optimistic locking) o estado invalido. */
export const conflict = (message: string): AppError => new AppError(409, 'conflict', message);

export const tooManyRequests = (message = 'Demasiados intentos'): AppError =>
  new AppError(429, 'rate_limited', message);
