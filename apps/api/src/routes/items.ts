/**
 * CRUD de la boveda. El servidor solo manipula blobs AEAD: no sabe si dentro
 * hay un titulo, un usuario o una contrasena, y no puede leerlos.
 *
 * Todas las consultas pasan por `withUser`, que activa las politicas RLS de
 * PostgreSQL. Aun asi filtramos explicitamente por `user_id`: la RLS es la
 * red de seguridad, no el unico candado.
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { z } from 'zod';
import {
  createItemRequestSchema,
  updateItemRequestSchema,
  itemKdfSchema,
  type ItemDto,
} from '@securekey/shared';
import type { Config } from '../config.js';
import { withUser } from '../db/withUser.js';
import { currentUser, requireAuth } from '../http/context.js';
import { audit } from '../auth/audit.js';
import { badRequest, conflict, notFound } from '../http/errors.js';

type ItemRow = {
  id: string;
  version: number;
  alg: string;
  kdf: unknown;
  nonce: Buffer;
  ciphertext: Buffer;
  created_at: Date;
  updated_at: Date;
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function parse<S extends z.ZodTypeAny>(schema: S, request: FastifyRequest): z.infer<S> {
  const result = schema.safeParse(request.body);
  if (!result.success) throw badRequest('Peticion invalida', result.error.flatten());
  return result.data;
}

function itemIdFrom(request: FastifyRequest): string {
  const params = request.params as { id?: string };
  const id = params.id;
  if (!id || !UUID_RE.test(id)) throw notFound('Item no encontrado');
  return id;
}

function toDto(row: ItemRow): ItemDto {
  const kdf = itemKdfSchema.parse(row.kdf);
  if (row.alg !== 'AES-256-GCM') {
    throw badRequest(`Algoritmo de cifrado no soportado: ${row.alg}`);
  }
  return {
    id: row.id,
    version: row.version,
    blob: {
      alg: 'AES-256-GCM',
      kdf,
      nonce: row.nonce.toString('base64'),
      ciphertext: row.ciphertext.toString('base64'),
    },
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

export async function itemRoutes(app: FastifyInstance, opts: { config: Config }): Promise<void> {
  const { config } = opts;
  const guard = { preHandler: requireAuth(config) };

  // Listado. El descifrado y el filtrado por texto ocurren en el cliente.
  app.get('/items', guard, async (request) => {
    const user = currentUser(request);
    const rows = await withUser(config, user.userId, async (tx) => {
      const res = await tx.query<ItemRow>(
        `SELECT id, version, alg, kdf, nonce, ciphertext, created_at, updated_at
           FROM items
          WHERE user_id = $1 AND deleted_at IS NULL
          ORDER BY updated_at DESC`,
        [user.userId],
      );
      return res.rows;
    });
    return { items: rows.map(toDto) };
  });

  app.get('/items/:id', guard, async (request) => {
    const user = currentUser(request);
    const id = itemIdFrom(request);
    const row = await withUser(config, user.userId, async (tx) => {
      const res = await tx.query<ItemRow>(
        `SELECT id, version, alg, kdf, nonce, ciphertext, created_at, updated_at
           FROM items
          WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
        [id, user.userId],
      );
      return res.rows[0];
    });
    if (!row) throw notFound('Item no encontrado');
    await audit(config, { userId: user.userId, action: 'items.read', itemId: id, request });
    return toDto(row);
  });

  app.post('/items', guard, async (request, reply) => {
    const user = currentUser(request);
    const body = parse(createItemRequestSchema, request);
    const kdf = itemKdfSchema.parse(body.blob.kdf);

    // El id lo genera el cliente y es la clave primaria global, asi que un
    // reintento de la misma peticion (o dos pestanas que(uuid() en el mismo
    // instante) choca con la restriccion. Sin capturar el 23505 esto sale como
    // un 500 y el usuario ve "error del servidor" donde solo ha reintentado.
    const row = await withUser(config, user.userId, async (tx) => {
      try {
        const res = await tx.query<ItemRow>(
          `INSERT INTO items (id, user_id, version, alg, kdf, nonce, ciphertext)
           VALUES ($1, $2, 1, 'AES-256-GCM', $3::jsonb, $4, $5)
           RETURNING id, version, alg, kdf, nonce, ciphertext, created_at, updated_at`,
          [
            body.id,
            user.userId,
            JSON.stringify(kdf),
            Buffer.from(body.blob.nonce, 'base64'),
            Buffer.from(body.blob.ciphertext, 'base64'),
          ],
        );
        return res.rows[0];
      } catch (error) {
        if ((error as { code?: string }).code === '23505') return undefined;
        throw error;
      }
    });

    if (!row) throw conflict('Ya existe una credencial con ese identificador');

    await audit(config, { userId: user.userId, action: 'items.create', itemId: body.id, request });
    return reply.code(201).send(toDto(row));
  });

  // Optimistic locking: si otro dispositivo (o esta misma pestana) escribio
  // mientras editabamos, el UPDATE no afecta a ninguna fila y respondemos 409
  // en lugar de pisar el cambio.
  app.put('/items/:id', guard, async (request) => {
    const user = currentUser(request);
    const id = itemIdFrom(request);
    const body = parse(updateItemRequestSchema, request);
    const kdf = itemKdfSchema.parse(body.blob.kdf);

    const row = await withUser(config, user.userId, async (tx) => {
      const res = await tx.query<ItemRow>(
        `UPDATE items
            SET ciphertext = $3, nonce = $4, kdf = $5::jsonb,
                version = version + 1, updated_at = now()
          WHERE id = $1 AND user_id = $2 AND version = $6 AND deleted_at IS NULL
          RETURNING id, version, alg, kdf, nonce, ciphertext, created_at, updated_at`,
        [
          id,
          user.userId,
          Buffer.from(body.blob.ciphertext, 'base64'),
          Buffer.from(body.blob.nonce, 'base64'),
          JSON.stringify(kdf),
          body.version,
        ],
      );
      return res.rows[0];
    });

    if (!row) {
      // El UPDATE no afecto a ninguna fila. Hay dos motivos muy distintos y el
      // cliente necesita saber cual: o el item no es de este usuario / ya no
      // existe (404, y la RLS hace que no podamos ni comprobarlo en la misma
      // consulta), o existe pero la version cambio (409). Solo en el camino de
      // error pagamos una consulta extra.
      const exists = await withUser(config, user.userId, async (tx) => {
        const res = await tx.query(
          `SELECT 1 FROM items WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
          [id, user.userId],
        );
        return (res.rowCount ?? 0) > 0;
      });
      if (!exists) throw notFound('Item no encontrado');
      throw conflict('El item fue modificado en otro sitio. Recarga y vuelve a intentarlo');
    }

    await audit(config, { userId: user.userId, action: 'items.update', itemId: id, request });
    return toDto(row);
  });

  // Borrado logico: permite sincronizar borrados entre dispositivos sin que
  // reaparezcan items "resucitados" por una operacion concurrente.
  app.delete('/items/:id', guard, async (request, reply) => {
    const user = currentUser(request);
    const id = itemIdFrom(request);
    const deleted = await withUser(config, user.userId, async (tx) => {
      const res = await tx.query(
        `UPDATE items SET deleted_at = now()
          WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
          RETURNING id`,
        [id, user.userId],
      );
      return (res.rowCount ?? 0) > 0;
    });

    if (!deleted) throw notFound('Item no encontrado');
    await audit(config, { userId: user.userId, action: 'items.delete', itemId: id, request });
    return reply.code(204).send();
  });
}
