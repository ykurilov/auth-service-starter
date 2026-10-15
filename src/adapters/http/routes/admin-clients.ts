import { ZodError } from 'zod';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { HttpDeps } from '../deps.js';
import type { Client } from '../../../domain/clients/client.js';
import {
  ClientValidationError,
  assertProvidersAllowedForType,
  clientCreateByBaseUrlSchema,
  clientCreateSchema,
  clientPatchSchema,
} from '../../../domain/clients/client-validation.js';
import { deriveClientFromBaseUrl } from '../../../domain/clients/derive-client.js';
import { checkAdminAuth } from '../admin-auth.js';

// Admin REST API реестра клиентов. Монтируется только когда заданы и токен, и
// записываемый реестр — иначе роуты не регистрируются (эндпойнты дают 404).
export function registerAdminClients(app: FastifyInstance, deps: HttpDeps): void {
  if (!deps.config.adminApiToken || !deps.adminClients) return;
  // Локальные const сужают типы (поля deps опциональны).
  const store = deps.adminClients;
  const token = deps.config.adminApiToken;

  // Проверка Bearer в начале каждого хендлера. Возвращает false и уже
  // отправленный 401, если авторизация не прошла.
  const requireAuth = (req: FastifyRequest, reply: FastifyReply): boolean => {
    if (checkAdminAuth(req.headers['authorization'], token)) return true;
    reply.header('www-authenticate', 'Bearer');
    reply.status(401).send({ error: 'unauthorized' });
    return false;
  };

  app.get('/admin/clients', async (req, reply) => {
    if (!requireAuth(req, reply)) return reply;
    return reply.status(200).send(await store.list());
  });

  // Общий хвост создания для обеих форм тела запроса: доменная проверка
  // провайдеров → проверка конфликта id → запись → 201 с телом клиента.
  const createClient = async (
    client: Client,
    reply: FastifyReply,
  ): Promise<FastifyReply> => {
    try {
      assertProvidersAllowedForType(client.type, client.allowedProviders);
    } catch (err) {
      if (err instanceof ClientValidationError) {
        return reply.status(400).send({ error: 'invalid_request', detail: err.message });
      }
      throw err;
    }
    // Конфликт id определяем явной проверкой, а не перехватом любой ошибки:
    // иначе сбой БД (потеря соединения и т.п.) замаскировался бы под 409.
    // Настоящие ошибки create пробрасываются в глобальный errorHandler (500).
    if (await store.findClient(client.id)) {
      return reply.status(409).send({ error: 'conflict' });
    }
    await store.create(client);
    return reply.status(201).send(client);
  };

  app.post('/admin/clients', async (req, reply) => {
    if (!requireAuth(req, reply)) return reply;

    // Краткая форма: тело содержит baseUrl — адреса возврата выводятся по
    // конвенции (см. deriveClientFromBaseUrl). Иначе — прежняя полная форма.
    const body = req.body;
    const isByBaseUrl =
      typeof body === 'object' && body !== null && 'baseUrl' in body;

    if (isByBaseUrl) {
      let parsed;
      try {
        parsed = clientCreateByBaseUrlSchema.parse(body);
      } catch (err) {
        if (err instanceof ZodError) {
          return reply.status(400).send({ error: 'invalid_request' });
        }
        throw err;
      }
      return createClient(deriveClientFromBaseUrl(parsed), reply);
    }

    let parsed;
    try {
      parsed = clientCreateSchema.parse(body);
    } catch (err) {
      if (err instanceof ZodError) {
        return reply.status(400).send({ error: 'invalid_request' });
      }
      throw err;
    }
    const client: Client = {
      id: parsed.id,
      type: parsed.type,
      redirectUris: parsed.redirectUris,
      allowedProviders: parsed.allowedProviders,
      ...(parsed.postLogoutRedirectUris !== undefined
        ? { postLogoutRedirectUris: parsed.postLogoutRedirectUris }
        : {}),
    };
    return createClient(client, reply);
  });

  app.get<{ Params: { id: string } }>('/admin/clients/:id', async (req, reply) => {
    if (!requireAuth(req, reply)) return reply;
    const found = await store.findClient(req.params.id);
    if (!found) return reply.status(404).send({ error: 'not_found' });
    return reply.status(200).send(found);
  });

  app.patch<{ Params: { id: string } }>('/admin/clients/:id', async (req, reply) => {
    if (!requireAuth(req, reply)) return reply;
    let patch;
    try {
      patch = clientPatchSchema.parse(req.body);
    } catch (err) {
      if (err instanceof ZodError) {
        return reply.status(400).send({ error: 'invalid_request' });
      }
      throw err;
    }
    const existing = await store.findClient(req.params.id);
    if (!existing) return reply.status(404).send({ error: 'not_found' });

    const type = patch.type ?? existing.type;
    const providers = patch.allowedProviders ?? existing.allowedProviders;
    try {
      assertProvidersAllowedForType(type, providers);
    } catch (err) {
      if (err instanceof ClientValidationError) {
        return reply.status(400).send({ error: 'invalid_request', detail: err.message });
      }
      throw err;
    }
    await store.update(req.params.id, patch);
    if (patch.allowedProviders !== undefined) {
      await deps.sessions.revokeForClient(req.params.id, patch.allowedProviders);
    }
    return reply.status(200).send(await store.findClient(req.params.id));
  });

  app.delete<{ Params: { id: string } }>('/admin/clients/:id', async (req, reply) => {
    if (!requireAuth(req, reply)) return reply;
    const found = await store.findClient(req.params.id);
    if (!found) return reply.status(404).send({ error: 'not_found' });
    await store.delete(req.params.id);
    await deps.sessions.revokeForClient(req.params.id);
    return reply.status(204).send();
  });
}
