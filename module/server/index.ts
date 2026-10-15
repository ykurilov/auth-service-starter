// Публичная поверхность модуля. Приложение импортирует только отсюда
// (адаптер Hono — из ./hono.js).
export { createAuthHandlers } from './handlers.js';
export { createSessionGuard, type GuardOptions, type GuardDecision } from './session-guard.js';
export { createAuthMiddleware, type MiddlewareOptions, type NextHandler } from './nextjs.js';
export { getUser, silentCheckDone } from './server.js';
export type { SessionUser, SessionData } from './core/session-data.js';
export type { ModuleConfig } from './core/config.js';
