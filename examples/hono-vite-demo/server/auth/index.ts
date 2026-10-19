// Публичная поверхность модуля. Приложение импортирует только отсюда
// (адаптер Hono — из ./hono.js).
export { createAuthHandlers } from './handlers';
export { createSessionGuard, type GuardOptions, type GuardDecision } from './session-guard';
export { createAuthMiddleware, type MiddlewareOptions, type NextHandler } from './nextjs';
export { getUser, silentCheckDone } from './server';
export type { SessionUser, SessionData } from './core/session-data';
export type { ModuleConfig } from './core/config';
