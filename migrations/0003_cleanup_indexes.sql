-- Индексы под автоочистку (CleanupService.runOnce -> deleteExpired):
-- без них каждый прогон — последовательное сканирование растущих таблиц.

create index authorization_codes_expires_at_idx on authorization_codes(expires_at);
create index email_secrets_expires_at_idx on email_secrets(expires_at);
create index sessions_expires_at_idx on sessions(expires_at);
-- Хотелось бы partial (where revoked_at is not null) — отозванных мало, — но
-- pg-mem в контрактных тестах неверно строит план по partial-индексу на
-- nullable-колонке с условием is not null (запросы с revoked_at начинают
-- терять строки). Обычный btree-индекс даёт тот же выигрыш для deleteExpired.
create index sessions_revoked_at_idx on sessions(revoked_at);
-- Каскадное удаление refresh-токенов ищет их по session_id.
create index refresh_tokens_session_id_idx on refresh_tokens(session_id);
create index sso_sessions_expires_at_idx on sso_sessions(expires_at);
