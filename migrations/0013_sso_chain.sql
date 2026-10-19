-- Цепочка SSO-сессий одного браузера. Новая SSO-сессия, сменившая прежнюю
-- sso-cookie, наследует её цепочку. Сессия приложения помнит цепочку, через
-- которую выдана: смена аккаунта в браузере гасит прежний аккаунт во всех
-- приложениях этого браузера, выход — все сессии цепочки.
--
-- Старые SSO-сессии получают каждая свою цепочку, старые сессии приложений —
-- никакой (их по-прежнему гасит выход пользователя). Копия прежней версии,
-- работающая во время раскатки, пишет так же.
alter table sso_sessions add column chain_id uuid not null default gen_random_uuid();
-- Вход, которым начата SSO-сессия (auth.loginId): обмен кода находит по нему цепочку.
alter table sso_sessions add column login_id text;
create index sso_sessions_chain_idx on sso_sessions(chain_id);
create index sso_sessions_login_idx on sso_sessions(login_id);
alter table sessions add column sso_chain_id uuid;
create index sessions_sso_chain_idx on sessions(sso_chain_id);
