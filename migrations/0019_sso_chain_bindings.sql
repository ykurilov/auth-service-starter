-- Несколько привязок браузера на цепочку SSO. Две вкладки, одновременно
-- получившие привязку, получают разные секреты, а браузер сохраняет тот,
-- чей ответ пришёл последним. Поэтому действует каждая выданная привязка,
-- каждая со своим сроком; выход по любой из них гасит цепочку и удаляет все
-- её привязки.
--
-- Отдельная таблица, а не смена ключа sso_browser_bindings: копия прежней
-- версии, работающая во время раскатки, пишет туда с on conflict (chain_id).
-- Новая версия туда не пишет, но находит и продлевает (переносом сюда)
-- записанные ею привязки. За срок привязки таблица опустеет; её удалит
-- одна из следующих миграций.
create table sso_chain_bindings (
  token_hash text primary key,
  chain_id uuid not null,
  created_at timestamptz not null,
  expires_at timestamptz not null
);
create index sso_chain_bindings_chain_idx on sso_chain_bindings(chain_id);
create index sso_chain_bindings_expires_idx on sso_chain_bindings(expires_at);
-- Из старой таблицы удаляются только перенесённые секреты. Привязку, которую
-- копия прежней версии запишет или заменит, пока идёт перенос, удаление не
-- заденет: она останется в старой таблице, и новая версия её найдёт.
insert into sso_chain_bindings (token_hash, chain_id, created_at, expires_at)
  select token_hash, chain_id, created_at, expires_at from sso_browser_bindings;
delete from sso_browser_bindings where token_hash in (select token_hash from sso_chain_bindings);
