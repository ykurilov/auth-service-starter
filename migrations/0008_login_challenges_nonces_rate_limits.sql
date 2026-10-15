-- Попытки входа по коду из письма. Каждый запрос кода — своя попытка со
-- случайным handle (в БД только хеш), привязанная к браузеру (binding_hash).
-- Код хранится хешем с солью handle; число проверок и переотправок ограничено
-- на самой попытке, поэтому чужие ошибки не трогают попытку владельца.
-- link_* — отложенная привязка внешней личности (Google без подтверждённого
-- владения адресом): привязывается только после верного кода из письма.
create table email_login_challenges (
  id uuid primary key,
  handle_hash text not null unique,
  binding_hash text not null,
  email text not null,
  code_hash text not null,
  attempts int not null,
  max_attempts int not null,
  resends int not null,
  max_resends int not null,
  link_provider text,
  link_subject text,
  link_name text,
  created_at timestamptz not null,
  expires_at timestamptz not null,
  consumed_at timestamptz
);
create index email_login_challenges_expires_idx on email_login_challenges(expires_at);

-- Одноразовые nonce для входа через Google: выпускаются сервером, привязаны к
-- браузеру и клиенту, гасятся атомарно при первом предъявлении.
create table google_login_nonces (
  nonce_hash text primary key,
  binding_hash text not null,
  client_id text not null,
  created_at timestamptz not null,
  expires_at timestamptz not null,
  consumed_at timestamptz
);
create index google_login_nonces_expires_idx on google_login_nonces(expires_at);

-- Счётчики лимитов, общие для всех экземпляров сервиса и переживающие
-- перезапуск. Ключ — хеш (в БД нет сырых адресов и IP).
create table rate_limit_counters (
  key_hash text primary key,
  count int not null,
  expires_at timestamptz not null
);
create index rate_limit_counters_expires_idx on rate_limit_counters(expires_at);
