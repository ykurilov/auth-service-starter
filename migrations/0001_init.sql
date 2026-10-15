-- Начальная схема сервиса авторизации. Соответствует доменным типам
-- (src/domain/**). Временные метки — timestamptz; auth/profile — jsonb.

create table users (
  id uuid primary key,
  display_name text,
  status text not null,
  created_at timestamptz not null
);

create table identities (
  id uuid primary key,
  user_id uuid not null references users(id),
  provider text not null,
  subject text not null,
  created_at timestamptz not null,
  unique(provider, subject)
);

create table email_addresses (
  id uuid primary key,
  user_id uuid not null references users(id),
  email text not null,
  verified boolean not null,
  created_at timestamptz not null,
  unique(user_id, email)
);
-- Один подтверждённый владелец на адрес (findUserByVerifiedEmail).
create unique index email_addresses_verified_email_uk on email_addresses(email) where verified;

create table password_credentials (
  email text primary key,
  password_hash text not null,
  created_at timestamptz not null
);

create table authorization_codes (
  id uuid primary key,
  code_hash text not null unique,
  client_id text not null,
  user_id uuid not null,
  redirect_uri text not null,
  code_challenge text not null,
  scope text not null,
  nonce text,
  auth jsonb not null,
  expires_at timestamptz not null,
  consumed_at timestamptz
);

create table sessions (
  id uuid primary key,
  user_id uuid not null,
  client_id text not null,
  provider text not null,
  profile jsonb not null,
  device_fingerprint text not null,
  ip_hash text not null,
  created_at timestamptz not null,
  last_used_at timestamptz not null,
  expires_at timestamptz not null,
  revoked_at timestamptz
);
-- Быстрый поиск живых сессий пользователя (findActiveByUser).
create index sessions_active_user_idx on sessions(user_id) where revoked_at is null;

create table refresh_tokens (
  id uuid primary key,
  session_id uuid not null references sessions(id),
  token_hash text not null unique,
  previous_token_id uuid,
  replaced_by_id uuid,
  created_at timestamptz not null,
  consumed_at timestamptz
);

create table sso_sessions (
  id uuid primary key,
  user_id uuid not null,
  auth jsonb not null,
  token_hash text not null unique,
  created_at timestamptz not null,
  last_used_at timestamptz not null,
  expires_at timestamptz not null,
  revoked_at timestamptz
);

create table email_secrets (
  id uuid primary key,
  purpose text not null,
  email text not null,
  secret_hash text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz
);
-- Самый свежий активный секрет пары (purpose, email) — findActive.
create index email_secrets_active_idx on email_secrets(purpose, email) where consumed_at is null;

create table clients (
  id text primary key,
  type text not null,
  redirect_uris jsonb not null,
  allowed_providers jsonb not null,
  post_logout_redirect_uris jsonb,
  created_at timestamptz not null,
  updated_at timestamptz not null
);
