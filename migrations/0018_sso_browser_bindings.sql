-- Привязка браузера к цепочке SSO. Отдельная долгоживущая cookie браузера
-- хранит случайный секрет, здесь — только его хеш. Права входа она не даёт:
-- по ней выход и смена аккаунта находят цепочку браузера, когда SSO-cookie
-- уже истекла, а сессии приложений, выданные через цепочку, ещё живы. Сессия
-- приложения не продлевается дальше expires_at привязки своей цепочки.
--
-- Цепочкам, начатым до обновления, привязка выдаётся при следующем заходе
-- браузера с живой SSO-cookie. До этого их сессии приложений продлеваются не
-- дальше срока SSO-сессий цепочки.
create table sso_browser_bindings (
  chain_id uuid primary key,
  token_hash text not null unique,
  created_at timestamptz not null,
  expires_at timestamptz not null
);
create index sso_browser_bindings_expires_idx on sso_browser_bindings(expires_at);
