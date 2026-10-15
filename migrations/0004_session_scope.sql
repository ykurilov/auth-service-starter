-- Scope, одобренный при входе, теперь хранится в сессии: refresh-ротация
-- перевыпускает токены с тем же набором, а id_token/userinfo фильтруют
-- profile-claims по нему. Существующим (выданным до этого изменения) сессиям
-- проставляем полный набор — они были выпущены, когда сервис всегда отдавал
-- email и name, так что их поведение при refresh не меняется.
alter table sessions add column scope text not null default 'openid profile email';
