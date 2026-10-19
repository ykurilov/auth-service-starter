-- Семейство refresh-токена: новые токены имеют вид «<семейство>.<секрет>», и
-- семейство одно у всей цепочки ротаций сессии. Здесь — его хеш. Очистка
-- удаляет строки давно погашенных токенов (история активной сессии больше не
-- растёт), а предъявленный такой токен по семейству находит свою сессию:
-- повтор отзывает её, как и раньше. Токены прежнего формата продолжают
-- работать; следующий refresh выдаёт уже токен с семейством (hmac-sha256-v2).
alter table refresh_tokens add column family_hash text;
create index refresh_tokens_family_hash_idx on refresh_tokens(family_hash);
alter table refresh_tokens drop constraint refresh_tokens_derivation_version_check;
alter table refresh_tokens add constraint refresh_tokens_derivation_version_check
  check (derivation_version is null or derivation_version in ('hmac-sha256-v1', 'hmac-sha256-v2'));
