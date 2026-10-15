-- Регистрация клиента: новое значение при каждом создании, PATCH его не меняет.
-- Код авторизации запоминает регистрацию, под которой выдан. Клиент, удалённый
-- и созданный заново с тем же id, — другая регистрация: прежние коды ему не
-- подходят. Код, записанный уже после удаления клиента, остаётся без
-- регистрации и не подходит никому.
alter table clients add column registration_id uuid not null default gen_random_uuid();
alter table authorization_codes add column client_registration_id uuid;
-- Коды, выданные до обновления (живут минуту), продолжают работать.
update authorization_codes
   set client_registration_id = clients.registration_id
  from clients
 where clients.id = authorization_codes.client_id;
