-- Номера слотов повторной отправки кода. last_slot — последний выданный слот
-- (растёт и тогда, когда слот возвращён после отказа провайдера), code_slot —
-- слот письма, чей код сейчас действует (0 — первое письмо попытки). Код из
-- письма записывается, только если его слот новее действующего: письмо более
-- раннего слота, ответ на которое пришёл позже, не затирает код более нового.
--
-- У попыток, начатых до обновления, действует код последней удачной
-- переотправки: считаем его слотом текущее число переотправок.
alter table email_login_challenges add column last_slot int not null default 0;
alter table email_login_challenges add column code_slot int not null default 0;
update email_login_challenges set last_slot = resends, code_slot = resends;
