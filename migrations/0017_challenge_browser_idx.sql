-- Повторная отправка формы почты (двойное нажатие, «Назад», обновление
-- страницы) ищет живую попытку браузера на этот адрес: по хешу привязки к
-- браузеру и адресу.
create index email_login_challenges_browser_idx on email_login_challenges(binding_hash, email);
