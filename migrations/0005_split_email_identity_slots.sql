-- Развести общий email-слот личности на password/code.
-- Раньше вход по паролю и по коду делили один слот (provider='email',
-- subject=<email>). Пароль не доказывает владение почтой, код — доказывает;
-- общий слот позволял непроверенной пароль-регистрации на чужой email
-- «перехватить» законный вход по коду (захват аккаунта). Теперь subject
-- разведён по способу входа. Существующим личностям сохраняем доступ,
-- переименовывая слот по фактической проверенности email.

-- Подтверждённый email -> code-слот (владение доказано).
update identities
set subject = 'code:' || identities.subject
from email_addresses ea
where identities.provider = 'email'
  and identities.subject not like 'password:%'
  and identities.subject not like 'code:%'
  and ea.user_id = identities.user_id
  and ea.email = identities.subject
  and ea.verified;

-- Остальные email-личности -> password-слот (владение не доказано).
update identities
set subject = 'password:' || subject
where provider = 'email'
  and subject not like 'password:%'
  and subject not like 'code:%';
