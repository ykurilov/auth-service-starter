import { domainToASCII, domainToUnicode } from 'node:url';

// Адрес с национальным доменом (ivan@почта.рф): домен переводим в punycode до
// строгой проверки, письмо уходит на xn--адрес. Имя до @ остаётся ASCII:
// не-ASCII имена ящиков поддерживают не все почтовые серверы, такие адреса
// по-прежнему отклоняются.
export function toAsciiEmail(raw: string): string {
  const value = raw.trim();
  const at = value.lastIndexOf('@');
  if (at < 0) return value;
  const domain = value.slice(at + 1);
  if (/^[\x00-\x7f]*$/.test(domain)) return value;
  const ascii = domainToASCII(domain.toLowerCase());
  return ascii ? `${value.slice(0, at)}@${ascii}` : value;
}

// Адрес для показа человеку: punycode-домен — в привычном виде.
export function displayEmail(email: string): string {
  const at = email.lastIndexOf('@');
  if (at < 0 || !email.includes('xn--', at)) return email;
  const unicode = domainToUnicode(email.slice(at + 1));
  return unicode ? `${email.slice(0, at)}@${unicode}` : email;
}
