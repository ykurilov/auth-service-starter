// Scope, которые сервис реально умеет обслуживать. Порядок задаёт стабильную
// нормализованную форму. openid — базовый для OIDC-потока и присутствует всегда.
export const SUPPORTED_SCOPES = ['openid', 'profile', 'email'] as const;

// Парсит scope-строку в нормализованный набор известных сервису scope.
// Неизвестные молча отбрасываются (OAuth 2.0 §3.3 допускает игнорировать
// нераспознанные), дубликаты схлопываются, openid добавляется всегда.
export function parseScopes(raw: string | undefined): Set<string> {
  const set = new Set<string>(['openid']);
  for (const s of (raw ?? '').split(/\s+/)) {
    if ((SUPPORTED_SCOPES as readonly string[]).includes(s)) set.add(s);
  }
  return set;
}

// Каноничная scope-строка для хранения и выдачи: стабильный порядок, только
// поддерживаемые значения. Используется как значение claim `scope` в access-token
// и как то, что кладётся в сессию/код.
export function normalizeScope(raw: string | undefined): string {
  const set = parseScopes(raw);
  return SUPPORTED_SCOPES.filter((s) => set.has(s)).join(' ');
}

export interface ScopedProfile {
  email?: string;
  emailVerified?: boolean;
  name?: string;
}

// Отбирает из профиля только claims, покрытые запрошенным scope:
// scope `profile` открывает name, scope `email` — email и email_verified.
// Всё, что не покрыто, не попадает в id_token / userinfo.
export function profileForScope(profile: ScopedProfile, scope: string): ScopedProfile {
  const scopes = parseScopes(scope);
  const out: ScopedProfile = {};
  if (scopes.has('profile')) out.name = profile.name;
  if (scopes.has('email')) {
    out.email = profile.email;
    out.emailVerified = profile.emailVerified;
  }
  return out;
}
