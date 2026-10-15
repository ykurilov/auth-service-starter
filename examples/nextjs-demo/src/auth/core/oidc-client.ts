import type { ModuleConfig } from './config.js';

// Фиксированный путь callback — должен совпадать с деривацией redirect_uri на
// стороне сервиса (Admin API строит именно /api/auth/callback).
export const CALLBACK_PATH = '/api/auth/callback';

export interface TokenSet {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  expiresIn: number;
}

// Ошибка обмена/обновления. error — код из тела ответа сервиса (invalid_grant и пр.).
export class OidcError extends Error {
  readonly error: string;
  readonly status?: number;
  constructor(error: string, message?: string, status?: number) {
    super(message ?? error);
    this.name = 'OidcError';
    this.error = error;
    this.status = status;
  }
}

interface RawTokenResponse {
  access_token: string;
  id_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export class OidcClient {
  // Поле объявлено отдельно, а не сокращённой записью в конструкторе: та
  // компилируется в код, а не стирается вместе с типами, и приложения с
  // erasableSyntaxOnly (Next.js со скриптами на node --strip-types) на ней
  // спотыкаются.
  private readonly config: ModuleConfig;

  constructor(config: ModuleConfig) {
    this.config = config;
  }

  private get redirectUri(): string {
    return `${this.config.appUrl}${CALLBACK_PATH}`;
  }

  // prompt: 'none' — тихая проверка единой SSO-сессии: сервис не показывает
  // никакого экрана, а сразу возвращает code или error=login_required.
  buildAuthorizeUrl(params: { challenge: string; state: string; prompt?: 'none' }): string {
    const url = new URL('/authorize', this.config.authUrl);
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.redirectUri);
    url.searchParams.set('code_challenge', params.challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    // Приложению нужен профиль пользователя (getUser отдаёт email/имя),
    // поэтому запрашиваем profile и email, а не только базовый openid.
    url.searchParams.set('scope', 'openid profile email');
    url.searchParams.set('state', params.state);
    if (params.prompt) url.searchParams.set('prompt', params.prompt);
    return url.toString();
  }

  buildLogoutUrl(): string {
    const url = new URL('/logout', this.config.authUrl);
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('post_logout_redirect_uri', `${this.config.appUrl}/`);
    return url.toString();
  }

  async exchangeCode(params: { code: string; verifier: string }): Promise<TokenSet> {
    return this.token({
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: this.redirectUri,
      client_id: this.config.clientId,
      code_verifier: params.verifier,
    });
  }

  async refreshTokens(refreshToken: string): Promise<TokenSet> {
    return this.token({ grant_type: 'refresh_token', refresh_token: refreshToken });
  }

  // Deadline охватывает и fetch, и тело. Race ограничивает также внедрённый
  // fetch, который не поддерживает AbortSignal.
  private async bounded<T>(run: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        run(controller.signal),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new OidcError('timeout'));
          }, this.config.timeoutMs ?? 10_000);
        }),
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private async token(body: Record<string, string>): Promise<TokenSet> {
    return this.bounded(async (signal) => {
      let res: Response;
      try {
        res = await this.config.fetch(`${this.config.authUrl}/oauth/token`, {
          method: 'POST', signal, redirect: 'error',
          headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
        });
      } catch {
        throw new OidcError('network_error');
      }
      if (!res.ok) {
        let error = 'http_error';
        try {
          const data: unknown = await res.json();
          if (data && typeof data === 'object' && 'error' in data && typeof data.error === 'string') error = data.error;
        } catch { /* Неизвестный ответ не является доказательством отзыва. */ }
        throw new OidcError(error, undefined, res.status);
      }
      let data: RawTokenResponse;
      try { data = await res.json() as RawTokenResponse; }
      catch { throw new OidcError('invalid_response'); }
      if (!data || typeof data !== 'object' ||
          typeof data.access_token !== 'string' || !data.access_token.trim() ||
          typeof data.id_token !== 'string' || !data.id_token.trim() ||
          typeof data.refresh_token !== 'string' || !data.refresh_token.trim() ||
          typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer' ||
          !Number.isSafeInteger(data.expires_in) || data.expires_in <= 0 || data.expires_in > 30 * 24 * 3600) {
        throw new OidcError('invalid_response');
      }
      return { accessToken: data.access_token, idToken: data.id_token,
        refreshToken: data.refresh_token, expiresIn: data.expires_in };
    });
  }

  async revoke(refreshToken: string): Promise<void> {
    try {
      await this.bounded(async (signal) => {
        const res = await this.config.fetch(`${this.config.authUrl}/oauth/revoke`, {
          method: 'POST', signal, redirect: 'error',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ token: refreshToken }),
        });
        await res.body?.cancel();
      });
    } catch { /* Локальный выход продолжается при любом сбое. */ }
  }
}
