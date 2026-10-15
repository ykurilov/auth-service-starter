import { describe, it, expect, vi } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import {
  makeTestDeps,
  type TestDeps,
  TEST_CSRF,
  FORM_HEADERS,
  browserHeaders,
  extractChallenge,
} from './helpers.js';
import {
  GoogleProvider,
  type GoogleTokenPayload,
} from '../../../src/domain/google-login/google-provider.js';
import { GoogleNonceService } from '../../../src/domain/google-login/google-nonce.js';
import { InMemoryGoogleNonceStore } from '../../../src/adapters/repository/in-memory-google-nonce-store.js';
import { systemClock } from '../../../src/ports/clock.js';
import type { Client } from '../../../src/domain/clients/client.js';

const GOOGLE_CLIENT: Client = {
  id: 'app',
  type: 'internal',
  redirectUris: ['https://app.example/cb'],
  allowedProviders: ['email', 'google'],
};

// Фейковая проверка ID Token: токен → заранее заданная полезная нагрузка.
// nonce в ней — тот, что сервер выпустил на странице (его достаёт тест).
type Payloads = Map<string, GoogleTokenPayload>;

function fakeGoogle(deps: TestDeps, clientId = 'google-cid'): Payloads {
  const payloads: Payloads = new Map();
  deps.config.googleClientId = clientId;
  deps.googleNonces = new GoogleNonceService(new InMemoryGoogleNonceStore(), systemClock);
  deps.googleProvider = new GoogleProvider(
    {
      verify: async (idToken: string) => {
        const p = payloads.get(idToken);
        if (!p) throw new Error('bad token');
        return p;
      },
    },
    deps.googleNonces,
  );
  return payloads;
}

function form(overrides: Record<string, string> = {}): string {
  const base: Record<string, string> = {
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    code_challenge: 'chal',
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
    csrf: TEST_CSRF,
    credential: 'good-token',
  };
  return new URLSearchParams({ ...base, ...overrides }).toString();
}

const authorizeUrl =
  '/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb' +
  '&code_challenge=chal&code_challenge_method=S256&scope=openid';

type App = ReturnType<typeof buildServer>;

// Страница входа в браузере с csrf-cookie: сервер выпускает nonce для кнопки.
async function renderNonce(app: App, csrf = TEST_CSRF): Promise<string> {
  const res = await app.inject({ method: 'GET', url: authorizeUrl, headers: { cookie: `csrf=${csrf}` } });
  const m = /nonce: '([^']+)'/.exec(res.body);
  if (!m) throw new Error('на странице нет nonce Google');
  return m[1]!;
}

function postGoogle(app: App, headers: Record<string, string> = FORM_HEADERS, overrides: Record<string, string> = {}) {
  return app.inject({ method: 'POST', url: '/authorize/google', payload: form(overrides), headers });
}

function cookies(res: { headers: Record<string, unknown> }): string {
  const raw = res.headers['set-cookie'];
  return Array.isArray(raw) ? raw.join('\n') : String(raw ?? '');
}

function userCount(deps: TestDeps): number {
  return (deps.repo as unknown as { users: Map<string, unknown> }).users.size;
}

describe('кнопка Google на странице входа', () => {
  it('R02: лимит nonce исчерпан → страница входа без кнопки Google, вход по почте работает', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    fakeGoogle(deps);
    deps.config.rateLimits.identifyPerIp.limit = 1;
    const issue = vi.spyOn(deps.googleNonces!, 'issue');
    const app = buildServer(deps);
    try {
      const first = await app.inject({ method: 'GET', url: authorizeUrl });
      expect(first.body).toContain('google-btn');
      const limited = await app.inject({ method: 'GET', url: authorizeUrl, headers: { cookie: `csrf=${TEST_CSRF}` } });
      expect(limited.statusCode).toBe(200);
      expect(limited.body).toContain('name="email"');
      expect(limited.body).not.toContain('google-btn');
      expect(issue).toHaveBeenCalledTimes(1);
      // Вход по почте с той же страницы не задет лимитом nonce.
      expect(extractChallenge((await app.inject({
        method: 'POST', url: '/authorize/identify', payload: form({ email: 'u@x.com', credential: '' }), headers: FORM_HEADERS,
      })).body)).toBeTruthy();
    } finally { await app.close(); }
  });

  it('R02: лимит на POST /authorize/google сохраняется', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    fakeGoogle(deps);
    deps.config.rateLimits.identifyPerIp.limit = 1;
    const app = buildServer(deps);
    try {
      await postGoogle(app, FORM_HEADERS, { credential: 'unknown' });
      const blocked = await postGoogle(app, FORM_HEADERS, { credential: 'unknown' });
      expect(blocked.statusCode).toBe(429);
      expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    } finally { await app.close(); }
  });

  it('рендерится с серверным nonce, когда Google настроен и разрешён клиенту', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    fakeGoogle(deps);
    const app = buildServer(deps);
    const res = await app.inject({ method: 'GET', url: authorizeUrl });
    expect(res.body).toContain('google-btn');
    expect(res.body).toContain('/authorize/google');
    expect(res.body).toContain('google-cid');
    // nonce не уходит в cookie: он хранится на сервере.
    expect(cookies(res)).not.toContain('g_nonce');
    await app.close();
  });

  it('не рендерится клиенту без google в allowedProviders', async () => {
    const deps = await makeTestDeps();
    fakeGoogle(deps);
    const app = buildServer(deps);
    const res = await app.inject({ method: 'GET', url: authorizeUrl });
    expect(res.body).not.toContain('google-btn');
    await app.close();
  });

  it('не рендерится, когда Google не настроен', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const app = buildServer(deps);
    const res = await app.inject({ method: 'GET', url: authorizeUrl });
    expect(res.body).not.toContain('google-btn');
    await app.close();
  });
});

describe('POST /authorize/google', () => {
  it('валидный ID Token (gmail) с серверным nonce → 302 с кодом, SSO-cookie', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true, name: 'G', nonce });
    const res = await postGoogle(app);
    expect(res.statusCode).toBe(302);
    const location = res.headers['location'] as string;
    expect(location).toContain('code=');
    expect(location.startsWith('https://app.example/cb')).toBe(true);
    expect(cookies(res)).toMatch(/sso=[^;]+/);
    await app.close();
  });

  it('невалидный токен → 200 со страницей входа и ошибкой', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    fakeGoogle(deps);
    const app = buildServer(deps);
    const res = await postGoogle(app, FORM_HEADERS, { credential: 'forged' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Не удалось войти через Google');
    await app.close();
  });

  it('F14: повтор того же id_token отклоняется — nonce погашен на сервере', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true, nonce });
    expect((await postGoogle(app)).statusCode).toBe(302);
    const replay = await postGoogle(app);
    expect(replay.statusCode).toBe(200);
    expect(replay.body).toContain('Не удалось войти через Google');
    expect(cookies(replay)).not.toMatch(/sso=[^;]+/);
    await app.close();
  });

  it('F14: параллельные предъявления одного id_token — вход ровно один', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true, nonce });
    const results = await Promise.all(Array.from({ length: 5 }, () => postGoogle(app)));
    expect(results.filter((r) => r.statusCode === 302)).toHaveLength(1);
    await app.close();
  });

  it('F14: nonce, выпущенный другому браузеру, не принимается', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const nonce = await renderNonce(app, 'victim-csrf');
    payloads.set('good-token', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true, nonce });
    const res = await postGoogle(app);
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Не удалось войти через Google');
    // Браузер-владелец nonce по-прежнему может войти (чужая попытка его не погасила).
    const own = await postGoogle(app, browserHeaders('victim-csrf'), { csrf: 'victim-csrf' });
    expect(own.statusCode).toBe(302);
    await app.close();
  });

  it('F14: токен с nonce, который сервер не выпускал (или без nonce) → отказ', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    payloads.set('good-token', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true, nonce: 'made-up' });
    payloads.set('no-nonce', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true });
    expect((await postGoogle(app)).body).toContain('Не удалось войти через Google');
    expect((await postGoogle(app, FORM_HEADERS, { credential: 'no-nonce' })).body).toContain(
      'Не удалось войти через Google',
    );
    await app.close();
  });

  it('F14: nonce выпущен для другого клиента → отказ', async () => {
    const other: Client = { ...GOOGLE_CLIENT, id: 'app2', redirectUris: ['https://app2.example/cb'] };
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT, other] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const nonce = await deps.googleNonces!.issue(TEST_CSRF, 'app2');
    payloads.set('good-token', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true, nonce });
    const res = await postGoogle(app);
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Не удалось войти через Google');
    await app.close();
  });

  it('клиент без google в allowedProviders → редирект с error=unauthorized_client', async () => {
    const deps = await makeTestDeps();
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const nonce = await deps.googleNonces!.issue(TEST_CSRF, 'app');
    payloads.set('good-token', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true, nonce });
    const res = await postGoogle(app);
    expect(res.statusCode).toBe(302);
    const location = res.headers['location'] as string;
    expect(location.startsWith('https://app.example/cb')).toBe(true);
    expect(location).toContain('error=unauthorized_client');
    expect(cookies(res)).not.toMatch(/sso=[^;]+/);
    await app.close();
  });

  it('Google не настроен → 400', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const app = buildServer(deps);
    const res = await postGoogle(app);
    expect(res.statusCode).toBe(400);
    await app.close();
  });

  it('gmail-адрес (владение доказано) линкуется к аккаунту с той же подтверждённой почтой', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const first = await deps.login.completeLogin(
      await deps.login.validateRequest({
        clientId: 'app',
        redirectUri: 'https://app.example/cb',
        codeChallenge: 'chal',
        codeChallengeMethod: 'S256',
        scope: 'openid',
      }),
      { provider: 'email', subject: 'code:g@gmail.com', email: 'g@gmail.com', emailVerified: true, profile: {} },
    );
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true, nonce });
    expect((await postGoogle(app)).statusCode).toBe(302);
    expect((await deps.repo.findIdentity('google', 'g-1'))?.userId).toBe(first.userId);
    await app.close();
  });

  it('Workspace-аккаунт: hd совпадает с доменом адреса → владение доказано, вход сразу', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-ws', email: 'boss@corp.example', emailVerified: true, hd: 'corp.example', nonce });
    expect((await postGoogle(app)).statusCode).toBe(302);
    expect(await deps.repo.findIdentity('google', 'g-ws')).not.toBeNull();
    await app.close();
  });
});

describe('R01: сторонний адрес Google (без gmail/hd) не даёт права на аккаунт', () => {
  async function victimAccount(deps: TestDeps): Promise<string> {
    const done = await deps.login.completeLogin(
      await deps.login.validateRequest({
        clientId: 'app',
        redirectUri: 'https://app.example/cb',
        codeChallenge: 'chal',
        codeChallengeMethod: 'S256',
        scope: 'openid',
      }),
      { provider: 'email', subject: 'code:boss@corp.example', email: 'boss@corp.example', emailVerified: true, profile: {} },
    );
    return done.userId;
  }

  it('не присоединяет к чужому пользователю и не создаёт нового — просит код из письма', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    await victimAccount(deps);
    const usersBefore = userCount(deps);
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-attacker', email: 'boss@corp.example', emailVerified: true, nonce });
    const res = await postGoogle(app);
    expect(res.statusCode).toBe(200);
    expect(res.headers['location']).toBeUndefined();
    expect(cookies(res)).not.toMatch(/sso=[^;]+/);
    expect(res.body).toContain('Google не подтверждает');
    expect(res.body).toContain('name="challenge"');
    // Код ушёл владельцу адреса, а не владельцу Google-аккаунта.
    expect(deps.mailer.last?.to).toBe('boss@corp.example');
    expect(await deps.repo.findIdentity('google', 'g-attacker')).toBeNull();
    expect(userCount(deps)).toBe(usersBefore);
    // hd другого домена владение не доказывает.
    const nonce2 = await renderNonce(app);
    payloads.set('hd-mismatch', { sub: 'g-attacker', email: 'boss@corp.example', emailVerified: true, hd: 'evil.example', nonce: nonce2 });
    const res2 = await postGoogle(app, FORM_HEADERS, { credential: 'hd-mismatch' });
    expect(res2.body).toContain('Google не подтверждает');
    expect(await deps.repo.findIdentity('google', 'g-attacker')).toBeNull();
    await app.close();
  });

  it('без кода из письма связывание невозможно: неверные коды → Google-личность не привязана', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    await victimAccount(deps);
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-attacker', email: 'boss@corp.example', emailVerified: true, nonce });
    const challenge = extractChallenge((await postGoogle(app)).body);
    for (let i = 0; i < 5; i++) {
      await app.inject({
        method: 'POST',
        url: '/authorize/code/verify',
        payload: form({ challenge, code: `BAD${i}`, credential: '' }),
        headers: FORM_HEADERS,
      });
    }
    expect(await deps.repo.findIdentity('google', 'g-attacker')).toBeNull();
    await app.close();
  });

  it('владелец подтверждает адрес кодом → Google-личность привязывается к его аккаунту, дальше вход сразу', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const victimId = await victimAccount(deps);
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-owner', email: 'boss@corp.example', emailVerified: true, name: 'Boss', nonce });
    const challenge = extractChallenge((await postGoogle(app)).body);
    const verified = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: form({ challenge, code: 'CODE55' }),
      headers: FORM_HEADERS,
    });
    expect(verified.statusCode).toBe(302);
    expect(verified.headers['location'] as string).toContain('code=');
    expect((await deps.repo.findIdentity('google', 'g-owner'))?.userId).toBe(victimId);
    // Следующий вход через Google — без кода: личность уже известна.
    const nonce2 = await renderNonce(app);
    payloads.set('again', { sub: 'g-owner', email: 'boss@corp.example', emailVerified: true, nonce: nonce2 });
    expect((await postGoogle(app, FORM_HEADERS, { credential: 'again' })).statusCode).toBe(302);
    await app.close();
  });

  it('нового адреса нет ни у кого: пользователь создаётся только после кода', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-new', email: 'new@corp.example', emailVerified: true, nonce });
    const challenge = extractChallenge((await postGoogle(app)).body);
    expect(userCount(deps)).toBe(0);
    const verified = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: form({ challenge, code: 'CODE55' }),
      headers: FORM_HEADERS,
    });
    expect(verified.statusCode).toBe(302);
    const identity = await deps.repo.findIdentity('google', 'g-new');
    expect(identity).not.toBeNull();
    expect((await deps.repo.findUserByVerifiedEmail('new@corp.example'))?.id).toBe(identity!.userId);
    await app.close();
  });
});

describe('R19: вход через Google гасит прежнюю SSO-сессию', () => {
  it('прежняя сессия из cookie отозвана', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const old = await deps.sso.start('user-old', { provider: 'email', email: 'o@x.com', emailVerified: true });
    const nonce = await renderNonce(app);
    payloads.set('good-token', { sub: 'g-1', email: 'g@gmail.com', emailVerified: true, nonce });
    const res = await postGoogle(app, { ...FORM_HEADERS, cookie: `${FORM_HEADERS.cookie}; sso=${old.rawToken}` });
    expect(res.statusCode).toBe(302);
    expect(await deps.sso.resolve(old.rawToken)).toBeNull();
    await app.close();
  });
});
