import { randomUUID } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import { sha256Hex } from '../shared/hash.js';
import type { AuthSnapshot } from '../login/authorization-code.js';
import {
  BROWSER_BINDING_TTL_SECONDS,
  generateSsoToken,
  type BrowserBinding,
  type SsoSession,
  type SsoSessionStore,
  type SsoStoreSet,
  type SsoStores,
} from './sso-session.js';

export interface SsoSessionServiceConfig { ssoTtlSeconds: number; }

// Цепочка браузера, через которую выдан код входа loginId; null — вход без
// SSO-сессии (код выдан до обновления), к цепочке не привязан.
export async function chainOfLogin(sso: SsoSessionStore, loginId: string | undefined): Promise<string | null> {
  if (!loginId) return null;
  return (await sso.findByLogin(loginId))?.chainId ?? null;
}

export class SsoSessionService {
  constructor(
    private readonly stores: SsoStores,
    private readonly clock: Clock,
    private readonly config: SsoSessionServiceConfig,
  ) {}

  private slide(now: Date): Date { return new Date(now.getTime() + this.config.ssoTtlSeconds * 1000); }

  // previousRawToken — SSO-cookie браузера до этого входа, previousBinding —
  // его cookie привязки. Тот же пользователь продолжает цепочку браузера (по
  // SSO-cookie, а если та истекла — по привязке): прежние SSO-сессии цепочки
  // отзываются, сессии приложений и привязка остаются.
  //
  // Другой пользователь начинает новую цепочку, а прежняя закрывается целиком:
  // её SSO-сессии и сессии приложений отзываются, привязки удаляются. В
  // браузере не остаётся прежнего аккаунта ни в одном приложении, на других
  // устройствах он остаётся. Старые секреты (SSO-cookie и копии привязок)
  // ведут только в закрытую цепочку: владелец подсаженной в браузер привязки,
  // войдя потом со своей прежней cookie, продолжит свою цепочку, а не цепочку
  // вошедшего, и выйти за него не сможет. Цепочка без SSO-сессий (их уже
  // удалила очистка) продолжается: её прежних SSO-cookie больше нет, привязки
  // удаляются, сессии приложений других пользователей гаснут. Привязка другой
  // цепочки, чем у SSO-cookie, у браузера не остаётся.
  //
  // Возвращает и секрет привязки цепочки — его cookie продлевается вместе с
  // SSO-cookie. Прежний секрет остаётся, только если цепочка продолжается тем
  // же пользователем.
  //
  // Цепочки обеих cookie блокируются одним lockChains до любых изменений
  // (порядок блокировок — у signOut). Решаем по состоянию под блокировками, а
  // не по прежней cookie: вход из соседней вкладки или задержанный вход со
  // старой cookie мог уже сменить аккаунт, а выход — удалить привязку. Новую
  // цепочку блокировать не нужно: до фиксации о ней никто не знает. Время
  // берём под блокировкой: порядок created_at в цепочке совпадает с порядком
  // входов (findLatestInChain).
  async start(
    userId: string,
    auth: AuthSnapshot,
    previousRawToken?: string | null,
    previousBinding?: string | null,
  ): Promise<{ session: SsoSession; rawToken: string; bindingToken: string }> {
    const rawToken = generateSsoToken();
    return this.stores.atomically(async ({ sso, sessions }) => {
      const previous = previousRawToken ? await sso.findByHash(sha256Hex(previousRawToken)) : null;
      await sso.lockChains(chainsOf(previous, await this.liveBinding(sso, previousBinding)));
      const binding = await this.liveBinding(sso, previousBinding);
      const browserChain = previous?.chainId ?? binding?.chainId ?? null;
      if (binding && binding.chainId !== browserChain) await sso.deleteBinding(binding.tokenHash);
      const latest = browserChain ? await sso.findLatestInChain(browserChain) : null;
      const now = this.clock.now();
      let chainId = browserChain ?? randomUUID();
      if (browserChain && latest && latest.userId !== userId) {
        await sso.revokeChain(browserChain, now);
        await sessions.revokeForSsoChain(browserChain, now);
        await sso.deleteChainBindings(browserChain);
        chainId = randomUUID();
      } else if (browserChain) {
        if (!latest) await sso.deleteChainBindings(browserChain);
        await sso.revokeChain(browserChain, now);
        await sessions.revokeOthersInSsoChain(browserChain, userId, now);
      }
      const session: SsoSession = {
        id: randomUUID(), userId, auth, tokenHash: sha256Hex(rawToken), chainId,
        createdAt: now, lastUsedAt: now, expiresAt: this.slide(now), revokedAt: null,
      };
      await sso.save(session);
      const kept = latest?.userId === userId && binding?.chainId === chainId ? previousBinding! : null;
      const bindingToken = await this.renewBinding(sso, chainId, kept, now);
      return { session, rawToken, bindingToken };
    });
  }

  // Живая SSO-сессия браузера (заход на страницы входа): продлевает привязку
  // её цепочки, а цепочке без привязки (начатой до обновления) выдаёт новую,
  // не трогая прочие привязки цепочки: соседняя вкладка могла получить свою.
  // Привязку другой цепочки удаляет — у браузера она не остаётся. Возвращает
  // секрет для cookie. Обе цепочки — под блокировками, взятыми до изменений.
  async bindBrowser(session: Pick<SsoSession, 'chainId'>, rawBinding?: string | null): Promise<string> {
    return this.stores.atomically(async ({ sso }) => {
      await sso.lockChains(chainsOf(session, await this.liveBinding(sso, rawBinding)));
      const binding = await this.liveBinding(sso, rawBinding);
      if (binding && binding.chainId !== session.chainId) await sso.deleteBinding(binding.tokenHash);
      const kept = binding?.chainId === session.chainId ? rawBinding! : null;
      return this.renewBinding(sso, session.chainId, kept, this.clock.now());
    });
  }

  private async liveBinding(sso: SsoSessionStore, rawBinding?: string | null): Promise<BrowserBinding | null> {
    if (!rawBinding) return null;
    const binding = await sso.findBinding(sha256Hex(rawBinding));
    return binding && binding.expiresAt.getTime() > this.clock.now().getTime() ? binding : null;
  }

  // Продлевает привязку kept, а если её нет (или её успели удалить) — выдаёт
  // цепочке новую. Возвращает секрет для cookie.
  private async renewBinding(sso: SsoSessionStore, chainId: string, kept: string | null, now: Date): Promise<string> {
    const expiresAt = new Date(now.getTime() + BROWSER_BINDING_TTL_SECONDS * 1000);
    if (kept && await sso.renewBinding(sha256Hex(kept), expiresAt)) return kept;
    const token = generateSsoToken();
    await sso.addBinding({ chainId, tokenHash: sha256Hex(token), createdAt: now, expiresAt });
    return token;
  }

  async resolve(rawToken: string): Promise<SsoSession | null> {
    const now = this.clock.now();
    const session = await this.stores.sso.findByHash(sha256Hex(rawToken));
    if (!session || session.revokedAt !== null || session.expiresAt.getTime() <= now.getTime()) return null;
    const expiresAt = this.slide(now);
    await this.stores.sso.touch(session.id, now, expiresAt);
    return { ...session, lastUsedAt: now, expiresAt };
  }

  async revoke(sessionId: string): Promise<void> {
    await this.stores.sso.revoke(sessionId, this.clock.now());
  }

  // «Выйти»: гасит цепочку SSO этого браузера и сессии приложений, выданные
  // через неё (какого бы пользователя они ни были). Сессии пользователя в
  // других браузерах и на других устройствах не трогает: у них свои цепочки.
  // Одной транзакцией. Отозванная или истёкшая cookie только доделывает отзыв
  // своей цепочки (повтор после сбоя) и только если браузер не сменил её
  // новым входом.
  //
  // Привязка браузера (rawBinding) находит его цепочку и тогда, когда
  // SSO-cookie уже истекла: гасит её так же. Погашенная цепочка теряет все
  // свои привязки, а удалённая привязка (выходом или сменой аккаунта) уже
  // ничего не гасит.
  //
  // Порядок блокировок во всём сервисе: строка клиента (ClientLock, только
  // обмен кода и refresh) → блокировки цепочек SSO, все нужные операции сразу
  // и по возрастанию ключа (lockChains) → строки sso_sessions, привязок и
  // sessions. Вход, заход на страницы входа и выход сначала находят цепочки
  // обеих cookie (у SSO-сессии и привязки цепочка не меняется), берут их
  // блокировки и только потом читают состояние и меняют строки. Строки
  // цепочки меняют только под её блокировкой, а блокировку клиента под
  // блокировкой цепочки никто не ждёт: взаимной блокировки нет, в том числе
  // у двух выходов с противоположными парами cookie.
  async signOut(rawToken: string | null, rawBinding: string | null = null): Promise<void> {
    await this.stores.atomically(async (stores) => {
      const { sso, sessions } = stores;
      const found = rawToken ? await sso.findByHash(sha256Hex(rawToken)) : null;
      await sso.lockChains(chainsOf(found, await this.liveBinding(sso, rawBinding)));
      const signedOutChain = found ? await this.signOutBySsoToken(stores, found.tokenHash) : null;
      if (signedOutChain) await sso.deleteChainBindings(signedOutChain);
      const binding = await this.liveBinding(sso, rawBinding);
      if (!binding || binding.chainId === signedOutChain) return;
      const now = this.clock.now();
      await sso.revokeChain(binding.chainId, now);
      await sessions.revokeForSsoChain(binding.chainId, now);
      await sso.deleteChainBindings(binding.chainId);
    });
  }

  // Выход по SSO-cookie под уже взятой блокировкой её цепочки. Возвращает
  // погашенную цепочку (null — ничего не гасили).
  private async signOutBySsoToken({ sso, sessions }: SsoStoreSet, tokenHash: string): Promise<string | null> {
    // Перечитываем cookie: вход, начатый раньше, мог её отозвать и сменить
    // последней в цепочке.
    const session = await sso.findByHash(tokenHash);
    if (!session) return null;
    const now = this.clock.now();
    const live = session.revokedAt === null && session.expiresAt.getTime() > now.getTime();
    if (!live && (await sso.findLatestInChain(session.chainId))?.id !== session.id) return null;
    await sso.revokeChain(session.chainId, now);
    await sessions.revokeForSsoChain(session.chainId, now);
    return session.chainId;
  }
}

// Цепочки, к которым относятся cookie браузера (без повторов и пустых).
function chainsOf(...owners: Array<{ chainId: string } | null | undefined>): string[] {
  return [...new Set(owners.flatMap((o) => (o ? [o.chainId] : [])))];
}
