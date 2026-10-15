import type { User } from './user.js';
import { normalizeEmail } from './user.js';
import { IdentityConflictError, type IdentityRepository } from './identity-repository.js';
import type { ProviderIdentity } from './provider-identity.js';

export interface ResolveLoginResult {
  user: User;
  createdUser: boolean;
  linkedIdentity: boolean;
}

// Новая личность принесла адрес почты, владение которым провайдер не доказал
// (например, Google-аккаунт со сторонней почтой без hd). По такому адресу нельзя
// ни создать пользователя, ни присоединиться к существующему: сначала владелец
// подтверждает адрес кодом из письма. Ничего не записано.
export class EmailOwnershipRequiredError extends Error {
  constructor(readonly email: string) {
    super('владение адресом почты не подтверждено провайдером');
    this.name = 'EmailOwnershipRequiredError';
  }
}

// Сколько раз повторяем единицу работы при конфликте уникальности, который
// всё-таки проскочил мимо блокировок (страховка; при блокировках не случается).
const MAX_CONFLICT_RETRIES = 3;

export class IdentityService {
  constructor(private readonly repo: IdentityRepository) {}

  // Разрешение входа целиком атомарно: поиск личности, поиск владельца почты,
  // создание пользователя, привязка личности и почты — одна единица работы под
  // блокировками личности и адреса. Параллельные первые входы одним адресом
  // (Google и код в двух вкладках) выстраиваются в очередь: второй видит
  // результат первого и присоединяется к нему, а не создаёт двойника. Сбой
  // откатывает всё — «сирот» (пользователя без личности) не остаётся.
  async resolveLogin(pid: ProviderIdentity): Promise<ResolveLoginResult> {
    const email = pid.email !== undefined ? normalizeEmail(pid.email) : undefined;
    const lockKeys = [`identity:${pid.provider}:${pid.subject}`];
    if (email) lockKeys.push(`email:${email}`);
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.repo.runAtomic(lockKeys, (repo) => this.resolveIn(repo, pid, email));
      } catch (err) {
        if (err instanceof IdentityConflictError && attempt < MAX_CONFLICT_RETRIES) continue;
        throw err;
      }
    }
  }

  private async resolveIn(
    repo: IdentityRepository,
    pid: ProviderIdentity,
    email: string | undefined,
  ): Promise<ResolveLoginResult> {
    // 1. Личность уже известна → её пользователь.
    const existing = await repo.findIdentity(pid.provider, pid.subject);
    if (existing) {
      const user = await repo.findUserById(existing.userId);
      if (!user) {
        throw new Error(
          `identity ${existing.id} ссылается на отсутствующего пользователя ${existing.userId}`,
        );
      }
      await this.attachEmail(repo, user, pid, email);
      return { user, createdUser: false, linkedIdentity: false };
    }

    // 2. Первый вход этой личности. Адрес без доказанного владения не даёт
    // права ни на чужой аккаунт, ни на новый с этим адресом.
    if (email && !pid.emailVerified) throw new EmailOwnershipRequiredError(email);

    let user: User | null = email ? await repo.findUserByVerifiedEmail(email) : null;
    const createdUser = user === null;
    if (!user) user = await repo.createUser({ displayName: pid.profile.name });

    await repo.addIdentity({ userId: user.id, provider: pid.provider, subject: pid.subject });
    await this.attachEmail(repo, user, pid, email);
    return { user, createdUser, linkedIdentity: !createdUser };
  }

  // Подтверждённым адрес становится только у одного пользователя. Если он уже
  // подтверждён у другого (например, сменили почту в Google-аккаунте на чужой
  // занятый адрес), вход не ломаем: адрес записывается неподтверждённым.
  private async attachEmail(
    repo: IdentityRepository,
    user: User,
    pid: ProviderIdentity,
    email: string | undefined,
  ): Promise<void> {
    if (!email) return;
    const owner = pid.emailVerified ? await repo.findUserByVerifiedEmail(email) : null;
    const mayVerify = pid.emailVerified && (owner === null || owner.id === user.id);
    const existing = await repo.findEmail(user.id, email);
    if (!existing) {
      await repo.addEmail({ userId: user.id, email, verified: mayVerify });
      return;
    }
    if (mayVerify && !existing.verified) await repo.markEmailVerified(existing.id);
  }
}
