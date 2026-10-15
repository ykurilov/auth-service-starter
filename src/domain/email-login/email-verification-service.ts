import type { Mailer } from '../../ports/mailer.js';
import type { IdentityRepository } from '../identity/identity-repository.js';
import { normalizeEmail } from '../identity/user.js';
import type { EmailSecretService } from '../email-secret/email-secret.js';

// Подтверждение владения почтой через тот же одноразовый секрет (purpose='email-verify').
// Нужно, например, после входа по паролю, где emailVerified изначально false.
export class EmailVerificationService {
  static readonly PURPOSE = 'email-verify';

  constructor(
    private readonly secrets: EmailSecretService,
    private readonly mailer: Mailer,
    private readonly repo: IdentityRepository,
  ) {}

  async requestVerification(_userId: string, rawEmail: string): Promise<void> {
    const email = normalizeEmail(rawEmail);
    const token = await this.secrets.issue(EmailVerificationService.PURPOSE, email);
    await this.mailer.send({
      to: email,
      subject: 'Подтверждение почты',
      text: `Ссылка для подтверждения (токен): ${token}`,
    });
  }

  // true — почта подтверждена (или уже была). false — токен неверен/просрочен/погашен либо у пользователя нет такого email.
  async confirm(userId: string, rawEmail: string, token: string): Promise<boolean> {
    const email = normalizeEmail(rawEmail);
    if (!(await this.secrets.verify(EmailVerificationService.PURPOSE, email, token))) {
      return false;
    }
    const record = await this.repo.findEmail(userId, email);
    if (!record) return false;
    if (!record.verified) await this.repo.markEmailVerified(record.id);
    return true;
  }
}
