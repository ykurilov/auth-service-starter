import type { Mailer, OutgoingEmail } from '../../ports/mailer.js';

export class FakeMailer implements Mailer {
  readonly sent: OutgoingEmail[] = [];

  async send(email: OutgoingEmail): Promise<void> {
    this.sent.push({ ...email });
  }

  get last(): OutgoingEmail | null {
    return this.sent[this.sent.length - 1] ?? null;
  }
}
