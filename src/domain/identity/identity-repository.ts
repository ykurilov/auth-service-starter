import type { User, Identity, EmailAddress } from './user.js';

export interface IdentityRepository {
  findUserById(id: string): Promise<User | null>;
  findIdentity(provider: string, subject: string): Promise<Identity | null>;
  findUserByVerifiedEmail(email: string): Promise<User | null>;
  createUser(data: { displayName?: string }): Promise<User>;
  addIdentity(data: {
    userId: string;
    provider: string;
    subject: string;
  }): Promise<Identity>;
  addEmail(data: {
    userId: string;
    email: string;
    verified: boolean;
  }): Promise<EmailAddress>;
  findEmail(userId: string, email: string): Promise<EmailAddress | null>;
  findEmailsForUser(userId: string): Promise<EmailAddress[]>;
  markEmailVerified(emailId: string): Promise<void>;
  // Задаёт имя пользователя, только если оно ещё пустое.
  fillDisplayName(userId: string, name: string): Promise<void>;
  // Выполняет fn атомарно и взаимоисключающе по ключам lockKeys: все записи fn
  // либо фиксируются целиком, либо откатываются (нет «сирот»), а параллельные
  // вызовы с пересекающимися ключами идут строго по очереди. fn получает
  // репозиторий, привязанный к этой единице работы.
  runAtomic<T>(lockKeys: string[], fn: (repo: IdentityRepository) => Promise<T>): Promise<T>;
}

// Нарушение уникальности при записи (гонка, которую не поймали блокировки):
// вызывающий может повторить единицу работы целиком.
export class IdentityConflictError extends Error {
  constructor(message = 'конфликт уникальности личности/почты') {
    super(message);
    this.name = 'IdentityConflictError';
  }
}
