export interface SessionProfile {
  email?: string;
  emailVerified?: boolean;
  name?: string;
}

// Аудит устройства при продлении сессии.
export interface DeviceAudit {
  fingerprint: string;
  ipHash: string;
}

export interface Session {
  id: string;
  userId: string;
  clientId: string;
  provider: string;
  profile: SessionProfile;
  scope: string;              // нормализованный scope, выданный при входе; переживает refresh-ротацию
  deviceFingerprint: string; // хеш user-agent, мягкая привязка
  ipHash: string;            // хеш IP, только для аудита
  createdAt: Date;
  lastUsedAt: Date;
  expiresAt: Date;           // скользящее продление
  revokedAt: Date | null;
}

export interface SessionStore {
  save(session: Session): Promise<void>;
  findById(id: string): Promise<Session | null>;
  // Скользящее продление + обновление аудита устройства.
  touch(id: string, at: Date, expiresAt: Date, device: DeviceAudit): Promise<void>;
  revoke(id: string, at: Date): Promise<void>;
  // Revoke the client's sessions except those using a currently allowed provider.
  revokeForClient(clientId: string, at: Date, allowedProviders?: string[]): Promise<void>;
  // Отзывает все живые сессии пользователя во всех клиентах.
  revokeForUser(userId: string, at: Date): Promise<void>;
  // Живые (не отозванные и не истёкшие на момент now) сессии пользователя.
  findActiveByUser(userId: string, now: Date): Promise<Session[]>;
  // Удаляет сессии с expires_at < before ИЛИ (отозвана И revoked_at < before).
  // Вместе с сессией удаляются её refresh-токены (внешний ключ без каскада —
  // реализация обязана удалить их сама, одной транзакцией у pg-адаптера).
  // Возвращает число удалённых СЕССИЙ.
  deleteExpired(before: Date): Promise<number>;
}
