import { createHmac, randomBytes } from 'node:crypto';

// В хранилище — только SHA-256-хеш этого значения (см. shared/hash).
export function generateRefreshToken(): string {
  return randomBytes(32).toString('base64url');
}

// Parent secret is the HMAC key; database hashes cannot recover descendants.
export function deriveRefreshToken(parentSecret: string, successorId: string): string {
  return createHmac('sha256', parentSecret)
    .update(`auth-v3:refresh:hmac-sha256-v1:${successorId}`).digest('base64url');
}

export interface RefreshTokenRecord {
  id: string;
  sessionId: string;
  tokenHash: string;             // sha256Hex(raw)
  previousTokenId: string | null; // предшественник в цепочке
  replacedById: string | null;    // преемник (проставляется при гашении)
  createdAt: Date;
  consumedAt: Date | null;
  derivationVersion?: 'hmac-sha256-v1'; // absent on legacy random tokens
}

export interface RefreshTokenStore {
  // Atomic CAS + successor publication. Failure leaves both records unchanged.
  rotate(headId: string, successor: RefreshTokenRecord, at: Date): Promise<boolean>;
  save(record: RefreshTokenRecord): Promise<void>;
  findByHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
  findById(id: string): Promise<RefreshTokenRecord | null>;
  // CAS: пометить consumed + проставить replacedById, только если ещё не погашен.
  // true — этот вызов реально погасил (выиграл гонку).
  consume(id: string, replacedById: string, at: Date): Promise<boolean>;
}
