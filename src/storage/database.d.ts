import { KeyPairPem } from '../utils/cryptoHelper.d.ts';

export * from './schema.d.ts';

export interface DbMessage {
  id: string;
  sender: string;
  receiver: string;
  content: string;
  isAction: boolean;
  isSnippet: boolean;
  isE2ee: boolean;
  deletedBy: string;
  timestamp: string;
}

export interface DbProfile {
  contacts: string[];
  history: string[];
  passwordHash: string;
  publicKey: string;
  publicKeys: string[];
  kemPublicKey: string;
  allowTelnet: boolean;
}

export interface DbNodeIdentity {
  nodeId: string;
  identityKeyPair: KeyPairPem;
  kemKeyPair: KeyPairPem;
}

export interface OutboxItem {
  id: string;
  from: string;
  to: string;
  content: string;
  isAction: boolean;
  isSnippet: boolean;
  isE2EE: boolean;
  retries: number;
  nextRetry: number;
  timestamp: string;
  createdAt: number;
}

export class Database {
  filepath: string;
  db: any;
  lockFile: string | null;
  hasLock: boolean;

  constructor(filepath: string);

  init(): void;
  acquireLock(): void;
  releaseLock(): void;
  getNodeIdentity(): DbNodeIdentity;
  saveTrustedNodeKey(nodeAddress: string, identityPublicKey: string, kemPublicKey: string): void;
  getTrustedNodeKey(nodeAddress: string): { identity_public_key: string; kem_public_key: string } | null;
  saveRemoteUserKemKey(userAddress: string, kemPublicKey: string): void;
  close(): void;
  getUserProfile(userAddress: string): DbProfile;
  updateUserProfile(userAddress: string, contacts: string[], history: string[]): void;
  saveMessage(sender: string, receiver: string, content: string, isAction?: boolean, isSnippet?: boolean, isE2ee?: boolean): string;
  getConversation(userA: string, userB: string, limit?: number): DbMessage[];
  getChannelMessages(channel: string, limit?: number): DbMessage[];
  clearConversationForUser(userAddress: string, targetAddress: string): void;
  deleteExpiredCircuits(maxAgeMs?: number): any;
  queueOutbox(options: {
    id?: string;
    from: string;
    to: string;
    content: string;
    isAction?: boolean;
    isSnippet?: boolean;
    isE2EE?: boolean;
    timestamp?: string;
    createdAt?: number;
  }): void;
  getPendingOutbox(forceAll?: boolean): OutboxItem[];
  removeOutbox(id: string): void;
  cleanExpiredOutbox(ttl?: number, maxRetries?: number): number;
  updateOutboxRetry(id: string, maxRetries?: number, ttl?: number): { expired: boolean; retries: number; nextRetry?: number } | null;
  resetOutboxForTarget(target: string): void;
}
