import { KeyPairPem } from '../utils/cryptoHelper.d.ts';

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

export class Database {
  filepath: string;
  db: any;

  constructor(filepath: string);

  init(): void;
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
}
