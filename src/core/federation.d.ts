/// <reference types="node" />
import { EventEmitter } from 'node:events';
import type { Server, Socket } from 'node:net';
import { NodeId, MeshRole, ProtocolPacket } from '../types/protocol.d.ts';
import { PeerManager } from './peerManager.d.ts';
import { OnionRouter } from './onionRouter.d.ts';
import { KeyPairPem } from '../utils/cryptoHelper.d.ts';

export class NonceTracker {
  ttlMs: number;
  nonces: Map<string, number>;

  constructor(ttlMs?: number);

  track(nonce: string, remoteIp?: string): boolean;
  cleanup(now: number): void;
}

export class SecureChannel extends EventEmitter {
  socket: Socket;
  myIdentity: any;
  db: any;
  isReady: boolean;
  peerNodeAddress: string | null;
  peerIdentityKey: string | null;
  peerKemKey: string | null;
  sessionKey: Buffer | null;

  constructor(socket: Socket, myIdentity: any, db: any);

  writePayload(payload: ProtocolPacket | object): void;
  sendPacket(payload: ProtocolPacket | object): void;
  destroy(): void;
}

export interface PresenceRecord {
  nodeId: NodeId;
  nodeAddress: string;
  timestamp: number;
  onlineUsers: string[];
  subscribedChannels: string[];
  relays?: string[];
}

export interface NodeIdentityState {
  nodeId: NodeId;
  meshAddress: string;
  nodeAddress: string;
  identityKeyPair: KeyPairPem;
  kemKeyPair: KeyPairPem;
  role: MeshRole;
  getRelayAnnounceAddress: () => string;
}

export class FederationEngine extends EventEmitter {
  db: any;
  peerManager: PeerManager;
  server: Server | null;
  nodeId: NodeId;
  meshAddress: string;
  nodeAddress: string;
  identityKeyPair: KeyPairPem;
  kemKeyPair: KeyPairPem;
  myIdentity: NodeIdentityState;
  role: MeshRole;
  onionRouter: OnionRouter;
  remoteOnlineUsers: Map<string, { lastSeen: number; nodeId?: string; isTunnelUser?: boolean }>;
  rendezvousTunnels: Map<string, any>;
  presenceTable: Map<string, PresenceRecord>;

  constructor(db: any, peerManager: PeerManager);

  start(port?: number): Promise<void>;
  close(): Promise<void>;
  sendPacket(host: string, port: number, packet: ProtocolPacket | object): Promise<any>;
  getOrCreateSecureChannel(host: string, port: number): Promise<SecureChannel>;
  broadcastUserOffline(userAddress: string): void;
  broadcastPresence(status?: string): void;
  routeMessage(packet: ProtocolPacket | object): Promise<boolean>;
  setLocalStateGetter(fn: () => { users: string[]; memberships: string[] }): void;
  getAllOnlineUsers(): string[];
  getOnlineUsers(): string[];
  subscribeRemoteChannel(host: string, port: number, channel: string): Promise<void>;
  unsubscribeRemoteChannel(host: string, port: number, channel: string): Promise<void>;
  subscribeNodeChannel(nodeId: string, channel: string): Promise<void>;
  unsubscribeNodeChannel(nodeId: string, channel: string): Promise<void>;
  getRelayAnnounceAddress(): string;
  getSystemStats(): any;
}
