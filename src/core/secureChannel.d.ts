/// <reference types="node" />
import { EventEmitter } from 'node:events';
import type { Socket } from 'node:net';
import { ProtocolPacket } from '../types/protocol.d.ts';

export class NonceTracker {
  ttlMs: number;
  nonces: Map<string, number>;

  constructor(ttlMs?: number);

  track(nonce: string, remoteIp?: string): boolean;
  cleanup(now: number): void;
}

export class MessageTtlCache {
  ttlMs: number;
  cache: Map<string, number>;

  constructor(ttlMs?: number);

  has(id: string): boolean;
  add(id: string): void;
  cleanup(now: number): void;
}

export class SecureChannel extends EventEmitter {
  socket: Socket;
  isInitiator: boolean;
  myIdentity: any;
  db: any;
  nonceTracker: NonceTracker;
  isReady: boolean;
  peerNodeAddress: string | null;
  peerIdentityKey: string | null;
  peerKemKey: string | null;
  sessionKey: Buffer | null;
  observedAddress: string | null;

  constructor(socket: Socket, isInitiator: boolean, myIdentity: any, db: any, nonceTracker?: NonceTracker);

  initSocketHandlers(): Promise<void>;
  sendHandshakeInit(): void;
  handleFrame(frame: any): Promise<void>;
  validatePeerIp(declaredNodeAddress: string, identityPublicKey?: string | null): Promise<boolean>;
  markReady(): void;
  writePayload(payload: ProtocolPacket | object): void;
  sendPacket(payload: ProtocolPacket | object): void;
  destroy(): void;
}
