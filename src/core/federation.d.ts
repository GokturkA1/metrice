/// <reference types="node" />
import { EventEmitter } from 'node:events';
import type { Server, Socket } from 'node:net';
import { NodeId, MeshRole, ProtocolPacket } from '../types/protocol.d.ts';
import { PeerManager } from './peerManager.d.ts';
import { OnionRouter } from './onionRouter.d.ts';
import { KeyPairPem } from '../utils/cryptoHelper.d.ts';
import { NonceTracker, MessageTtlCache, SecureChannel } from './secureChannel.d.ts';
import { AutoNatService } from './autoNat.d.ts';
import { RendezvousManager } from './rendezvousManager.d.ts';
import { PresenceManager } from './presenceManager.d.ts';
import { FederationPacketHandler } from './federationPacketHandler.d.ts';

export {
  NonceTracker,
  MessageTtlCache,
  SecureChannel,
  AutoNatService,
  RendezvousManager,
  PresenceManager,
  FederationPacketHandler
};

export interface PresenceRecord {
  nodeId: NodeId;
  nodeAddress?: string;
  role?: string;
  rendezvousNodes?: string[];
  kemPublicKey?: string;
  identityPublicKey?: string;
  channels?: string[];
  lastSeen?: number;
  timestamp?: number;
  onlineUsers?: string[];
  subscribedChannels?: string[];
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
  publicIp: string | null;
  observedAddressVotes: Map<string, Set<string>>;
  isDialbackRunning: boolean;
  isMaintainingTunnels: boolean;
  nodePhysicalAddresses: Map<string, string>;
  pendingDialbacks: Map<string, any>;
  rendezvousTunnels: Map<string, any>;
  rendezvousRelays: Map<string, any>;
  boundRendezvousRelays: Set<string>;
  presenceTable: Map<string, PresenceRecord>;
  remoteOnlineUsers: Map<string, any>;
  channelSubscribers: Map<string, Set<string>>;
  connectionPool: Map<string, SecureChannel>;
  nonceTracker: NonceTracker;
  seenMessages: MessageTtlCache;

  onionRouter: OnionRouter;
  autoNat: AutoNatService;
  rendezvousManager: RendezvousManager;
  presenceManager: PresenceManager;
  packetHandler: FederationPacketHandler;

  constructor(db: any, peerManager: PeerManager);

  setRole(newRole: string): void;
  getRole(): string;
  isRelay(): boolean;
  isSelfPeerAddress(host: string, port?: number): boolean;
  isTransitEdge(): boolean;
  checkTransitEdgeRole(): void;
  setLocalStateGetter(fn: () => any): void;

  getAllOnlineUsers(): string[];
  getChannelMembers(channelName: string): string[];
  getRemoteUserSecurity(userAddress: string): { isSsh: boolean; kemPublicKey: string } | null;

  start(port?: number): Promise<void> | void;
  startWorkers(): void;
  close(): Promise<void> | void;

  handleIncoming(payload: any, channel?: SecureChannel | any, remotePeer?: string): void;
  forwardToChannelSubscribers(channelName: string, msg: any, exceptPeer?: string | null): void;

  getOrCreateSecureChannel(host: string, port: number): Promise<SecureChannel>;
  sendPacket(host: string, port: number, data: any): Promise<any>;

  broadcastPresence(): Promise<void>;
  broadcastUserOffline(userAddress: string): Promise<void>;
  broadcastChannelMessage(msg: any, exceptPeer?: any): Promise<void>;
  performRandomGossip(): Promise<void>;

  subscribeRemoteChannel(host: string, port: number, channel: string): Promise<void>;
  unsubscribeRemoteChannel(host: string, port: number, channel: string): Promise<void>;
  subscribeNodeChannel(nodeId: string, channel: string): Promise<void>;
  unsubscribeNodeChannel(nodeId: string, channel: string): Promise<void>;

  handleObservedAddress(observedAddress: string, peer: string): void;
  initiateDialback(targetIp: string): Promise<string>;
  handleDialbackConfirm(payload: any): void;

  maintainRendezvousTunnels(): Promise<void>;
  bindToRendezvousRelay(relayAddr: string): Promise<boolean>;
  sendRendezvousHeartbeat(): void;

  getLocalChannels(): string[];
  getRelayAnnounceAddress(): string;
  broadcastRouteUpdate(nodeId: string, rendezvousAddr: string, kemPublicKey?: string | null, identityPublicKey?: string | null): void;
  createPresenceAnnouncePayload(): any;
  broadcastPresenceAnnounce(): void;
  cleanupExpiredPresence(): void;

  handleLocalDeliveredMessage(payload: any): void;
  sendViaOnion(targetNodeId: string, payload: any, fromOutbox?: boolean): Promise<any>;
  processOutbox(forceAll?: boolean): Promise<void>;
  sendRemoteMessage(from: string, to: string, content: string, isAction?: boolean, isSnippet?: boolean, isE2EE?: boolean): Promise<any>;
  sendTyping(from: string, to: string): Promise<void>;
}
