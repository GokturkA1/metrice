import type { FederationEngine } from './federation.d.ts';

export class PresenceManager {
  federation: FederationEngine;

  constructor(federation: FederationEngine);

  getLocalChannels(): string[];
  getRelayAnnounceAddress(): string;
  getAllOnlineUsers(): string[];
  getChannelMembers(channelName: string): string[];
  getRemoteUserSecurity(userAddress: string): { isSsh: boolean; kemPublicKey: string } | null;
  broadcastRouteUpdate(nodeId: string, rendezvousAddr: string, kemPublicKey?: string | null, identityPublicKey?: string | null): void;
  createPresenceAnnouncePayload(): any;
  broadcastPresenceAnnounce(): void;
  broadcastPresence(): Promise<void>;
  broadcastUserOffline(userAddress: string): Promise<void>;
  broadcastChannelMessage(msg: any, exceptPeer?: any): Promise<void>;
  performRandomGossip(): Promise<void>;
  subscribeRemoteChannel(host: string, port: number, channel: string): Promise<void>;
  unsubscribeRemoteChannel(host: string, port: number, channel: string): Promise<void>;
  subscribeNodeChannel(nodeId: string, channel: string): Promise<void>;
  unsubscribeNodeChannel(nodeId: string, channel: string): Promise<void>;
  cleanupExpiredPresence(): void;
}
