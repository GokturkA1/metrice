import type { FederationEngine } from './federation.d.ts';
import type { SecureChannel } from './secureChannel.d.ts';

export class FederationPacketHandler {
  federation: FederationEngine;
  seenPresenceAnnounces: Set<string>;
  seenRouteUpdates: Set<string>;
  seenOfflineAnnounces: Set<string>;

  constructor(federation: FederationEngine);

  handleIncoming(payload: any, channel?: SecureChannel | any, remotePeer?: string): void;
  handlePresenceAnnounce(payload: any, channel?: SecureChannel | any, remotePeer?: string): void;
  handleRouteUpdate(payload: any, channel?: SecureChannel | any, remotePeer?: string): void;
  handleDirectOrChannelMessage(payload: any, channel?: SecureChannel | any, remotePeer?: string): void;
  handleChannelSubscribe(payload: any, channel?: SecureChannel | any): void;
  handleChannelUnsubscribe(payload: any, channel?: SecureChannel | any): void;
  handleTyping(payload: any): void;
  handleUserOffline(payload: any, channel?: SecureChannel | any, remotePeer?: string): void;
  handleGossipDiscovery(payload: any, channel?: SecureChannel | any): void;
  forwardToChannelSubscribers(channelName: string, msg: any, exceptPeer?: string | null): void;
}
