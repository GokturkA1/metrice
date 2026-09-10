/**
 * Metrice P2P-Mesh Protokol ve Tip Tanimlari
 */

export type NodeId = string;
export type UserAddress = `@${string}:${string}.mesh` | `@${string}`;
export type ChannelAddress = `#${string}:${string}.mesh` | `#${string}`;
export type MeshRole = 'RELAY' | 'EDGE' | 'CAP_EDGE_TRANSIT';

export interface HandshakeInitPacket {
  type: 'HANDSHAKE_INIT';
  nodeAddress: string;
  identityPublicKey: string;
  kemPublicKey: string;
  nonce: string;
  sig: string;
  strictPq?: boolean;
  role?: MeshRole;
}

export interface HandshakeReplyPacket {
  type: 'HANDSHAKE_REPLY';
  nodeAddress: string;
  identityPublicKey: string;
  kemCiphertext: string;
  nonce: string;
  sig: string;
  observedAddress?: string;
  observedPort?: number;
  status: 'ok' | 'rejected';
  role?: MeshRole;
}

export interface DialbackRequestPacket {
  type: 'DIALBACK_REQUEST';
  targetPort: number;
  nonce: string;
}

export interface DialbackConfirmPacket {
  type: 'DIALBACK_CONFIRM';
  nonce: string;
  confirmed: boolean;
  observedIp?: string;
}

export interface RendezvousBindPacket {
  type: 'RENDEZVOUS_BIND';
  nodeId: string;
  identityPublicKey: string;
  timestamp: number;
  nonce: string;
  sig: string;
}

export interface RendezvousAckPacket {
  type: 'RENDEZVOUS_ACK';
  status: 'ok' | 'error';
  relayNodeId: string;
  error?: string;
}

export interface PresenceAnnouncePacket {
  type: 'PRESENCE_ANNOUNCE';
  nodeId: string;
  nodeAddress: string;
  timestamp: number;
  onlineUsers?: string[];
  subscribedChannels?: string[];
  sig: string;
  status?: string;
}

export interface UserOfflinePacket {
  type: 'USER_OFFLINE';
  user: string;
  nodeId: string;
  timestamp: number;
  sig: string;
}

export interface OnionCellPacket {
  type: 'ONION_CELL';
  circuitId: string;
  iv: string;
  authTag: string;
  ciphertext: string;
  pad?: string;
}

export interface EncryptedFramePacket {
  type: 'ENCRYPTED_FRAME';
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface DirectMessagePacket {
  type: 'DIRECT_MESSAGE';
  from: string;
  to: string;
  content: string;
  timestamp: number;
  messageId: string;
  sig?: string;
}

export interface ChannelMessagePacket {
  type: 'CHANNEL_MESSAGE';
  from: string;
  channel: string;
  content: string;
  timestamp: number;
  messageId: string;
  sig?: string;
}

export type ProtocolPacket =
  | HandshakeInitPacket
  | HandshakeReplyPacket
  | DialbackRequestPacket
  | DialbackConfirmPacket
  | RendezvousBindPacket
  | RendezvousAckPacket
  | PresenceAnnouncePacket
  | UserOfflinePacket
  | OnionCellPacket
  | EncryptedFramePacket
  | DirectMessagePacket
  | ChannelMessagePacket;

export interface ParsedAddress {
  type: 'USER' | 'CHANNEL';
  raw: string;
  name: string;
  nodeId: string | null;
  host: string | null;
  port: number | null;
  isGlobalChannel?: boolean;
  isLocal: boolean;
}

export interface PeerInfo {
  nodeId: string;
  address: string;
  host?: string;
  port?: number;
  role: MeshRole;
  identityPublicKey?: string;
  kemPublicKey?: string;
  lastSeen: number;
  viaRendezvous?: boolean;
  rendezvousRelay?: string;
}
