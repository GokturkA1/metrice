/// <reference types="node" />
import type { Socket as DgramSocket } from 'node:dgram';

export interface PeerMetadata {
  score: number;
  lastSeen: number;
  failures: number;
}

export class PeerManager {
  storagePath: string | null;
  peers: Map<string, PeerMetadata>;
  udpSocket: DgramSocket | null;
  broadcastPort: number;
  selfNodeAddress: string;
  publicIp: string | null;
  edgeIps: Set<string>;

  constructor(storagePath?: string | null);

  registerEdgeIp(ip: string): void;
  evictHost(host: string): void;
  isSelfAddress(host: string, port?: number | null): boolean;
  setPublicIp(ip: string): void;
  loadPeers(): void;
  savePeers(): void;
  addOrUpdate(peerAddr: string, success?: boolean, fromGossip?: boolean): void;
  getRandomSample(k?: number): string[];
  getAllPeers(): string[];
  startLanDiscovery(): void;
  sendBeacon(): void;
  close(): void;
}
