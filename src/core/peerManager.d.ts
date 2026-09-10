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

  constructor(storagePath: string | null);

  isSelfAddress(host: string, port: number): boolean;
  loadPeers(): void;
  savePeers(): void;
  addOrUpdate(peerAddr: string, success?: boolean): void;
  getRandomSample(k?: number): string[];
  getAllPeers(): string[];
  startLanDiscovery(): void;
  sendBeacon(): void;
  close(): void;
}
