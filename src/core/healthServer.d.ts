import net from 'node:net';
import { Database } from '../storage/database.d.ts';
import { FederationEngine } from './federation.d.ts';
import { PeerManager } from './peerManager.d.ts';
import { HealthCheckResponse, HeartbeatStatusResponse } from '../types/protocol.d.ts';

export interface HealthServerOptions {
  port?: number;
  allowOuterHeartbeat?: boolean;
}

export class HealthServer {
  db: Database | null;
  federation: FederationEngine | null;
  peerManager: PeerManager | null;
  port: number;
  allowOuter: boolean;
  host: string;
  server: net.Server | null;
  sockets: Set<net.Socket>;
  startTime: number;

  constructor(
    db?: Database | null,
    federation?: FederationEngine | null,
    peerManager?: PeerManager | null,
    options?: HealthServerOptions
  );

  start(): Promise<void>;
  handleConnection(socket: net.Socket): void;
  getHealthData(): HealthCheckResponse;
  getStatusData(): HeartbeatStatusResponse;
  close(): void;
}
