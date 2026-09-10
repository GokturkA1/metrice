import { LogLevel } from '../utils/logger.d.ts';
import { MeshRole } from '../types/protocol.d.ts';

export interface AppConfig {
  version: string;
  defaultSshServerVersion: string;
  serverName: string;
  clientPort: number;
  sshPort: number;
  federationPort: number;
  publicFederationPort: number;
  publicSshPort: number;
  publicClientPort: number;
  defaultFedPort: number;
  sshServerVersion: string;
  meshRole: MeshRole | string;
  bootstrapPeers: string[];
  maxRendezvousTunnels: number;
  rendezvousKeepaliveInterval: number;
  presenceTtl: number;
  circuitTtl: number;
  uniformCellSize: number;
  secureBufferLimit: number;
  trustProxy: boolean;
  useProxyProtocol: boolean;
  proxyProtocolTrustedIps: string[];
  allowEdgeRouting: boolean;
  allowEdgeGossip: boolean;
  maxEdgeRendezvousRelays: number;
  strictPq: boolean;
  environment: string;
  locale: string;
  dbFile: string;
  peerCacheFile: string;
  logLevel: LogLevel | string;
}

export const CONFIG: AppConfig;
