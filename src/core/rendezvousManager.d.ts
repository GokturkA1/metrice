import type { FederationEngine } from './federation.d.ts';
import type { SecureChannel } from './secureChannel.d.ts';

export class RendezvousManager {
  federation: FederationEngine;

  constructor(federation: FederationEngine);

  maintainRendezvousTunnels(): Promise<void>;
  bindToRendezvousRelay(relayAddr: string): Promise<boolean>;
  sendRendezvousHeartbeat(): void;
  handleRendezvousBind(payload: any, channel: SecureChannel): void;
}
