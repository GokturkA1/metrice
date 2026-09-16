import type { FederationEngine } from './federation.d.ts';
import type { SecureChannel } from './secureChannel.d.ts';

export class AutoNatService {
  federation: FederationEngine;
  dialbackRateLimit: Map<string, number>;
  activeDialbacks: number;
  maxConcurrentDialbacks: number;

  constructor(federation: FederationEngine);

  handleObservedAddress(observedAddress: string, peer: string): void;
  initiateDialback(targetIp: string): Promise<string>;
  handleDialbackConfirm(payload: any): void;
  handleDialbackRequest(payload: any, channel: SecureChannel): void;
}
