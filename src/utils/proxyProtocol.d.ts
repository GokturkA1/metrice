/// <reference types="node" />
import type { Socket } from 'node:net';

export interface ProxyParseResult {
  status: 'OK' | 'REJECT' | 'PASSTHROUGH' | 'WAIT';
  success?: boolean;
  version?: 1 | 2 | null;
  realRemoteAddress?: string;
  realRemotePort?: number;
  reason?: string;
  remainder?: Buffer;
}

export interface ProxyHandleOptions {
  trustedIps?: string[];
  timeoutMs?: number;
}

export class ProxyProtocolParser {
  static V2_MAGIC: Buffer;
  static V2_SIGNATURE: Buffer;
  static V1_PREFIX: Buffer;

  static parse(buf: Buffer, remoteIp?: string, trustedIps?: string[]): ProxyParseResult;
  static formatIPv6(buf: Buffer, offset?: number): string;
  static parseBuffer(buf: Buffer, remoteIp?: string, trustedIps?: string[]): ProxyParseResult;
  static handle(
    socket: Socket,
    options: ProxyHandleOptions,
    callback: (err: Error | null, socket: Socket) => void
  ): void;
}
