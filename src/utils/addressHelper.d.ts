import { ParsedAddress } from '../types/protocol.d.ts';

export class AddressHelper {
  static USER_REGEX: RegExp;
  static NODE_ID_REGEX: RegExp;
  static localNodeId: string | null;

  static setLocalNodeId(nodeId: string): void;
  static getLocalNodeId(): string | null;
  static isValidUsername(username: string): boolean;
  static isValidNodeId(nodeId: string): boolean;
  static isGlobalChannel(target: string): boolean;
  static isSystemConsole(target: string): boolean;
  static canonicalizeIPv6(ip: string): string;
  static isPrivateOrLoopbackIP(ip: string): boolean;
  static parseTarget(target: string): { host: string; port: number } | null;
  static parse(addressString: string, contextNodeId?: string | null): ParsedAddress | null;
  static formatUser(username: string, nodeId?: string | null): string;
  static formatChannel(channelName: string, nodeId?: string | null): string;
  static getMeshDomain(nodeId: string): string;
}
