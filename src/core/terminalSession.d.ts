/// <reference types="node" />
import { EventEmitter } from 'node:events';
import type { Socket } from 'node:net';

export interface SystemLogEntry {
  from: string;
  content: string;
  timestamp: string;
}

export interface UserProfile {
  contacts?: string[];
  history?: string[];
  publicKey?: string;
  publicKeys?: string[];
}

export class TerminalSession extends EventEmitter {
  socket: Socket;
  userAddress: string;
  userNick: string;
  activeTarget: string;
  contacts: string[];
  history: string[];
  systemLogs: SystemLogEntry[];
  width: number;
  height: number;
  isSsh: boolean;
  isSecureE2EE: boolean;

  constructor(
    socket: Socket,
    userAddress: string,
    initialProfile: UserProfile | null,
    getOnlineUsersFn: () => any[],
    getChannelMembersFn?: ((channel: string) => any[]) | null,
    onProfileChangeFn?: ((contacts: string[], history: string[]) => void) | null,
    getSystemStatsFn?: (() => any) | null,
    getKnownCommandsFn?: (() => any) | null
  );

  isUserMentioned(content: string): boolean;
  isMemberOf(target: string): boolean;
  isViewingTarget(target: string): boolean;
  getMyChannels(): string[];
  notifyProfileChange(): void;
  resize(width?: number, height?: number): void;
  addContact(target: string): void;
  removeContact(target: string): void;
  setTarget(target: string): void;
  addSystemLog(content: string): void;
  render(messages?: any[]): void;
  handleAction(action: any): void;
  destroy(): void;
}
