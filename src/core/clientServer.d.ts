/// <reference types="node" />
import type { Server, Socket } from 'node:net';
import { TerminalSession } from './terminalSession.d.ts';

export class ClientServer {
  db: any;
  federation: any;
  sessions: Map<string, TerminalSession>;
  commands: any;
  server: Server | null;

  constructor(db: any, federation: any);

  updateTargetMigration(canonicalUser: string): void;
  initFederationListeners(): void;
  getLocalOnlineUsers(): string[];
  getLocalMemberships(): string[];
  findLocalSession(address: string): TerminalSession | null;
  notifyAllSessionsRender(): void;
  getSystemStats(): any;
  start(port?: number): Promise<void>;
  close(): Promise<void>;
}
