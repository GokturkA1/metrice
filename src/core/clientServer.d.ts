/// <reference types="node" />
import type { Server } from 'node:net';
import { TerminalSession } from './terminalSession.d.ts';

export * from './telnetClientConnection.d.ts';

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
  getLocalMemberships(): any[];
  getOnlineUsers(): string[];
  getChannelMembers(target: string): string[];
  getCurrentConversation(userAddress: string, activeTarget: string, systemLogs: any[]): any[];
  findLocalSession(address: string): TerminalSession | null;
  notifyAllSessionsRender(): void;
  handleOutboundMessage(
    session: TerminalSession,
    from: string,
    to: string,
    content: string,
    isAction?: boolean,
    isSnippet?: boolean
  ): Promise<void>;
  start(port?: number): void;
  close(): void;
}
