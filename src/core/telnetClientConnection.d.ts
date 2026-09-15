/// <reference types="node" />
import type { Socket } from 'node:net';
import type { ClientServer } from './clientServer.d.ts';
import { TerminalSession } from './terminalSession.d.ts';

export const TELNET: Record<string, number>;
export const AUTH_STATE: Record<string, string>;

export class TelnetClientConnection {
  socket: Socket;
  clientServer: ClientServer;
  clientAddr: string;
  authState: string;
  targetUserAddress: string | null;
  userAddress: string | null;
  session: TerminalSession | null;

  constructor(socket: Socket, clientServer: ClientServer);

  sendHandshakeAndSizeQuery(): void;
  completeLogin(): Promise<void>;
  initSocket(): void;
  handleAuthInput(action: any): Promise<void>;
  handlePaste(action: any): Promise<void>;
  handleSessionInput(action: any): Promise<void>;
}
