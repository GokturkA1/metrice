import type { TerminalSession } from './terminalSession.d.ts';
import type { ClientServer } from './clientServer.d.ts';
import type { Socket } from 'node:net';

export class SessionInputHandler {
  static handlePaste(
    session: TerminalSession,
    clientServer: ClientServer,
    userAddress: string,
    action: { type: string; content?: string }
  ): Promise<void>;

  static handleAction(
    action: { type: string; char?: string; content?: string; width?: number; height?: number },
    session: TerminalSession,
    clientServer: ClientServer,
    userAddress: string,
    socket?: Socket | any,
    db?: any
  ): Promise<void>;
}
