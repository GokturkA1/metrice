/// <reference types="node" />
import { EventEmitter } from 'node:events';
import type { Server, Socket } from 'node:net';
import type { KeyObject } from 'node:crypto';
import { TerminalSession } from './terminalSession.d.ts';

export interface SshHostKey {
  privateKey: KeyObject;
  publicKey: KeyObject;
  rawEd25519Pub: Buffer;
}

export interface SshServerOptions {
  serverVersion?: string;
  banner?: string;
}

export class SshClientConnection extends EventEmitter {
  socket: Socket;
  hostKey: SshHostKey;
  db: any;
  clientServer: any;
  options: SshServerOptions;
  state: string;
  inBuffer: Buffer;
  clientVersion: string;
  serverVersion: string;
  session: TerminalSession | null;
  authenticatedUser: string | null;

  constructor(
    socket: Socket,
    hostKey: SshHostKey,
    db: any,
    clientServer: any,
    options?: SshServerOptions
  );

  sendPacket(payload: Buffer): void;
  cleanup(): void;
}

export class SshServer {
  db: any;
  clientServer: any;
  options: SshServerOptions;
  server: Server | null;
  hostKey: SshHostKey;

  constructor(db: any, clientServer: any, options?: SshServerOptions);

  start(port: number): void;
  close(): void;
}
