/// <reference types="node" />
import type { Server } from 'node:net';
import type { SshHostKey, SshServerOptions } from './sshClientConnection.d.ts';

export * from './sshClientConnection.d.ts';

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
