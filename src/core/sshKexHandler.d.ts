import type { SshClientConnection } from './sshClientConnection.d.ts';
import type { SshPacketReader } from '../utils/sshPacket.d.ts';

export class SshKexHandler {
  static kemSpkiPrefix: Buffer | null;

  static deriveKey(conn: SshClientConnection, char: string, length: number): Buffer;
  static prepareKeys(conn: SshClientConnection): void;
  static handleKexInitMessage(conn: SshClientConnection, reader: SshPacketReader): void;
}
