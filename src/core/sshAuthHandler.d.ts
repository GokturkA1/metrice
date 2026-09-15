import type { SshClientConnection } from './sshClientConnection.d.ts';
import type { SshPacketReader } from '../utils/sshPacket.d.ts';

export class SshAuthHandler {
  static handleUserAuth(conn: SshClientConnection, reader: SshPacketReader, rawPayload: Buffer): Promise<void>;
}
