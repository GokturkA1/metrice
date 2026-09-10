/// <reference types="node" />

export class SshPacketReader {
  buffer: Buffer;
  offset: number;
  readonly remaining: number;

  constructor(buffer: Buffer);

  readByte(): number;
  readBoolean(): boolean;
  readUInt32(): number;
  readString(encoding?: BufferEncoding): string;
  readBuffer(): Buffer;
  readMpint(): Buffer;
  readNameList(): string[];
}

export class SshPacketWriter {
  buffer: Buffer;
  offset: number;

  constructor(initialSize?: number);

  ensureCapacity(bytesNeeded: number): void;
  writeByte(val: number): this;
  writeBoolean(val: boolean): this;
  writeUInt32(val: number): this;
  writeRaw(buf: Buffer): this;
  writeBuffer(buf: Buffer): this;
  writeString(str: string, encoding?: BufferEncoding): this;
  writeMpint(buf: Buffer): this;
  writeNameList(list: string[]): this;
  toBuffer(): Buffer;
}
