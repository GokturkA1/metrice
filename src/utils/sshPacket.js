import { I18n } from '../locales/i18n.js';

export class SshPacketReader {
  constructor(buffer) {
    this.buffer = buffer;
    this.offset = 0;
  }

  get remaining() {
    return this.buffer.length - this.offset;
  }

  readByte() {
    const val = this.buffer.readUInt8(this.offset);
    this.offset += 1;
    return val;
  }

  readBoolean() {
    return this.readByte() !== 0;
  }

  readUInt32() {
    const val = this.buffer.readUInt32BE(this.offset);
    this.offset += 4;
    return val;
  }

  readString(encoding = 'utf8') {
    const len = this.readUInt32();
    if (this.offset + len > this.buffer.length) {
      throw new Error(I18n.t('SSH_BUFFER_OVERFLOW', { target: 'string' }));
    }
    const str = this.buffer.toString(encoding, this.offset, this.offset + len);
    this.offset += len;
    return str;
  }

  readBuffer() {
    const len = this.readUInt32();
    if (this.offset + len > this.buffer.length) {
      throw new Error(I18n.t('SSH_BUFFER_OVERFLOW', { target: 'buffer' }));
    }
    const buf = this.buffer.subarray(this.offset, this.offset + len);
    this.offset += len;
    return buf;
  }

  readMpint() {
    return this.readBuffer();
  }

  readNameList() {
    const raw = this.readString('ascii');
    return raw ? raw.split(',') : [];
  }
}

export class SshPacketWriter {
  constructor(initialSize = 512) {
    this.buffer = Buffer.alloc(initialSize);
    this.offset = 0;
  }

  ensureCapacity(bytesNeeded) {
    if (this.offset + bytesNeeded > this.buffer.length) {
      let nextSize = this.buffer.length * 2;
      while (this.offset + bytesNeeded > nextSize) {
        nextSize *= 2;
      }
      const nextBuf = Buffer.alloc(nextSize);
      this.buffer.copy(nextBuf);
      this.buffer = nextBuf;
    }
  }

  writeByte(val) {
    this.ensureCapacity(1);
    this.buffer.writeUInt8(val, this.offset);
    this.offset += 1;
    return this;
  }

  writeBoolean(val) {
    return this.writeByte(val ? 1 : 0);
  }

  writeUInt32(val) {
    this.ensureCapacity(4);
    this.buffer.writeUInt32BE(val, this.offset);
    this.offset += 4;
    return this;
  }

  writeRaw(buf) {
    this.ensureCapacity(buf.length);
    buf.copy(this.buffer, this.offset);
    this.offset += buf.length;
    return this;
  }

  writeBuffer(buf) {
    this.ensureCapacity(4 + buf.length);
    this.writeUInt32(buf.length);
    buf.copy(this.buffer, this.offset);
    this.offset += buf.length;
    return this;
  }

  writeString(str, encoding = 'utf8') {
    const strBuf = Buffer.from(str, encoding);
    return this.writeBuffer(strBuf);
  }

  writeMpint(buf) {
    let raw = buf;
    if (raw.length === 0 || (raw[0] & 0x80) !== 0) {
      const padded = Buffer.alloc(raw.length + 1);
      padded[0] = 0x00;
      raw.copy(padded, 1);
      raw = padded;
    }
    return this.writeBuffer(raw);
  }

  writeNameList(list) {
    return this.writeString(list.join(','), 'ascii');
  }

  toBuffer() {
    return this.buffer.subarray(0, this.offset);
  }
}