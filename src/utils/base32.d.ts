/// <reference types="node" />

export class Base32 {
  static ALPHABET: string;
  static encode(buffer: Buffer | Uint8Array, padding?: boolean): string;
  static decode(str: string): Buffer;
}
