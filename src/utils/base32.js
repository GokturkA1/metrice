/**
 * RFC 4648 Base32 Kodlayıcı ve Kod Çözücü
 * Harici bağımlılık barındırmayan saf JavaScript implementasyonu.
 */
export class Base32 {
  static ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

  /**
   * Bir buffer veya Uint8Array'i Base32 dizgisine kodlar (küçük harf, varsayılan olarak dolgusuz).
   * @param {Buffer|Uint8Array} buffer 
   * @param {boolean} padding 
   * @returns {string}
   */
  static encode(buffer, padding = false) {
    if (!buffer || buffer.length === 0) return '';
    const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);

    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < buf.length; i++) {
      value = (value << 8) | buf[i];
      bits += 8;

      while (bits >= 5) {
        output += this.ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += this.ALPHABET[(value << (5 - bits)) & 31];
    }

    if (padding) {
      while (output.length % 8 !== 0) {
        output += '=';
      }
    }

    return output;
  }

  /**
   * Base32 dizgisini Buffer'a çözer.
   * @param {string} str 
   * @returns {Buffer}
   */
  static decode(str) {
    if (!str || typeof str !== 'string') return Buffer.alloc(0);
    const cleanStr = str.toLowerCase().replace(/=+$/, '');

    let bits = 0;
    let value = 0;
    const result = [];

    for (let i = 0; i < cleanStr.length; i++) {
      const idx = this.ALPHABET.indexOf(cleanStr[i]);
      if (idx === -1) continue;

      value = (value << 5) | idx;
      bits += 5;

      if (bits >= 8) {
        result.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }

    return Buffer.from(result);
  }
}
