import { Buffer } from 'node:buffer';

/**
 * HAProxy PROXY Protocol (v1 Text & v2 Binary) Ayrıştırıcı Ara Yazılımı
 * Sıfır harici bağımlılık ile Layer 4 TCP ters vekil sunucuları (HAProxy, Nginx Stream, AWS NLB)
 * arkasındaki gerçek istemci IP ve portunu (realRemoteAddress, realRemotePort) çözer.
 */
export class ProxyProtocolParser {
  // PROXY v2 12-baytlık ikili sihirli başlık imzası
  static V2_MAGIC = Buffer.from([
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
  ]);

  static V2_SIGNATURE = Buffer.from([
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
  ]);

  static V1_PREFIX = Buffer.from('PROXY ');

  /**
   * Tamponu PROXY v1 veya v2 protokolüne göre ayrıştırır ve sonuç döner
   * @param {Buffer} buf
   * @param {string} [remoteIp='127.0.0.1']
   * @param {string[]} [trustedIps=['127.0.0.1']]
   */
  static parse(buf, remoteIp = '127.0.0.1', trustedIps = ['127.0.0.1']) {
    const res = ProxyProtocolParser.parseBuffer(buf, remoteIp, trustedIps);
    const isV2 = buf && buf.length >= 12 && buf.subarray(0, 12).equals(ProxyProtocolParser.V2_MAGIC);
    const isV1 = buf && buf.length >= 6 && buf.subarray(0, 6).equals(ProxyProtocolParser.V1_PREFIX);
    return {
      ...res,
      success: res.status === 'OK',
      version: isV2 ? 2 : (isV1 ? 1 : null)
    };
  }

  /**
   * IPv6 16-baytlık bellek dilimini standart formatta hex string'e çevirir
   * @param {Buffer} buf 
   * @param {number} offset 
   * @returns {string}
   */
  static formatIPv6(buf, offset) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(buf.readUInt16BE(offset + i).toString(16));
    }
    return parts.join(':');
  }

  /**
   * Tamponu PROXY v1 veya v2 protokolüne göre ayrıştırır
   * @param {Buffer} buf
   * @param {string} remoteIp
   * @param {string[]} trustedIps
   * @returns {{ status: 'OK'|'NEED_MORE'|'REJECT'|'PASSTHROUGH', realRemoteAddress?: string, realRemotePort?: number, remainder?: Buffer, reason?: string }}
   */
  static parseBuffer(buf, remoteIp, trustedIps = []) {
    const cleanRemote = (remoteIp || '').replace(/^::ffff:/, '');
    const isTrusted = trustedIps.includes(cleanRemote);

    // Başlık adaylığı kontrolleri
    const isV1Possible = buf.length >= 6 && buf.subarray(0, 6).equals(ProxyProtocolParser.V1_PREFIX);
    const isV2Possible = buf.length >= 12 && buf.subarray(0, 12).equals(ProxyProtocolParser.V2_MAGIC);

    // Kısmi tampon kontrolleri (henüz ilk baytlar tamamlanmamış olabilir)
    if (buf.length < 6 && ProxyProtocolParser.V1_PREFIX.subarray(0, buf.length).equals(buf)) {
      return { status: 'NEED_MORE' };
    }
    if (buf.length < 12 && ProxyProtocolParser.V2_MAGIC.subarray(0, buf.length).equals(buf)) {
      return { status: 'NEED_MORE' };
    }

    // IP Spoofing Koruması: Yetkisiz bir IP PROXY başlığı göndermeye kalkarsa bağlantıyı anında düşür
    if (isV1Possible || isV2Possible) {
      if (!isTrusted) {
        return { status: 'REJECT', reason: 'untrusted_proxy_header_spoof' };
      }
    }

    // --- PROXY v1 (US-ASCII Text) ---
    if (isV1Possible) {
      const crlfIdx = buf.indexOf('\r\n');
      if (crlfIdx === -1) {
        if (buf.length > 107) {
          return { status: 'REJECT', reason: 'v1_header_exceeds_max_length' };
        }
        return { status: 'NEED_MORE' };
      }

      const line = buf.subarray(0, crlfIdx).toString('ascii');
      const remainder = buf.subarray(crlfIdx + 2);
      const tokens = line.split(' ');

      if (tokens[1] === 'UNKNOWN') {
        return {
          status: 'OK',
          realRemoteAddress: cleanRemote,
          realRemotePort: 0,
          remainder
        };
      }

      if ((tokens[1] === 'TCP4' || tokens[1] === 'TCP6') && tokens.length >= 6) {
        const srcIp = tokens[2];
        const srcPort = parseInt(tokens[4], 10);
        if (!srcIp || isNaN(srcPort)) {
          return { status: 'REJECT', reason: 'v1_invalid_address_or_port' };
        }
        return {
          status: 'OK',
          realRemoteAddress: srcIp,
          realRemotePort: srcPort,
          remainder
        };
      }

      return { status: 'REJECT', reason: 'v1_unsupported_protocol_token' };
    }

    // --- PROXY v2 (Binary) ---
    if (isV2Possible) {
      if (buf.length < 16) {
        return { status: 'NEED_MORE' };
      }

      const verCmd = buf[12];
      const ver = (verCmd >> 4) & 0x0F;
      const cmd = verCmd & 0x0F;

      if (ver !== 2) {
        return { status: 'REJECT', reason: 'v2_unsupported_version' };
      }

      const famProto = buf[13];
      const fam = (famProto >> 4) & 0x0F;
      const length = buf.readUInt16BE(14);
      const totalHeaderLength = 16 + length;

      if (buf.length < totalHeaderLength) {
        return { status: 'NEED_MORE' };
      }

      const remainder = buf.subarray(totalHeaderLength);

      // cmd 0x00 = LOCAL (vekilin doğrudan kendi sağlık denetimi / doğrudan bağlantısı)
      if (cmd === 0x00) {
        return {
          status: 'OK',
          realRemoteAddress: cleanRemote,
          realRemotePort: 0,
          remainder
        };
      }

      // cmd 0x01 = PROXY (arkasındaki istemcinin IP/port bilgisi)
      if (cmd === 0x01) {
        if (fam === 0x01) {
          // AF_INET (IPv4) - 12 bayt adres bloğu
          if (length < 12) {
            return { status: 'REJECT', reason: 'v2_ipv4_address_block_short' };
          }
          const srcIp = `${buf[16]}.${buf[17]}.${buf[18]}.${buf[19]}`;
          const srcPort = buf.readUInt16BE(24);
          return {
            status: 'OK',
            realRemoteAddress: srcIp,
            realRemotePort: srcPort,
            remainder
          };
        } else if (fam === 0x02) {
          // AF_INET6 (IPv6) - 36 bayt adres bloğu
          if (length < 36) {
            return { status: 'REJECT', reason: 'v2_ipv6_address_block_short' };
          }
          const srcIp = ProxyProtocolParser.formatIPv6(buf, 16);
          const srcPort = buf.readUInt16BE(48);
          return {
            status: 'OK',
            realRemoteAddress: srcIp,
            realRemotePort: srcPort,
            remainder
          };
        } else {
          // AF_UNSPEC veya diğer protokoller
          return {
            status: 'OK',
            realRemoteAddress: cleanRemote,
            realRemotePort: 0,
            remainder
          };
        }
      }

      return { status: 'REJECT', reason: 'v2_invalid_command' };
    }

    // PROXY başlığı içermeyen doğrudan bağlantı (Doğrudan geçiş)
    return {
      status: 'PASSTHROUGH',
      remainder: buf
    };
  }

  /**
   * Soket üzerinde PROXY protokolünü şeffaf bir şekilde işler.
   * Çözümleme bittiğinde socket.realRemoteAddress ve socket.realRemotePort alanlarını atar,
   * kalan veriyi sokete unshift edip geri arama (callback) fonksiyonunu çağırır.
   * 
   * @param {import('node:net').Socket} socket
   * @param {object} options
   * @param {string[]} [options.trustedIps]
   * @param {number} [options.timeoutMs]
   * @param {function(Error|null, import('node:net').Socket): void} callback
   */
  static handle(socket, options = {}, callback) {
    const rawTrusted = options.trustedIps || ['127.0.0.1', '::1'];
    const trustedIps = rawTrusted.map((ip) => String(ip).trim().replace(/^::ffff:/, ''));
    const timeoutMs = options.timeoutMs || 3000;

    let buffer = Buffer.alloc(0);
    let finished = false;

    const cleanup = () => {
      finished = true;
      if (timer) clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
    };

    const onError = (err) => {
      if (!finished) {
        cleanup();
        if (typeof callback === 'function') callback(err, socket);
      }
    };

    const onClose = () => {
      if (!finished) {
        cleanup();
      }
    };

    const timer = setTimeout(() => {
      if (!finished) {
        cleanup();
        socket.destroy();
        if (typeof callback === 'function') {
          callback(new Error('PROXY protocol handshake timeout'), socket);
        }
      }
    }, timeoutMs);

    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const remoteIp = socket.remoteAddress || '';
      const res = ProxyProtocolParser.parseBuffer(buffer, remoteIp, trustedIps);

      if (res.status === 'NEED_MORE') {
        if (buffer.length > 4096) {
          cleanup();
          socket.destroy();
          if (typeof callback === 'function') {
            callback(new Error('PROXY protocol header size overflow'), socket);
          }
        }
        return;
      }

      if (res.status === 'REJECT') {
        cleanup();
        socket.destroy();
        if (typeof callback === 'function') {
          callback(new Error(`PROXY protocol rejected: ${res.reason || 'untrusted'}`), socket);
        }
        return;
      }

      cleanup();

      if (res.status === 'OK') {
        socket.realRemoteAddress = res.realRemoteAddress;
        socket.realRemotePort = res.realRemotePort;
        if (res.remainder && res.remainder.length > 0) {
          socket.unshift(res.remainder);
        }
      } else if (res.status === 'PASSTHROUGH') {
        socket.realRemoteAddress = socket.remoteAddress;
        socket.realRemotePort = socket.remotePort;
        if (buffer.length > 0) {
          socket.unshift(buffer);
        }
      }

      if (typeof callback === 'function') {
        callback(null, socket);
      }
    };

    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  }

  /**
   * Soket üzerinde PROXY protokolünü şeffaf bir şekilde işler (handle için kısayol).
   * @param {import('node:net').Socket} socket
   * @param {string[]|object} trustedIps
   * @param {function(Error|null, import('node:net').Socket): void} callback
   */
  static wrapSocket(socket, trustedIps, callback) {
    const opts = Array.isArray(trustedIps) ? { trustedIps } : (trustedIps || {});
    return ProxyProtocolParser.handle(socket, opts, callback);
  }
}
