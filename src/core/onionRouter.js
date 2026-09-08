import EventEmitter from 'node:events';
import { CryptoHelper } from '../utils/cryptoHelper.js';
import { Logger } from '../utils/logger.js';
import { I18n } from '../locales/i18n.js';
import { CONFIG } from '../config/index.js';

const log = new Logger('ONION');

export const UNIFORM_CELL_SIZE = (CONFIG && CONFIG.uniformCellSize) || 2048;
export const MAX_ONION_PAYLOAD = 768;

export class OnionRouter extends EventEmitter {
  constructor({ federation, db, myIdentity, rendezvousTunnels }) {
    super();
    this.federation = federation;
    this.db = db;
    this.myIdentity = myIdentity;
    this.rendezvousTunnels = rendezvousTunnels;
    this.clientCircuits = new Map(); // circuitId -> { circuitId, hops, keys, createdAt }
    this.circuitTtl = (CONFIG && CONFIG.circuitTtl) || 600000; // 10 minutes
  }

  /**
   * ONION_CELL nesnesini tam UNIFORM_CELL_SIZE bayt (JSON formatında) olacak şekilde pad ile doldurur.
   */
  static getPaddedCellObject(cell) {
    const raw = {
      type: 'ONION_CELL',
      circuitId: cell.circuitId,
      iv: cell.iv,
      authTag: cell.authTag,
      ciphertext: cell.ciphertext,
      pad: ''
    };

    const initialLen = Buffer.byteLength(JSON.stringify(raw) + '\n', 'utf-8');
    const diff = UNIFORM_CELL_SIZE - initialLen;
    if (diff > 0) {
      raw.pad = '0'.repeat(diff);
    } else if (diff < 0) {
      log.warn(`Onion hücresi boyutu uniform sınırı aştı (${initialLen} > ${UNIFORM_CELL_SIZE})`);
    }
    return raw;
  }

  /**
   * ONION_CELL formatını tam UNIFORM_CELL_SIZE bayt (varsayılan 2048 bayt, trailing newline dahil) olacak şekilde biçimlendirir.
   */
  static formatPaddedCell(cell) {
    const raw = this.getPaddedCellObject(cell);
    return JSON.stringify(raw) + '\n';
  }

  /**
   * Soket veya güvenli kanal düzeyinde tutarlı önceki atlama (prevHop) kimliği üretir.
   */
  static getHopIdentifier(channel) {
    if (!channel) return 'unknown';
    if (channel.peerNodeAddress) return channel.peerNodeAddress;
    const remoteIp = channel.socket?.remoteAddress ? channel.socket.remoteAddress.replace(/^::ffff:/, '') : null;
    const remotePort = channel.socket?.remotePort;
    if (remoteIp && remotePort) {
      const formattedIp = remoteIp.includes(':') ? `[${remoteIp}]` : remoteIp;
      return `${formattedIp}:${remotePort}`;
    }
    return remoteIp || 'unknown';
  }

  /**
   * Belirtilen 1-3 RELAY düğümü boyunca teleskopik devre (telescoping circuit) kurar.
   * @param {Array<{ address: string, kemPublicKey: string, nodeId: string }>} hops
   * @param {string|null} targetNodeId
   */
  async buildCircuit(hops, targetNodeId = null) {
    if (!hops || hops.length === 0) {
      throw new Error('Circuit requires at least 1 relay hop');
    }

    const circuitId = CryptoHelper.generateRandomKey(16);
    const keys = [];
    const encKeys = [];

    for (let i = 0; i < hops.length; i++) {
      const hop = hops[i];
      if (!hop.kemPublicKey) {
        throw new Error(`Hop ${i} (${hop.address || hop.nodeId}) has no kemPublicKey`);
      }
      const { sharedSecret, encapsulatedKey } = CryptoHelper.encapsulateKey(hop.kemPublicKey);
      const symmetricKey = CryptoHelper.deriveKey(sharedSecret, circuitId, 'p2p-mesh-onion-v2');
      keys.push(symmetricKey);
      encKeys.push(encapsulatedKey);
    }

    // Teleskopik devre paketini içten dışa oluştur
    let currentPayload = null;

    for (let i = hops.length - 1; i >= 0; i--) {
      const isExit = i === hops.length - 1;
      const nextHopAddr = isExit ? null : hops[i + 1].address;

      if (isExit) {
        currentPayload = {
          type: i === 0 ? 'CIRCUIT_CREATE' : 'CIRCUIT_EXTEND',
          circuitId,
          encapsulatedKey: encKeys[i],
          nextHop: null,
          extendPayload: null
        };
      } else {
        const encryptedInner = CryptoHelper.encrypt(JSON.stringify(currentPayload), keys[i]);
        currentPayload = {
          type: i === 0 ? 'CIRCUIT_CREATE' : 'CIRCUIT_EXTEND',
          circuitId,
          encapsulatedKey: encKeys[i],
          nextHop: nextHopAddr,
          extendPayload: encryptedInner
        };
      }
    }

    // R1'e gönder
    const firstHop = hops[0];
    const [host, portStr] = firstHop.address.split(':');
    const port = parseInt(portStr, 10);

    const res = await this.federation.sendPacket(host, port, currentPayload);
    if (!res || res.status !== 'circuit_ready') {
      log.warn(`Circuit creation unacknowledged by Guard relay: ${firstHop.address}`);
    }

    const circuitRecord = {
      circuitId,
      hops,
      keys,
      targetNodeId: targetNodeId || null,
      createdAt: Date.now()
    };

    this.clientCircuits.set(circuitId, circuitRecord);
    return circuitRecord;
  }

  /**
   * Hedef NodeID için süresi dolmamış aktif devreyi getirir.
   * Süresi dolan devreleri temizler.
   */
  getActiveCircuitForTarget(targetNodeId) {
    if (!targetNodeId) return null;
    const now = Date.now();
    for (const [circuitId, circuit] of this.clientCircuits.entries()) {
      if (now - circuit.createdAt > this.circuitTtl) {
        this.clientCircuits.delete(circuitId);
        continue;
      }
      if (circuit.targetNodeId === targetNodeId) {
        return circuit;
      }
    }
    return null;
  }

  /**
   * İletim hatası veya sonlanma durumunda istemci devresini havuzdan siler.
   */
  removeClientCircuit(circuitId) {
    if (circuitId) {
      this.clientCircuits.delete(circuitId);
    }
  }

  /**
   * Belirtilen atlama adresini (Guard veya ara relay) kullanan tüm istemci devrelerini havuzdan siler.
   * @param {string} hopAddress
   */
  removeCircuitsForHop(hopAddress) {
    if (!hopAddress) return;
    for (const [circuitId, circuit] of this.clientCircuits.entries()) {
      if (circuit.hops && circuit.hops.some((h) => h.address === hopAddress)) {
        this.clientCircuits.delete(circuitId);
        log.debug(`Kopan soket ilişkili istemci devresi havuzdan düşürüldü: ${circuitId} (${hopAddress})`);
      }
    }
  }

  /**
   * Verilen devre üzerinden hedef NodeID'ye katmanlı şifreli ONION_CELL gönderir.
   */
  async sendOnionCell(circuit, targetNodeId, payload) {
    const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const payloadBytes = Buffer.byteLength(payloadStr, 'utf-8');
    if (payloadBytes > MAX_ONION_PAYLOAD) {
      throw new Error(`Onion payload boyutu MAX_ONION_PAYLOAD (${MAX_ONION_PAYLOAD}) sınırını aştı: ${payloadBytes} bayt`);
    }

    const { hops, keys, circuitId } = circuit;
    const numHops = hops.length;

    let innerCell = null;

    for (let i = numHops - 1; i >= 0; i--) {
      const key = keys[i];
      let layerData;

      if (i === numHops - 1) {
        // En iç katman (Exit / Rendezvous Relayı)
        layerData = {
          deliverTo: targetNodeId,
          payload
        };
      } else {
        // Ara katmanlar
        layerData = {
          forwardTo: hops[i + 1].address,
          cell: innerCell
        };
      }

      const enc = CryptoHelper.encrypt(JSON.stringify(layerData), key);
      innerCell = {
        circuitId,
        iv: enc.iv,
        authTag: enc.authTag,
        ciphertext: enc.ciphertext
      };
    }

    const guardHop = hops[0];
    const [host, portStr] = guardHop.address.split(':');
    const port = parseInt(portStr, 10);

    const channel = await this.federation.getOrCreateSecureChannel(host, port);
    const paddedObj = OnionRouter.getPaddedCellObject(innerCell);
    if (channel && typeof channel.writePayload === 'function') {
      channel.writePayload(paddedObj);
    } else if (channel && channel.socket) {
      channel.socket.write(JSON.stringify(paddedObj) + '\n');
    }

    return { status: 'onion_sent', circuitId };
  }

  /**
   * Gelen CIRCUIT_CREATE veya CIRCUIT_EXTEND paketini işler.
   */
  async handleCircuitSetup(payload, channel) {
    const { circuitId, encapsulatedKey, nextHop, extendPayload } = payload;
    if (!circuitId || !encapsulatedKey) {
      channel.writePayload({ status: 'error', reason: 'invalid_circuit_payload' });
      return;
    }

    try {
      const sharedSecret = CryptoHelper.decapsulateKey(
        this.myIdentity.kemKeyPair.privateKey,
        encapsulatedKey
      );
      const symmetricKey = CryptoHelper.deriveKey(sharedSecret, circuitId, 'p2p-mesh-onion-v2');

      const prevHop = OnionRouter.getHopIdentifier(channel);
      this.db.saveCircuit({
        circuitId,
        prevHop,
        nextHop: nextHop || null,
        symmetricKey,
        createdAt: Date.now()
      });

      log.info(`Devre atlaması kaydedildi: ${circuitId} (Önceki: ${prevHop}, Sonraki: ${nextHop || 'Exit'})`);

      if (nextHop && extendPayload) {
        // Sonraki atlamaya devreyi uzat
        const decryptedJson = CryptoHelper.decrypt(extendPayload, symmetricKey);
        if (!decryptedJson) {
          log.warn(`Devre uzatma paketi deşifre edilemedi: ${circuitId}`);
          channel.writePayload({ status: 'error', reason: 'extend_decrypt_failed' });
          return;
        }

        const nextExtendPayload = JSON.parse(decryptedJson);
        const [nextHost, nextPortStr] = nextHop.split(':');
        const nextPort = parseInt(nextPortStr, 10);

        const res = await this.federation.sendPacket(nextHost, nextPort, nextExtendPayload);
        if (res && res.status === 'circuit_ready') {
          channel.writePayload({ status: 'circuit_ready', circuitId });
        } else {
          channel.writePayload({ status: 'circuit_ready', circuitId, warn: 'next_hop_pending' });
        }
      } else {
        // Exit relay reached
        channel.writePayload({ status: 'circuit_ready', circuitId });
      }
    } catch (err) {
      log.error(`Devre kurulum hatası: ${err.message}`);
      channel.writePayload({ status: 'error', reason: err.message });
    }
  }

  /**
   * Gelen ONION_CELL paketini soyar ve yönlendirir veya teslim eder.
   */
  async handleOnionCell(cell, channel) {
    const { circuitId, iv, authTag, ciphertext } = cell;
    if (!circuitId || !iv || !authTag || !ciphertext) {
      log.warn('Geçersiz ONION_CELL çerçevesi alındı');
      return;
    }

    const prevHop = OnionRouter.getHopIdentifier(channel);
    const circuit = this.db.getCircuit(circuitId, prevHop);
    if (!circuit || !circuit.symmetricKey) {
      log.warn(`Bilinmeyen devre hücresi alındı, düşürülüyor: ${circuitId} (Önceki: ${prevHop})`);
      return;
    }

    const decryptedStr = CryptoHelper.decrypt({ iv, authTag, ciphertext }, circuit.symmetricKey);
    if (!decryptedStr) {
      log.warn(`Onion hücresi deşifre edilemedi (AuthTag hatası): ${circuitId}`);
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(decryptedStr);
    } catch (err) {
      log.warn(`Onion hücresi JSON hatası: ${err.message}`);
      return;
    }

    // 1. Ara Atlama: Sonraki Relay'e İlet
    if (parsed.forwardTo && parsed.cell) {
      const [nextHost, nextPortStr] = parsed.forwardTo.split(':');
      const nextPort = parseInt(nextPortStr, 10);

      try {
        const nextChannel = await this.federation.getOrCreateSecureChannel(nextHost, nextPort);
        const paddedObj = OnionRouter.getPaddedCellObject(parsed.cell);
        if (nextChannel && typeof nextChannel.writePayload === 'function') {
          nextChannel.writePayload(paddedObj);
        } else if (nextChannel && nextChannel.socket) {
          nextChannel.socket.write(JSON.stringify(paddedObj) + '\n');
        }
        log.debug(`Onion hücresi şifreli kanal ile iletildi -> ${parsed.forwardTo} (Devre: ${circuitId})`);
      } catch (err) {
        log.error(`Onion iletim hatası (${parsed.forwardTo}): ${err.message}`);
      }
      return;
    }

    // 2. Çıkış / Rendezvous Atlaması: Hedefe Teslim Et
    if (parsed.deliverTo && parsed.payload) {
      const targetNodeId = parsed.deliverTo;
      log.info(`Onion hücresi çıkış noktasına ulaştı. Hedef: ${targetNodeId}`);

      // Yerel hedef mi?
      if (targetNodeId === this.myIdentity.nodeId) {
        this.emit('deliver_local', parsed.payload);
        return;
      }

      // Rendezvous tersine tüneli var mı?
      const tunnel = this.rendezvousTunnels.get(targetNodeId);
      const isSocketWritable = !tunnel?.channel?.socket || tunnel.channel.socket.writable !== false;
      if (tunnel && tunnel.channel && isSocketWritable) {
        log.info(`Onion mesajı tersine tünel üzerinden teslim ediliyor -> NodeID: ${targetNodeId}`);
        if (typeof tunnel.channel.writePayload === 'function') {
          tunnel.channel.writePayload(parsed.payload);
        } else if (tunnel.channel.socket && typeof tunnel.channel.socket.write === 'function') {
          tunnel.channel.socket.write(JSON.stringify(parsed.payload) + '\n');
        }
        return;
      }

      log.warn(`Onion hücresi teslim edilemedi: ${targetNodeId} için aktif tersine tünel bulunamadı`);
    }
  }

  cleanupExpiredCircuits() {
    const now = Date.now();
    for (const [id, c] of this.clientCircuits.entries()) {
      if (now - c.createdAt > this.circuitTtl) {
        this.clientCircuits.delete(id);
      }
    }
  }
}
