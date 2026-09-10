/// <reference types="node" />
import type { KeyPairSyncResult, KeyObject } from 'node:crypto';

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
}

export interface KemEncapsulationResult {
  sharedSecret: Buffer;
  encapsulatedKey: string;
}

export interface KeyPairPem {
  publicKey: string;
  privateKey: string;
}

export interface ValidatedOpenSshKey {
  algo: 'ssh-ed25519';
  rawKey: Buffer;
  saltPart: Buffer;
  base64: string;
  fingerprint: string;
}

export class CryptoHelper {
  static AES_ALGO: string;
  static IV_LENGTH: number;
  static AUTH_TAG_LENGTH: number;
  static KEM_ALGO: string;
  static HAS_ML_KEM: boolean;
  static SENTINEL_TEXT: string;

  static verifyQuantumSafePosture(): boolean;
  static generateIdentityKeyPair(): KeyPairPem;
  static deriveNodeId(publicKeyPemOrDer: string | Buffer | KeyObject): string;
  static sign(content: string | object, privateKeyPem: string): string;
  static verify(content: string | object, signatureBase64: string, publicKeyPem: string): boolean;

  static deriveVaultSeed(passphrase: string, clientRawPub: Buffer, nodeAddress: string): Buffer;
  static createVaultAuthToken(seedBuffer: Buffer): EncryptedPayload;
  static verifyVaultAuthToken(tokenEncrypted: EncryptedPayload, seedBuffer: Buffer): boolean;
  static deriveDeterministicX25519(seed32: Buffer | Uint8Array): KeyPairPem;

  static generateKemKeyPair(): KeyPairPem;
  static encapsulateKey(remotePublicKeyPem: string): KemEncapsulationResult;
  static decapsulateKey(privateKeyPem: string, encapsulatedKeyBase64: string): Buffer;
  static normalizeKey(key: Buffer | ArrayBuffer | ArrayBufferView | string): Buffer;
  static deriveKey(sharedSecret: Buffer, salt?: string | Buffer, info?: string): Buffer;

  static encrypt(plaintext: string, keyBuffer: Buffer | string): EncryptedPayload;
  static decrypt(payload: EncryptedPayload, keyBuffer: Buffer | string): string | null;

  static parseAndValidateOpenSshKey(keyString: string): ValidatedOpenSshKey;
  static hashPassword(password: string): Promise<string>;
  static verifyPassword(password: string, storedHash: string, clientRawPub?: Buffer | string | null, nodeAddress?: string): Promise<boolean>;
  static generateRandomKey(bytes?: number): string;
}
