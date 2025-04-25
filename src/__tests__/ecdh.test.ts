import { ECDH, deriveSymmetricKey, deriveAESKeyFromECDH } from '../algorithms/ecdh';
import { KeyPair } from '../types/interfaces';

// Мокаем модуль 'crypto' для Node.js
const mockECDH = {
  generateKeys: jest.fn(),
  getPublicKey: jest.fn(() => Buffer.from('mockedPublicKey')),
  getPrivateKey: jest.fn(() => Buffer.from('mockedPrivateKey')),
  setPrivateKey: jest.fn(),
  computeSecret: jest.fn(() => Buffer.from('mockedSharedSecret')),
};

jest.mock('crypto', () => ({
  createECDH: jest.fn(() => mockECDH),
}));

// Мокаем @noble/hashes/hkdf и @noble/hashes/sha256
jest.mock('@noble/hashes/hkdf', () => ({
  hkdf: jest.fn(() => new Uint8Array(32)),
}));
jest.mock('@noble/hashes/sha256', () => ({
  sha256: jest.fn(),
}));

describe('ECDH', () => {
  let ecdh: ECDH;

  beforeEach(() => {
    ecdh = new ECDH();
    jest.clearAllMocks();
    // Эмулируем Node.js среду
    Object.defineProperty(global, 'window', { value: undefined, writable: true });
    Object.defineProperty(global, 'process', { value: { versions: { node: '16' } }, writable: true });
  });

  describe('generateKeyPair', () => {
    it('should generate a key pair in Node.js environment', async () => {
      const curve = 'P-256';
      const keyPair = await ecdh.generateKeyPair({ curve });

      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('privateKey');
      expect(require('crypto').createECDH).toHaveBeenCalledWith('prime256v1');
      expect(mockECDH.generateKeys).toHaveBeenCalled();
    });

    it('should throw an error for unsupported curve', async () => {
      const curve = 'invalid-curve';
      await expect(ecdh.generateKeyPair({ curve })).rejects.toThrow(
        `Unsupported ECDH curve: ${curve}. Supported curves: P-256, P-384, P-521`
      );
    });

    it('should throw an error if crypto API is unavailable', async () => {
      Object.defineProperty(global, 'process', { value: undefined, writable: true });
      await expect(ecdh.generateKeyPair()).rejects.toThrow(
        'Crypto API is not available in this environment'
      );
    });
  });

  describe('deriveSharedSecret', () => {
    it('should derive shared secret in Node.js environment', async () => {
      const privateKey = new Uint8Array(32);
      const peerPublicKey = new Uint8Array(65);
      const curve = 'P-256';
      const sharedSecret = await ecdh.deriveSharedSecret(privateKey, peerPublicKey, curve);

      expect(sharedSecret).toBeInstanceOf(Uint8Array);
      expect(require('crypto').createECDH).toHaveBeenCalledWith('prime256v1');
      expect(mockECDH.setPrivateKey).toHaveBeenCalledWith(Buffer.from(privateKey));
      expect(mockECDH.computeSecret).toHaveBeenCalledWith(Buffer.from(peerPublicKey));
    });

    it('should throw an error for unsupported curve', async () => {
      const privateKey = new Uint8Array(32);
      const peerPublicKey = new Uint8Array(65);
      const curve = 'invalid-curve';
      await expect(ecdh.deriveSharedSecret(privateKey, peerPublicKey, curve)).rejects.toThrow(
        `Unsupported ECDH curve: ${curve}. Supported curves: P-256, P-384, P-521`
      );
    });

    it('should throw an error if crypto API is unavailable', async () => {
      Object.defineProperty(global, 'process', { value: undefined, writable: true });
      const privateKey = new Uint8Array(32);
      const peerPublicKey = new Uint8Array(65);
      await expect(ecdh.deriveSharedSecret(privateKey, peerPublicKey)).rejects.toThrow(
        'Crypto API is not available in this environment'
      );
    });
  });

  describe('deriveSymmetricKey', () => {
    it('should derive a symmetric key using HKDF', () => {
      const sharedSecret = new Uint8Array(32);
      const salt = new Uint8Array(16);
      const info = new Uint8Array(8);
      const length = 32;
      const key = deriveSymmetricKey(sharedSecret, salt, info, length);

      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(length);
      expect(require('@noble/hashes/hkdf').hkdf).toHaveBeenCalled();
    });

    it('should throw an error for invalid key length', () => {
      const sharedSecret = new Uint8Array(32);
      const length = 0;
      expect(() => deriveSymmetricKey(sharedSecret, undefined, undefined, length)).toThrow(
        `Invalid key length: ${length}. Must be a positive number.`
      );
    });
  });

  describe('deriveAESKeyFromECDH', () => {
    it('should derive an AES key from ECDH shared secret', async () => {
      const privateKey = new Uint8Array(32);
      const peerPublicKey = new Uint8Array(65);
      const curve = 'P-256';
      const salt = new Uint8Array(16);
      const info = new Uint8Array(8);
      const keyLength = 32;
      const key = await deriveAESKeyFromECDH(privateKey, peerPublicKey, curve, salt, info, keyLength);

      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(keyLength);
      expect(mockECDH.computeSecret).toHaveBeenCalled();
      expect(require('@noble/hashes/hkdf').hkdf).toHaveBeenCalled();
    });

    it('should throw an error for invalid key length', async () => {
      const privateKey = new Uint8Array(32);
      const peerPublicKey = new Uint8Array(65);
      const keyLength = -1;
      await expect(deriveAESKeyFromECDH(privateKey, peerPublicKey, 'P-256', undefined, undefined, keyLength)).rejects.toThrow(
        `Invalid key length: ${keyLength}. Must be a positive number.`
      );
    });
  });

  describe('end-to-end key exchange', () => {
    it('should generate key pairs and derive matching shared secrets', async () => {
      jest.unmock('crypto');
      jest.unmock('@noble/hashes/hkdf');
      jest.unmock('@noble/hashes/sha256');

      const ecdh1 = new ECDH();
      const ecdh2 = new ECDH();
      const curve = 'P-256';

      const keyPair1 = await ecdh1.generateKeyPair({ curve });
      const keyPair2 = await ecdh2.generateKeyPair({ curve });

      const sharedSecret1 = await ecdh1.deriveSharedSecret(keyPair1.privateKey, keyPair2.publicKey, curve);
      const sharedSecret2 = await ecdh2.deriveSharedSecret(keyPair2.privateKey, keyPair1.publicKey, curve);

      expect(sharedSecret1).toEqual(sharedSecret2);

      const aesKey1 = await deriveAESKeyFromECDH(keyPair1.privateKey, keyPair2.publicKey, curve);
      const aesKey2 = await deriveAESKeyFromECDH(keyPair2.privateKey, keyPair1.publicKey, curve);

      expect(aesKey1).toEqual(aesKey2);
    });
  });
});