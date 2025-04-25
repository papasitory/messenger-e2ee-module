import { Ed25519 } from '../algorithms/ed25519';
import { KeyPair } from '../types/interfaces';

// Мокаем модуль 'crypto' для Node.js
const mockCrypto = {
  generateKeyPairSync: jest.fn(() => ({
    publicKey: Buffer.from('mockedPublicKey'),
    privateKey: Buffer.from('mockedPrivateKey'),
  })),
  createPrivateKey: jest.fn(() => ({})),
  createPublicKey: jest.fn(() => ({})),
  sign: jest.fn(() => Buffer.from('mockedSignature')),
  verify: jest.fn(() => true),
};

jest.mock('crypto', () => mockCrypto);

// Мокаем window.crypto.subtle для браузерной среды (опционально, для минимального покрытия)
const mockCryptoSubtle = {
  generateKey: jest.fn(),
  exportKey: jest.fn(),
  importKey: jest.fn(),
  sign: jest.fn(),
  verify: jest.fn(),
};

describe('Ed25519', () => {
  let ed25519: Ed25519;

  beforeEach(() => {
    ed25519 = new Ed25519();
    jest.clearAllMocks();
    // Эмулируем Node.js среду
    Object.defineProperty(global, 'window', { value: undefined, writable: true });
    Object.defineProperty(global, 'process', { value: { versions: { node: '16' } }, writable: true });
  });

  describe('generateKeyPair', () => {
    it('should generate a key pair in Node.js environment', async () => {
      const keyPair = await ed25519.generateKeyPair();

      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('privateKey');
      expect(mockCrypto.generateKeyPairSync).toHaveBeenCalledWith('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      });
    });

    it('should throw an error if crypto API is unavailable', async () => {
      Object.defineProperty(global, 'process', { value: undefined, writable: true });
      await expect(ed25519.generateKeyPair()).rejects.toThrow(
        'Ed25519 key generation not supported in this environment. Native crypto API is unavailable.'
      );
    });

    it('should throw an error if key generation fails', async () => {
      mockCrypto.generateKeyPairSync.mockImplementation(() => {
        throw new Error('Key generation error');
      });
      await expect(ed25519.generateKeyPair()).rejects.toThrow(
        'Ed25519 key generation failed in Node.js environment: Key generation error'
      );
    });
  });

  describe('sign', () => {
    it('should sign a message in Node.js environment', async () => {
      const message = new Uint8Array([1, 2, 3]);
      const privateKey = new Uint8Array(32).fill(1);
      const signature = await ed25519.sign(message, privateKey);

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(mockCrypto.createPrivateKey).toHaveBeenCalledWith({
        key: Buffer.from(privateKey),
        format: 'der',
        type: 'pkcs8',
      });
      expect(mockCrypto.sign).toHaveBeenCalledWith(null, Buffer.from(message), {});
    });

    it('should throw an error for invalid private key length', async () => {
      const message = new Uint8Array([1, 2, 3]);
      const privateKey = new Uint8Array(31); // Слишком короткий ключ
      await expect(ed25519.sign(message, privateKey)).rejects.toThrow(
        `Invalid private key length: ${privateKey.length} bytes. Expected at least 32 bytes for Ed25519.`
      );
    });

    it('should throw an error if signing fails', async () => {
      mockCrypto.sign.mockImplementation(() => {
        throw new Error('Signing error');
      });
      const message = new Uint8Array([1, 2, 3]);
      const privateKey = new Uint8Array(32).fill(1);
      await expect(ed25519.sign(message, privateKey)).rejects.toThrow(
        'Ed25519 signing failed in Node.js environment: Signing error'
      );
    });

    it('should throw an error if crypto API is unavailable', async () => {
      Object.defineProperty(global, 'process', { value: undefined, writable: true });
      const message = new Uint8Array([1, 2, 3]);
      const privateKey = new Uint8Array(32).fill(1);
      await expect(ed25519.sign(message, privateKey)).rejects.toThrow(
        'Ed25519 signing not supported in this environment. Native crypto API is unavailable.'
      );
    });
  });

  describe('verify', () => {
    it('should verify a signature in Node.js environment', async () => {
      const message = new Uint8Array([1, 2, 3]);
      const signature = new Uint8Array(64).fill(1);
      const publicKey = new Uint8Array(32).fill(1);
      const isValid = await ed25519.verify(message, signature, publicKey);

      expect(isValid).toBe(true);
      expect(mockCrypto.createPublicKey).toHaveBeenCalledWith({
        key: Buffer.from(publicKey),
        format: 'der',
        type: 'spki',
      });
      expect(mockCrypto.verify).toHaveBeenCalledWith(
        null,
        Buffer.from(message),
        {},
        Buffer.from(signature)
      );
    });

    it('should throw an error for invalid signature length', async () => {
      const message = new Uint8Array([1, 2, 3]);
      const signature = new Uint8Array(63); // Слишком короткая подпись
      const publicKey = new Uint8Array(32).fill(1);
      await expect(ed25519.verify(message, signature, publicKey)).rejects.toThrow(
        `Invalid signature length: ${signature.length} bytes. Expected 64 bytes for Ed25519.`
      );
    });

    it('should throw an error for invalid public key length', async () => {
      const message = new Uint8Array([1, 2, 3]);
      const signature = new Uint8Array(64).fill(1);
      const publicKey = new Uint8Array(31); // Слишком короткий ключ
      await expect(ed25519.verify(message, signature, publicKey)).rejects.toThrow(
        `Invalid public key length: ${publicKey.length} bytes. Expected at least 32 bytes for Ed25519.`
      );
    });

    it('should throw an error if verification fails', async () => {
      mockCrypto.verify.mockImplementation(() => {
        throw new Error('Verification error');
      });
      const message = new Uint8Array([1, 2, 3]);
      const signature = new Uint8Array(64).fill(1);
      const publicKey = new Uint8Array(32).fill(1);
      await expect(ed25519.verify(message, signature, publicKey)).rejects.toThrow(
        'Ed25519 verification failed in Node.js environment: Verification error'
      );
    });

    it('should throw an error if crypto API is unavailable', async () => {
      Object.defineProperty(global, 'process', { value: undefined, writable: true });
      const message = new Uint8Array([1, 2, 3]);
      const signature = new Uint8Array(64).fill(1);
      const publicKey = new Uint8Array(32).fill(1);
      await expect(ed25519.verify(message, signature, publicKey)).rejects.toThrow(
        'Ed25519 verification not supported in this environment. Native crypto API is unavailable.'
      );
    });
  });

  describe('end-to-end signature and verification', () => {
    it('should sign and verify a message correctly', async () => {
      jest.unmock('crypto');

      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const keyPair = await ed25519.generateKeyPair();
      const signature = await ed25519.sign(message, keyPair.privateKey);
      const isValid = await ed25519.verify(message, signature, keyPair.publicKey);

      expect(isValid).toBe(true);
    });

    it('should fail verification with incorrect message', async () => {
      jest.unmock('crypto');

      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const wrongMessage = new Uint8Array([5, 4, 3, 2, 1]);
      const keyPair = await ed25519.generateKeyPair();
      const signature = await ed25519.sign(message, keyPair.privateKey);
      const isValid = await ed25519.verify(wrongMessage, signature, keyPair.publicKey);

      expect(isValid).toBe(false);
    });
  });
});