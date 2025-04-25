import { Blowfish } from '../algorithms/blowfish';
import { CryptoUtils } from '../utils/crypto-utils';
import { EncryptionResult } from '../types/interfaces';

// Мокаем crypto-js, чтобы избежать реальных криптографических операций
jest.mock('crypto-js', () => ({
  lib: {
    WordArray: {
      create: jest.fn((data) => ({ data, toString: jest.fn(() => 'mockedHex') })),
      CipherParams: { create: jest.fn((data) => ({ ciphertext: data.ciphertext })) },
    },
  },
  enc: {
    Hex: { parse: jest.fn((hex) => ({ toString: jest.fn(() => hex) })) },
  },
  Blowfish: {
    encrypt: jest.fn(() => ({
      ciphertext: { toString: jest.fn(() => 'mockedCiphertext') },
    })),
    decrypt: jest.fn(() => ({ toString: jest.fn(() => 'mockedDecrypted') })),
  },
  mode: { CBC: {} },
  pad: { Pkcs7: {} },
}));

describe('Blowfish', () => {
  let blowfish: Blowfish;

  beforeEach(() => {
    blowfish = new Blowfish();
    jest.spyOn(CryptoUtils, 'randomBytes').mockResolvedValue(new Uint8Array(8));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('generateKey', () => {
    it('should generate a key of the specified size', async () => {
      const keySize = 128; // 128 бит = 16 байт
      const key = await blowfish.generateKey({ keySize });
      expect(key.length).toBe(keySize / 8);
      expect(CryptoUtils.randomBytes).toHaveBeenCalledWith(keySize / 8);
    });

    it('should throw an error for invalid key size', async () => {
      const invalidKeySize = 450; // Некратное 8 и больше 448
      await expect(blowfish.generateKey({ keySize: invalidKeySize })).rejects.toThrow(
        `Invalid Blowfish key size: ${invalidKeySize} bits. Must be between 32 and 448 bits and a multiple of 8.`
      );
    });

    it('should default to 256 bits if no key size is provided', async () => {
      const key = await blowfish.generateKey();
      expect(key.length).toBe(256 / 8);
      expect(CryptoUtils.randomBytes).toHaveBeenCalledWith(256 / 8);
    });
  });

  describe('encrypt', () => {
    it('should encrypt data with a provided key and IV', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const key = new Uint8Array(16);
      const iv = new Uint8Array(8);
      const result = await blowfish.encrypt(data, key, iv);

      expect(result).toHaveProperty('ciphertext');
      expect(result).toHaveProperty('iv');
      expect(result.iv).toEqual(iv);
      expect(CryptoUtils.randomBytes).not.toHaveBeenCalled(); // IV предоставлен
    });

    it('should generate a random IV if none is provided', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const key = new Uint8Array(16);
      const result = await blowfish.encrypt(data, key);

      expect(result).toHaveProperty('ciphertext');
      expect(result).toHaveProperty('iv');
      expect(CryptoUtils.randomBytes).toHaveBeenCalledWith(8);
    });

    it('should throw an error if encryption fails', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const key = new Uint8Array(16);
      jest.spyOn(require('crypto-js').Blowfish, 'encrypt').mockImplementation(() => {
        throw new Error('Encryption error');
      });

      await expect(blowfish.encrypt(data, key)).rejects.toThrow(
        'Blowfish encryption failed: Encryption error'
      );
    });
  });

  describe('decrypt', () => {
    it('should decrypt data with a valid encryption result and key', async () => {
      const encResult: EncryptionResult = {
        ciphertext: new Uint8Array([4, 5, 6]),
        iv: new Uint8Array(8),
      };
      const key = new Uint8Array(16);
      const decrypted = await blowfish.decrypt(encResult, key);

      expect(decrypted).toBeInstanceOf(Uint8Array);
    });

    it('should throw an error if decryption fails', async () => {
      const encResult: EncryptionResult = {
        ciphertext: new Uint8Array([4, 5, 6]),
        iv: new Uint8Array(8),
      };
      const key = new Uint8Array(16);
      jest.spyOn(require('crypto-js').Blowfish, 'decrypt').mockImplementation(() => {
        throw new Error('Decryption error');
      });

      await expect(blowfish.decrypt(encResult, key)).rejects.toThrow(
        'Blowfish decryption failed: Decryption error'
      );
    });
  });

  describe('end-to-end encryption and decryption', () => {
    it('should encrypt and decrypt data correctly', async () => {
      // Реальная проверка требует отключения мока crypto-js
      jest.unmock('crypto-js');
      const originalData = new Uint8Array([1, 2, 3, 4, 5]);
      const key = await blowfish.generateKey({ keySize: 128 });
      const encResult = await blowfish.encrypt(originalData, key);
      const decryptedData = await blowfish.decrypt(encResult, key);

      expect(decryptedData).toEqual(originalData);
    });
  });
});