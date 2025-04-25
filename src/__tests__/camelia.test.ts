import { Camellia } from '../algorithms/camellia';
import { CryptoUtils } from '../utils/crypto-utils';
import { EncryptionResult } from '../types/interfaces';
import * as forge from 'node-forge';

// Мокаем node-forge для избежания реальных криптографических операций
jest.mock('node-forge', () => ({
  util: {
    createBuffer: jest.fn((data) => ({ data, getBytes: jest.fn(() => data) })),
  },
  cipher: {
    createCipher: jest.fn(() => ({
      start: jest.fn(),
      update: jest.fn(),
      finish: jest.fn(() => true),
      output: { getBytes: jest.fn(() => 'mockedCiphertext') },
    })),
    createDecipher: jest.fn(() => ({
      start: jest.fn(),
      update: jest.fn(),
      finish: jest.fn(() => true),
      output: { getBytes: jest.fn(() => 'mockedDecrypted') },
    })),
  },
}));

describe('Camellia', () => {
  let camellia: Camellia;

  beforeEach(() => {
    camellia = new Camellia();
    jest.spyOn(CryptoUtils, 'randomBytes').mockResolvedValue(new Uint8Array(16));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('generateKey', () => {
    it('should generate a key of the specified size', async () => {
      const keySize = 128; // 128 бит = 16 байт
      const key = await camellia.generateKey({ keySize });
      expect(key.length).toBe(keySize / 8);
      expect(CryptoUtils.randomBytes).toHaveBeenCalledWith(keySize / 8);
    });

    it('should throw an error for invalid key size', async () => {
      const invalidKeySize = 256 + 1; // Недопустимый размер
      await expect(camellia.generateKey({ keySize: invalidKeySize as 128 })).rejects.toThrow(
        `Invalid Camellia key size: ${invalidKeySize} bits. Must be 128, 192, or 256 bits.`
      );
    });

    it('should default to 256 bits if no key size is provided', async () => {
      const key = await camellia.generateKey();
      expect(key.length).toBe(256 / 8);
      expect(CryptoUtils.randomBytes).toHaveBeenCalledWith(256 / 8);
    });
  });

  describe('encrypt', () => {
    it('should encrypt data with a provided key and IV', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const key = new Uint8Array(16);
      const iv = new Uint8Array(16);
      const result = await camellia.encrypt(data, key, iv);

      expect(result).toHaveProperty('ciphertext');
      expect(result).toHaveProperty('iv');
      expect(result.iv).toEqual(iv);
      expect(CryptoUtils.randomBytes).not.toHaveBeenCalled(); // IV предоставлен
      expect(forge.cipher.createCipher).toHaveBeenCalledWith('CAMELLIA-CBC', expect.anything());
    });

    it('should generate a random IV if none is provided', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const key = new Uint8Array(16);
      const result = await camellia.encrypt(data, key);

      expect(result).toHaveProperty('ciphertext');
      expect(result).toHaveProperty('iv');
      expect(CryptoUtils.randomBytes).toHaveBeenCalledWith(16);
    });

    it('should throw an error if encryption fails', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const key = new Uint8Array(16);
      const iv = new Uint8Array(16);
      jest.spyOn(forge.cipher, 'createCipher').mockReturnValue({
        start: jest.fn(),
        update: jest.fn(),
        finish: jest.fn(() => false),
        output: { getBytes: jest.fn() },
      } as any);

      await expect(camellia.encrypt(data, key, iv)).rejects.toThrow(
        'Camellia encryption failed: Camellia encryption process failed'
      );
    });
  });

  describe('decrypt', () => {
    it('should decrypt data with a valid encryption result and key', async () => {
      const encResult: EncryptionResult = {
        ciphertext: new Uint8Array([4, 5, 6]),
        iv: new Uint8Array(16),
      };
      const key = new Uint8Array(16);
      const decrypted = await camellia.decrypt(encResult, key);

      expect(decrypted).toBeInstanceOf(Uint8Array);
      expect(forge.cipher.createDecipher).toHaveBeenCalledWith('CAMELLIA-CBC', expect.anything());
    });

    it('should throw an error if decryption fails', async () => {
      const encResult: EncryptionResult = {
        ciphertext: new Uint8Array([4, 5, 6]),
        iv: new Uint8Array(16),
      };
      const key = new Uint8Array(16);
      jest.spyOn(forge.cipher, 'createDecipher').mockReturnValue({
        start: jest.fn(),
        update: jest.fn(),
        finish: jest.fn(() => false),
        output: { getBytes: jest.fn() },
      } as any);

      await expect(camellia.decrypt(encResult, key)).rejects.toThrow(
        'Camellia decryption failed: Camellia decryption process failed'
      );
    });
  });

  describe('end-to-end encryption and decryption', () => {
    it('should encrypt and decrypt data correctly', async () => {
      // Реальная проверка требует отключения мока node-forge
      jest.unmock('node-forge');
      const originalData = new Uint8Array([1, 2, 3, 4, 5]);
      const key = await camellia.generateKey({ keySize: 128 });
      const encResult = await camellia.encrypt(originalData, key);
      const decryptedData = await camellia.decrypt(encResult, key);

      expect(decryptedData).toEqual(originalData);
    });
  });
});