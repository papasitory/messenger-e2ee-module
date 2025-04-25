import { AES_GCM } from '../algorithms/aes';
import { EncryptionResult } from '../types/interfaces';

// Настраиваем полноценный process объект для Node.js
beforeAll(() => {
  delete (global as any).window;
  global.process = {
    versions: { node: '14' },
    cwd: () => '/mocked/path',
  } as any;
});

afterAll(() => {
  delete (global as any).process;
});

describe('AES_GCM', () => {
  // Тесты для generateKey
  describe('generateKey', () => {
    it('should generate keys of correct length', async () => {
      const key128 = await AES_GCM.generateKey(128);
      expect(key128.length).toBe(16); // 128 бит = 16 байт

      const key192 = await AES_GCM.generateKey(192);
      expect(key192.length).toBe(24); // 192 бит = 24 байта

      const key256 = await AES_GCM.generateKey(256);
      expect(key256.length).toBe(32); // 256 бит = 32 байта
    });

    it('should throw error if crypto API is unavailable', async () => {
      const originalProcess = global.process;
      delete (global as any).process;

      await expect(AES_GCM.generateKey()).rejects.toThrow('Crypto API is not available in this environment');

      global.process = originalProcess;
    });
  });

  // Тесты для encrypt
  describe('encrypt', () => {
    it('should encrypt data correctly', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const encResult = await AES_GCM.encrypt(data, key);

      expect(encResult).toHaveProperty('ciphertext');
      expect(encResult).toHaveProperty('iv');
      expect(encResult.authTag).toBeDefined();
      expect(encResult.ciphertext).toBeInstanceOf(Uint8Array);
      expect(encResult.iv).toBeInstanceOf(Uint8Array);
      expect(encResult.authTag).toBeInstanceOf(Uint8Array);
      expect(encResult.iv.length).toBe(12); // IV должен быть 12 байт
      expect(encResult.authTag!.length).toBe(16); // AuthTag должен быть 16 байт
    });

    it('should encrypt with associated data', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const associatedData = new Uint8Array([6, 7, 8]);
      const encResult = await AES_GCM.encrypt(data, key, associatedData);

      expect(encResult.ciphertext.length).toBeGreaterThan(0);
      expect(encResult.iv.length).toBe(12);
      expect(encResult.authTag).toBeDefined();
      expect(encResult.authTag!.length).toBe(16);
    });

    it('should throw error on invalid key length', async () => {
      const invalidKey = new Uint8Array(10); // Неверная длина
      const data = new Uint8Array([1, 2, 3]);
      await expect(AES_GCM.encrypt(data, invalidKey)).rejects.toThrow('Invalid key length');
    });

    it('should throw error if crypto API is unavailable', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3]);
      const originalProcess = global.process;
      delete (global as any).process;

      await expect(AES_GCM.encrypt(data, key)).rejects.toThrow('Crypto API is not available in this environment');

      global.process = originalProcess;
    });

    it('should handle empty data', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([]);
      const encResult = await AES_GCM.encrypt(data, key);

      expect(encResult.ciphertext).toBeInstanceOf(Uint8Array);
      expect(encResult.ciphertext.length).toBe(0);
      expect(encResult.iv.length).toBe(12);
      expect(encResult.authTag).toBeDefined();
      expect(encResult.authTag!.length).toBe(16);
    });
  });

  // Тесты для decrypt
  describe('decrypt', () => {
    it('should decrypt data correctly', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const encResult = await AES_GCM.encrypt(data, key);
      const decrypted = await AES_GCM.decrypt(encResult, key);

      expect(decrypted).toEqual(data);
    });

    it('should decrypt with associated data', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const associatedData = new Uint8Array([6, 7, 8]);
      const encResult = await AES_GCM.encrypt(data, key, associatedData);
      const decrypted = await AES_GCM.decrypt(encResult, key, associatedData);

      expect(decrypted).toEqual(data);
    });

    it('should throw error on invalid authTag', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const encResult = await AES_GCM.encrypt(data, key);
      encResult.authTag = new Uint8Array(16); // Неверный authTag

      await expect(AES_GCM.decrypt(encResult, key)).rejects.toThrow('AES-GCM decryption failed');
    });

    it('should throw error if authTag is missing', async () => {
      const key = await AES_GCM.generateKey(256);
      const encResult: Partial<EncryptionResult> = {
        ciphertext: new Uint8Array([1, 2, 3]),
        iv: new Uint8Array(12),
      };

      await expect(AES_GCM.decrypt(encResult as EncryptionResult, key)).rejects.toThrow(
        'Authentication tag is required for AES-GCM decryption'
      );
    });

    it('should throw error if crypto API is unavailable', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3]);
      const encResult = await AES_GCM.encrypt(data, key);
      const originalProcess = global.process;
      delete (global as any).process;

      await expect(AES_GCM.decrypt(encResult, key)).rejects.toThrow('Crypto API is not available in this environment');

      global.process = originalProcess;
    });

    it('should throw error on invalid IV length', async () => {
      const key = await AES_GCM.generateKey(256);
      const encResult: EncryptionResult = {
        ciphertext: new Uint8Array([1, 2, 3]),
        iv: new Uint8Array(5), // Неверная длина IV
        authTag: new Uint8Array(16),
      };

      await expect(AES_GCM.decrypt(encResult, key)).rejects.toThrow('Invalid IV length');
    });

    it('should throw error on invalid key length', async () => {
      const invalidKey = new Uint8Array(10); // Неверная длина
      const encResult: EncryptionResult = {
        ciphertext: new Uint8Array([1, 2, 3]),
        iv: new Uint8Array(12),
        authTag: new Uint8Array(16),
      };

      await expect(AES_GCM.decrypt(encResult, invalidKey)).rejects.toThrow('Invalid key length');
    });

    it('should throw error on empty ciphertext', async () => {
      const key = await AES_GCM.generateKey(256);
      const encResult: EncryptionResult = {
        ciphertext: new Uint8Array([]),
        iv: new Uint8Array(12),
        authTag: new Uint8Array(16),
      };

      await expect(AES_GCM.decrypt(encResult, key)).rejects.toThrow('Ciphertext cannot be empty');
    });

    it('should throw error on invalid authTag length', async () => {
      const key = await AES_GCM.generateKey(256);
      const encResult: EncryptionResult = {
        ciphertext: new Uint8Array([1, 2, 3]),
        iv: new Uint8Array(12),
        authTag: new Uint8Array(15), // Неверная длина
      };

      await expect(AES_GCM.decrypt(encResult, key)).rejects.toThrow('Invalid authTag length');
    });
  });

  // Тесты для методов экземпляра класса
  describe('instance methods', () => {
    const aes = new AES_GCM();

    it('should generate key via instance method', async () => {
      const key256 = await aes.generateKey(256);
      expect(key256.length).toBe(32); // 256 бит = 32 байта
    });

    it('should encrypt data via instance method', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const encResult = await aes.encrypt(data, key);

      expect(encResult).toHaveProperty('ciphertext');
      expect(encResult).toHaveProperty('iv');
      expect(encResult.authTag).toBeDefined();
    });

    it('should decrypt data via instance method', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const encResult = await aes.encrypt(data, key);
      const decrypted = await aes.decrypt(encResult, key);

      expect(decrypted).toEqual(data);
    });
  });

  // Дополнительные тесты для повышения покрытия
  describe('additional coverage', () => {
    it('should fail decryption with incorrect associatedData', async () => {
      const key = await AES_GCM.generateKey(256);
      const data = new Uint8Array([1, 2, 3]);
      const associatedData = new Uint8Array([4, 5, 6]);
      const wrongAssociatedData = new Uint8Array([7, 8, 9]);
      const encResult = await AES_GCM.encrypt(data, key, associatedData);
      await expect(AES_GCM.decrypt(encResult, key, wrongAssociatedData)).rejects.toThrow('AES-GCM decryption failed');
    });

    it('should handle large data', async () => {
      const key = await AES_GCM.generateKey(256);
      const largeData = new Uint8Array(1024).fill(42); // 1KB данных
      const encResult = await AES_GCM.encrypt(largeData, key);
      const decrypted = await AES_GCM.decrypt(encResult, key);
      expect(decrypted).toEqual(largeData);
    });

    it('should handle minimum key size (128 bits)', async () => {
      const key = await AES_GCM.generateKey(128);
      const data = new Uint8Array([1, 2, 3]);
      const encResult = await AES_GCM.encrypt(data, key);
      const decrypted = await AES_GCM.decrypt(encResult, key);
      expect(decrypted).toEqual(data);
    });
  });
});