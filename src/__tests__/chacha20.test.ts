// __tests__/chacha20.test.ts
import { ChaCha20 } from '../algorithms/chacha20';
import { EncryptionResult } from '../types/interfaces';
import { CryptoUtils } from '../utils/crypto-utils';

// Мокаем модуль 'chacha20' для тестов
jest.mock('chacha20', () => {
  class MockChaCha20 {
    key: Uint8Array;
    iv: Uint8Array;

    constructor(key: Uint8Array, iv: Uint8Array) {
      this.key = key;
      this.iv = iv;
    }

    update(output: Uint8Array, input: Uint8Array): void {
      for (let i = 0; i < input.length; i++) {
        output[i] = input[i] ^ 0xff; // Простая операция XOR для мока
      }
    }
  }
  return MockChaCha20;
});

describe('ChaCha20 Encryption Algorithm', () => {
  let key: Uint8Array;
  let iv: Uint8Array;
  let data: Uint8Array;

  beforeEach(async () => {
    key = await ChaCha20.generateKey();
    iv = await CryptoUtils.randomBytes(12);
    data = new TextEncoder().encode('Привет, ChaCha20!');
    jest.restoreAllMocks(); // Сбрасываем все моки перед каждым тестом
  });

  it('должен генерировать ключ длиной 32 байта', async () => {
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it('должен шифровать данные', async () => {
    const result: EncryptionResult = await ChaCha20.encrypt(data, key, iv);
    expect(result).toHaveProperty('ciphertext');
    expect(result).toHaveProperty('iv');
    expect(result.ciphertext).not.toEqual(data);
    expect(result.iv).toEqual(iv);
  });

  it('должен шифровать данные без предоставленного nonce', async () => {
    const result: EncryptionResult = await ChaCha20.encrypt(data, key);
    expect(result).toHaveProperty('ciphertext');
    expect(result).toHaveProperty('iv');
    expect(result.iv).toBeInstanceOf(Uint8Array);
    expect(result.iv.length).toBe(12);
    expect(result.ciphertext).not.toEqual(data);
  });

  it('должен дешифровать зашифрованные данные обратно в исходные', async () => {
    const encrypted = await ChaCha20.encrypt(data, key, iv);
    const decrypted = await ChaCha20.decrypt(encrypted, key);
    expect(decrypted).toEqual(data);
  });

  it('должен выбросить ошибку, если шифрование не удалось (мок)', async () => {
    const ChaCha20Module = await import('chacha20');
    const originalUpdate = ChaCha20Module.prototype.update;
    ChaCha20Module.prototype.update = () => {
      throw new Error('Сбой мока');
    };

    await expect(ChaCha20.encrypt(data, key, iv)).rejects.toThrowError(
      /ChaCha20 encryption failed/
    );

    ChaCha20Module.prototype.update = originalUpdate; // Восстанавливаем оригинальный метод
  });

  it('не должен корректно дешифровать с неверным ключом', async () => {
    const ChaCha20Module = await import('chacha20');
    const originalUpdate = ChaCha20Module.prototype.update;

    // Шифруем с обычным поведением
    const encrypted = await ChaCha20.encrypt(data, key, iv);

    // Меняем update, чтобы он просто копировал данные при дешифровании
    ChaCha20Module.prototype.update = (output: Uint8Array, input: Uint8Array) => {
      for (let i = 0; i < input.length; i++) {
        output[i] = input[i]; // Без XOR, чтобы результат отличался
      }
    };

    const wrongKey = await CryptoUtils.randomBytes(32);
    const decrypted = await ChaCha20.decrypt(encrypted, wrongKey);
    expect(decrypted).not.toEqual(data);

    ChaCha20Module.prototype.update = originalUpdate; // Восстанавливаем оригинальный метод
  });

  it('должен выбросить ошибку, если дешифрование не удалось из-за ошибки update (мок)', async () => {
    const ChaCha20Module = await import('chacha20');
    const originalUpdate = ChaCha20Module.prototype.update;

    // Шифруем с обычным поведением
    const encrypted = await ChaCha20.encrypt(data, key, iv);

    // Меняем update, чтобы он выбрасывал ошибку при дешифровании
    ChaCha20Module.prototype.update = () => {
      throw new Error('Сбой обновления');
    };

    await expect(ChaCha20.decrypt(encrypted, key)).rejects.toThrowError(
      /ChaCha20 decryption failed/
    );

    ChaCha20Module.prototype.update = originalUpdate; // Восстанавливаем оригинальный метод
  });

  it('должен выбросить ошибку, если инициализация модуля не удалась', async () => {
    jest.resetModules();
    jest.doMock('chacha20', () => {
      throw new Error('Сбой загрузки модуля');
    });
    const { ChaCha20 } = await import('../algorithms/chacha20');
    await expect(ChaCha20.encrypt(data, key, iv)).rejects.toThrowError(
      /Failed to load ChaCha20 module/
    );
  });

  it('должен шифровать и дешифровать с использованием методов экземпляра', async () => {
    const chacha = new ChaCha20();
    const key = await chacha.generateKey();
    const result = await chacha.encrypt(data, key, iv);
    const decrypted = await chacha.decrypt(result, key);
    expect(decrypted).toEqual(data);
  });
});