// src/utils/crypto-utils.ts
import { KeyPair, SerializedKeyPair, EncryptionResult, SerializedEncryptionResult } from '../types/interfaces';

export class CryptoUtils {
  /**
   * Генерирует заданное количество случайных байтов
   */
  static async randomBytes(length: number): Promise<Uint8Array> {
    if (typeof window !== 'undefined' && window.crypto) {
      const bytes = new Uint8Array(length);
      window.crypto.getRandomValues(bytes);
      return bytes;
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      const crypto = await import('crypto');
      return new Uint8Array(crypto.randomBytes(length));
    }
    throw new Error('Crypto API is not available in this environment');
  }

  /**
   * Конвертирует Uint8Array в строку Base64
   */
  static toBase64(data: Uint8Array): string {
    if (typeof btoa === 'function') {
      // В браузере
      const binary = Array.from(data)
        .map(byte => String.fromCharCode(byte))
        .join('');
      return btoa(binary);
    } else if (typeof Buffer !== 'undefined') {
      // В Node.js
      return Buffer.from(data).toString('base64');
    }
    throw new Error('Base64 encoding is not available in this environment');
  }

  /**
   * Конвертирует строку Base64 в Uint8Array
   */
  static fromBase64(data: string): Uint8Array {
    if (typeof atob === 'function') {
      // В браузере
      const binary = atob(data);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } else if (typeof Buffer !== 'undefined') {
      // В Node.js
      return new Uint8Array(Buffer.from(data, 'base64'));
    }
    throw new Error('Base64 decoding is not available in this environment');
  }

  /**
   * Сериализует пару ключей в формат, пригодный для хранения
   */
  static serializeKeyPair(keyPair: KeyPair): SerializedKeyPair {
    return {
      publicKey: this.toBase64(keyPair.publicKey),
      privateKey: this.toBase64(keyPair.privateKey)
    };
  }

  /**
   * Десериализует пару ключей из строкового представления
   */
  static deserializeKeyPair(serialized: SerializedKeyPair): KeyPair {
    return {
      publicKey: this.fromBase64(serialized.publicKey),
      privateKey: this.fromBase64(serialized.privateKey)
    };
  }

  /**
   * Сериализует результат шифрования в формат, пригодный для хранения
   */
  static serializeEncryptionResult(result: EncryptionResult): SerializedEncryptionResult {
    const serialized: SerializedEncryptionResult = {
      ciphertext: this.toBase64(result.ciphertext),
      iv: this.toBase64(result.iv)
    };
    
    if (result.authTag) {
      serialized.authTag = this.toBase64(result.authTag);
    }
    
    return serialized;
  }

  /**
   * Десериализует результат шифрования из строкового представления
   */
  static deserializeEncryptionResult(serialized: SerializedEncryptionResult): EncryptionResult {
    const result: EncryptionResult = {
      ciphertext: this.fromBase64(serialized.ciphertext),
      iv: this.fromBase64(serialized.iv)
    };
    
    if (serialized.authTag) {
      result.authTag = this.fromBase64(serialized.authTag);
    }
    
    return result;
  }

  /**
   * Преобразует строку в Uint8Array с использованием UTF-8 кодировки
   */
  static stringToBytes(str: string): Uint8Array {
    if (typeof TextEncoder !== 'undefined') {
      return new TextEncoder().encode(str);
    } else if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(str, 'utf8'));
    }
    
    // Резервный вариант, если ни один из вышеперечисленных методов недоступен
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      bytes[i] = str.charCodeAt(i) & 0xff;
    }
    return bytes;
  }

  /**
   * Преобразует Uint8Array в строку с использованием UTF-8 кодировки
   */
  static bytesToString(bytes: Uint8Array): string {
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder('utf-8').decode(bytes);
    } else if (typeof Buffer !== 'undefined') {
      return Buffer.from(bytes).toString('utf8');
    }
    
    // Резервный вариант, если ни один из вышеперечисленных методов недоступен
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
      result += String.fromCharCode(bytes[i]);
    }
    return result;
  }

  /**
   * Сравнивает два Uint8Array в защищенном от тайминговых атак режиме
   */
  static constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    
    return result === 0;
  }
}