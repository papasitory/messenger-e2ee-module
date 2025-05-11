import { EncryptionResult, SymmetricEncryptionAlgorithm } from '../types/interfaces';
import { CryptoUtils } from '../utils/crypto-utils';
import crypto from 'crypto';

export interface LocalSymmetricEncryptionAlgorithm {
  generateKey(options?: any): Promise<Uint8Array>;
  encrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Promise<EncryptionResult>;
  decrypt(result: EncryptionResult, key: Uint8Array): Promise<Uint8Array>;
}

export class AES_GCM implements LocalSymmetricEncryptionAlgorithm {
  async generateKey(bits: 128 | 192 | 256 = 256): Promise<Uint8Array> {
    return AES_GCM.generateKey(bits);
  }

  async encrypt(
    data: Uint8Array, 
    key: Uint8Array, 
    associatedData?: Uint8Array
  ): Promise<EncryptionResult> {
    return AES_GCM.encrypt(data, key, associatedData);
  }

  async decrypt(
    encResult: EncryptionResult, 
    key: Uint8Array, 
    associatedData?: Uint8Array
  ): Promise<Uint8Array> {
    return AES_GCM.decrypt(encResult, key, associatedData);
  }

  static async generateKey(bits: 128 | 192 | 256 = 256): Promise<Uint8Array> {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const key = await window.crypto.subtle.generateKey(
          { name: 'AES-GCM', length: bits },
          true,
          ['encrypt', 'decrypt']
        );
        const exportedKey = await window.crypto.subtle.exportKey('raw', key);
        return new Uint8Array(exportedKey);
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        throw new Error(`AES key generation failed: ${errorMessage}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      const keyBytes = bits / 8;
      return await CryptoUtils.randomBytes(keyBytes);
    }
    throw new Error('Crypto API is not available in this environment');
  }

  static async encrypt(
    data: Uint8Array, 
    key: Uint8Array, 
    associatedData?: Uint8Array
  ): Promise<EncryptionResult> {
    // Проверка длины ключа
    if (![16, 24, 32].includes(key.length)) {
      throw new Error('Invalid key length');
    }

    const iv = await CryptoUtils.randomBytes(12);

    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const importedKey = await window.crypto.subtle.importKey(
          'raw', key, { name: 'AES-GCM', length: key.length * 8 }, false, ['encrypt']
        );
        const params: AesGcmParams = { name: 'AES-GCM', iv, tagLength: 128 };
        if (associatedData) params.additionalData = associatedData;

        const encryptedData = await window.crypto.subtle.encrypt(params, importedKey, data);
        const encryptedBytes = new Uint8Array(encryptedData);
        const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
        const authTag = encryptedBytes.slice(encryptedBytes.length - 16);

        return { ciphertext, iv, authTag };
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        throw new Error(`AES-GCM encryption failed: ${errorMessage}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = await import('crypto');
        const cipher = crypto.createCipheriv(`aes-${key.length * 8}-gcm`, Buffer.from(key), Buffer.from(iv));
        if (associatedData) (cipher as crypto.CipherGCM).setAAD(Buffer.from(associatedData));

        let encrypted = cipher.update(Buffer.from(data));
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const authTag = (cipher as crypto.CipherGCM).getAuthTag();

        return { ciphertext: new Uint8Array(encrypted), iv, authTag: new Uint8Array(authTag) };
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        throw new Error(`AES-GCM encryption failed: ${errorMessage}`);
      }
    }
    throw new Error('Crypto API is not available in this environment');
  }

  static async decrypt(
    encResult: EncryptionResult, 
    key: Uint8Array, 
    associatedData?: Uint8Array
  ): Promise<Uint8Array> {
    // Проверки входных данных
    if (![16, 24, 32].includes(key.length)) {
      throw new Error('Invalid key length');
    }
    if (encResult.iv.length !== 12) {
      throw new Error('Invalid IV length');
    }
    if (encResult.ciphertext.length === 0) {
      throw new Error('Ciphertext cannot be empty');
    }
    if (!encResult.authTag) {
      throw new Error('Authentication tag is required for AES-GCM decryption');
    }
    if (encResult.authTag.length !== 16) {
      throw new Error('Invalid authTag length');
    }

    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const importedKey = await window.crypto.subtle.importKey(
          'raw', key, { name: 'AES-GCM', length: key.length * 8 }, false, ['decrypt']
        );
        const encryptedWithTag = new Uint8Array(encResult.ciphertext.length + encResult.authTag.length);
        encryptedWithTag.set(encResult.ciphertext);
        encryptedWithTag.set(encResult.authTag, encResult.ciphertext.length);

        const params: AesGcmParams = { name: 'AES-GCM', iv: encResult.iv, tagLength: 128 };
        if (associatedData) params.additionalData = associatedData;

        const decryptedData = await window.crypto.subtle.decrypt(params, importedKey, encryptedWithTag);
        return new Uint8Array(decryptedData);
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        throw new Error(`AES-GCM decryption failed: ${errorMessage}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = await import('crypto');
        const decipher = crypto.createDecipheriv(
          `aes-${key.length * 8}-gcm`, Buffer.from(key), Buffer.from(encResult.iv)
        );
        (decipher as crypto.DecipherGCM).setAuthTag(Buffer.from(encResult.authTag));
        if (associatedData) (decipher as crypto.DecipherGCM).setAAD(Buffer.from(associatedData));

        let decrypted = decipher.update(Buffer.from(encResult.ciphertext));
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return new Uint8Array(decrypted);
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        throw new Error(`AES-GCM decryption failed: ${errorMessage}`);
      }
    }
    throw new Error('Crypto API is not available in this environment');
  }
}