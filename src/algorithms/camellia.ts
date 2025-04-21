import { EncryptionResult, SymmetricEncryptionAlgorithm } from '../types/interfaces';
import { CryptoUtils } from '../utils/crypto-utils';
import * as forge from 'node-forge';

export class Camellia implements SymmetricEncryptionAlgorithm {
  async generateKey(options?: { keySize?: 128 | 192 | 256 }): Promise<Uint8Array> {
    const keySize = options?.keySize || 256;
    return Camellia.generateKey(keySize);
  }

  async encrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Promise<EncryptionResult> {
    if (!iv) {
      iv = await CryptoUtils.randomBytes(16);
    }
    return Camellia.encrypt(data, key, iv);
  }

  async decrypt(result: EncryptionResult, key: Uint8Array): Promise<Uint8Array> {
    return Camellia.decrypt(result, key);
  }

  static async generateKey(keySize: 128 | 192 | 256 = 256): Promise<Uint8Array> {
    const keyBytes = keySize / 8;
    return CryptoUtils.randomBytes(keyBytes);
  }

  static async encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<EncryptionResult> {
    try {
      // Convert Uint8Array to forge buffer format
      const forgeData = forge.util.createBuffer(Buffer.from(data).toString('binary'));
      const forgeKey = forge.util.createBuffer(Buffer.from(key).toString('binary'));
      const forgeIv = forge.util.createBuffer(Buffer.from(iv).toString('binary'));

      // Create cipher
      const cipher = forge.cipher.createCipher('CAMELLIA-CBC', forgeKey); // Replace 'camellia' with a supported algorithm like 'AES-CBC'
      cipher.start({ iv: forgeIv });
      cipher.update(forgeData);
      const success = cipher.finish();

      if (!success) {
        throw new Error('Camellia encryption failed');
      }

      // Convert output to Uint8Array
      const ciphertext = new Uint8Array(
        Buffer.from(cipher.output.getBytes(), 'binary')
      );

      return { ciphertext, iv };
    } catch (err) {
      if (err instanceof Error) {
        throw new Error(`Camellia encryption failed: ${err.message}`);
      } else {
        throw new Error('Camellia encryption failed: Unknown error');
      }
    }
  }

  static async decrypt(encResult: EncryptionResult, key: Uint8Array): Promise<Uint8Array> {
    try {
      // Convert to forge buffer format
      const forgeCiphertext = forge.util.createBuffer(Buffer.from(encResult.ciphertext).toString('binary'));
      const forgeKey = forge.util.createBuffer(Buffer.from(key).toString('binary'));
      const forgeIv = forge.util.createBuffer(Buffer.from(encResult.iv).toString('binary'));

      // Create decipher
      const decipher = forge.cipher.createDecipher('AES-CBC', forgeKey);
      decipher.start({ iv: forgeIv });
      decipher.update(forgeCiphertext);
      const success = decipher.finish();

      if (!success) {
        throw new Error('Camellia decryption failed');
      }

      // Convert output back to Uint8Array
      return new Uint8Array(
        Buffer.from(decipher.output.getBytes(), 'binary')
      );
    } catch (err) {
      if (err instanceof Error) {
        throw new Error(`Camellia decryption failed: ${err.message}`);
      } else {
        throw new Error('Camellia decryption failed: Unknown error');
      }
    }
  }
}