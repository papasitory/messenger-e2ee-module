// src/symmetric/chacha20.ts
import { EncryptionResult, SymmetricEncryptionAlgorithm } from '../types/interfaces';
import { CryptoUtils } from '../utils/crypto-utils';


let chacha20Module: any = null;

export class ChaCha20 implements SymmetricEncryptionAlgorithm {
  async generateKey(options?: any): Promise<Uint8Array> {
    return ChaCha20.generateKey();
  }

  async encrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Promise<EncryptionResult> {
    return ChaCha20.encrypt(data, key, iv);
  }

  async decrypt(result: EncryptionResult, key: Uint8Array): Promise<Uint8Array> {
    return ChaCha20.decrypt(result, key);
  }

  private static async _initializeModule(): Promise<void> {
    if (chacha20Module) return;

    try {
      chacha20Module = await import('chacha20');
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to load ChaCha20 module: ${error.message}. Make sure chacha20 is installed.`);
      }
      throw new Error('Failed to load ChaCha20 module: An unknown error occurred. Make sure chacha20 is installed.');
    }
  }

  static async generateKey(): Promise<Uint8Array> {
    return await CryptoUtils.randomBytes(32);
  }

  static async encrypt(
    data: Uint8Array,
    key: Uint8Array,
    nonce?: Uint8Array
  ): Promise<EncryptionResult> {
    await this._initializeModule();

    try {
      const iv = nonce || (await CryptoUtils.randomBytes(12));

      const chacha = new chacha20Module.ChaCha20(key, iv);

      const ciphertext = new Uint8Array(data.length);
      chacha.update(ciphertext, data);

      return { ciphertext, iv };
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`ChaCha20 encryption failed: ${error.message}`);
      }
      throw new Error('ChaCha20 encryption failed: An unknown error occurred.');
    }
  }

  static async decrypt(
    encResult: EncryptionResult,
    key: Uint8Array
  ): Promise<Uint8Array> {
    await this._initializeModule();

    try {
      const chacha = new chacha20Module.ChaCha20(key, encResult.iv);

      const plaintext = new Uint8Array(encResult.ciphertext.length);
      chacha.update(plaintext, encResult.ciphertext);

      return plaintext;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`ChaCha20 decryption failed: ${error.message}`);
      }
      throw new Error('ChaCha20 decryption failed: An unknown error occurred.');
    }
  }
}