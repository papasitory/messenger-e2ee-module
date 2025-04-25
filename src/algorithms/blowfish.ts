import { EncryptionResult, SymmetricEncryptionAlgorithm } from '../types/interfaces';
import { CryptoUtils } from '../utils/crypto-utils';
import crypto from 'crypto';

declare const require: any;

export class Blowfish implements SymmetricEncryptionAlgorithm {
  async generateKey(options?: { keySize?: number }): Promise<Uint8Array> {
    const keySize = options?.keySize || 256;
    return Blowfish.generateKey(keySize);
  }

  async encrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Promise<EncryptionResult> {
    if (!iv) {
      iv = await CryptoUtils.randomBytes(8);
    }
    return Blowfish.encrypt(data, key, iv);
  }

  async decrypt(result: EncryptionResult, key: Uint8Array): Promise<Uint8Array> {
    return Blowfish.decrypt(result, key);
  }

  static async generateKey(keySize: number = 256): Promise<Uint8Array> {
    if (keySize < 32 || keySize > 448 || keySize % 8 !== 0) {
      throw new Error(`Invalid Blowfish key size: ${keySize} bits. Must be between 32 and 448 bits and a multiple of 8.`);
    }
    const keyBytes = keySize / 8;
    return CryptoUtils.randomBytes(keyBytes);
  }

  static async encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<EncryptionResult> {
    try {
      let CryptoJS;
      if (typeof window !== 'undefined') {
        CryptoJS = await import('crypto-js');
      } else {
        CryptoJS = require('crypto-js');
      }

      const dataWordArray = CryptoJS.lib.WordArray.create(Array.from(data));
      const keyWordArray = CryptoJS.lib.WordArray.create(Array.from(key));
      const ivWordArray = CryptoJS.lib.WordArray.create(Array.from(iv));

      const encrypted = CryptoJS.Blowfish.encrypt(
        dataWordArray,
        keyWordArray,
        { iv: ivWordArray, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
      );

      const ciphertextWordArray = encrypted.ciphertext;

      const ciphertextHex = ciphertextWordArray.toString(CryptoJS.enc.Hex);
      const ciphertext: Uint8Array = new Uint8Array(ciphertextHex.match(/.{1,2}/g)!.map((byte: string): number => parseInt(byte, 16)));

      return { ciphertext, iv };
    } catch (err) {
      throw new Error(`Blowfish encryption failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  }

  static async decrypt(encResult: EncryptionResult, key: Uint8Array): Promise<Uint8Array> {
    try {
      let CryptoJS;
      if (typeof window !== 'undefined') {
        CryptoJS = await import('crypto-js');
      } else {
        CryptoJS = require('crypto-js');
      }

      const ciphertextHex = Array.from(encResult.ciphertext)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
      const ciphertextWordArray = CryptoJS.enc.Hex.parse(ciphertextHex);
      const keyWordArray = CryptoJS.lib.WordArray.create(Array.from(key));
      const ivWordArray = CryptoJS.lib.WordArray.create(Array.from(encResult.iv));

      const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: ciphertextWordArray
      });

      const decrypted = CryptoJS.Blowfish.decrypt(
        cipherParams,
        keyWordArray,
        { iv: ivWordArray, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
      );

      const decryptedHex = decrypted.toString(CryptoJS.enc.Hex);
      return new Uint8Array(decryptedHex.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)));
    } catch (err) {
      throw new Error(`Blowfish decryption failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  }
}