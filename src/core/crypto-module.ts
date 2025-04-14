import { CryptoUtils } from '../utils/crypto-utils';
import { AES_GCM } from '../algorithms/aes';
import { Blowfish } from '../algorithms/blowfish';
import { Camellia } from '../algorithms/camellia';
import { ECDH } from '../algorithms/ecdh';
import { Ed25519 } from '../algorithms/ed25519';

/**
 * Основной класс для работы с криптографическими алгоритмами
 */
export class CryptoModule {
  static utils = CryptoUtils;
  
  // Симметричные алгоритмы
  static aesGcm = AES_GCM;
  static blowfish = Blowfish;
  static camellia = Camellia;
  
  // Асимметричные алгоритмы
  static ecdh = ECDH;
  static ed25519 = Ed25519;
  
  /**
   * Шифрует текст с использованием выбранного симметричного алгоритма
   * @param text Текст для шифрования
   * @param key Ключ шифрования
   * @param algorithm Алгоритм шифрования ('aes-gcm' | 'twofish' | 'blowfish' | 'camellia')
   * @returns Сериализованный результат шифрования
   */
  static async encryptText(
    text: string, 
    key: Uint8Array, 
    algorithm: 'aes-gcm' | 'blowfish' = 'aes-gcm'
  ): Promise<string> {
    const data = CryptoUtils.stringToBytes(text);
    let result;
    
    switch (algorithm) {
      case 'aes-gcm':
        result = await AES_GCM.encrypt(data, key);
        break;
      case 'blowfish':
        result = await Blowfish.encrypt(data, key);
        break;
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    
    return JSON.stringify(CryptoUtils.serializeEncryptionResult(result));
  }
  
  /**
   * Расшифровывает текст с использованием выбранного симметричного алгоритма
   * @param encryptedText Сериализованный результат шифрования
   * @param key Ключ шифрования
   * @param algorithm Алгоритм шифрования ('aes-gcm' | 'twofish' | 'blowfish' | 'camellia')
   * @returns Расшифрованный текст
   */
  static async decryptText(
    encryptedText: string, 
    key: Uint8Array, 
    algorithm: 'aes-gcm' | 'blowfish' = 'aes-gcm'
  ): Promise<string> {
    const serialized = JSON.parse(encryptedText);
    const result = CryptoUtils.deserializeEncryptionResult(serialized);
    
    let decrypted;
    switch (algorithm) {
      case 'aes-gcm':
        decrypted = await AES_GCM.decrypt(result, key);
        break;
      case 'blowfish':
        decrypted = await Blowfish.decrypt(result, key);
        break;
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    
    return CryptoUtils.bytesToString(decrypted);
  }
  
  /**
   * Генерирует случайный ключ для выбранного симметричного алгоритма
   * @param algorithm Алгоритм шифрования ('aes-gcm' | 'twofish' | 'blowfish' | 'camellia')
   * @param keySize Размер ключа в битах
   * @returns Сгенерированный ключ
   */
  static async generateKey(
    algorithm: 'aes-gcm' | 'blowfish'  = 'aes-gcm',
    keySize: 128 | 192 | 256 = 256
  ): Promise<Uint8Array> {
    switch (algorithm) {
      case 'aes-gcm':
        return await AES_GCM.generateKey(keySize);
      case 'blowfish':
        return await Blowfish.generateKey(keySize);
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }
  
  /**
   * Устанавливает защищенное соединение между двумя сторонами с использованием ECDH
   * @param myKeyPair Моя пара ключей ECDH
   * @param peerPublicKey Публичный ключ другой стороны
   * @returns Общий секретный ключ
   */
  static async establishSecureConnection(
    myKeyPair: { privateKey: Uint8Array },
    peerPublicKey: Uint8Array
  ): Promise<Uint8Array> {
    return await ECDH.deriveSharedSecret(myKeyPair.privateKey, peerPublicKey);
  }
  
  /**
   * Подписывает сообщение с использованием Ed25519
   * @param message Сообщение для подписи
   * @param privateKey Приватный ключ Ed25519
   * @returns Подпись в формате Base64
   */
  static async signMessage(message: string, privateKey: Uint8Array): Promise<string> {
    const data = CryptoUtils.stringToBytes(message);
    const signature = await Ed25519.sign(data, privateKey);
    return CryptoUtils.toBase64(signature);
  }
  
  /**
   * Проверяет подпись сообщения с использованием Ed25519
   * @param message Исходное сообщение
   * @param signature Подпись в формате Base64
   * @param publicKey Публичный ключ Ed25519
   * @returns true, если подпись действительна
   */
  static async verifySignature(message: string, signature: string, publicKey: Uint8Array): Promise<boolean> {
    const data = CryptoUtils.stringToBytes(message);
    const signatureBytes = CryptoUtils.fromBase64(signature);
    return await Ed25519.verify(data, signatureBytes, publicKey);
  }
}