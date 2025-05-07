import { KeyPair, PostQuantumKeyExchangeAlgorithm } from '../types/interfaces';
import { CryptoUtils } from '../utils/crypto-utils';

// Для удобства тестирования, переменная должна быть доступна для сброса
export let kyberModule: any = null;

export class Kyber implements PostQuantumKeyExchangeAlgorithm {
  async generateKeyPair(options?: { variant?: string }): Promise<KeyPair> {
    const variant = options?.variant || Kyber.KYBER768;
    return await Kyber.generateKeyPair(variant);
  }

  async encapsulate(publicKey: Uint8Array, options?: { variant?: string }): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array }> {
    const variant = options?.variant || Kyber.KYBER768;
    return await Kyber.encapsulate(publicKey, variant);
  }

  async decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array, options?: { variant?: string }): Promise<Uint8Array> {
    const variant = options?.variant || Kyber.KYBER768;
    return await Kyber.decapsulate(ciphertext, privateKey, variant);
  }

  // Security levels for Kyber
  static readonly KYBER512 = 'kyber512';
  static readonly KYBER768 = 'kyber768';
  static readonly KYBER1024 = 'kyber1024';

  // Изменено для тестирования - сделаем функцию не async
  private static _initializeModule(): void {
    if (kyberModule) return;

    try {
      // При тестировании здесь будет ошибка, если Jest mockImplementation бросает исключение
      kyberModule = require('pqc-kyber');
    } catch (error) {
      throw new Error(`Failed to load Kyber module: ${error instanceof Error ? error.message : 'Unknown error'}. Make sure pqc-kyber is installed.`);
    }

    // Проверка наличия необходимых алгоритмов после успешной загрузки модуля
    if (!kyberModule.kyber512 || !kyberModule.kyber768 || !kyberModule.kyber1024) {
      throw new Error('Kyber module is missing required algorithms (kyber512, kyber768, kyber1024).');
    }
  }

  static async generateKeyPair(variant: string = Kyber.KYBER768): Promise<KeyPair> {
    // Это ключевое изменение - мы не используем try/catch здесь
    this._initializeModule();
      
    const kyberAlgo = kyberModule[variant];
    if (!kyberAlgo) {
      throw new Error(`Kyber module is missing required algorithms (kyber512, kyber768, kyber1024).`);
    }

    try {
      const keyPair = kyberAlgo.keypair();

      return {
        publicKey: new Uint8Array(keyPair.publicKey),
        privateKey: new Uint8Array(keyPair.secretKey),
      };
    } catch (error) {
      throw new Error(`Kyber key generation failed for ${variant}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  static async encapsulate(
    publicKey: Uint8Array,
    variant: string = Kyber.KYBER768
  ): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array }> {
    // Инициализация без try/catch
    this._initializeModule();
      
    const kyberAlgo = kyberModule[variant];
    if (!kyberAlgo) {
      throw new Error(`Unsupported Kyber variant: ${variant}. Supported variants: ${[Kyber.KYBER512, Kyber.KYBER768, Kyber.KYBER1024].join(', ')}`);
    }

    try {
      const encapsulated = kyberAlgo.encap(publicKey);

      return {
        sharedSecret: new Uint8Array(encapsulated.sharedSecret),
        ciphertext: new Uint8Array(encapsulated.ciphertext),
      };
    } catch (error) {
      throw new Error(`Kyber encapsulation failed for ${variant}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  static async decapsulate(
    ciphertext: Uint8Array,
    privateKey: Uint8Array,
    variant: string = Kyber.KYBER768
  ): Promise<Uint8Array> {
    // Инициализация без try/catch
    this._initializeModule();
      
    const kyberAlgo = kyberModule[variant];
    if (!kyberAlgo) {
      throw new Error(`Unsupported Kyber variant: ${variant}. Supported variants: ${[Kyber.KYBER512, Kyber.KYBER768, Kyber.KYBER1024].join(', ')}`);
    }

    try {
      const sharedSecret = kyberAlgo.decap(ciphertext, privateKey);

      return new Uint8Array(sharedSecret);
    } catch (error) {
      throw new Error(`Kyber decapsulation failed for ${variant}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}