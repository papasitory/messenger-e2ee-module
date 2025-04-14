// src/post-quantum/kyber.ts
import { KeyPair, PostQuantumKeyExchangeAlgorithm } from '../types/interfaces';
import { CryptoUtils } from '../utils/crypto-utils';

let kyberModule: any = null;

export class Kyber implements PostQuantumKeyExchangeAlgorithm {
  async generateKeyPair(options?: { variant?: string }): Promise<KeyPair> {
    const variant = options?.variant || Kyber.KYBER768;
    return await Kyber.generateKeyPair(variant);
  }

  async encapsulate(publicKey: Uint8Array, options?: { variant?: string }): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array; }> {
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

  private static async _initializeModule(): Promise<void> {
    if (kyberModule) return;

    try {
      kyberModule = await import('pqc-kyber');
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to load Kyber module: ${error.message}. Make sure pqc-kyber is installed.`);
      }
      throw new Error('Failed to load Kyber module: Unknown error. Make sure pqc-kyber is installed.');
    }
  }

  static async generateKeyPair(variant: string = Kyber.KYBER768): Promise<KeyPair> {
    await this._initializeModule();

    try {
      const kyberAlgo = kyberModule[variant];
      if (!kyberAlgo) {
        throw new Error(`Unsupported Kyber variant: ${variant}`);
      }

      const keyPair = kyberAlgo.keypair();

      return {
        publicKey: new Uint8Array(keyPair.publicKey),
        privateKey: new Uint8Array(keyPair.secretKey)
      };
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Kyber key generation failed: ${error.message}`);
      }
      throw new Error('Kyber key generation failed: Unknown error.');
    }
  }

  static async encapsulate(
    publicKey: Uint8Array,
    variant: string = Kyber.KYBER768
  ): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array }> {
    await this._initializeModule();

    try {
      const kyberAlgo = kyberModule[variant];
      if (!kyberAlgo) {
        throw new Error(`Unsupported Kyber variant: ${variant}`);
      }
      const encapsulated = kyberAlgo.encap(publicKey);

      return {
        sharedSecret: new Uint8Array(encapsulated.sharedSecret),
        ciphertext: new Uint8Array(encapsulated.ciphertext)
      };
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Kyber encapsulation failed: ${error.message}`);
      }
      throw new Error('Kyber encapsulation failed: Unknown error.');
    }
  }

  static async decapsulate(
    ciphertext: Uint8Array,
    privateKey: Uint8Array,
    variant: string = Kyber.KYBER768
  ): Promise<Uint8Array> {
    await this._initializeModule();

    try {
      const kyberAlgo = kyberModule[variant];
      if (!kyberAlgo) {
        throw new Error(`Unsupported Kyber variant: ${variant}`);
      }

      const sharedSecret = kyberAlgo.decap(ciphertext, privateKey);

      return new Uint8Array(sharedSecret);
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Kyber decapsulation failed: ${error.message}`);
      }
      throw new Error('Kyber decapsulation failed: Unknown error.');
    }
  }
}
