// src/asymmetric/ecdh.ts
import { KeyPair, AsymmetricKeyExchangeAlgorithm } from '../types/interfaces';
import { CryptoUtils } from '../utils/crypto-utils';

export class ECDH implements AsymmetricKeyExchangeAlgorithm {
  async generateKeyPair(options?: { curve?: string }): Promise<KeyPair> {
    const curve = options?.curve || 'P-256';
    return await ECDH.generateKeyPair(curve);
  }

  async deriveSharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Promise<Uint8Array> {
    return await ECDH.deriveSharedSecret(privateKey, peerPublicKey);
  }

  static async generateKeyPair(curve: string = 'P-256'): Promise<KeyPair> {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const keyPair = await window.crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: curve
          },
          true,
          ['deriveKey', 'deriveBits']
        );

        const publicKeyExported = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
        const privateKeyExported = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        return {
          publicKey: new Uint8Array(publicKeyExported),
          privateKey: new Uint8Array(privateKeyExported)
        };
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        throw new Error(`ECDH key generation failed: ${errorMessage}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = await import('crypto');
        const ecdh = crypto.createECDH(curve);
        ecdh.generateKeys();

        return {
          publicKey: new Uint8Array(ecdh.getPublicKey()),
          privateKey: new Uint8Array(ecdh.getPrivateKey())
        };
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        throw new Error(`ECDH key generation failed: ${errorMessage}`);
      }
    }
    throw new Error('Crypto API is not available in this environment');
  }

  static async deriveSharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array, curve: string = 'P-256'): Promise<Uint8Array> {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const privateKeyImported = await window.crypto.subtle.importKey(
          'pkcs8',
          privateKey,
          {
            name: 'ECDH',
            namedCurve: curve
          },
          false,
          ['deriveKey', 'deriveBits']
        );

        const publicKeyImported = await window.crypto.subtle.importKey(
          'raw',
          peerPublicKey,
          {
            name: 'ECDH',
            namedCurve: curve
          },
          false,
          []
        );

        const sharedSecretBits = await window.crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: publicKeyImported
          },
          privateKeyImported,
          256
        );

        return new Uint8Array(sharedSecretBits);
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        throw new Error(`Failed to derive ECDH shared secret: ${errorMessage}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = await import('crypto');
        const ecdh = crypto.createECDH(curve);
        ecdh.setPrivateKey(Buffer.from(privateKey));
        const sharedSecret = ecdh.computeSecret(Buffer.from(peerPublicKey));
        return new Uint8Array(sharedSecret);
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        throw new Error(`Failed to derive ECDH shared secret: ${errorMessage}`);
      }
    }
    throw new Error('Crypto API is not available in this environment');
  }
}
