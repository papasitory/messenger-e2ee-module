import { KeyPair, AsymmetricSignatureAlgorithm } from '../types/interfaces';

export class Ed25519 implements AsymmetricSignatureAlgorithm {
  async generateKeyPair(): Promise<KeyPair> {
    return Ed25519.generateKeyPair();
  }

  async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    return Ed25519.sign(message, privateKey);
  }

  async verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return Ed25519.verify(message, signature, publicKey);
  }

  static async generateKeyPair(): Promise<KeyPair> {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const keyPair = await window.crypto.subtle.generateKey(
          {
            name: 'Ed25519',
          },
          true,
          ['sign', 'verify']
        );

        const publicKeyExported = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
        const privateKeyExported = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        return {
          publicKey: new Uint8Array(publicKeyExported),
          privateKey: new Uint8Array(privateKeyExported),
        };
      } catch (err: unknown) {
        throw new Error(`Ed25519 key generation failed in browser environment: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = await import('crypto');
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
          publicKeyEncoding: { type: 'spki', format: 'der' },
          privateKeyEncoding: { type: 'pkcs8', format: 'der' },
        });

        return {
          publicKey: new Uint8Array(publicKey),
          privateKey: new Uint8Array(privateKey),
        };
      } catch (err: unknown) {
        throw new Error(`Ed25519 key generation failed in Node.js environment: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    }
    throw new Error('Ed25519 key generation not supported in this environment. Native crypto API is unavailable.');
  }

  static async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    if (privateKey.length < 32) {
      throw new Error(`Invalid private key length: ${privateKey.length} bytes. Expected at least 32 bytes for Ed25519.`);
    }

    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const importedPrivateKey = await window.crypto.subtle.importKey(
          'pkcs8',
          privateKey,
          {
            name: 'Ed25519',
          },
          false,
          ['sign']
        );
        const signature = await window.crypto.subtle.sign(
          { name: 'Ed25519' },
          importedPrivateKey,
          message
        );

        return new Uint8Array(signature);
      } catch (err: unknown) {
        throw new Error(`Ed25519 signing failed in browser environment: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = await import('crypto');
        const key = crypto.createPrivateKey({
          key: Buffer.from(privateKey),
          format: 'der',
          type: 'pkcs8',
        });

        const signature = crypto.sign(null, Buffer.from(message), key);
        return new Uint8Array(signature);
      } catch (err: unknown) {
        throw new Error(`Ed25519 signing failed in Node.js environment: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    }

    throw new Error('Ed25519 signing not supported in this environment. Native crypto API is unavailable.');
  }

  static async verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    if (signature.length !== 64) {
      throw new Error(`Invalid signature length: ${signature.length} bytes. Expected 64 bytes for Ed25519.`);
    }
    if (publicKey.length < 32) {
      throw new Error(`Invalid public key length: ${publicKey.length} bytes. Expected at least 32 bytes for Ed25519.`);
    }

    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const importedPublicKey = await window.crypto.subtle.importKey(
          'raw',
          publicKey,
          {
            name: 'Ed25519',
          },
          false,
          ['verify']
        );

        return await window.crypto.subtle.verify(
          { name: 'Ed25519' },
          importedPublicKey,
          signature,
          message
        );
      } catch (err: unknown) {
        throw new Error(`Ed25519 verification failed in browser environment: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = await import('crypto');
        const key = crypto.createPublicKey({
          key: Buffer.from(publicKey),
          format: 'der',
          type: 'spki',
        });

        return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature));
      } catch (err: unknown) {
        throw new Error(`Ed25519 verification failed in Node.js environment: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    }

    throw new Error('Ed25519 verification not supported in this environment. Native crypto API is unavailable.');
  }
}