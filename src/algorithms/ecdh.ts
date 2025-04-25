import { KeyPair, AsymmetricKeyExchangeAlgorithm } from '../types/interfaces';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { CryptoUtils } from '../utils/crypto-utils';

const SUPPORTED_CURVES = ['P-256', 'P-384', 'P-521'] as const;
const NODE_CURVE_MAP: Record<string, string> = {
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
};

export class ECDH implements AsymmetricKeyExchangeAlgorithm {
  async generateKeyPair(options?: { curve?: string }): Promise<KeyPair> {
    const curve = options?.curve || 'P-256';
    return await ECDH.generateKeyPair(curve);
  }

  async deriveSharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array, curve?: string): Promise<Uint8Array> {
    return await ECDH.deriveSharedSecret(privateKey, peerPublicKey, curve || 'P-256');
  }

  static async generateKeyPair(curve: string = 'P-256'): Promise<KeyPair> {
    if (!SUPPORTED_CURVES.includes(curve as any)) {
      throw new Error(`Unsupported ECDH curve: ${curve}. Supported curves: ${SUPPORTED_CURVES.join(', ')}`);
    }

    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const keyPair = await window.crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: curve,
          },
          true,
          ['deriveKey', 'deriveBits']
        );

        const publicKeyExported = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
        const privateKeyExported = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        return {
          publicKey: new Uint8Array(publicKeyExported),
          privateKey: new Uint8Array(privateKeyExported),
        };
      } catch (err: unknown) {
        throw new Error(`ECDH key pair generation failed for curve ${curve}: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const resolvedCurve = NODE_CURVE_MAP[curve] || curve;
        const crypto = await import('crypto');
        const ecdh = crypto.createECDH(resolvedCurve);
        ecdh.generateKeys();

        return {
          publicKey: new Uint8Array(ecdh.getPublicKey()),
          privateKey: new Uint8Array(ecdh.getPrivateKey()),
        };
      } catch (err: unknown) {
        throw new Error(`ECDH key pair generation failed for curve ${curve}: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    }
    throw new Error('Crypto API is not available in this environment');
  }

  static async deriveSharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array, curve: string = 'P-256'): Promise<Uint8Array> {
    if (!SUPPORTED_CURVES.includes(curve as any)) {
      throw new Error(`Unsupported ECDH curve: ${curve}. Supported curves: ${SUPPORTED_CURVES.join(', ')}`);
    }

    const resolvedCurve = NODE_CURVE_MAP[curve] || curve;

    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const privateKeyImported = await window.crypto.subtle.importKey(
          'pkcs8',
          privateKey,
          {
            name: 'ECDH',
            namedCurve: curve,
          },
          false,
          ['deriveKey', 'deriveBits']
        );

        const publicKeyImported = await window.crypto.subtle.importKey(
          'raw',
          peerPublicKey,
          {
            name: 'ECDH',
            namedCurve: curve,
          },
          false,
          []
        );

        const sharedSecretBits = await window.crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: publicKeyImported,
          },
          privateKeyImported,
          256
        );

        return new Uint8Array(sharedSecretBits);
      } catch (err: unknown) {
        throw new Error(`Failed to derive ECDH shared secret for curve ${curve}: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    } else if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        const crypto = await import('crypto');
        const ecdh = crypto.createECDH(resolvedCurve);
        ecdh.setPrivateKey(Buffer.from(privateKey));
        const sharedSecret = ecdh.computeSecret(Buffer.from(peerPublicKey));
        return new Uint8Array(sharedSecret);
      } catch (err: unknown) {
        throw new Error(`Failed to derive ECDH shared secret for curve ${curve}: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    }
    throw new Error('Crypto API is not available in this environment');
  }
}

export function deriveSymmetricKey(
  sharedSecret: Uint8Array,
  salt: Uint8Array = new Uint8Array(0),
  info: Uint8Array = new Uint8Array(0),
  length: number = 32
): Uint8Array {
  if (length <= 0) {
    throw new Error(`Invalid key length: ${length}. Must be a positive number.`);
  }
  return hkdf(sha256, sharedSecret, salt, info, length);
}

export async function deriveAESKeyFromECDH(
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
  curve: string = 'P-256',
  salt?: Uint8Array,
  info?: Uint8Array,
  keyLength: number = 32
): Promise<Uint8Array> {
  if (keyLength <= 0) {
    throw new Error(`Invalid key length: ${keyLength}. Must be a positive number.`);
  }
  const sharedSecret = await ECDH.deriveSharedSecret(privateKey, peerPublicKey, curve);
  return deriveSymmetricKey(sharedSecret, salt, info, keyLength);
}