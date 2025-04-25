// src/__tests__/crypto-utils.test.ts
import { CryptoUtils } from '../utils/crypto-utils';

describe('CryptoUtils', () => {
  describe('randomBytes', () => {
    it('should return Uint8Array of given length', async () => {
      const len = 16;
      const bytes = await CryptoUtils.randomBytes(len);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes).toHaveLength(len);
    });
  });

  describe('Base64 encoding/decoding', () => {
    const sample = new Uint8Array([0, 1, 2, 250, 255]);

    it('toBase64 should encode data to Base64 string', () => {
      const b64 = CryptoUtils.toBase64(sample);
      // "AAEC+v8=" is expected Base64 for [0,1,2,250,255]
      expect(b64).toBe('AAEC+v8=');
    });

    it('fromBase64 should decode Base64 string back to Uint8Array', () => {
      const b64 = 'AAEC+v8=';
      const arr = CryptoUtils.fromBase64(b64);
      expect(arr).toBeInstanceOf(Uint8Array);
      expect(Array.from(arr)).toEqual(Array.from(sample));
    });

    it('round-trip toBase64/fromBase64 preserves data', () => {
      const b64 = CryptoUtils.toBase64(sample);
      const arr = CryptoUtils.fromBase64(b64);
      expect(Array.from(arr)).toEqual(Array.from(sample));
    });
  });

  describe('KeyPair serialization', () => {
    const kp = {
      publicKey: new Uint8Array([10, 20, 30]),
      privateKey: new Uint8Array([40, 50, 60])
    };

    it('serializeKeyPair should produce base64 strings', () => {
      const serialized = CryptoUtils.serializeKeyPair(kp);
      expect(typeof serialized.publicKey).toBe('string');
      expect(typeof serialized.privateKey).toBe('string');
    });

    it('deserializeKeyPair should restore original Uint8Array values', () => {
      const serialized = CryptoUtils.serializeKeyPair(kp);
      const deserialized = CryptoUtils.deserializeKeyPair(serialized);
      expect(Array.from(deserialized.publicKey)).toEqual(Array.from(kp.publicKey));
      expect(Array.from(deserialized.privateKey)).toEqual(Array.from(kp.privateKey));
    });
  });

  describe('EncryptionResult serialization', () => {
    const baseResult = {
      ciphertext: new Uint8Array([1, 2, 3]),
      iv: new Uint8Array([4, 5, 6]),
      authTag: new Uint8Array([7, 8, 9])
    };

    it('serializeEncryptionResult and deserializeEncryptionResult with authTag', () => {
      const serialized = CryptoUtils.serializeEncryptionResult(baseResult);
      expect(serialized).toHaveProperty('ciphertext');
      expect(serialized).toHaveProperty('iv');
      expect(serialized).toHaveProperty('authTag');

      const deserialized = CryptoUtils.deserializeEncryptionResult(serialized);
      expect(Array.from(deserialized.ciphertext)).toEqual(Array.from(baseResult.ciphertext));
      expect(Array.from(deserialized.iv)).toEqual(Array.from(baseResult.iv));
      expect(Array.from(deserialized.authTag!)).toEqual(Array.from(baseResult.authTag));
    });

    it('serializeEncryptionResult without authTag omits authTag field', () => {
      const { authTag, ...partial } = baseResult;
      const serialized = CryptoUtils.serializeEncryptionResult(partial as any);
      expect(serialized).not.toHaveProperty('authTag');

      const deserialized = CryptoUtils.deserializeEncryptionResult(serialized);
      expect(deserialized).not.toHaveProperty('authTag');
      expect(Array.from(deserialized.ciphertext)).toEqual(Array.from(partial.ciphertext));
    });
  });

  describe('String <-> Bytes conversion', () => {
    const tests = ['hello', 'Привет, мир!'];

    tests.forEach(str => {
      it(`stringToBytes and bytesToString round-trip for "${str}"`, () => {
        const bytes = CryptoUtils.stringToBytes(str);
        expect(bytes).toBeInstanceOf(Uint8Array);
        const back = CryptoUtils.bytesToString(bytes);
        expect(back).toBe(str);
      });
    });
  });

  describe('constantTimeEqual', () => {
    it('returns true for identical arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3]);
      expect(CryptoUtils.constantTimeEqual(a, b)).toBe(true);
    });

    it('returns false for arrays with same length but different content', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 4]);
      expect(CryptoUtils.constantTimeEqual(a, b)).toBe(false);
    });

    it('returns false for arrays of different length', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2]);
      expect(CryptoUtils.constantTimeEqual(a, b)).toBe(false);
    });
  });
});
