declare module 'chacha20' {
    export class ChaCha20 {
      constructor(key: Uint8Array, nonce: Uint8Array);
      update(output: Uint8Array, input: Uint8Array): void;
    }
  }