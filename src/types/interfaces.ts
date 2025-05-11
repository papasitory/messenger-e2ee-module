// src/types/interfaces.ts
export interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  }
  
  export interface SerializedKeyPair {
    publicKey: string;
    privateKey: string;
  }
  
  export interface EncryptionResult {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    authTag?: Uint8Array; // Для аутентифицированного шифрования (AES-GCM)
  }
  
  export interface SerializedEncryptionResult {
    ciphertext: string;
    iv: string;
    authTag?: string;
  }
  
  export interface SymmetricEncryptionAlgorithm {
    generateKey(options?: any): Promise<Uint8Array>;
    encrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Promise<EncryptionResult>;
    decrypt(result: EncryptionResult, key: Uint8Array): Promise<Uint8Array>;
  }
  
  export interface AsymmetricKeyExchangeAlgorithm {
    generateKeyPair(options?: any): Promise<KeyPair>;
    deriveSharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Promise<Uint8Array>;
  }
  
  export interface AsymmetricSignatureAlgorithm {
    generateKeyPair(options?: any): Promise<KeyPair>;
    sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
  }
  
  export interface PostQuantumKeyExchangeAlgorithm {
    generateKeyPair(options?: any): Promise<KeyPair>;
    encapsulate(publicKey: Uint8Array): Promise<{sharedSecret: Uint8Array, ciphertext: Uint8Array}>;
    decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
  }
  
  export interface PostQuantumSignatureAlgorithm {
    generateKeyPair(options?: any): Promise<KeyPair>;
    sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
  }