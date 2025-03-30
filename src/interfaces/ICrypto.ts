export interface ICrypto {
    generateKeys(): Promise<{ publicKey: string; privateKey: string }>;
    encrypt(data: string, key: string): Promise<string>;
    decrypt(data: string, key: string): Promise<string>;
    sign?(message: string, privateKey: string): Promise<string>;
    verify?(message: string, signature: string, publicKey: string): Promise<boolean>;
}
