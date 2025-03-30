import { ICrypto } from "./interfaces/ICrypto";
import { AESGCM } from "./algorithms/aes";
import { ECDH } from "./algorithms/ecdh";
import { Ed25519 } from "./algorithms/ed25519";

export class CryptoManager {
    private algorithm: ICrypto;

    constructor(algorithm: ICrypto) {
        this.algorithm = algorithm;
    }

    async generateKeys() {
        return this.algorithm.generateKeys();
    }

    async encrypt(data: string, key: string) {
        return this.algorithm.encrypt(data, key);
    }

    async decrypt(data: string, key: string) {
        return this.algorithm.decrypt(data, key);
    }

    async sign?(message: string, privateKey: string) {
        return this.algorithm.sign?.(message, privateKey);
    }

    async verify?(message: string, signature: string, publicKey: string) {
        return this.algorithm.verify?.(message, signature, publicKey);
    }
}
