import { ICrypto } from "../interfaces/ICrypto";
import nacl from "tweetnacl";

export class ECDH implements ICrypto {
    async generateKeys(): Promise<{ publicKey: string; privateKey: string }> {
        const keyPair = nacl.box.keyPair();
        return {
            publicKey: Buffer.from(keyPair.publicKey).toString("base64"),
            privateKey: Buffer.from(keyPair.secretKey).toString("base64"),
        };
    }

    async encrypt(plainText: string, receiverPublicKey: string): Promise<string> {
        const nonce = nacl.randomBytes(nacl.box.nonceLength);
        const encrypted = nacl.box(
            Buffer.from(plainText, "utf8"),
            nonce,
            Buffer.from(receiverPublicKey, "base64"),
            Buffer.from(receiverPublicKey, "base64")
        );
        return Buffer.concat([nonce, Buffer.from(encrypted)]).toString("base64");
    }

    async decrypt(cipherText: string, privateKey: string): Promise<string> {
        const decoded = Buffer.from(cipherText, "base64");
        const nonce = decoded.slice(0, nacl.box.nonceLength);
        const message = decoded.slice(nacl.box.nonceLength);
        const decrypted = nacl.box.open(
            message,
            nonce,
            Buffer.from(privateKey, "base64"),
            Buffer.from(privateKey, "base64")
        );
        return decrypted ? Buffer.from(decrypted).toString("utf8") : "";
    }
}
