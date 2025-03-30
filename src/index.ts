import nacl from "tweetnacl";
import { encodeBase64, decodeBase64 } from "./utils";

export class ECDH {
    private keyPair: nacl.BoxKeyPair;

    constructor() {
        this.keyPair = nacl.box.keyPair();
    }

    getPublicKey(): string {
        return encodeBase64(this.keyPair.publicKey);
    }

    getPrivateKey(): Uint8Array {
        return this.keyPair.secretKey;
    }

    computeSharedSecret(peerPublicKeyBase64: string): Uint8Array {
        const peerPublicKey = decodeBase64(peerPublicKeyBase64);
        return nacl.box.before(peerPublicKey, this.keyPair.secretKey);
    }
}

export async function encryptMessage(key: Uint8Array, message: string): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedMessage = encoder.encode(message);

    const cryptoKey = await crypto.subtle.importKey(
        "raw", key, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
    );

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        encodedMessage
    );

    return encodeBase64(new Uint8Array([...iv, ...new Uint8Array(encrypted)]));
}

export async function decryptMessage(key: Uint8Array, encryptedBase64: string): Promise<string> {
    const encryptedData = decodeBase64(encryptedBase64);
    const iv = encryptedData.slice(0, 12);
    const encryptedMessage = encryptedData.slice(12);

    const cryptoKey = await crypto.subtle.importKey(
        "raw", key, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        encryptedMessage
    );

    return new TextDecoder().decode(decrypted);
}

export class Ed25519 {
    private keyPair: nacl.SignKeyPair;

    constructor() {
        this.keyPair = nacl.sign.keyPair();
    }

    getPublicKey(): string {
        return encodeBase64(this.keyPair.publicKey);
    }

    signMessage(message: string): string {
        const encodedMessage = new TextEncoder().encode(message);
        return encodeBase64(nacl.sign(encodedMessage, this.keyPair.secretKey));
    }

    verifySignature(message: string, signatureBase64: string, publicKeyBase64: string): boolean {
        const encodedMessage = new TextEncoder().encode(message);
        const signature = decodeBase64(signatureBase64);
        const publicKey = decodeBase64(publicKeyBase64);

        return nacl.sign.open(signature, publicKey) !== null;
    }
}
