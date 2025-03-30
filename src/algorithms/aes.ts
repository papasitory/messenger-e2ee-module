import { ICrypto } from "../interfaces/ICrypto";

export class AESGCM implements ICrypto {
    private static ALGORITHM = "AES-GCM";
    private static KEY_LENGTH = 256;
    private static IV_LENGTH = 12;

    async generateKeys(): Promise<{ publicKey: string; privateKey: string }> {
        const key = await crypto.subtle.generateKey(
            { name: AESGCM.ALGORITHM, length: AESGCM.KEY_LENGTH },
            true,
            ["encrypt", "decrypt"]
        );
        const exportedKey = Buffer.from(await crypto.subtle.exportKey("raw", key)).toString("base64");
        return { publicKey: exportedKey, privateKey: exportedKey };
    }

    async encrypt(plainText: string, base64Key: string): Promise<string> {
        const key = await this.importKey(base64Key);
        const iv = crypto.getRandomValues(new Uint8Array(AESGCM.IV_LENGTH));
        const encrypted = await crypto.subtle.encrypt(
            { name: AESGCM.ALGORITHM, iv },
            key,
            new TextEncoder().encode(plainText)
        );
        return Buffer.concat([Buffer.from(iv), Buffer.from(encrypted)]).toString("base64");
    }

    async decrypt(cipherText: string, base64Key: string): Promise<string> {
        const key = await this.importKey(base64Key);
        const data = Buffer.from(cipherText, "base64");
        const iv = data.slice(0, AESGCM.IV_LENGTH);
        const encryptedData = data.slice(AESGCM.IV_LENGTH);
        const decrypted = await crypto.subtle.decrypt({ name: AESGCM.ALGORITHM, iv }, key, encryptedData);
        return new TextDecoder().decode(decrypted);
    }

    private async importKey(base64Key: string): Promise<CryptoKey> {
        return await crypto.subtle.importKey(
            "raw",
            Buffer.from(base64Key, "base64"),
            { name: AESGCM.ALGORITHM },
            false,
            ["encrypt", "decrypt"]
        );
    }
}
