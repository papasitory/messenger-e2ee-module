import nacl from "tweetnacl";

export class Ed25519 {
    async generateKeys(): Promise<{ publicKey: string; privateKey: string }> {
        const keyPair = nacl.sign.keyPair();
        return {
            publicKey: Buffer.from(keyPair.publicKey).toString("base64"),
            privateKey: Buffer.from(keyPair.secretKey).toString("base64"),
        };
    }

    async signMessage(message: string, privateKey: string): Promise<string> {
        const signedMessage = nacl.sign(
            Buffer.from(message, "utf8"),
            Buffer.from(privateKey, "base64")
        );
        return Buffer.from(signedMessage).toString("base64");
    }

    async verifySignature(signedMessage: string, publicKey: string): Promise<boolean> {
        const decodedMessage = Buffer.from(signedMessage, "base64");
        const verified = nacl.sign.open(
            decodedMessage,
            Buffer.from(publicKey, "base64")
        );
        return verified !== null;
    }
}
