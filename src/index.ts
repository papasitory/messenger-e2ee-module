import { CryptoManager } from "./crypto";
import { AESGCM } from "./algorithms/aes";

async function test() {
    const crypto = new CryptoManager(new AESGCM());
    const keys = await crypto.generateKeys();
    const encrypted = await crypto.encrypt("Hello, World!", keys.publicKey);
    const decrypted = await crypto.decrypt(encrypted, keys.publicKey);

    console.log("🔒 Encrypted:", encrypted);
    console.log("🔓 Decrypted:", decrypted);
}

test();
