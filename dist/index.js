"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Ed25519 = exports.ECDH = void 0;
exports.encryptMessage = encryptMessage;
exports.decryptMessage = decryptMessage;
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const utils_1 = require("./utils");
class ECDH {
    constructor() {
        this.keyPair = tweetnacl_1.default.box.keyPair();
    }
    getPublicKey() {
        return (0, utils_1.encodeBase64)(this.keyPair.publicKey);
    }
    getPrivateKey() {
        return this.keyPair.secretKey;
    }
    computeSharedSecret(peerPublicKeyBase64) {
        const peerPublicKey = (0, utils_1.decodeBase64)(peerPublicKeyBase64);
        return tweetnacl_1.default.box.before(peerPublicKey, this.keyPair.secretKey);
    }
}
exports.ECDH = ECDH;
function encryptMessage(key, message) {
    return __awaiter(this, void 0, void 0, function* () {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();
        const encodedMessage = encoder.encode(message);
        const cryptoKey = yield crypto.subtle.importKey("raw", key, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
        const encrypted = yield crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, encodedMessage);
        return (0, utils_1.encodeBase64)(new Uint8Array([...iv, ...new Uint8Array(encrypted)]));
    });
}
function decryptMessage(key, encryptedBase64) {
    return __awaiter(this, void 0, void 0, function* () {
        const encryptedData = (0, utils_1.decodeBase64)(encryptedBase64);
        const iv = encryptedData.slice(0, 12);
        const encryptedMessage = encryptedData.slice(12);
        const cryptoKey = yield crypto.subtle.importKey("raw", key, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
        const decrypted = yield crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, encryptedMessage);
        return new TextDecoder().decode(decrypted);
    });
}
class Ed25519 {
    constructor() {
        this.keyPair = tweetnacl_1.default.sign.keyPair();
    }
    getPublicKey() {
        return (0, utils_1.encodeBase64)(this.keyPair.publicKey);
    }
    signMessage(message) {
        const encodedMessage = new TextEncoder().encode(message);
        return (0, utils_1.encodeBase64)(tweetnacl_1.default.sign(encodedMessage, this.keyPair.secretKey));
    }
    verifySignature(message, signatureBase64, publicKeyBase64) {
        const encodedMessage = new TextEncoder().encode(message);
        const signature = (0, utils_1.decodeBase64)(signatureBase64);
        const publicKey = (0, utils_1.decodeBase64)(publicKeyBase64);
        return tweetnacl_1.default.sign.open(signature, publicKey) !== null;
    }
}
exports.Ed25519 = Ed25519;
