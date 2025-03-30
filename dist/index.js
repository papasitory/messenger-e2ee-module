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
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("./crypto");
const aes_1 = require("./algorithms/aes");
function test() {
    return __awaiter(this, void 0, void 0, function* () {
        const crypto = new crypto_1.CryptoManager(new aes_1.AESGCM());
        const keys = yield crypto.generateKeys();
        const encrypted = yield crypto.encrypt("Hello, World!", keys.publicKey);
        const decrypted = yield crypto.decrypt(encrypted, keys.publicKey);
        console.log("🔒 Encrypted:", encrypted);
        console.log("🔓 Decrypted:", decrypted);
    });
}
test();
