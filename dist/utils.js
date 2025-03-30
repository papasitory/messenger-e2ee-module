"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encodeBase64 = encodeBase64;
exports.decodeBase64 = decodeBase64;
function encodeBase64(data) {
    return Buffer.from(data).toString("base64");
}
function decodeBase64(base64) {
    return new Uint8Array(Buffer.from(base64, "base64"));
}
