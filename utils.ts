export function encodeBase64(data: Uint8Array): string {
    return Buffer.from(data).toString("base64");
}

export function decodeBase64(base64: string): Uint8Array {
    return new Uint8Array(Buffer.from(base64, "base64"));
}
