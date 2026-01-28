import type {
    Bytes20,
    Bytes32,
    MessageHash,
    PrivateKey,
    PublicKey,
    Satoshi,
    SchnorrSignature,
    Signature,
    XOnlyPublicKey,
} from './branded.js';

// ---------------------------------------------------------------------------
// Internal byte utilities (no external deps)
// ---------------------------------------------------------------------------

export function fromHexInternal(hex: string): Uint8Array {
    const len = hex.length;
    if (len % 2 !== 0) throw new TypeError('fromHexInternal: odd-length hex string');
    const out = new Uint8Array(len / 2);
    for (let i = 0; i < len; i += 2) {
        const hi = charToNibble(hex.charCodeAt(i));
        const lo = charToNibble(hex.charCodeAt(i + 1));
        if (hi === -1 || lo === -1) throw new TypeError('fromHexInternal: invalid hex character');
        out[i >> 1] = (hi << 4) | lo;
    }
    return out;
}

function charToNibble(c: number): number {
    if (c >= 48 && c <= 57) return c - 48; // 0-9
    if (c >= 65 && c <= 70) return c - 55; // A-F
    if (c >= 97 && c <= 102) return c - 87; // a-f
    return -1;
}

export function isZeroBytes(bytes: Uint8Array): boolean {
    for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] !== 0) return false;
    }
    return true;
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const minLen = Math.min(a.length, b.length);
    for (let i = 0; i < minLen; i++) {
        const ai = a[i] as number;
        const bi = b[i] as number;
        if (ai < bi) return -1;
        if (ai > bi) return 1;
    }
    if (a.length < b.length) return -1;
    if (a.length > b.length) return 1;
    return 0;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

export function toHex(bytes: Uint8Array): string {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += (bytes[i] as number).toString(16).padStart(2, '0');
    }
    return hex;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    let totalLen = 0;
    for (const a of arrays) totalLen += a.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
        result.set(a, offset);
        offset += a.length;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** secp256k1 curve order. */
export const EC_N: bigint =
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** secp256k1 field prime. */
export const EC_P: bigint =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

/** Maximum satoshi value (21 million BTC). */
export const SATOSHI_MAX: bigint = 21n * 10n ** 14n;

// ---------------------------------------------------------------------------
// Internal helpers for validation
// ---------------------------------------------------------------------------

function bytesToBigInt(bytes: Uint8Array): bigint {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result = (result << 8n) | BigInt(bytes[i] as number);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

export function isBytes32(value: unknown): value is Bytes32 {
    return value instanceof Uint8Array && value.length === 32;
}

export function isBytes20(value: unknown): value is Bytes20 {
    return value instanceof Uint8Array && value.length === 20;
}

export function isPrivateKey(value: unknown): value is PrivateKey {
    if (!(value instanceof Uint8Array) || value.length !== 32) return false;
    if (isZeroBytes(value)) return false;
    const n = bytesToBigInt(value);
    return n < EC_N;
}

export function isPublicKey(value: unknown): value is PublicKey {
    if (!(value instanceof Uint8Array)) return false;
    const prefix = value[0];
    if (value.length === 33 && (prefix === 0x02 || prefix === 0x03)) return true;
    if (
        value.length === 65 &&
        (prefix === 0x04 || prefix === 0x06 || prefix === 0x07)
    )
        return true;
    return false;
}

export function isXOnlyPublicKey(value: unknown): value is XOnlyPublicKey {
    if (!(value instanceof Uint8Array) || value.length !== 32) return false;
    return !isZeroBytes(value);
}

export function isSignature(value: unknown): value is Signature {
    return value instanceof Uint8Array && value.length >= 8 && value.length <= 73;
}

export function isSchnorrSignature(value: unknown): value is SchnorrSignature {
    return value instanceof Uint8Array && value.length === 64;
}

export function isMessageHash(value: unknown): value is MessageHash {
    return value instanceof Uint8Array && value.length === 32;
}

export function isSatoshi(value: unknown): value is Satoshi {
    return typeof value === 'bigint' && value >= 0n && value <= SATOSHI_MAX;
}

// ---------------------------------------------------------------------------
// Assertion functions
// ---------------------------------------------------------------------------

export function assertBytes32(value: unknown): asserts value is Bytes32 {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertBytes32: expected Uint8Array');
    }
    if (value.length !== 32) {
        throw new TypeError(`assertBytes32: expected 32 bytes, got ${value.length} bytes`);
    }
}

export function assertPrivateKey(value: unknown): asserts value is PrivateKey {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertPrivateKey: expected Uint8Array');
    }
    if (value.length !== 32) {
        throw new TypeError(
            `assertPrivateKey: expected 32 bytes, got ${value.length} bytes`,
        );
    }
    if (isZeroBytes(value)) {
        throw new TypeError('assertPrivateKey: key is zero');
    }
    const n = bytesToBigInt(value);
    if (n >= EC_N) {
        throw new TypeError('assertPrivateKey: key not in range [1, n)');
    }
}

export function assertPublicKey(value: unknown): asserts value is PublicKey {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertPublicKey: expected Uint8Array');
    }
    if (!isPublicKey(value)) {
        throw new TypeError(
            `assertPublicKey: invalid SEC1 public key (length=${value.length}, prefix=0x${(value[0] ?? 0).toString(16).padStart(2, '0')})`,
        );
    }
}

export function assertXOnlyPublicKey(value: unknown): asserts value is XOnlyPublicKey {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertXOnlyPublicKey: expected Uint8Array');
    }
    if (value.length !== 32) {
        throw new TypeError(
            `assertXOnlyPublicKey: expected 32 bytes, got ${value.length} bytes`,
        );
    }
    if (isZeroBytes(value)) {
        throw new TypeError('assertXOnlyPublicKey: key is zero');
    }
}

export function assertMessageHash(value: unknown): asserts value is MessageHash {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError('assertMessageHash: expected Uint8Array');
    }
    if (value.length !== 32) {
        throw new TypeError(
            `assertMessageHash: expected 32 bytes, got ${value.length} bytes`,
        );
    }
}

// ---------------------------------------------------------------------------
// Creation functions
// ---------------------------------------------------------------------------

export function createBytes32(bytes: Uint8Array): Bytes32 {
    assertBytes32(bytes);
    return bytes;
}

export function createBytes20(bytes: Uint8Array): Bytes20 {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 20) {
        throw new TypeError(`createBytes20: expected 20 bytes Uint8Array`);
    }
    // No assertion function for Bytes20, manual brand cast required
    return bytes as Bytes20;
}

export function createPrivateKey(bytes: Uint8Array): PrivateKey {
    assertPrivateKey(bytes);
    return bytes;
}

export function createPublicKey(bytes: Uint8Array): PublicKey {
    assertPublicKey(bytes);
    return bytes;
}

export function createXOnlyPublicKey(bytes: Uint8Array): XOnlyPublicKey {
    assertXOnlyPublicKey(bytes);
    return bytes;
}

export function createSignature(bytes: Uint8Array): Signature {
    if (!isSignature(bytes)) {
        throw new TypeError(
            `createSignature: expected 8-73 bytes, got ${bytes.length} bytes`,
        );
    }
    return bytes;
}

export function createSchnorrSignature(bytes: Uint8Array): SchnorrSignature {
    if (!isSchnorrSignature(bytes)) {
        throw new TypeError(
            `createSchnorrSignature: expected 64 bytes, got ${bytes.length} bytes`,
        );
    }
    return bytes;
}

export function createMessageHash(bytes: Uint8Array): MessageHash {
    assertMessageHash(bytes);
    return bytes;
}

export function createSatoshi(value: bigint): Satoshi {
    if (!isSatoshi(value)) {
        throw new TypeError(`createSatoshi: value out of range [0, ${SATOSHI_MAX}]`);
    }
    return value;
}
