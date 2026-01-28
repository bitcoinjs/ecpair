declare const __brand: unique symbol;

/**
 * Branded type utility. Creates a nominal type from a structural base type.
 * Prevents accidental misuse of structurally identical types (e.g. PrivateKey vs MessageHash).
 */
export type Brand<T, B extends string> = T & { readonly [__brand]: B };

/** 32-byte generic array with length guarantee. */
export type Bytes32 = Brand<Uint8Array, 'Bytes32'>;

/** 20-byte generic array with length guarantee. */
export type Bytes20 = Brand<Uint8Array, 'Bytes20'>;

/** 32-byte valid secp256k1 scalar (private key). */
export type PrivateKey = Brand<Uint8Array, 'PrivateKey'>;

/** 33 or 65-byte SEC1 encoded public key. */
export type PublicKey = Brand<Uint8Array, 'PublicKey'>;

/** 32-byte BIP340 x-only public key. */
export type XOnlyPublicKey = Brand<Uint8Array, 'XOnlyPublicKey'>;

/** DER-encoded ECDSA signature (8-73 bytes). */
export type Signature = Brand<Uint8Array, 'Signature'>;

/** 64-byte BIP340 Schnorr signature. */
export type SchnorrSignature = Brand<Uint8Array, 'SchnorrSignature'>;

/** 32-byte hash being signed. Semantically distinct from PrivateKey and Bytes32. */
export type MessageHash = Brand<Uint8Array, 'MessageHash'>;

/** Bitcoin script bytecode. */
export type Script = Brand<Uint8Array, 'Script'>;

/** Bitcoin amount in satoshis. */
export type Satoshi = Brand<bigint, 'Satoshi'>;
