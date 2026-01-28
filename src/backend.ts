import type {
    Bytes32,
    MessageHash,
    PrivateKey,
    PublicKey,
    SchnorrSignature,
    Signature,
    XOnlyPublicKey,
} from './branded.js';

export type Parity = 0 | 1;

export interface XOnlyPointAddTweakResult {
    readonly parity: Parity;
    readonly xOnlyPubkey: XOnlyPublicKey;
}

export interface CryptoBackend {
    isPrivate(d: Uint8Array): boolean;
    isPoint(p: Uint8Array): boolean;
    pointFromScalar(d: PrivateKey, compressed?: boolean): PublicKey | null;
    pointCompress(p: PublicKey, compressed?: boolean): PublicKey;
    pointAddScalar(p: PublicKey, tweak: Bytes32, compressed?: boolean): PublicKey | null;
    xOnlyPointAddTweak(p: XOnlyPublicKey, tweak: Bytes32): XOnlyPointAddTweakResult | null;
    privateAdd(d: PrivateKey, tweak: Bytes32): PrivateKey | null;
    privateNegate(d: PrivateKey): PrivateKey;
    sign(hash: MessageHash, privateKey: PrivateKey, extraEntropy?: Uint8Array): Signature;
    verify(hash: MessageHash, publicKey: PublicKey, signature: Signature): boolean;
    signSchnorr?(hash: MessageHash, privateKey: PrivateKey, extraEntropy?: Uint8Array): SchnorrSignature;
    verifySchnorr?(hash: MessageHash, publicKey: XOnlyPublicKey, signature: SchnorrSignature): boolean;
    generatePrivateKey?(): PrivateKey;
}
