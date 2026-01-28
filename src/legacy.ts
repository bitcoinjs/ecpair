import type { CryptoBackend, XOnlyPointAddTweakResult } from './backend.js';
import type {
    Bytes32,
    MessageHash,
    PrivateKey,
    PublicKey,
    SchnorrSignature,
    Signature,
    XOnlyPublicKey,
} from './branded.js';

export interface TinySecp256k1Interface {
    isPoint(p: Uint8Array): boolean;
    pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array;
    isPrivate(d: Uint8Array): boolean;
    pointFromScalar(d: Uint8Array, compressed?: boolean): Uint8Array | null;
    pointAddScalar?(p: Uint8Array, tweak: Uint8Array, compressed?: boolean): Uint8Array | null;
    xOnlyPointAddTweak(
        p: Uint8Array,
        tweak: Uint8Array,
    ): { parity: 1 | 0; xOnlyPubkey: Uint8Array } | null;
    privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
    privateNegate(d: Uint8Array): Uint8Array;
    sign(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
    signSchnorr?(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
    verify(h: Uint8Array, Q: Uint8Array, signature: Uint8Array, strict?: boolean): boolean;
    verifySchnorr?(h: Uint8Array, Q: Uint8Array, signature: Uint8Array): boolean;
}

export class LegacyBackend implements CryptoBackend {
    readonly #ecc: TinySecp256k1Interface;

    public constructor(ecc: TinySecp256k1Interface) {
        this.#ecc = ecc;
    }

    public isPrivate(d: Uint8Array): boolean {
        return this.#ecc.isPrivate(d);
    }

    public isPoint(p: Uint8Array): boolean {
        return this.#ecc.isPoint(p);
    }

    public pointFromScalar(d: PrivateKey, compressed?: boolean): PublicKey | null {
        return this.#ecc.pointFromScalar(d, compressed) as PublicKey | null;
    }

    public pointCompress(p: PublicKey, compressed?: boolean): PublicKey {
        return this.#ecc.pointCompress(p, compressed) as PublicKey;
    }

    public pointAddScalar(p: PublicKey, tweak: Bytes32, compressed?: boolean): PublicKey | null {
        if (!this.#ecc.pointAddScalar) {
            throw new Error('pointAddScalar not supported by ecc library');
        }
        return this.#ecc.pointAddScalar(p, tweak, compressed) as PublicKey | null;
    }

    public xOnlyPointAddTweak(p: XOnlyPublicKey, tweak: Bytes32): XOnlyPointAddTweakResult | null {
        const result = this.#ecc.xOnlyPointAddTweak(p, tweak);
        if (result === null) return null;
        return {
            parity: result.parity,
            xOnlyPubkey: result.xOnlyPubkey as XOnlyPublicKey,
        };
    }

    public privateAdd(d: PrivateKey, tweak: Bytes32): PrivateKey | null {
        return this.#ecc.privateAdd(d, tweak) as PrivateKey | null;
    }

    public privateNegate(d: PrivateKey): PrivateKey {
        return this.#ecc.privateNegate(d) as PrivateKey;
    }

    public sign(hash: MessageHash, privateKey: PrivateKey, extraEntropy?: Uint8Array): Signature {
        return this.#ecc.sign(hash, privateKey, extraEntropy) as Signature;
    }

    public verify(hash: MessageHash, publicKey: PublicKey, signature: Signature): boolean {
        return this.#ecc.verify(hash, publicKey, signature);
    }

    public signSchnorr(hash: MessageHash, privateKey: PrivateKey, extraEntropy?: Uint8Array): SchnorrSignature {
        if (!this.#ecc.signSchnorr) {
            throw new Error('signSchnorr not supported by ecc library');
        }
        return this.#ecc.signSchnorr(hash, privateKey, extraEntropy) as SchnorrSignature;
    }

    public verifySchnorr(hash: MessageHash, publicKey: XOnlyPublicKey, signature: SchnorrSignature): boolean {
        if (!this.#ecc.verifySchnorr) {
            throw new Error('verifySchnorr not supported by ecc library');
        }
        return this.#ecc.verifySchnorr(hash, publicKey, signature);
    }

    public get hasSchnorrSign(): boolean {
        return typeof this.#ecc.signSchnorr === 'function';
    }

    public get hasSchnorrVerify(): boolean {
        return typeof this.#ecc.verifySchnorr === 'function';
    }
}

export function createLegacyBackend(ecc: TinySecp256k1Interface): LegacyBackend {
    return new LegacyBackend(ecc);
}
