import type { CryptoBackend } from './backend.js';
import type {
    Bytes32,
    MessageHash,
    PrivateKey,
    PublicKey,
    SchnorrSignature,
    Signature,
    XOnlyPublicKey,
} from './branded.js';
import { SignerCapability } from './capability.js';
import type { Network } from './networks.js';
import * as networks from './networks.js';
import { createPrivateKey, createPublicKey, concatBytes } from './types.js';
import { encodeWIF, decodeWIF } from './wif.js';

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface Signer {
    readonly publicKey: PublicKey;
    readonly network?: Network | undefined;
    sign(hash: MessageHash, lowR?: boolean): Signature;
    signSchnorr?(hash: MessageHash): SchnorrSignature;
}

export interface SignerAsync {
    readonly publicKey: PublicKey;
    readonly network?: Network | undefined;
    sign(hash: MessageHash, lowR?: boolean): Promise<Signature>;
    signSchnorr?(hash: MessageHash): Promise<SchnorrSignature>;
}

export interface UniversalSigner extends Signer {
    readonly xOnlyPublicKey: XOnlyPublicKey;
    readonly network: Network;
    readonly compressed: boolean;
    readonly capabilities: ReadonlySet<SignerCapability>;
    readonly privateKey?: PrivateKey | undefined;
    hasCapability(cap: SignerCapability): boolean;
    verify(hash: MessageHash, signature: Signature): boolean;
    verifySchnorr(hash: MessageHash, signature: SchnorrSignature): boolean;
    tweak(t: Bytes32): UniversalSigner;
    toWIF(): string;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface SignerOptions {
    readonly compressed?: boolean | undefined;
    readonly network?: Network | undefined;
}

export interface RandomSignerOptions extends SignerOptions {
    readonly rng?: ((size: number) => Uint8Array) | undefined;
}

// ---------------------------------------------------------------------------
// ECPairSigner
// ---------------------------------------------------------------------------

const toXOnly = (pubKey: Uint8Array): Uint8Array =>
    pubKey.length === 32 ? pubKey : pubKey.subarray(1, 33);

export class ECPairSigner implements UniversalSigner {
    readonly #backend: CryptoBackend;
    readonly #privateKey: PrivateKey | undefined;
    readonly #network: Network;
    readonly #compressed: boolean;
    #publicKey: PublicKey | undefined;
    #xOnlyPublicKey: XOnlyPublicKey | undefined;
    #capabilities: ReadonlySet<SignerCapability> | undefined;

    private constructor(
        backend: CryptoBackend,
        privateKey: PrivateKey | undefined,
        publicKey: PublicKey | undefined,
        options?: SignerOptions,
    ) {
        this.#backend = backend;
        this.#privateKey = privateKey;
        this.#compressed = options?.compressed ?? true;
        this.#network = options?.network ?? networks.bitcoin;

        if (publicKey !== undefined) {
            this.#publicKey = backend.pointCompress(publicKey, this.#compressed);
        }
    }

    // -----------------------------------------------------------------------
    // Static factories
    // -----------------------------------------------------------------------

    public static fromPrivateKey(
        backend: CryptoBackend,
        privateKey: PrivateKey,
        options?: SignerOptions,
    ): ECPairSigner {
        if (!backend.isPrivate(privateKey)) {
            throw new TypeError('Private key not in range [1, n)');
        }
        return new ECPairSigner(backend, privateKey, undefined, options);
    }

    public static fromPublicKey(
        backend: CryptoBackend,
        publicKey: PublicKey,
        options?: SignerOptions,
    ): ECPairSigner {
        if (!backend.isPoint(publicKey)) {
            throw new Error('Point not on the curve');
        }
        return new ECPairSigner(backend, undefined, publicKey, options);
    }

    public static fromWIF(
        backend: CryptoBackend,
        wifString: string,
        network?: Network | readonly Network[],
    ): ECPairSigner {
        const defaultNetwork = network ?? networks.bitcoin;
        const decoded = decodeWIF(wifString, defaultNetwork);
        return ECPairSigner.fromPrivateKey(backend, decoded.privateKey, {
            compressed: decoded.compressed,
            network: decoded.network,
        });
    }

    public static makeRandom(backend: CryptoBackend, options?: RandomSignerOptions): ECPairSigner {
        let privateKeyBytes: Uint8Array;

        if (backend.generatePrivateKey && !options?.rng) {
            privateKeyBytes = backend.generatePrivateKey();
        } else {
            const rng =
                options?.rng ?? ((size: number) => crypto.getRandomValues(new Uint8Array(size)));
            do {
                privateKeyBytes = rng(32);
                if (privateKeyBytes.length !== 32) {
                    throw new TypeError(
                        `Expected 32 bytes from rng, got ${privateKeyBytes.length} bytes`,
                    );
                }
            } while (!backend.isPrivate(privateKeyBytes));
        }

        return ECPairSigner.fromPrivateKey(backend, createPrivateKey(privateKeyBytes), options);
    }

    // -----------------------------------------------------------------------
    // Public properties
    // -----------------------------------------------------------------------

    public get privateKey(): PrivateKey | undefined {
        return this.#privateKey;
    }

    public get publicKey(): PublicKey {
        if (this.#publicKey === undefined) {
            const pk = this.#privateKey;
            if (pk === undefined) {
                throw new Error('Missing both private and public key');
            }
            const p = this.#backend.pointFromScalar(pk, this.#compressed);
            if (p === null) {
                throw new Error('Failed to derive public key from private key');
            }
            this.#publicKey = p;
        }
        return this.#publicKey;
    }

    public get xOnlyPublicKey(): XOnlyPublicKey {
        if (this.#xOnlyPublicKey === undefined) {
            this.#xOnlyPublicKey = toXOnly(this.publicKey) as XOnlyPublicKey;
        }
        return this.#xOnlyPublicKey;
    }

    public get network(): Network {
        return this.#network;
    }

    public get compressed(): boolean {
        return this.#compressed;
    }

    public get capabilities(): ReadonlySet<SignerCapability> {
        if (this.#capabilities === undefined) {
            const caps = new Set<SignerCapability>();
            caps.add(SignerCapability.EcdsaVerify);
            caps.add(SignerCapability.PublicKeyTweak);
            if (this.#privateKey !== undefined) {
                caps.add(SignerCapability.EcdsaSign);
                caps.add(SignerCapability.PrivateKeyExport);
            }
            if (this.#backend.signSchnorr && this.#privateKey !== undefined) {
                caps.add(SignerCapability.SchnorrSign);
            }
            if (this.#backend.verifySchnorr) {
                caps.add(SignerCapability.SchnorrVerify);
            }
            this.#capabilities = caps;
        }
        return this.#capabilities;
    }

    // -----------------------------------------------------------------------
    // Methods
    // -----------------------------------------------------------------------

    public hasCapability(cap: SignerCapability): boolean {
        return this.capabilities.has(cap);
    }

    public sign(hash: MessageHash, lowR?: boolean): Signature {
        if (this.#privateKey === undefined) throw new Error('Missing private key');
        if (lowR === false || lowR === undefined) {
            return this.#backend.sign(hash, this.#privateKey);
        }
        // lowR grinding
        let sig = this.#backend.sign(hash, this.#privateKey);
        const extraData = new Uint8Array(32);
        const view = new DataView(extraData.buffer, extraData.byteOffset, extraData.byteLength);
        let counter = 0;
        while (sig[0] !== undefined && sig[0] > 0x7f) {
            counter++;
            view.setUint32(0, counter, true); // LE
            sig = this.#backend.sign(hash, this.#privateKey, extraData);
        }
        return sig;
    }

    public signSchnorr(hash: MessageHash): SchnorrSignature {
        if (this.#privateKey === undefined) throw new Error('Missing private key');
        if (!this.#backend.signSchnorr) {
            throw new Error('signSchnorr not supported by ecc library');
        }
        return this.#backend.signSchnorr(hash, this.#privateKey);
    }

    public verify(hash: MessageHash, signature: Signature): boolean {
        return this.#backend.verify(hash, this.publicKey, signature);
    }

    public verifySchnorr(hash: MessageHash, signature: SchnorrSignature): boolean {
        if (!this.#backend.verifySchnorr) {
            throw new Error('verifySchnorr not supported by ecc library');
        }
        return this.#backend.verifySchnorr(hash, this.xOnlyPublicKey, signature);
    }

    public tweak(t: Bytes32): ECPairSigner {
        if (this.#privateKey !== undefined) {
            return this.#tweakFromPrivateKey(t);
        }
        return this.#tweakFromPublicKey(t);
    }

    public toWIF(): string {
        if (this.#privateKey === undefined) throw new Error('Missing private key');
        return encodeWIF(this.#privateKey, this.#compressed, this.#network);
    }

    // -----------------------------------------------------------------------
    // Private tweak helpers
    // -----------------------------------------------------------------------

    #tweakFromPrivateKey(t: Bytes32): ECPairSigner {
        const pubKey = this.publicKey;
        const privateKey = this.#privateKey;
        if (privateKey === undefined) {
            throw new Error('Missing private key');
        }
        const hasOddY =
            pubKey[0] === 3 || (pubKey[0] === 4 && pubKey.length === 65 && ((pubKey[64] as number) & 1) === 1);
        const effectiveKey = hasOddY
            ? this.#backend.privateNegate(privateKey)
            : privateKey;

        const tweakedPrivateKey = this.#backend.privateAdd(effectiveKey, t);
        if (tweakedPrivateKey === null) throw new Error('Invalid tweaked private key!');

        return ECPairSigner.fromPrivateKey(this.#backend, tweakedPrivateKey, {
            network: this.#network,
            compressed: this.#compressed,
        });
    }

    #tweakFromPublicKey(t: Bytes32): ECPairSigner {
        const xOnlyPubKey = this.xOnlyPublicKey;
        const tweakedPublicKey = this.#backend.xOnlyPointAddTweak(xOnlyPubKey, t);
        if (tweakedPublicKey === null || tweakedPublicKey.xOnlyPubkey === null) {
            throw new Error('Cannot tweak public key!');
        }
        const parityByte = new Uint8Array([tweakedPublicKey.parity === 0 ? 0x02 : 0x03]);
        const fullKey = concatBytes(parityByte, tweakedPublicKey.xOnlyPubkey);
        return ECPairSigner.fromPublicKey(this.#backend, createPublicKey(fullKey), {
            network: this.#network,
            compressed: this.#compressed,
        });
    }
}
