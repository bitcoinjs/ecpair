import { Network } from './networks';
import * as networks from './networks';
export { networks };
import * as v from 'valibot';
declare const ECPairOptionsSchema: v.OptionalSchema<v.ObjectSchema<{
    readonly compressed: v.OptionalSchema<v.BooleanSchema<undefined>, never>;
    readonly network: v.OptionalSchema<v.ObjectSchema<{
        readonly messagePrefix: v.UnionSchema<[v.StringSchema<undefined>, v.InstanceSchema<Uint8ArrayConstructor, undefined>], undefined>;
        readonly bech32: v.StringSchema<undefined>;
        readonly bip32: v.ObjectSchema<{
            readonly public: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 4294967295, undefined>]>;
            readonly private: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 4294967295, undefined>]>;
        }, undefined>;
        readonly pubKeyHash: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 255, undefined>]>;
        readonly scriptHash: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 255, undefined>]>;
        readonly wif: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 255, undefined>]>;
    }, undefined>, never>;
    readonly rng: v.OptionalSchema<v.SchemaWithPipe<[v.InstanceSchema<FunctionConstructor, undefined>, v.TransformAction<Function, (arg?: number) => Uint8Array>]>, never>;
}, undefined>, never>;
type ECPairOptions = v.InferOutput<typeof ECPairOptionsSchema>;
export interface Signer {
    publicKey: Uint8Array;
    network?: any;
    sign(hash: Uint8Array, lowR?: boolean): Uint8Array;
}
export interface SignerAsync {
    publicKey: Uint8Array;
    network?: any;
    sign(hash: Uint8Array, lowR?: boolean): Promise<Uint8Array>;
}
export interface ECPairInterface extends Signer {
    compressed: boolean;
    network: Network;
    lowR: boolean;
    privateKey?: Uint8Array;
    toWIF(): string;
    tweak(t: Uint8Array): ECPairInterface;
    verify(hash: Uint8Array, signature: Uint8Array): boolean;
    verifySchnorr(hash: Uint8Array, signature: Uint8Array): boolean;
    signSchnorr(hash: Uint8Array): Uint8Array;
}
export interface ECPairAPI {
    isPoint(maybePoint: any): boolean;
    fromPrivateKey(buffer: Uint8Array, options?: ECPairOptions): ECPairInterface;
    fromPublicKey(buffer: Uint8Array, options?: ECPairOptions): ECPairInterface;
    fromWIF(wifString: string, network?: Network | Network[]): ECPairInterface;
    makeRandom(options?: ECPairOptions): ECPairInterface;
}
export interface TinySecp256k1Interface {
    isPoint(p: Uint8Array): boolean;
    pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array;
    isPrivate(d: Uint8Array): boolean;
    pointFromScalar(d: Uint8Array, compressed?: boolean): Uint8Array | null;
    xOnlyPointAddTweak(p: Uint8Array, tweak: Uint8Array): XOnlyPointAddTweakResult | null;
    privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
    privateNegate(d: Uint8Array): Uint8Array;
    sign(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
    signSchnorr?(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
    verify(h: Uint8Array, Q: Uint8Array, signature: Uint8Array, strict?: boolean): boolean;
    verifySchnorr?(h: Uint8Array, Q: Uint8Array, signature: Uint8Array): boolean;
}
interface XOnlyPointAddTweakResult {
    parity: 1 | 0;
    xOnlyPubkey: Uint8Array;
}
export declare function ECPairFactory(ecc: TinySecp256k1Interface): ECPairAPI;
