/// <reference types="node" />
import { Network } from './networks';
import * as networks from './networks';
export { networks };
interface ECPairOptions {
    compressed?: boolean;
    network?: Network;
    rng?(arg0: number): Buffer;
}
export interface Signer {
    publicKey: Buffer;
    network?: any;
    sign(hash: Buffer, lowR?: boolean): Buffer;
    getPublicKey?(): Buffer;
}
export interface SignerAsync {
    publicKey: Buffer;
    network?: any;
    sign(hash: Buffer, lowR?: boolean): Promise<Buffer>;
    getPublicKey?(): Buffer;
}
export interface ECPairInterface extends Signer {
    compressed: boolean;
    network: Network;
    lowR: boolean;
    privateKey?: Buffer;
    toWIF(): string;
    verify(hash: Buffer, signature: Buffer): boolean;
}
export interface ECPairAPI {
    isPoint(maybePoint: any): boolean;
    fromPrivateKey(buffer: Buffer, options?: ECPairOptions): ECPairInterface;
    fromPublicKey(buffer: Buffer, options?: ECPairOptions): ECPairInterface;
    fromWIF(wifString: string, network?: Network | Network[]): ECPairInterface;
    makeRandom(options?: ECPairOptions): ECPairInterface;
}
export interface TinySecp256k1Interface {
    isPoint(p: Buffer): boolean;
    pointCompress(p: Buffer, compressed?: boolean): Buffer;
    isPrivate(d: Buffer): boolean;
    pointFromScalar(d?: Buffer, compressed?: boolean): Buffer | null;
    sign(h: Buffer, d: Buffer): Buffer;
    signWithEntropy(h: Buffer, d: Buffer, e?: Buffer): Buffer;
    verify(h: Buffer, Q: Buffer, signature: Buffer, strict?: boolean): boolean;
}
export declare function ECPairFactory(ecc: TinySecp256k1Interface): ECPairAPI;
