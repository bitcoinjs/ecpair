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
export declare class ECPair implements ECPairInterface {
    private __D?;
    private __Q?;
    static isPoint(maybePoint: any): boolean;
    static fromPrivateKey(buffer: Buffer, options?: ECPairOptions): ECPair;
    static fromPublicKey(buffer: Buffer, options?: ECPairOptions): ECPair;
    static fromWIF(wifString: string, network?: Network | Network[]): ECPair;
    static makeRandom(options?: ECPairOptions): ECPair;
    compressed: boolean;
    network: Network;
    lowR: boolean;
    protected constructor(__D?: Buffer | undefined, __Q?: Buffer | undefined, options?: ECPairOptions);
    get privateKey(): Buffer | undefined;
    get publicKey(): Buffer;
    toWIF(): string;
    sign(hash: Buffer, lowR?: boolean): Buffer;
    verify(hash: Buffer, signature: Buffer): boolean;
}
