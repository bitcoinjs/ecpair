import { Network } from './networks';
import * as networks from './networks';
import * as types from './types';
import * as randomBytes from 'randombytes';
import * as wif from 'wif';
export { networks };

const ecc = require('tiny-secp256k1');

const isOptions = types.typeforce.maybe(
  types.typeforce.compile({
    compressed: types.maybe(types.Boolean),
    network: types.maybe(types.Network),
  }),
);

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

export class ECPair implements ECPairInterface {
  static isPoint(maybePoint: any): boolean {
    return ecc.isPoint(maybePoint);
  }

  static fromPrivateKey(buffer: Buffer, options?: ECPairOptions): ECPair {
    types.typeforce(types.Buffer256bit, buffer);
    if (!ecc.isPrivate(buffer))
      throw new TypeError('Private key not in range [1, n)');
    types.typeforce(isOptions, options);

    return new ECPair(buffer, undefined, options);
  }

  static fromPublicKey(buffer: Buffer, options?: ECPairOptions): ECPair {
    types.typeforce(ecc.isPoint, buffer);
    types.typeforce(isOptions, options);
    return new ECPair(undefined, buffer, options);
  }

  static fromWIF(wifString: string, network?: Network | Network[]): ECPair {
    const decoded = wif.decode(wifString);
    const version = decoded.version;

    // list of networks?
    if (types.Array(network)) {
      network = (network as Network[])
        .filter((x: Network) => {
          return version === x.wif;
        })
        .pop() as Network;

      if (!network) throw new Error('Unknown network version');

      // otherwise, assume a network object (or default to bitcoin)
    } else {
      network = network || networks.bitcoin;

      if (version !== (network as Network).wif)
        throw new Error('Invalid network version');
    }

    return this.fromPrivateKey(decoded.privateKey, {
      compressed: decoded.compressed,
      network: network as Network,
    });
  }

  static makeRandom(options?: ECPairOptions): ECPair {
    types.typeforce(isOptions, options);
    if (options === undefined) options = {};
    const rng = options.rng || randomBytes;

    let d;
    do {
      d = rng(32);
      types.typeforce(types.Buffer256bit, d);
    } while (!ecc.isPrivate(d));

    return this.fromPrivateKey(d, options);
  }

  compressed: boolean;
  network: Network;
  lowR: boolean;

  protected constructor(
    private __D?: Buffer,
    private __Q?: Buffer,
    options?: ECPairOptions,
  ) {
    this.lowR = false;
    if (options === undefined) options = {};
    this.compressed =
      options.compressed === undefined ? true : options.compressed;
    this.network = options.network || networks.bitcoin;

    if (__Q !== undefined) this.__Q = ecc.pointCompress(__Q, this.compressed);
  }

  get privateKey(): Buffer | undefined {
    return this.__D;
  }

  get publicKey(): Buffer {
    if (!this.__Q)
      this.__Q = ecc.pointFromScalar(this.__D, this.compressed) as Buffer;
    return this.__Q;
  }

  toWIF(): string {
    if (!this.__D) throw new Error('Missing private key');
    return wif.encode(this.network.wif, this.__D, this.compressed);
  }

  sign(hash: Buffer, lowR?: boolean): Buffer {
    if (!this.__D) throw new Error('Missing private key');
    if (lowR === undefined) lowR = this.lowR;
    if (lowR === false) {
      return ecc.sign(hash, this.__D);
    } else {
      let sig = ecc.sign(hash, this.__D);
      const extraData = Buffer.alloc(32, 0);
      let counter = 0;
      // if first try is lowR, skip the loop
      // for second try and on, add extra entropy counting up
      while (sig[0] > 0x7f) {
        counter++;
        extraData.writeUIntLE(counter, 0, 6);
        sig = ecc.signWithEntropy(hash, this.__D, extraData);
      }
      return sig;
    }
  }

  verify(hash: Buffer, signature: Buffer): boolean {
    return ecc.verify(hash, this.publicKey, signature);
  }
}
