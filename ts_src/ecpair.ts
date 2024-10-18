import * as networks from './networks.js';
import { Network } from './networks.js';
import * as types from './types.js';
import * as wif from 'wif';
import { testEcc } from './testecc.js';
import * as v from 'valibot';
import * as tools from 'uint8array-tools';

export { networks };

const ECPairOptionsSchema = v.optional(
  v.object({
    compressed: v.optional(v.boolean()),
    network: v.optional(types.NetworkSchema),
    // https://github.com/fabian-hiller/valibot/issues/243#issuecomment-2182514063
    rng: v.optional(
      v.pipe(
        v.instance(Function),
        v.transform((func) => {
          return (arg?: number) => {
            const parsedArg = v.parse(v.optional(v.number()), arg);
            const returnedValue = func(parsedArg);
            return v.parse(v.instance(Uint8Array), returnedValue);
          };
        }),
      ),
    ),
  }),
);

type ECPairOptions = v.InferOutput<typeof ECPairOptionsSchema>;

const toXOnly = (pubKey: Uint8Array) =>
  pubKey.length === 32 ? pubKey : pubKey.subarray(1, 33);

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
  xOnlyPointAddTweak(
    p: Uint8Array,
    tweak: Uint8Array,
  ): XOnlyPointAddTweakResult | null;

  privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
  privateNegate(d: Uint8Array): Uint8Array;

  sign(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
  signSchnorr?(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;

  verify(
    h: Uint8Array,
    Q: Uint8Array,
    signature: Uint8Array,
    strict?: boolean,
  ): boolean;
  verifySchnorr?(h: Uint8Array, Q: Uint8Array, signature: Uint8Array): boolean;
}

interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}

export function ECPairFactory(ecc: TinySecp256k1Interface): ECPairAPI {
  testEcc(ecc);
  function isPoint(maybePoint: any): boolean {
    return ecc.isPoint(maybePoint);
  }

  function fromPrivateKey(
    buffer: Uint8Array,
    options?: ECPairOptions,
  ): ECPairInterface {
    v.parse(types.Buffer256Bit, buffer);
    if (!ecc.isPrivate(buffer))
      throw new TypeError('Private key not in range [1, n)');
    v.parse(ECPairOptionsSchema, options);

    return new ECPair(buffer, undefined, options);
  }

  function fromPublicKey(
    buffer: Uint8Array,
    options?: ECPairOptions,
  ): ECPairInterface {
    if (!ecc.isPoint(buffer)) {
      throw new Error('Point not on the curve');
    }
    v.parse(ECPairOptionsSchema, options);
    return new ECPair(undefined, buffer, options);
  }

  function fromWIF(
    wifString: string,
    network?: Network | Network[],
  ): ECPairInterface {
    const decoded = wif.decode(wifString);
    const version = decoded.version;

    // list of networks?
    if (Array.isArray(network)) {
      network = network
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

    return fromPrivateKey(decoded.privateKey, {
      compressed: decoded.compressed,
      network: network as Network,
    });
  }

  /**
   * Generates a random ECPairInterface.
   *
   * Uses `crypto.getRandomValues` under the hood for options.rng function, which is still an experimental feature as of Node.js 18.19.0. To work around this you can do one of the following:
   * 1. Use a polyfill for crypto.getRandomValues()
   * 2. Use the `--experimental-global-webcrypto` flag when running node.js.
   * 3. Pass in a custom rng function to generate random values.
   *
   * @param {ECPairOptions} options - Options for the ECPairInterface.
   * @return {ECPairInterface} A random ECPairInterface.
   */
  function makeRandom(options?: ECPairOptions): ECPairInterface {
    v.parse(ECPairOptionsSchema, options);
    if (options === undefined) options = {};
    const rng =
      options.rng ||
      ((size: any) => crypto.getRandomValues(new Uint8Array(size)));

    let d;
    do {
      d = rng(32);
      v.parse(types.Buffer256Bit, d);
    } while (!ecc.isPrivate(d));

    return fromPrivateKey(d, options);
  }

  class ECPair implements ECPairInterface {
    compressed: boolean;
    network: Network;
    lowR: boolean;

    constructor(
      private __D?: Uint8Array,
      private __Q?: Uint8Array,
      options?: ECPairOptions,
    ) {
      this.lowR = false;
      if (options === undefined) options = {};
      this.compressed =
        options.compressed === undefined ? true : options.compressed;
      this.network = options.network || networks.bitcoin;

      if (__Q !== undefined) this.__Q = ecc.pointCompress(__Q, this.compressed);
    }

    get privateKey(): Uint8Array | undefined {
      return this.__D;
    }

    get publicKey(): Uint8Array {
      if (!this.__Q) {
        // It is not possible for both `__Q` and `__D` to be `undefined` at the same time.
        // The factory methods guard for this.
        const p = ecc.pointFromScalar(this.__D!, this.compressed)!;
        // It is not possible for `p` to be null.
        // `fromPrivateKey()` checks that `__D` is a valid scalar.
        this.__Q = p;
      }

      return this.__Q;
    }

    toWIF(): string {
      if (!this.__D) throw new Error('Missing private key');
      return wif.encode({
        compressed: this.compressed,
        privateKey: this.__D,
        version: this.network.wif,
      });
    }

    tweak(t: Uint8Array): ECPairInterface {
      if (this.privateKey) return this.tweakFromPrivateKey(t);
      return this.tweakFromPublicKey(t);
    }

    sign(hash: Uint8Array, lowR?: boolean): Uint8Array {
      if (!this.__D) throw new Error('Missing private key');
      if (lowR === undefined) lowR = this.lowR;
      if (lowR === false) {
        return ecc.sign(hash, this.__D);
      } else {
        let sig = ecc.sign(hash, this.__D);
        const extraData = new Uint8Array(32);
        let counter = 0;
        // if first try is lowR, skip the loop
        // for second try and on, add extra entropy counting up
        while (sig[0] > 0x7f) {
          counter++;
          tools.writeUInt32(extraData, 0, counter, 'LE');
          sig = ecc.sign(hash, this.__D, extraData);
        }
        return sig;
      }
    }

    signSchnorr(hash: Uint8Array): Uint8Array {
      if (!this.privateKey) throw new Error('Missing private key');
      if (!ecc.signSchnorr)
        throw new Error('signSchnorr not supported by ecc library');
      return ecc.signSchnorr(hash, this.privateKey);
    }

    verify(hash: Uint8Array, signature: Uint8Array): boolean {
      return ecc.verify(hash, this.publicKey, signature);
    }

    verifySchnorr(hash: Uint8Array, signature: Uint8Array): boolean {
      if (!ecc.verifySchnorr)
        throw new Error('verifySchnorr not supported by ecc library');
      return ecc.verifySchnorr(hash, this.publicKey.subarray(1, 33), signature);
    }

    private tweakFromPublicKey(t: Uint8Array): ECPairInterface {
      const xOnlyPubKey = toXOnly(this.publicKey);
      const tweakedPublicKey = ecc.xOnlyPointAddTweak(xOnlyPubKey, t);
      if (!tweakedPublicKey || tweakedPublicKey.xOnlyPubkey === null)
        throw new Error('Cannot tweak public key!');
      const parityByte = Uint8Array.from([
        tweakedPublicKey.parity === 0 ? 0x02 : 0x03,
      ]);
      return fromPublicKey(
        tools.concat([parityByte, tweakedPublicKey.xOnlyPubkey]),
        {
          network: this.network,
          compressed: this.compressed,
        },
      );
    }

    private tweakFromPrivateKey(t: Uint8Array): ECPairInterface {
      const hasOddY =
        this.publicKey[0] === 3 ||
        (this.publicKey[0] === 4 && (this.publicKey[64] & 1) === 1);
      const privateKey = hasOddY
        ? ecc.privateNegate(this.privateKey!)
        : this.privateKey;

      const tweakedPrivateKey = ecc.privateAdd(privateKey!, t);
      if (!tweakedPrivateKey) throw new Error('Invalid tweaked private key!');

      return fromPrivateKey(tweakedPrivateKey, {
        network: this.network,
        compressed: this.compressed,
      });
    }
  }

  return {
    isPoint,
    fromPrivateKey,
    fromPublicKey,
    fromWIF,
    makeRandom,
  };
}
