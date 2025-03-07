import * as networks from './networks.js';
import * as types from './types.js';
import * as wif from 'wif';
import { testEcc } from './testecc.js';
export { networks };
import * as v from 'valibot';
import * as tools from 'uint8array-tools';
const ECPairOptionsSchema = v.optional(
  v.object({
    compressed: v.optional(v.boolean()),
    network: v.optional(types.NetworkSchema),
    // https://github.com/fabian-hiller/valibot/issues/243#issuecomment-2182514063
    rng: v.optional(
      v.pipe(
        v.instance(Function),
        v.transform((func) => {
          return (arg) => {
            const parsedArg = v.parse(v.optional(v.number()), arg);
            const returnedValue = func(parsedArg);
            const parsedReturn = v.parse(v.instance(Uint8Array), returnedValue);
            return parsedReturn;
          };
        }),
      ),
    ),
  }),
);
const toXOnly = (pubKey) =>
  pubKey.length === 32 ? pubKey : pubKey.subarray(1, 33);
export function ECPairFactory(ecc) {
  testEcc(ecc);
  function isPoint(maybePoint) {
    return ecc.isPoint(maybePoint);
  }
  function fromPrivateKey(buffer, options) {
    v.parse(types.Buffer256Bit, buffer);
    if (!ecc.isPrivate(buffer))
      throw new TypeError('Private key not in range [1, n)');
    v.parse(ECPairOptionsSchema, options);
    return new ECPair(buffer, undefined, options);
  }
  function fromPublicKey(buffer, options) {
    if (!ecc.isPoint(buffer)) {
      throw new Error('Point not on the curve');
    }
    v.parse(ECPairOptionsSchema, options);
    return new ECPair(undefined, buffer, options);
  }
  function fromWIF(wifString, network) {
    const decoded = wif.decode(wifString);
    const version = decoded.version;
    // list of networks?
    if (Array.isArray(network)) {
      network = network
        .filter((x) => {
          return version === x.wif;
        })
        .pop();
      if (!network) throw new Error('Unknown network version');
      // otherwise, assume a network object (or default to bitcoin)
    } else {
      network = network || networks.bitcoin;
      if (version !== network.wif) throw new Error('Invalid network version');
    }
    return fromPrivateKey(decoded.privateKey, {
      compressed: decoded.compressed,
      network: network,
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
  function makeRandom(options) {
    v.parse(ECPairOptionsSchema, options);
    if (options === undefined) options = {};
    const rng =
      options.rng || ((size) => crypto.getRandomValues(new Uint8Array(size)));
    let d;
    do {
      d = rng(32);
      v.parse(types.Buffer256Bit, d);
    } while (!ecc.isPrivate(d));
    return fromPrivateKey(d, options);
  }
  class ECPair {
    __D;
    __Q;
    compressed;
    network;
    lowR;
    constructor(__D, __Q, options) {
      this.__D = __D;
      this.__Q = __Q;
      this.lowR = false;
      if (options === undefined) options = {};
      this.compressed =
        options.compressed === undefined ? true : options.compressed;
      this.network = options.network || networks.bitcoin;
      if (__Q !== undefined) this.__Q = ecc.pointCompress(__Q, this.compressed);
    }
    get privateKey() {
      return this.__D;
    }
    get publicKey() {
      if (!this.__Q) {
        // It is not possible for both `__Q` and `__D` to be `undefined` at the same time.
        // The factory methods guard for this.
        const p = ecc.pointFromScalar(this.__D, this.compressed);
        // It is not possible for `p` to be null.
        // `fromPrivateKey()` checks that `__D` is a valid scalar.
        this.__Q = p;
      }
      return this.__Q;
    }
    toWIF() {
      if (!this.__D) throw new Error('Missing private key');
      return wif.encode({
        compressed: this.compressed,
        privateKey: this.__D,
        version: this.network.wif,
      });
    }
    tweak(t) {
      if (this.privateKey) return this.tweakFromPrivateKey(t);
      return this.tweakFromPublicKey(t);
    }
    sign(hash, lowR) {
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
    signSchnorr(hash) {
      if (!this.privateKey) throw new Error('Missing private key');
      if (!ecc.signSchnorr)
        throw new Error('signSchnorr not supported by ecc library');
      return ecc.signSchnorr(hash, this.privateKey);
    }
    verify(hash, signature) {
      return ecc.verify(hash, this.publicKey, signature);
    }
    verifySchnorr(hash, signature) {
      if (!ecc.verifySchnorr)
        throw new Error('verifySchnorr not supported by ecc library');
      return ecc.verifySchnorr(hash, this.publicKey.subarray(1, 33), signature);
    }
    tweakFromPublicKey(t) {
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
    tweakFromPrivateKey(t) {
      const hasOddY =
        this.publicKey[0] === 3 ||
        (this.publicKey[0] === 4 && (this.publicKey[64] & 1) === 1);
      const privateKey = hasOddY
        ? ecc.privateNegate(this.privateKey)
        : this.privateKey;
      const tweakedPrivateKey = ecc.privateAdd(privateKey, t);
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
