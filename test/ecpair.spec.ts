import * as assert from 'assert';
import { createHash } from 'crypto';
import { beforeEach, describe, it } from 'mocha';
import { ECPairFactory, networks as NETWORKS } from '..';
import type { ECPairInterface, TinySecp256k1Interface } from '..';
import fixtures from './fixtures/ecpair.json';
import * as tinysecp from 'tiny-secp256k1';
import * as tools from 'uint8array-tools';

const ECPair = ECPairFactory(tinysecp);

const NETWORKS_LIST = Object.values(NETWORKS);
const ZERO = Buffer.alloc(32, 0);
const ONE = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
const GROUP_ORDER = Buffer.from(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  'hex',
);
const GROUP_ORDER_LESS_1 = Buffer.from(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
  'hex',
);

function sha256(buffer: Buffer): Buffer {
  return createHash('sha256').update(buffer).digest();
}

function tapTweakHash(pubKey: Buffer, h?: Buffer): Buffer {
  const data = Buffer.concat(h ? [pubKey, h] : [pubKey]);
  const tagHash = sha256(Buffer.from('TapTweak'));
  const tag = Buffer.concat([tagHash, tagHash]);
  return sha256(Buffer.concat([tag, data]));
}

describe('ECPair', () => {
  describe('getPublicKey', () => {
    let keyPair: ECPairInterface;

    beforeEach(() => {
      keyPair = ECPair.fromPrivateKey(ONE);
    });

    it('calls pointFromScalar lazily', () => {
      assert.strictEqual((keyPair as any).__Q, undefined);

      // .publicKey forces the memoization
      assert.strictEqual(
        tools.toHex(keyPair.publicKey),
        '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      );
      assert.strictEqual(
        tools.toHex((keyPair as any).__Q),
        '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      );
    });
  });

  describe('fromPrivateKey', () => {
    it('defaults to compressed', () => {
      const keyPair = ECPair.fromPrivateKey(ONE);

      assert.strictEqual(keyPair.compressed, true);
    });

    it('supports the uncompressed option', () => {
      const keyPair = ECPair.fromPrivateKey(ONE, {
        compressed: false,
      });

      assert.strictEqual(keyPair.compressed, false);
    });

    it('supports the network option', () => {
      const keyPair = ECPair.fromPrivateKey(ONE, {
        compressed: false,
        network: NETWORKS.testnet,
      });

      assert.strictEqual(keyPair.network, NETWORKS.testnet);
    });

    fixtures.valid.forEach((f) => {
      it('derives public key for ' + f.WIF, () => {
        const d = Buffer.from(f.d, 'hex');
        const keyPair = ECPair.fromPrivateKey(d, {
          compressed: f.compressed,
        });

        assert.strictEqual(tools.toHex(keyPair.publicKey), f.Q);
      });
    });

    fixtures.invalid.fromPrivateKey.forEach((f) => {
      it('throws ' + f.exception, () => {
        const d = Buffer.from(f.d, 'hex');
        assert.throws(() => {
          ECPair.fromPrivateKey(d, (f as any).options);
        }, new RegExp(f.exception));
      });
    });
  });

  describe('fromPublicKey', () => {
    fixtures.invalid.fromPublicKey.forEach((f) => {
      it('throws ' + f.exception, () => {
        const Q = Buffer.from(f.Q, 'hex');
        assert.throws(() => {
          ECPair.fromPublicKey(Q, (f as any).options);
        }, new RegExp(f.exception));
      });
    });
  });

  describe('fromWIF', () => {
    fixtures.valid.forEach((f) => {
      it('imports ' + f.WIF + ' (' + f.network + ')', () => {
        const network = (NETWORKS as any)[f.network];
        const keyPair = ECPair.fromWIF(f.WIF, network);

        assert.strictEqual(tools.toHex(keyPair.privateKey!), f.d);
        assert.strictEqual(keyPair.compressed, f.compressed);
        assert.strictEqual(keyPair.network, network);
      });
    });

    fixtures.valid.forEach((f) => {
      it('imports ' + f.WIF + ' (via list of networks)', () => {
        const keyPair = ECPair.fromWIF(f.WIF, NETWORKS_LIST);

        assert.strictEqual(tools.toHex(keyPair.privateKey!), f.d);
        assert.strictEqual(keyPair.compressed, f.compressed);
        assert.strictEqual(keyPair.network, (NETWORKS as any)[f.network]);
      });
    });

    fixtures.invalid.fromWIF.forEach((f) => {
      it('throws on ' + f.WIF, () => {
        assert.throws(() => {
          const networks = f.network
            ? (NETWORKS as any)[f.network]
            : NETWORKS_LIST;

          ECPair.fromWIF(f.WIF, networks);
        }, new RegExp(f.exception));
      });
    });
  });

  describe('toWIF', () => {
    fixtures.valid.forEach((f) => {
      it('exports ' + f.WIF, () => {
        const keyPair = ECPair.fromWIF(f.WIF, NETWORKS_LIST);
        const result = keyPair.toWIF();
        assert.strictEqual(result, f.WIF);
      });
    });
    it('throws if no private key is found', () => {
      assert.throws(() => {
        const keyPair = ECPair.makeRandom();
        delete (keyPair as any).__D;
        keyPair.toWIF();
      }, /Missing private key/);
    });
    it('throws if from public key only', () => {
      assert.throws(() => {
        const publicKey = Buffer.from(
          '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          'hex',
        );
        const keyPair = ECPair.fromPublicKey(publicKey);
        keyPair.toWIF();
      }, /Missing private key/);
    });
  });

  describe('makeRandom', () => {
    const d = Buffer.alloc(32, 4);
    const exWIF = 'KwMWvwRJeFqxYyhZgNwYuYjbQENDAPAudQx5VEmKJrUZcq6aL2pv';

    describe('uses crypto.getRandomBytes as RNG', () => {
      it('generates a ECPair', () => {
        const originalFn = crypto.getRandomValues;
        // @ts-ignore
        crypto.getRandomValues = (): Buffer => {
          return d;
        };

        const keyPair = ECPair.makeRandom();
        assert.strictEqual(keyPair.toWIF(), exWIF);
        crypto.getRandomValues = originalFn;
      });
    });

    it('allows a custom RNG to be used', () => {
      const keyPair = ECPair.makeRandom({
        rng: (size?: number): Uint8Array => {
          return d.slice(0, size);
        },
      });

      assert.strictEqual(keyPair.toWIF(), exWIF);
    });

    it('retains the same defaults as ECPair constructor', () => {
      const keyPair = ECPair.makeRandom();

      assert.strictEqual(keyPair.compressed, true);
      assert.strictEqual(keyPair.network, NETWORKS.bitcoin);
    });

    it('supports the options parameter', () => {
      const keyPair = ECPair.makeRandom({
        compressed: false,
        network: NETWORKS.testnet,
      });

      assert.strictEqual(keyPair.compressed, false);
      assert.strictEqual(keyPair.network, NETWORKS.testnet);
    });

    it('throws if d is bad length', () => {
      function rng(): Buffer {
        return Buffer.alloc(28);
      }

      assert.throws(() => {
        ECPair.makeRandom({ rng });
      }, /ValiError: Invalid length: Expected 32 but received 28/);
    });

    it('loops until d is within interval [1, n) : 1', () => {
      let counter = 0;
      const rng = () => {
        if (counter++ === 0) return ZERO;
        return ONE;
      };

      const keyPair = ECPair.makeRandom({ rng });
      assert.strictEqual(keyPair.privateKey!, ONE);
    });

    it('loops until d is within interval [1, n) : n - 1', () => {
      let counter = 0;
      const rng = () => {
        if (counter++ === 0) return ZERO; // <1
        if (counter++ === 1) return GROUP_ORDER; // >n-1
        return GROUP_ORDER_LESS_1; // n-1
      };

      const keyPair = ECPair.makeRandom({ rng });

      assert.strictEqual(keyPair.privateKey!, GROUP_ORDER_LESS_1);
    });
  });

  describe('tweak', () => {
    fixtures.valid.forEach((f) => {
      it('tweaks private and public key for ' + f.WIF, () => {
        const network = (NETWORKS as any)[f.network];
        const keyPair = ECPair.fromWIF(f.WIF, NETWORKS_LIST);
        const hash = tapTweakHash(Buffer.from(keyPair.publicKey.slice(1, 33)));

        const tweakedKeyPair = keyPair.tweak(hash);
        assert.strictEqual(tweakedKeyPair.toWIF(), f.tweak);

        const Q = Buffer.from(f.Q, 'hex');
        const pubOnlyKeyPair = ECPair.fromPublicKey(Q, {
          network,
          compressed: f.compressed,
        });
        const tweakedPubOnlyKeyPair = pubOnlyKeyPair.tweak(hash);

        assert.deepStrictEqual(
          tweakedKeyPair.publicKey,
          tweakedPubOnlyKeyPair.publicKey,
        );
      });
    });
  });

  describe('.network', () => {
    fixtures.valid.forEach((f) => {
      it('returns ' + f.network + ' for ' + f.WIF, () => {
        const network = (NETWORKS as any)[f.network];
        const keyPair = ECPair.fromWIF(f.WIF, NETWORKS_LIST);

        assert.strictEqual(keyPair.network, network);
      });
    });
  });

  describe('tinysecp wrappers', () => {
    let keyPair: ECPairInterface;
    let hash: Buffer;
    let signature: Buffer;

    beforeEach(() => {
      hash = ZERO;
      signature = Buffer.alloc(64, 1);
      const mockSign = (h: any, d: any) => {
        if (h === hash) {
          assert.strictEqual(h, hash);
          return signature;
        }
        return tinysecp.sign(h, d);
      };

      const mockSignSchnorr = (h: any, d: any, e: any) => {
        if (h === hash) {
          assert.strictEqual(h, hash);
          return signature;
        }
        return tinysecp.signSchnorr(h, d, e);
      };

      const mockVerify = (h: any, Q: any, sig: any) => {
        if (h === hash && sig === signature) {
          assert.strictEqual(h, hash);
          return true;
        }
        return tinysecp.verify(h, Q, sig);
      };

      const mockVerifySchnorr = (h: any, Q: any, sig: any) => {
        if (h === hash && sig === signature) {
          assert.strictEqual(h, hash);
          return true;
        }
        return tinysecp.verifySchnorr(h, Q, sig);
      };

      // @ts-ignore
      keyPair = ECPairFactory({
        ...tinysecp,
        sign: mockSign,
        signSchnorr: mockSignSchnorr,
        verify: mockVerify,
        verifySchnorr: mockVerifySchnorr,
      }).makeRandom();
    });

    describe('signing', () => {
      it('wraps tinysecp.sign', () => {
        assert.deepStrictEqual(keyPair.sign(hash), signature);
      });

      it('throws if no private key is found', () => {
        delete (keyPair as any).__D;

        assert.throws(() => {
          keyPair.sign(hash);
        }, /Missing private key/);
      });
    });

    describe('schnorr signing', () => {
      it('creates signature', () => {
        const kP = ECPair.fromPrivateKey(ONE, {
          compressed: false,
        });
        const h = Buffer.alloc(32, 2);
        const schnorrsig = Buffer.from(
          'cde43b67d4326fa6ff1b40711615b692a997e193cc512f3a40e5cd4a5c9be18ca871296fa967f4dc13634c70d965223d637546a0b519050bae82c76d3ae627ff',
          'hex',
        );

        assert.deepStrictEqual(
          tools.toHex(kP.signSchnorr(h)),
          schnorrsig.toString('hex'),
        );
      });

      it('wraps tinysecp.signSchnorr', () => {
        assert.deepStrictEqual(keyPair.signSchnorr(hash), signature);
      });

      it('throws if no private key is found', () => {
        delete (keyPair as any).__D;

        assert.throws(() => {
          keyPair.signSchnorr(hash);
        }, /Missing private key/);
      });

      it('throws if signSchnorr() not found', () => {
        assert.throws(() => {
          keyPair = ECPairFactory({
            ...tinysecp,
            signSchnorr: null,
          } as unknown as TinySecp256k1Interface).makeRandom();
          keyPair.signSchnorr(hash);
        }, /signSchnorr not supported by ecc library/);
      });
    });

    describe('verify', () => {
      it('wraps tinysecp.verify', () => {
        assert.strictEqual(keyPair.verify(hash, signature), true);
      });
    });

    describe('schnorr verify', () => {
      it('checks signature', () => {
        const kP = ECPair.fromPrivateKey(ONE, {
          compressed: false,
        });
        const h = Buffer.alloc(32, 2);
        const schnorrsig = Buffer.from(
          '4bc68cbd7c0b769b2dff262e9971756da7ab78402ed6f710c3788ce815e9c06a011bab7a527e33c6a1df0dad5ed05a04b8f3be656d8578502fef07f8215d37db',
          'hex',
        );

        assert.strictEqual(kP.verifySchnorr(h, schnorrsig), true);
      });

      it('wraps tinysecp.verifySchnorr', () => {
        assert.strictEqual(keyPair.verifySchnorr(hash, signature), true);
      });

      it('throws if verifySchnorr() not found', () => {
        assert.throws(() => {
          keyPair = ECPairFactory({
            ...tinysecp,
            verifySchnorr: null,
          } as unknown as TinySecp256k1Interface).makeRandom();
          keyPair.verifySchnorr(hash, signature);
        }, /verifySchnorr not supported by ecc library/);
      });
    });
  });

  describe('optional low R signing', () => {
    const sig = Buffer.from(
      '95a6619140fca3366f1d3b013b0367c4f86e39508a50fdce' +
        'e5245fbb8bd60aa6086449e28cf15387cf9f85100bfd0838624ca96759e59f65c10a00' +
        '16b86f5229',
      'hex',
    );
    const sigLowR = Buffer.from(
      '6a2660c226e8055afad317eeba918a304be79208d505' +
        '3bc5ea4a5e4c5892b4a061c717c5284ae5202d721c0e49b4717b79966280906b1d3b52' +
        '95d1fdde963c35',
      'hex',
    );
    const lowRKeyPair = ECPair.fromWIF(
      'L3nThUzbAwpUiBAjR5zCu66ybXSPMr2zZ3ikp' + 'ScpTPiYTxBynfZu',
    );
    const dataToSign = Buffer.from(
      'b6c5c548a7f6164c8aa7af5350901626ebd69f9ae' + '2c1ecf8871f5088ec204cfe',
      'hex',
    );

    it('signs with normal R by default', () => {
      const signed = lowRKeyPair.sign(dataToSign);
      assert.deepStrictEqual(sig, Buffer.from(signed));
    });

    it('signs with low R when true is passed', () => {
      const signed = lowRKeyPair.sign(dataToSign, true);
      assert.deepStrictEqual(sigLowR, Buffer.from(signed));
    });
  });
});
