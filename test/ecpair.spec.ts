import * as assert from 'assert';
import { beforeEach, describe, it } from 'mocha';
import * as proxyquire from 'proxyquire';
import { ECPairFactory, ECPairInterface, networks as NETWORKS } from '..';
import * as fixtures from './fixtures/ecpair.json';
const hoodwink = require('hoodwink');
const tinysecp = require('tiny-secp256k1');

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

describe('ECPair', () => {
  describe('getPublicKey', () => {
    let keyPair: ECPairInterface;

    beforeEach(() => {
      keyPair = ECPair.fromPrivateKey(ONE);
    });

    it(
      'calls pointFromScalar lazily',
      hoodwink(() => {
        assert.strictEqual((keyPair as any).__Q, undefined);

        // .publicKey forces the memoization
        assert.strictEqual(
          keyPair.publicKey.toString('hex'),
          '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        );
        assert.strictEqual(
          (keyPair as any).__Q.toString('hex'),
          '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        );
      }),
    );
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

        assert.strictEqual(keyPair.publicKey.toString('hex'), f.Q);
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

        assert.strictEqual(keyPair.privateKey!.toString('hex'), f.d);
        assert.strictEqual(keyPair.compressed, f.compressed);
        assert.strictEqual(keyPair.network, network);
      });
    });

    fixtures.valid.forEach((f) => {
      it('imports ' + f.WIF + ' (via list of networks)', () => {
        const keyPair = ECPair.fromWIF(f.WIF, NETWORKS_LIST);

        assert.strictEqual(keyPair.privateKey!.toString('hex'), f.d);
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

    describe('uses randombytes RNG', () => {
      it('generates a ECPair', () => {
        const stub = {
          randombytes: (): Buffer => {
            return d;
          },
        };
        const ProxiedECPair = proxyquire('../src/ecpair', stub);

        const keyPair = ProxiedECPair.ECPairFactory(tinysecp).makeRandom();
        assert.strictEqual(keyPair.toWIF(), exWIF);
      });
    });

    it('allows a custom RNG to be used', () => {
      const keyPair = ECPair.makeRandom({
        rng: (size): Buffer => {
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
      }, /Expected Buffer\(Length: 32\), got Buffer\(Length: 28\)/);
    });

    it(
      'loops until d is within interval [1, n) : 1',
      hoodwink(function (this: any): void {
        const rng = this.stub(() => {
          if (rng.calls === 0) return ZERO; // 0
          return ONE; // >0
        }, 2);

        ECPair.makeRandom({ rng });
      }),
    );

    it(
      'loops until d is within interval [1, n) : n - 1',
      hoodwink(function (this: any): void {
        const rng = this.stub(() => {
          if (rng.calls === 0) return ZERO; // <1
          if (rng.calls === 1) return GROUP_ORDER; // >n-1
          return GROUP_ORDER_LESS_1; // n-1
        }, 3);

        ECPair.makeRandom({ rng });
      }),
    );
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
      keyPair = ECPair.makeRandom();
      hash = ZERO;
      signature = Buffer.alloc(64, 1);
    });

    describe('signing', () => {
      it(
        'wraps tinysecp.sign',
        hoodwink(function (this: any): void {
          this.mock(
            tinysecp,
            'sign',
            (h: any, d: any) => {
              assert.strictEqual(h, hash);
              assert.strictEqual(d, keyPair.privateKey);
              return signature;
            },
            1,
          );

          assert.deepStrictEqual(keyPair.sign(hash), signature);
        }),
      );

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
          '4bc68cbd7c0b769b2dff262e9971756da7ab78402ed6f710c3788ce815e9c06a011bab7a527e33c6a1df0dad5ed05a04b8f3be656d8578502fef07f8215d37db',
          'hex',
        );

        assert.deepStrictEqual(
          kP.signSchnorr(h).toString('hex'),
          schnorrsig.toString('hex'),
        );
      });

      it('creates signature for tweaked private key', () => {
        const kP = ECPair.fromPrivateKey(ONE, {
          compressed: true,
        });
        const h = Buffer.alloc(32, 2);
        const tweakHash = Buffer.from(
          '3cf5216d476a5e637bf0da674e50ddf55c403270dd36494dfcca438132fa30e7',
          'hex',
        );
        const schnorrTweakedSig = Buffer.from(
          'c2cc6ba5ac926ae7a99b2dc4d410532c05787c562e5ae02fb4f204e8a4e86384ef4b436597bbc1808dcfa9f3e4223e0c2a9ab6fd4b43ab2c6d18405c43b8f0a6',
          'hex',
        );

        assert.deepStrictEqual(
          kP.signSchnorr(h, tweakHash).toString('hex'),
          schnorrTweakedSig.toString('hex'),
        );
      });

      it(
        'wraps tinysecp.signSchnorr',
        hoodwink(function (this: any): void {
          this.mock(
            tinysecp,
            'signSchnorr',
            (h: any) => {
              assert.strictEqual(h, hash);
              return signature;
            },
            1,
          );

          assert.deepStrictEqual(keyPair.signSchnorr(hash), signature);
        }),
      );

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
          }).makeRandom();
          keyPair.signSchnorr(hash);
        }, /signSchnorr not supported by ecc library/);
      });
    });

    describe('verify', () => {
      it(
        'wraps tinysecp.verify',
        hoodwink(function (this: any): void {
          this.mock(
            tinysecp,
            'verify',
            (h: any, q: any, s: any) => {
              assert.strictEqual(h, hash);
              assert.strictEqual(q, keyPair.publicKey);
              assert.strictEqual(s, signature);
              return true;
            },
            1,
          );

          assert.strictEqual(keyPair.verify(hash, signature), true);
        }),
      );
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

      it(
        'wraps tinysecp.verifySchnorr',
        hoodwink(function (this: any): void {
          this.mock(
            tinysecp,
            'verifySchnorr',
            (h: any, q: any, s: any) => {
              assert.strictEqual(h, hash);
              assert.deepStrictEqual(q, keyPair.publicKey.subarray(1, 33));
              assert.strictEqual(s, signature);
              return true;
            },
            1,
          );

          assert.strictEqual(keyPair.verifySchnorr(hash, signature), true);
        }),
      );

      it('throws if verifySchnorr() not found', () => {
        assert.throws(() => {
          keyPair = ECPairFactory({
            ...tinysecp,
            verifySchnorr: null,
          }).makeRandom();
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
      assert.deepStrictEqual(sig, signed);
    });

    it('signs with low R when true is passed', () => {
      const signed = lowRKeyPair.sign(dataToSign, true);
      assert.deepStrictEqual(sigLowR, signed);
    });
  });
});
