import type { CryptoBackend } from './backend.js';
import type { Bytes32, MessageHash, PrivateKey, PublicKey, XOnlyPublicKey } from './branded.js';
import { bytesEqual, fromHexInternal } from './types.js';

function h(hex: string): Uint8Array {
    return fromHexInternal(hex);
}

function assert(condition: boolean, message: string): void {
    if (!condition) throw new Error(`verifyCryptoBackend: ${message}`);
}

export function verifyCryptoBackend(backend: CryptoBackend): void {
    // isPoint
    assert(
        backend.isPoint(
            h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
        ),
        'isPoint should accept generator point',
    );
    assert(
        !backend.isPoint(
            h('030000000000000000000000000000000000000000000000000000000000000005'),
        ),
        'isPoint should reject invalid point',
    );

    // isPrivate
    assert(
        backend.isPrivate(
            h('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
        ),
        'isPrivate should accept valid scalar',
    );
    // order - 1
    assert(
        backend.isPrivate(
            h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'),
        ),
        'isPrivate should accept n-1',
    );
    // 0
    assert(
        !backend.isPrivate(
            h('0000000000000000000000000000000000000000000000000000000000000000'),
        ),
        'isPrivate should reject zero',
    );
    // order
    assert(
        !backend.isPrivate(
            h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
        ),
        'isPrivate should reject n',
    );
    // order + 1
    assert(
        !backend.isPrivate(
            h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142'),
        ),
        'isPrivate should reject n+1',
    );

    // privateAdd: 1 + 0 == 1
    const oneAddZero = backend.privateAdd(
        h('0000000000000000000000000000000000000000000000000000000000000001') as PrivateKey,
        h('0000000000000000000000000000000000000000000000000000000000000000') as Bytes32,
    );
    assert(
        oneAddZero !== null &&
            bytesEqual(
                oneAddZero,
                h('0000000000000000000000000000000000000000000000000000000000000001'),
            ),
        'privateAdd: 1 + 0 should equal 1',
    );

    // privateAdd: -3 + 3 == 0 (returns null)
    assert(
        backend.privateAdd(
            h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e') as PrivateKey,
            h('0000000000000000000000000000000000000000000000000000000000000003') as Bytes32,
        ) === null,
        'privateAdd: (n-3) + 3 should return null (result is zero mod n)',
    );

    // privateAdd with non-trivial values
    const addResult = backend.privateAdd(
        h('e211078564db65c3ce7704f08262b1f38f1ef412ad15b5ac2d76657a63b2c500') as PrivateKey,
        h('b51fbb69051255d1becbd683de5848242a89c229348dd72896a87ada94ae8665') as Bytes32,
    );
    assert(
        addResult !== null &&
            bytesEqual(
                addResult,
                h('9730c2ee69edbb958d42db7460bafa18fef9d955325aec99044c81c8282b0a24'),
            ),
        'privateAdd: known vector failed',
    );

    // privateNegate
    assert(
        bytesEqual(
            backend.privateNegate(
                h('0000000000000000000000000000000000000000000000000000000000000001') as PrivateKey,
            ),
            h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'),
        ),
        'privateNegate(1) should equal n-1',
    );
    assert(
        bytesEqual(
            backend.privateNegate(
                h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e') as PrivateKey,
            ),
            h('0000000000000000000000000000000000000000000000000000000000000003'),
        ),
        'privateNegate(n-3) should equal 3',
    );
    assert(
        bytesEqual(
            backend.privateNegate(
                h('b1121e4088a66a28f5b6b0f5844943ecd9f610196d7bb83b25214b60452c09af') as PrivateKey,
            ),
            h('4eede1bf775995d70a494f0a7bb6bc11e0b8cccd41cce8009ab1132c8b0a3792'),
        ),
        'privateNegate known vector failed',
    );

    // pointCompress: uncompressed -> compressed
    assert(
        bytesEqual(
            backend.pointCompress(
                h(
                    '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
                ) as PublicKey,
                true,
            ),
            h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
        ),
        'pointCompress uncompressed->compressed failed',
    );
    assert(
        bytesEqual(
            backend.pointCompress(
                h(
                    '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
                ) as PublicKey,
                false,
            ),
            h(
                '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
            ),
        ),
        'pointCompress uncompressed->uncompressed failed',
    );
    assert(
        bytesEqual(
            backend.pointCompress(
                h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798') as PublicKey,
                true,
            ),
            h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
        ),
        'pointCompress compressed->compressed failed',
    );
    assert(
        bytesEqual(
            backend.pointCompress(
                h('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798') as PublicKey,
                false,
            ),
            h(
                '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
            ),
        ),
        'pointCompress compressed->uncompressed failed',
    );

    // pointFromScalar
    const scalarResult = backend.pointFromScalar(
        h('b1121e4088a66a28f5b6b0f5844943ecd9f610196d7bb83b25214b60452c09af') as PrivateKey,
    );
    assert(
        scalarResult !== null &&
            bytesEqual(
                scalarResult,
                h('02b07ba9dca9523b7ef4bd97703d43d20399eb698e194704791a25ce77a400df99'),
            ),
        'pointFromScalar known vector failed',
    );

    // xOnlyPointAddTweak: null case
    assert(
        backend.xOnlyPointAddTweak(
            h('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798') as XOnlyPublicKey,
            h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140') as Bytes32,
        ) === null,
        'xOnlyPointAddTweak should return null for infinity result',
    );

    // xOnlyPointAddTweak: parity 1
    let xOnlyRes = backend.xOnlyPointAddTweak(
        h('1617d38ed8d8657da4d4761e8057bc396ea9e4b9d29776d4be096016dbd2509b') as XOnlyPublicKey,
        h('a8397a935f0dfceba6ba9618f6451ef4d80637abf4e6af2669fbc9de6a8fd2ac') as Bytes32,
    );
    assert(
        xOnlyRes !== null &&
            bytesEqual(
                xOnlyRes.xOnlyPubkey,
                h('e478f99dab91052ab39a33ea35fd5e6e4933f4d28023cd597c9a1f6760346adf'),
            ) &&
            xOnlyRes.parity === 1,
        'xOnlyPointAddTweak parity=1 case failed',
    );

    // xOnlyPointAddTweak: parity 0
    xOnlyRes = backend.xOnlyPointAddTweak(
        h('2c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991') as XOnlyPublicKey,
        h('823c3cd2142744b075a87eade7e1b8678ba308d566226a0056ca2b7a76f86b47') as Bytes32,
    );
    assert(
        xOnlyRes !== null &&
            bytesEqual(
                xOnlyRes.xOnlyPubkey,
                h('9534f8dc8c6deda2dc007655981c78b49c5d96c778fbf363462a11ec9dfd948c'),
            ) &&
            xOnlyRes.parity === 0,
        'xOnlyPointAddTweak parity=0 case failed',
    );

    // sign
    const signResult = backend.sign(
        h('5e9f0a0d593efdcf78ac923bc3313e4e7d408d574354ee2b3288c0da9fbba6ed') as MessageHash,
        h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140') as PrivateKey,
    );
    assert(
        bytesEqual(
            signResult,
            h(
                '54c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed07082304410efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5',
            ),
        ),
        'sign known vector failed',
    );

    // verify
    assert(
        backend.verify(
            h('5e9f0a0d593efdcf78ac923bc3313e4e7d408d574354ee2b3288c0da9fbba6ed') as MessageHash,
            h(
                '0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            ) as PublicKey,
            signResult,
        ),
        'verify known vector failed',
    );

    // signSchnorr (optional)
    if (backend.signSchnorr) {
        const schnorrSig = backend.signSchnorr(
            h('7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c') as MessageHash,
            h('c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9') as PrivateKey,
            h('c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906'),
        );
        assert(
            bytesEqual(
                schnorrSig,
                h(
                    '5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7',
                ),
            ),
            'signSchnorr known vector failed',
        );
    }

    // verifySchnorr (optional)
    if (backend.verifySchnorr) {
        assert(
            backend.verifySchnorr(
                h('7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c') as MessageHash,
                h('dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8') as XOnlyPublicKey,
                h(
                    '5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7',
                ) as import('./branded.js').SchnorrSignature,
            ),
            'verifySchnorr known vector failed',
        );
    }
}
