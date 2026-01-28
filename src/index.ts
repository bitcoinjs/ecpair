// ---------------------------------------------------------------------------
// 1. Branded types
// ---------------------------------------------------------------------------
export type {
    Brand,
    Bytes32,
    Bytes20,
    PrivateKey,
    PublicKey,
    XOnlyPublicKey,
    Signature,
    SchnorrSignature,
    MessageHash,
    Script,
    Satoshi,
} from './branded.js';

// ---------------------------------------------------------------------------
// 2. Type guards, assertions, creation functions, byte utilities
// ---------------------------------------------------------------------------
export {
    fromHexInternal,
    isZeroBytes,
    compareBytes,
    bytesEqual,
    toHex,
    concatBytes,
    EC_N,
    EC_P,
    SATOSHI_MAX,
    isBytes32,
    isBytes20,
    isPrivateKey,
    isPublicKey,
    isXOnlyPublicKey,
    isSignature,
    isSchnorrSignature,
    isMessageHash,
    isSatoshi,
    assertBytes32,
    assertPrivateKey,
    assertPublicKey,
    assertXOnlyPublicKey,
    assertMessageHash,
    createBytes32,
    createBytes20,
    createPrivateKey,
    createPublicKey,
    createXOnlyPublicKey,
    createSignature,
    createSchnorrSignature,
    createMessageHash,
    createSatoshi,
} from './types.js';

// ---------------------------------------------------------------------------
// 3. Network types and predefined networks
// ---------------------------------------------------------------------------
export type { Network, Bip32Versions } from './networks.js';
import * as networks from './networks.js';
export { networks };

// ---------------------------------------------------------------------------
// 4. SignerCapability
// ---------------------------------------------------------------------------
export { SignerCapability } from './capability.js';

// ---------------------------------------------------------------------------
// 5. CryptoBackend, Parity, XOnlyPointAddTweakResult
// ---------------------------------------------------------------------------
export type { CryptoBackend, Parity, XOnlyPointAddTweakResult } from './backend.js';

// ---------------------------------------------------------------------------
// 6. Signer interfaces + ECPairSigner
// ---------------------------------------------------------------------------
export type { Signer, SignerAsync, UniversalSigner, SignerOptions, RandomSignerOptions } from './signer.js';
export { ECPairSigner } from './signer.js';

// ---------------------------------------------------------------------------
// 7. Noble backend adapter
// ---------------------------------------------------------------------------
export { NobleBackend, createNobleBackend } from './noble.js';

// ---------------------------------------------------------------------------
// 8. Legacy backend adapter
// ---------------------------------------------------------------------------
export { LegacyBackend, createLegacyBackend } from './legacy.js';
export type { TinySecp256k1Interface } from './legacy.js';

// ---------------------------------------------------------------------------
// 9. CryptoBackend verification
// ---------------------------------------------------------------------------
export { verifyCryptoBackend } from './testecc.js';

// ---------------------------------------------------------------------------
// 10. WIF utilities
// ---------------------------------------------------------------------------
export { encodeWIF, decodeWIF } from './wif.js';
export type { WifDecodeResult } from './wif.js';

