export const SignerCapability = {
    EcdsaSign: 0,
    EcdsaVerify: 1,
    SchnorrSign: 2,
    SchnorrVerify: 3,
    PrivateKeyExport: 4,
    PublicKeyTweak: 5,
    HdDerivation: 6,
} as const;

export type SignerCapability = (typeof SignerCapability)[keyof typeof SignerCapability];
