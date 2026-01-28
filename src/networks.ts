// https://en.bitcoin.it/wiki/List_of_address_prefixes

export interface Bip32Versions {
    readonly public: number;
    readonly private: number;
}

export interface Network {
    readonly messagePrefix: string | Uint8Array;
    readonly bech32: string;
    readonly bip32: Bip32Versions;
    readonly pubKeyHash: number;
    readonly scriptHash: number;
    readonly wif: number;
}

export const bitcoin: Network = {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {
        public: 0x0488b21e,
        private: 0x0488ade4,
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80,
} as const;

export const testnet: Network = {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: {
        public: 0x043587cf,
        private: 0x04358394,
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
} as const;

export const regtest: Network = {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bcrt',
    bip32: {
        public: 0x043587cf,
        private: 0x04358394,
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
} as const;
