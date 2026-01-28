import type { PrivateKey } from './branded.js';
import type { Network } from './networks.js';
import { createPrivateKey } from './types.js';
import * as wif from 'wif';

export interface WifDecodeResult {
    readonly privateKey: PrivateKey;
    readonly compressed: boolean;
    readonly network: Network;
}

export function encodeWIF(privateKey: PrivateKey, compressed: boolean, network: Network): string {
    return wif.encode({
        version: network.wif,
        privateKey,
        compressed,
    });
}

export function decodeWIF(
    wifString: string,
    network: Network | readonly Network[],
): WifDecodeResult {
    const decoded = wif.decode(wifString);
    const version = decoded.version;

    if (Array.isArray(network)) {
        const nets = network as readonly Network[];
        const matched = nets.find((n) => n.wif === version);
        if (!matched) throw new Error('Unknown network version');
        return {
            privateKey: createPrivateKey(decoded.privateKey),
            compressed: decoded.compressed,
            network: matched,
        };
    }

    const net = network as Network;
    if (version !== net.wif) {
        throw new Error('Invalid network version');
    }
    return {
        privateKey: createPrivateKey(decoded.privateKey),
        compressed: decoded.compressed,
        network: net,
    };
}
