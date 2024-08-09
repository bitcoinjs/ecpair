import * as v from 'valibot';
import { NetworkSchema } from './types';
export type Network = v.InferOutput<typeof NetworkSchema>;
export declare const bitcoin: Network;
export declare const testnet: Network;
