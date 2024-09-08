import * as v from 'valibot';
export declare const NetworkSchema: v.ObjectSchema<{
    readonly messagePrefix: v.UnionSchema<[v.StringSchema<undefined>, v.InstanceSchema<Uint8ArrayConstructor, undefined>], undefined>;
    readonly bech32: v.StringSchema<undefined>;
    readonly bip32: v.ObjectSchema<{
        readonly public: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 4294967295, undefined>]>;
        readonly private: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 4294967295, undefined>]>;
    }, undefined>;
    readonly pubKeyHash: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 255, undefined>]>;
    readonly scriptHash: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 255, undefined>]>;
    readonly wif: v.SchemaWithPipe<[v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 255, undefined>]>;
}, undefined>;
export declare const Buffer256Bit: v.SchemaWithPipe<[v.InstanceSchema<Uint8ArrayConstructor, undefined>, v.LengthAction<Uint8Array, 32, undefined>]>;
