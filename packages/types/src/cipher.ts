export type CipherType = 'symmetric' | 'asymmetric';

export interface Cipher {
  name: string;
  type: CipherType;
  sharedKey?: Uint8Array;
  secret?: Uint8Array;
  encrypt<T = Record<string, unknown>>(payload: T, secretOrSharedKey: Uint8Array, key?: Uint8Array): Promise<string>;
  decrypt<T = Record<string, unknown>>(
    messageWithNonce: string,
    secretOrSharedKey: Uint8Array,
    key?: Uint8Array,
  ): Promise<T>;
}
