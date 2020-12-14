export type CipherType = 'symmetric' | 'asymmetric';

export interface Cipher {
  name: string;
  type: CipherType;

  encrypt(json: Record<string, unknown>, secretOrSharedKey: Uint8Array, key?: Uint8Array): Promise<string>;

  decrypt(messageWithNonce: string, secretOrSharedKey: Uint8Array, key?: Uint8Array): Promise<Record<string, unknown>>;
}
