import { createHmac } from 'crypto';
import { Chain } from 'key-derivation/dist';
import { DerivedKeyPair } from './types';
import { bufferToUint8Array, isValidDerivationPath, replaceDerive } from './utils';

const INVALID_DERIVATION_PATH = 'Invalid derivation path';
const ED25519_CURVE = 'ed25519 seed';

export const BIG_CHAIN_DERIVATION_PATH = `m/44'/822'`;
export const HARDENED_OFFSET = 0x80000000;

export class KeyDerivation {
  private _seedHex: string;

  static getMasterKeyFromSeed(seed: string, encoding: BufferEncoding = 'hex'): DerivedKeyPair {
    const hmac = createHmac('sha512', ED25519_CURVE);
    const I = hmac.update(Buffer.from(seed, encoding)).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
      key: bufferToUint8Array(IL),
      chainCode: bufferToUint8Array(IR),
      derivationPath: '',
    };
  }

  static childKeyDerivation(parentKeys: DerivedKeyPair, index: number): DerivedKeyPair {
    const { key, chainCode, derivationPath } = parentKeys;
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);
    const data = Buffer.concat([Buffer.alloc(1, 0), key, indexBuffer]);
    const I = createHmac('sha512', chainCode).update(data).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
      key: bufferToUint8Array(IL),
      chainCode: bufferToUint8Array(IR),
      derivationPath,
    };
  }

  static derivePath(path: string, seed: string): DerivedKeyPair {
    if (!isValidDerivationPath(path)) {
      throw new Error(INVALID_DERIVATION_PATH);
    }
    const { key, chainCode } = this.getMasterKeyFromSeed(seed);
    const segments = path
      .split('/')
      .slice(1)
      .map(replaceDerive)
      .map((el) => parseInt(el, 10));
    return segments.reduce((parentKeys, segment) => this.childKeyDerivation(parentKeys, segment + HARDENED_OFFSET), {
      key,
      chainCode,
      derivationPath: path,
    });
  }

  constructor(seedHex: string) {
    this._seedHex = seedHex;
  }

  getMasterKey(): DerivedKeyPair {
    return KeyDerivation.getMasterKeyFromSeed(this._seedHex);
  }

  derive(derivationPath: string): DerivedKeyPair {
    return KeyDerivation.derivePath(derivationPath, this._seedHex);
  }

  getBaseKey() {
    return this.derive(`${BIG_CHAIN_DERIVATION_PATH}`);
  }

  getAccountKey(account: number): DerivedKeyPair {
    return this.derive(`${BIG_CHAIN_DERIVATION_PATH}/${account}'`);
  }

  getAccountChildKey(account: number, index: number, chain: Chain = 0): DerivedKeyPair {
    return this.derive(`${BIG_CHAIN_DERIVATION_PATH}/${account}'/${chain}'/${index}'`);
  }
}
