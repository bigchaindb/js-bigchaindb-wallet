import { createHmac } from 'crypto';
import { Chain, DerivedKeyPair } from './types';
import { bufferToUint8Array, isValidDerivationPath, replaceDerive } from './utils';

const INVALID_DERIVATION_PATH = 'Invalid derivation path';
const INVALID_LENGTH = (el: string, length: number) => `${el} should be ${length} bytes length`;
const ED25519_CURVE = 'ed25519 seed';

export const BIG_CHAIN_DERIVATION_PATH = `m/44'/822'`;
export const HARDENED_OFFSET = 0x80000000;

export class KeyDerivation {
  static readonly keyLength = 32;
  static readonly seedLength = 64;
  static readonly chainCodeLength = 32;

  private _seedHex: string;

  static getMasterKeyFromSeed(seed: string | Buffer | Uint8Array, encoding: BufferEncoding = 'hex'): DerivedKeyPair {
    let seedBuffer: Buffer;
    if (seed instanceof Uint8Array) {
      seedBuffer = Buffer.from(seed);
    } else if (typeof seed === 'string') {
      seedBuffer = Buffer.from(seed, encoding);
    }
    // TODO: allow seed of 32, 48 and 64 bytes length
    const hmac = createHmac('sha512', ED25519_CURVE);
    if (seedBuffer.length !== this.seedLength) {
      throw new TypeError(INVALID_LENGTH('Seed', this.seedLength));
    }
    const I = hmac.update(seedBuffer).digest();
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
    if (key.length !== this.keyLength) {
      throw new TypeError(INVALID_LENGTH('Key', this.keyLength));
    }
    if (chainCode.length !== this.chainCodeLength) {
      throw new TypeError(INVALID_LENGTH('ChainCode', this.chainCodeLength));
    }
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

  getBaseKey(): DerivedKeyPair {
    return this.derive(`${BIG_CHAIN_DERIVATION_PATH}`);
  }

  getAccountKey(account: number): DerivedKeyPair {
    return this.derive(`${BIG_CHAIN_DERIVATION_PATH}/${account}'`);
  }

  getAccountChildKey(account: number, index: number, chain: Chain = 0): DerivedKeyPair {
    return this.derive(`${BIG_CHAIN_DERIVATION_PATH}/${account}'/${chain}'/${index}'`);
  }
}
