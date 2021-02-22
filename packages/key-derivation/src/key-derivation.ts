import { createHmac } from 'crypto';
import { Chain, DerivatedKeyPair, Purpose } from './types';
import { isValidDerivationPath, replaceDerive, toUint8Array } from './utils';

const INVALID_DERIVATION_PATH = 'Invalid derivation path';
const INVALID_LENGTH = (el: string, length: number) => `${el} should be ${length} bytes length`;

export const ED25519_CURVE = 'ed25519 seed';
export const X25519_CURVE = 'curve25519 seed';
export const BIG_CHAIN_DERIVATION_PATH = `m/44'/822'`;
export const HARDENED_OFFSET = 0x80000000;

export class KeyDerivation {
  static readonly keyLength = 32;
  static readonly seedLength = 64;
  static readonly chainCodeLength = 32;
  private encoding: BufferEncoding;
  private _seed: string;

  static getMasterKeyFromSeed(
    seed: string | Buffer | Uint8Array,
    purpose: Purpose = 'sign',
    encoding: BufferEncoding = 'hex',
  ): DerivatedKeyPair {
    let seedBuffer: Buffer;
    if (Buffer.isBuffer(seed)) {
      seedBuffer = seed;
    } else if (typeof seed === 'string') {
      seedBuffer = Buffer.from(seed, encoding);
    } else if (seed instanceof Uint8Array) {
      seedBuffer = Buffer.from(seed);
    } else {
      throw new TypeError('Seed should be a string, a Buffer or a Uint8Array');
    }
    // if (seedBuffer.length !== this.seedLength) {
    //   throw new TypeError(INVALID_LENGTH('Seed', this.seedLength));
    // }
    const key = purpose === 'sign' ? ED25519_CURVE : X25519_CURVE;
    const I = createHmac('sha512', key).update(seedBuffer).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
      key: toUint8Array(IL),
      chainCode: toUint8Array(IR),
      derivationPath: 'm',
      curve: key,
      depth: 0,
    };
  }

  static childKeyDerivation(parentKeys: DerivatedKeyPair, index: number, offset = HARDENED_OFFSET): DerivatedKeyPair {
    const { key, chainCode } = parentKeys;
    let { derivationPath } = parentKeys;
    if (key.length !== this.keyLength) {
      throw new TypeError(INVALID_LENGTH('Key', this.keyLength));
    }
    if (chainCode.length !== this.chainCodeLength) {
      throw new TypeError(INVALID_LENGTH('ChainCode', this.chainCodeLength));
    }
    derivationPath += `/${index}'`;
    const offsetIndex = index + offset;
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(offsetIndex, 0);
    const data = Buffer.concat([Buffer.alloc(1, 0), key, indexBuffer]);
    const I = createHmac('sha512', chainCode).update(data).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
      key: toUint8Array(IL),
      chainCode: toUint8Array(IR),
      derivationPath,
      curve: parentKeys.curve,
      depth: parentKeys.depth + 1,
    };
  }

  static derivePath(
    path: string,
    seed: string,
    purpose: Purpose = 'sign',
    encoding: BufferEncoding = 'hex',
    offset = HARDENED_OFFSET,
  ): DerivatedKeyPair {
    if (!isValidDerivationPath(path)) {
      throw new Error(INVALID_DERIVATION_PATH);
    }
    const { key, chainCode, curve, depth, derivationPath } = this.getMasterKeyFromSeed(seed, purpose, encoding);
    const segments = path
      .split('/')
      .slice(1)
      .map(replaceDerive)
      .map((el) => parseInt(el, 10));

    return segments.reduce((parentKeys, segment) => this.childKeyDerivation(parentKeys, segment, offset), {
      key,
      chainCode,
      derivationPath,
      curve,
      depth,
    });
  }

  constructor(seed: string, encoding: BufferEncoding = 'hex') {
    this._seed = seed;
    this.encoding = encoding;
  }

  getMasterKey(purpose: Purpose = 'sign'): DerivatedKeyPair {
    return KeyDerivation.getMasterKeyFromSeed(this._seed, purpose, this.encoding);
  }

  derive(derivationPath: string, purpose: Purpose = 'sign'): DerivatedKeyPair {
    return KeyDerivation.derivePath(derivationPath, this._seed, purpose, this.encoding);
  }

  getBaseKey(purpose: Purpose = 'sign'): DerivatedKeyPair {
    return this.derive(`${BIG_CHAIN_DERIVATION_PATH}`, purpose);
  }

  getAccountKey(account: number, purpose: Purpose = 'sign'): DerivatedKeyPair {
    return this.derive(`${BIG_CHAIN_DERIVATION_PATH}/${account}'`, purpose);
  }

  getAccountChildKey(account: number, index: number, chain: Chain = 0, purpose: Purpose = 'sign'): DerivatedKeyPair {
    return this.derive(`${BIG_CHAIN_DERIVATION_PATH}/${account}'/${chain}'/${index}'`, purpose);
  }
}
