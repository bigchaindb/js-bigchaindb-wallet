import * as base58 from 'bs58';
import { sign, SignKeyPair as NaclSignKeyPair } from 'tweetnacl';
import { KeyDerivation } from './key-derivation';
import {
  DerivedKeyPair,
  KeyEncodingMap,
  KeyPairDerivationOptions,
  SignKeyPairFactory,
  SignKeyPairObject,
} from './types';
import { bufferToUint8Array, encodeKey, base58Decode, isEqualBuffer, toUint8Array } from './utils';

const INVALID_LENGTH = (el: string, length: number) => `${el} should be ${length} bytes length`;

export const ED25519_SUITE_ID = 'Ed25519VerificationKey2018';

export class SignKeyPair {
  static readonly publicKeyLength = sign.publicKeyLength;
  static readonly privateKeyLength = sign.secretKeyLength / 2;
  static readonly fullPrivateKeyLength = sign.secretKeyLength;
  static readonly seedLength = sign.seedLength;
  static readonly suite = ED25519_SUITE_ID;

  publicKey: Uint8Array;
  privateKey?: Uint8Array;
  fullPrivateKey?: Uint8Array;
  chainCode?: Uint8Array;
  derivationPath?: string;
  type: string;
  id?: string;
  controller?: string;

  static getMasterKeyPair(seedHex: string): SignKeyPair {
    const derivedKeyPair = KeyDerivation.getMasterKeyFromSeed(seedHex, 'hex');
    return SignKeyPair.fromDerivedKeyPair(derivedKeyPair);
  }

  static getDerivedKeyPair(seedHex: string, options: KeyPairDerivationOptions = {}): SignKeyPair {
    const { account, index, chain = 0 } = options;
    const keyDerivation = new KeyDerivation(seedHex);
    let derivedKeyPair: DerivedKeyPair;
    if (typeof account == 'number' && typeof index === 'number') {
      derivedKeyPair = keyDerivation.getAccountChildKey(account, index, chain);
    } else if (typeof account == 'number') {
      derivedKeyPair = keyDerivation.getAccountKey(account);
    } else {
      derivedKeyPair = keyDerivation.getBaseKey();
    }
    return SignKeyPair.fromDerivedKeyPair(derivedKeyPair);
  }

  static fromDerivedKeyPair(keyPair: DerivedKeyPair): SignKeyPair {
    const { chainCode, key, derivationPath } = keyPair;
    if (derivationPath && !(typeof derivationPath === 'string')) {
      throw new TypeError('`derivationPath` must be string.');
    }
    if (!key || key.length !== KeyDerivation.keyLength) {
      throw new TypeError(INVALID_LENGTH('Key', KeyDerivation.keyLength));
    }
    if (!chainCode || chainCode.length !== KeyDerivation.chainCodeLength) {
      throw new TypeError(INVALID_LENGTH('ChainCode', KeyDerivation.chainCodeLength));
    }
    const publicKey = SignKeyPair.getPublicKey(key, false);
    const privateKey = key;
    const fullPrivateKey = SignKeyPair.getFullPrivateKey(key, publicKey);
    return new SignKeyPair({ chainCode, derivationPath, publicKey, privateKey, fullPrivateKey });
  }

  static fromFactory(factory: SignKeyPairFactory): SignKeyPair {
    const { chainCode, controller, derivationPath, id, publicKey, privateKey } = factory;
    return new SignKeyPair({
      chainCode: typeof chainCode === 'function' ? chainCode() : null,
      controller,
      derivationPath,
      id,
      publicKey: publicKey(),
      privateKey: typeof chainCode === 'function' ? privateKey() : null,
    });
  }

  static fromFingerprint(fingerprint: string): SignKeyPair {
    if (!fingerprint || !(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      throw new Error('`fingerprint` must be a multibase encoded string.');
    }
    // skip leading `z` that indicates base58 encoding
    const buffer: Buffer = base58.decode(fingerprint.substr(1));
    // buffer is: 0xed 0x01 <public key bytes>
    if (buffer[0] !== 0xed || buffer[1] !== 0x01) {
      throw new Error(`Unsupported fingerprint "${fingerprint}".`);
    }
    // TODO: find a way to pass derivationPath ?
    return new SignKeyPair({
      publicKey: bufferToUint8Array(buffer.slice(2)),
    });
  }

  static generate(options: {
    seed?: string | Uint8Array | Buffer;
    secretKey?: string | Uint8Array | Buffer;
  }): SignKeyPair {
    let keyPair: NaclSignKeyPair;
    if (options.seed) {
      const { seed } = options;
      const seedBytes = toUint8Array(seed);
      if (!(seedBytes instanceof Uint8Array && seedBytes.length === this.seedLength)) {
        throw new TypeError(INVALID_LENGTH('Seed', this.seedLength));
      }
      keyPair = sign.keyPair.fromSeed(seedBytes);
    } else if (options.secretKey) {
      const { secretKey } = options;
      const secretKeyBytes = toUint8Array(secretKey);
      if (!(secretKeyBytes instanceof Uint8Array && secretKeyBytes.length === this.fullPrivateKeyLength)) {
        throw new TypeError(INVALID_LENGTH('SecretKey', this.fullPrivateKeyLength));
      }
      keyPair = sign.keyPair.fromSecretKey(secretKeyBytes);
    } else {
      keyPair = sign.keyPair();
    }

    const privateKey = keyPair.secretKey.subarray(0, 32);
    return new SignKeyPair({
      publicKey: keyPair.publicKey,
      privateKey,
      fullPrivateKey: keyPair.secretKey,
    });
  }

  static getPublicKey(privateKey: Uint8Array, withZeroByte = true): Uint8Array {
    if (!privateKey || privateKey.length !== SignKeyPair.privateKeyLength) {
      throw new TypeError(INVALID_LENGTH('PrivateKey', SignKeyPair.privateKeyLength));
    }
    const keyPair = sign.keyPair.fromSeed(privateKey);
    const signPk = keyPair.secretKey.subarray(32);
    const zero = Buffer.alloc(1, 0);
    const pubKeyBuffer = withZeroByte ? Buffer.concat([zero, Buffer.from(signPk)]) : Buffer.from(signPk);
    return bufferToUint8Array(pubKeyBuffer);
  }

  static getFullPrivateKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    if (!privateKey || privateKey.length !== SignKeyPair.privateKeyLength) {
      throw new TypeError(INVALID_LENGTH('PrivateKey', SignKeyPair.privateKeyLength));
    }
    if (!publicKey || publicKey.length !== SignKeyPair.publicKeyLength) {
      throw new TypeError(INVALID_LENGTH('PublicKey', SignKeyPair.publicKeyLength));
    }
    const fullPrivateKey = new Uint8Array(privateKey.length + publicKey.length);
    fullPrivateKey.set(privateKey);
    fullPrivateKey.set(publicKey, privateKey.length);
    return fullPrivateKey;
  }

  static getFingerprintFromPublicKey(publicKeyBase58: string): string {
    // ed25519 cryptonyms are multicodec encoded values, specifically:
    // (multicodec ed25519-pub 0xed01 + key bytes)
    const pubkeyBytes = base58Decode({
      decode: base58.decode,
      keyMaterial: publicKeyBase58,
      type: 'public',
    });
    const buffer = new Uint8Array(2 + pubkeyBytes.length);
    buffer[0] = 0xed;
    buffer[1] = 0x01;
    buffer.set(pubkeyBytes, 2);
    // prefix with `z` to indicate multi-base base58btc encoding
    return `z${base58.encode(buffer)}`;
  }

  static verifyFingerprint(fingerprint: string, publicKeyBase58: string): { valid: boolean; error?: any } {
    // fingerprint should have `z` prefix indicating
    // that it's multi-base encoded
    if (!(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      return {
        error: new Error('`fingerprint` must be a multibase encoded string.'),
        valid: false,
      };
    }
    let fingerprintBuffer: Buffer;
    try {
      fingerprintBuffer = base58Decode({
        decode: base58.decode,
        keyMaterial: fingerprint.slice(1),
        type: `fingerprint's`,
      });
    } catch (e) {
      return { error: e, valid: false };
    }
    let publicKeyBuffer: Buffer;
    try {
      publicKeyBuffer = base58Decode({
        decode: base58.decode,
        keyMaterial: publicKeyBase58,
        type: 'public',
      });
    } catch (e) {
      return { error: e, valid: false };
    }

    const buffersEqual = isEqualBuffer(publicKeyBuffer, fingerprintBuffer.slice(2));
    // validate the first two multicodec bytes 0xed01
    const valid = fingerprintBuffer[0] === 0xed && fingerprintBuffer[1] === 0x01 && buffersEqual;
    if (!valid) {
      return {
        error: new Error('The fingerprint does not match the public key.'),
        valid: false,
      };
    }
    return { valid };
  }

  constructor(options: Partial<SignKeyPairObject>) {
    const { chainCode, controller, derivationPath, id, publicKey, privateKey, fullPrivateKey } = options;
    this.type = ED25519_SUITE_ID;
    this.controller = controller;
    this.id = id;
    this.chainCode = chainCode;
    this.derivationPath = derivationPath;
    this.publicKey = publicKey;
    if (!this.publicKey) {
      throw new TypeError('The "publicKey" property is required.');
    }
    if (privateKey && !fullPrivateKey) {
      this.privateKey = privateKey;
      this.fullPrivateKey = SignKeyPair.getFullPrivateKey(privateKey, publicKey);
    } else if (fullPrivateKey) {
      this.privateKey = privateKey;
      this.fullPrivateKey = fullPrivateKey;
    }
    if (this.controller && !this.id) {
      this.id = `${this.controller}#${this.getFingerprint()}`;
    }
  }

  getChainCode<K extends keyof KeyEncodingMap = 'default'>(
    encoding: K = 'default' as K,
  ): ReturnType<KeyEncodingMap[K]> {
    if (encoding === 'der' || encoding === 'pem' || encoding === 'keyObject') {
      throw new TypeError(`ChainCode cannot be encoded to ${encoding}`);
    }
    return this.chainCode ? encodeKey(this.chainCode, encoding) : null;
  }

  getPublicKey<K extends keyof KeyEncodingMap = 'default'>(
    encoding: K = 'default' as K,
  ): ReturnType<KeyEncodingMap[K]> {
    return encodeKey(this.publicKey, encoding);
  }

  getPrivateKey<K extends keyof KeyEncodingMap = 'default'>(
    encoding: K = 'default' as K,
  ): ReturnType<KeyEncodingMap[K]> {
    if (!this.privateKey) {
      return null;
    }
    if (encoding === 'der' || encoding === 'pem' || encoding === 'keyObject') {
      return encodeKey(this.fullPrivateKey, encoding, 'private', 'pkcs8');
    }
    return encodeKey(this.privateKey, encoding, 'private', 'pkcs8');
  }

  getFullPrivateKey<K extends keyof KeyEncodingMap = 'default'>(
    encoding: K = 'default' as K,
  ): ReturnType<KeyEncodingMap[K]> {
    return this.fullPrivateKey ? encodeKey(this.fullPrivateKey, encoding, 'private', 'pkcs8') : null;
  }

  getFingerprint(): string {
    return SignKeyPair.getFingerprintFromPublicKey(this.getPublicKey('base58'));
  }

  verifyFingerprint(fingerprint: string): { valid: boolean; error?: any } {
    return SignKeyPair.verifyFingerprint(fingerprint, this.getPublicKey('base58'));
  }

  toObject(addPrivateKey = false): SignKeyPairObject {
    const keyPair: SignKeyPairObject = {
      publicKey: this.getPublicKey(),
      chainCode: this.getChainCode(),
      fingerprint: this.getFingerprint(),
      derivationPath: this.derivationPath,
      type: this.type,
      id: this.id,
      controller: this.controller,
    };
    if (addPrivateKey) {
      keyPair.privateKey = this.getPrivateKey();
      keyPair.fullPrivateKey = this.getFullPrivateKey();
    }
    return keyPair;
  }

  factory(): SignKeyPairFactory {
    return {
      publicKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getPublicKey(encoding),
      privateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getPrivateKey(encoding),
      fullPrivateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getFullPrivateKey(encoding),
      chainCode: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getChainCode(encoding),
      fingerprint: () => this.getFingerprint(),
      derivationPath: this.derivationPath,
      type: this.type,
      id: this.id,
      controller: this.controller,
    };
  }
}
