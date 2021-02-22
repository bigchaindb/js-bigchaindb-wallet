import * as base58 from 'bs58';
import * as ed2curve from 'ed2curve';
import { box, BoxKeyPair as NaclBoxKeyPair } from 'tweetnacl';
import { KeyDerivation, X25519_CURVE } from './key-derivation';
import { SignKeyPair } from './sign-key-pair';
import {
  DerivatedKeyPair,
  EncryptKeyPairFactory,
  EncryptKeyPairObject,
  KeyEncodingMap,
  KeyPair,
  KeyPairDerivationOptions,
} from './types';
import { base58Decode, encodeKey, toUint8Array } from './utils';

const INVALID_LENGTH = (el: string, length: number) => `${el} should be ${length} bytes length`;

export const X25519_SUITE_ID = 'X25519KeyAgreementKey2019';

export class EncryptKeyPair {
  static readonly publicKeyLength = box.publicKeyLength;
  static readonly privateKeyLength = box.secretKeyLength;
  static readonly suite = X25519_SUITE_ID;

  publicKey: Uint8Array;
  privateKey?: Uint8Array;
  chainCode?: Uint8Array;
  derivationPath?: string;
  type: string;
  id?: string;
  controller?: string;

  static getMasterKeyPair(seedHex: string): EncryptKeyPair {
    const derivatedKeyPair = KeyDerivation.getMasterKeyFromSeed(seedHex, 'encrypt', 'hex');
    return EncryptKeyPair.fromDerivatedKeyPair(derivatedKeyPair);
  }

  static getDerivatedKeyPair(seedHex: string, options: KeyPairDerivationOptions = {}): EncryptKeyPair {
    const { account, index, chain = 0 } = options;
    const keyDerivation = new KeyDerivation(seedHex);
    let derivatedKeyPair: DerivatedKeyPair;
    if (typeof account == 'number' && typeof index === 'number') {
      derivatedKeyPair = keyDerivation.getAccountChildKey(account, index, chain, 'encrypt');
    } else if (typeof account == 'number') {
      derivatedKeyPair = keyDerivation.getAccountKey(account, 'encrypt');
    } else {
      derivatedKeyPair = keyDerivation.getBaseKey('encrypt');
    }
    return EncryptKeyPair.fromDerivatedKeyPair(derivatedKeyPair);
  }

  static fromDerivatedKeyPair(keyPair: DerivatedKeyPair): EncryptKeyPair {
    const { chainCode, curve, depth, key, derivationPath } = keyPair;
    if (derivationPath && !(typeof derivationPath === 'string')) {
      throw new TypeError('`derivationPath` must be string.');
    }
    if (!key || key.length !== KeyDerivation.keyLength) {
      throw new TypeError(INVALID_LENGTH('Key', KeyDerivation.keyLength));
    }
    if (!chainCode || chainCode.length !== KeyDerivation.chainCodeLength) {
      throw new TypeError(INVALID_LENGTH('ChainCode', KeyDerivation.chainCodeLength));
    }

    if (curve === X25519_CURVE) {
      const publicKey = EncryptKeyPair.getPublicKey(key, false);
      const privateKey = key;
      return new EncryptKeyPair({ chainCode, derivationPath, publicKey, privateKey });
    }
    // throw new TypeError(`'curve' must be ${X25519_CURVE}.`);
    const signingKeyPair = SignKeyPair.fromDerivatedKeyPair({ key, curve, chainCode, depth, derivationPath });
    const publicKey = EncryptKeyPair.convertPublicKeyToCurve(signingKeyPair.publicKey);
    const privateKey = EncryptKeyPair.convertPrivateKeyToCurve(signingKeyPair.fullPrivateKey);
    return new EncryptKeyPair({ chainCode, derivationPath, publicKey, privateKey });
  }

  static fromFactory(factory: EncryptKeyPairFactory): EncryptKeyPair {
    const { chainCode, controller, derivationPath, id, publicKey, privateKey } = factory;
    return new EncryptKeyPair({
      chainCode: typeof chainCode === 'function' ? chainCode() : null,
      controller,
      derivationPath,
      id,
      publicKey: publicKey(),
      privateKey: typeof chainCode === 'function' ? privateKey() : null,
    });
  }

  static fromSignKeyPair(signKeyPair: SignKeyPair): EncryptKeyPair {
    const { chainCode, derivationPath } = signKeyPair;
    if (signKeyPair.fullPrivateKey && signKeyPair.fullPrivateKey.length !== SignKeyPair.fullPrivateKeyLength) {
      throw new TypeError(INVALID_LENGTH('PrivateKey', SignKeyPair.fullPrivateKeyLength));
    }
    if (!signKeyPair.publicKey || signKeyPair.publicKey.length !== SignKeyPair.publicKeyLength) {
      throw new TypeError(INVALID_LENGTH('PublicKey', SignKeyPair.publicKeyLength));
    }
    const publicKey = EncryptKeyPair.convertPublicKeyToCurve(signKeyPair.publicKey);
    const privateKey = signKeyPair.fullPrivateKey
      ? EncryptKeyPair.convertPrivateKeyToCurve(signKeyPair.fullPrivateKey)
      : null;
    return new EncryptKeyPair({ chainCode, derivationPath, publicKey, privateKey });
  }

  static fromFingerprint(fingerprint: string): EncryptKeyPair {
    if (!fingerprint || !(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      throw new Error('`fingerprint` must be a multibase encoded string.');
    }
    // skip leading `z` that indicates base58 encoding
    const buffer: Buffer = base58.decode(fingerprint.substr(1));
    // buffer is: 0xec 0x01 <public key bytes>
    if (buffer[0] !== 0xec || buffer[1] !== 0x01) {
      throw new Error(`Unsupported Fingerprint Type: ${fingerprint}`);
    }

    // TODO: find a way to pass derivationPath ?
    return new EncryptKeyPair({ publicKey: toUint8Array(buffer.slice(2)) });
  }

  static generate(
    options: { secretKey?: string | Uint8Array | Buffer; encoding?: BufferEncoding } = {},
  ): EncryptKeyPair {
    let keyPair: NaclBoxKeyPair;
    if (options.secretKey) {
      const { encoding, secretKey } = options;
      const secretKeyBytes = toUint8Array(secretKey, encoding);
      if (!(secretKeyBytes instanceof Uint8Array && secretKeyBytes.length === this.privateKeyLength)) {
        throw new TypeError(INVALID_LENGTH('SecretKey', this.privateKeyLength));
      }
      keyPair = box.keyPair.fromSecretKey(secretKeyBytes);
    } else {
      keyPair = box.keyPair();
    }

    return new EncryptKeyPair({
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey,
    });
  }

  static getPublicKey(privateKey: Uint8Array, withZeroByte = true): Uint8Array {
    if (!privateKey || privateKey.length !== EncryptKeyPair.privateKeyLength) {
      throw new TypeError(INVALID_LENGTH('PrivateKey', EncryptKeyPair.privateKeyLength));
    }
    const keyPair = box.keyPair.fromSecretKey(privateKey);
    const zero = Buffer.from([0x40]);
    const pubKeyBuffer = withZeroByte
      ? Buffer.concat([zero, Buffer.from(keyPair.publicKey)])
      : Buffer.from(keyPair.publicKey);
    return toUint8Array(pubKeyBuffer);
  }

  static getSharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    if (publicKey.length === 33) {
      publicKey = publicKey.subarray(1, 33);
    }
    // TODO return non hashed shared key ? append 0x04 ?;
    return box.before(publicKey, privateKey);
  }

  static convertPublicKeyToCurve(publicKey: Uint8Array): Uint8Array {
    if (!publicKey || publicKey.length !== SignKeyPair.publicKeyLength) {
      throw new TypeError(INVALID_LENGTH('PublicKey', SignKeyPair.publicKeyLength));
    }
    const pubKey = ed2curve.convertPublicKey(publicKey);
    if (!pubKey) {
      throw new Error('Error converting to X25519; Invalid Ed25519 public key.');
    }
    return pubKey;
  }

  static convertPrivateKeyToCurve(privateKey: Uint8Array): Uint8Array {
    if (!privateKey || privateKey.length !== SignKeyPair.fullPrivateKeyLength) {
      throw new TypeError(INVALID_LENGTH('PrivateKey', SignKeyPair.fullPrivateKeyLength));
    }
    const privKey = ed2curve.convertSecretKey(privateKey);
    if (!privKey) {
      throw new Error('Error converting to X25519; Invalid Ed25519 private key.');
    }
    return privKey;
  }

  static convertKeyPairToCurve(keyPair: KeyPair): KeyPair {
    const { publicKey, privateKey } = keyPair;
    if (!privateKey || privateKey.length !== SignKeyPair.fullPrivateKeyLength) {
      throw new TypeError(INVALID_LENGTH('PrivateKey', SignKeyPair.fullPrivateKeyLength));
    }
    if (!publicKey || publicKey.length !== SignKeyPair.publicKeyLength) {
      throw new TypeError(INVALID_LENGTH('PublicKey', SignKeyPair.publicKeyLength));
    }
    return {
      publicKey: this.convertPublicKeyToCurve(publicKey),
      privateKey: this.convertPrivateKeyToCurve(privateKey),
    };
  }

  static getFingerprintFromPublicKey(publicKeyBase58: string): string {
    // X25519 cryptonyms are multicodec encoded values, specifically:
    // (multicodec('x25519-pub') + key bytes)
    const pubkeyBytes = base58Decode({
      decode: base58.decode,
      keyMaterial: publicKeyBase58,
      type: 'public',
    });
    const buffer = new Uint8Array(2 + pubkeyBytes.length);
    // See https://github.com/multiformats/multicodec/blob/master/table.csv
    // 0xec is the value for X25519 public key
    // 0x01 is from varint.encode(0xec) -> [0xec, 0x01]
    // See https://github.com/multiformats/unsigned-varint
    buffer[0] = 0xec; //
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
    // validate the first buffer multicodec bytes 0xec 0x01
    const valid =
      fingerprintBuffer[0] === 0xec &&
      fingerprintBuffer[1] === 0x01 &&
      publicKeyBuffer.toString() === fingerprintBuffer.slice(2).toString();
    if (!valid) {
      return {
        error: new Error('The fingerprint does not match the public key.'),
        valid: false,
      };
    }
    return { valid };
  }

  constructor(options: Partial<EncryptKeyPairObject>) {
    const { chainCode, controller, derivationPath, id, publicKey, privateKey } = options;
    this.type = X25519_SUITE_ID;
    this.controller = controller;
    this.id = id;
    this.chainCode = chainCode;
    this.derivationPath = derivationPath;
    this.publicKey = publicKey;
    if (!this.publicKey) {
      throw new TypeError('The "publicKey" property is required.');
    }
    this.privateKey = privateKey;
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
    if (encoding === 'der' || encoding === 'keyObject' || encoding === 'pem') {
      throw new TypeError(`Encoding ${encoding} not supported for ${X25519_SUITE_ID}`);
    }
    return this.privateKey ? encodeKey(this.privateKey, encoding, 'private', 'sec1') : null;
  }

  getFingerprint(): string {
    return EncryptKeyPair.getFingerprintFromPublicKey(this.getPublicKey('base58'));
  }

  verifyFingerprint(fingerprint: string): { valid: boolean; error?: any } {
    return EncryptKeyPair.verifyFingerprint(fingerprint, this.getPublicKey('base58'));
  }

  toObject(options: { publicKey: boolean; privateKey: boolean }): EncryptKeyPairObject {
    const { publicKey = false, privateKey = false } = options;
    if (!publicKey && !privateKey) {
      throw new Error('Export requires specifying either "publicKey" or "privateKey".');
    }
    const keyPair: EncryptKeyPairObject = {
      chainCode: this.getChainCode(),
      fingerprint: this.getFingerprint(),
      derivationPath: this.derivationPath,
      type: this.type,
      id: this.id,
      controller: this.controller,
    };
    if (publicKey) {
      keyPair.publicKey = this.getPublicKey();
    }
    if (privateKey) {
      keyPair.privateKey = this.getPrivateKey();
    }
    return keyPair;
  }

  factory(): EncryptKeyPairFactory {
    return {
      publicKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getPublicKey(encoding),
      privateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getPrivateKey(encoding),
      chainCode: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getChainCode(encoding),
      fingerprint: () => this.getFingerprint(),
      derivationPath: this.derivationPath,
      type: this.type,
      id: this.id,
      controller: this.controller,
    };
  }
}
