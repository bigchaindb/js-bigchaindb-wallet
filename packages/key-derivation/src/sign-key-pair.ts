import nacl from 'tweetnacl';
import { KeyDerivation } from './key-derivation';
import { DerivedKeyPair, KeyEncodingMap, KeyPairDerivationOptions, SignKeyPairFactory } from './types';
import { bufferToUint8Array, encodeKey } from './utils';

export class SignKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  fullPrivateKey: Uint8Array;
  chainCode: Uint8Array;
  derivationPath: string;

  static getMasterKeyPair(seedHex: string): SignKeyPair {
    const derivedKeyPair = KeyDerivation.getMasterKeyFromSeed(seedHex, 'hex');
    return new SignKeyPair(derivedKeyPair);
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
    return new SignKeyPair(derivedKeyPair);
  }

  static getPublicKey(privateKey: Uint8Array, withZeroByte = true): Uint8Array {
    const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
    const signPk = keyPair.secretKey.subarray(32);
    const zero = Buffer.alloc(1, 0);
    const pubKeyBuffer = withZeroByte ? Buffer.concat([zero, Buffer.from(signPk)]) : Buffer.from(signPk);
    return bufferToUint8Array(pubKeyBuffer);
  }

  static getFullPrivateKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    const fullPrivateKey = new Uint8Array(privateKey.length + publicKey.length);
    fullPrivateKey.set(privateKey);
    fullPrivateKey.set(publicKey, privateKey.length);
    return fullPrivateKey;
  }

  constructor(options: DerivedKeyPair) {
    const { key, chainCode, derivationPath } = options;
    this.chainCode = chainCode;
    this.derivationPath = derivationPath;
    this.publicKey = SignKeyPair.getPublicKey(key, false);
    this.privateKey = key;
    this.fullPrivateKey = SignKeyPair.getFullPrivateKey(key, this.publicKey);
  }

  getChainCode<K extends keyof KeyEncodingMap = 'default'>(
    encoding: K = 'default' as K,
  ): ReturnType<KeyEncodingMap[K]> {
    return encodeKey(this.chainCode, encoding);
  }

  getPublicKey<K extends keyof KeyEncodingMap = 'default'>(
    encoding: K = 'default' as K,
  ): ReturnType<KeyEncodingMap[K]> {
    return encodeKey(this.publicKey, encoding);
  }

  getPrivateKey<K extends keyof KeyEncodingMap = 'default'>(
    encoding: K = 'default' as K,
  ): ReturnType<KeyEncodingMap[K]> {
    return encodeKey(this.privateKey, encoding, 'secret');
  }

  getFullPrivateKey<K extends keyof KeyEncodingMap = 'default'>(
    encoding: K = 'default' as K,
  ): ReturnType<KeyEncodingMap[K]> {
    return encodeKey(this.fullPrivateKey, encoding, 'secret');
  }

  factory(): SignKeyPairFactory {
    return {
      publicKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getPublicKey(encoding),
      privateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getPrivateKey(encoding),
      fullPrivateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getFullPrivateKey(encoding),
      chainCode: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getChainCode(encoding),
      derivationPath: this.derivationPath,
    };
  }
}
