import * as ed2curve from 'ed2curve';
import { KeyDerivation } from './key-derivation';
import { SignKeyPair } from './sign-key-pair';
import { DerivedKeyPair, EncryptKeyPairFactory, KeyEncodingMap, KeyPair, KeyPairDerivationOptions } from './types';
import { encodeKey } from './utils';

export class EncryptKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  chainCode: Uint8Array;
  derivationPath: string;

  static getMasterKeyPair(seedHex: string): EncryptKeyPair {
    const derivedKeyPair = KeyDerivation.getMasterKeyFromSeed(seedHex, 'hex');
    return new EncryptKeyPair(derivedKeyPair);
  }

  static getDerivedKeyPair(seedHex: string, options: KeyPairDerivationOptions = {}): EncryptKeyPair {
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
    return new EncryptKeyPair(derivedKeyPair);
  }

  static fromSigninKeyPair(signKeyPair: SignKeyPair): EncryptKeyPair {
    const { privateKey: key, chainCode, derivationPath } = signKeyPair;
    return new EncryptKeyPair({ key, chainCode, derivationPath });
  }

  static convertPublicKeyToCurve(publicKey: Uint8Array): Uint8Array {
    return ed2curve.convertPublicKey(publicKey);
  }

  static convertPrivateKeyToCurve(privateKey: Uint8Array): Uint8Array {
    return ed2curve.convertSecretKey(privateKey);
  }

  // privateKey must be the full private key (eg. 64 bytes)
  static convertKeyPairToCurve(keyPair: KeyPair): KeyPair {
    const { publicKey, privateKey } = keyPair;
    return {
      publicKey: this.convertPublicKeyToCurve(publicKey),
      privateKey: this.convertPrivateKeyToCurve(privateKey),
    };
  }

  constructor(options: DerivedKeyPair) {
    const { key, chainCode, derivationPath } = options;
    this.chainCode = chainCode;
    this.derivationPath = derivationPath;
    const signingKeyPair = new SignKeyPair({ key, chainCode, derivationPath });
    this.publicKey = EncryptKeyPair.convertPublicKeyToCurve(signingKeyPair.publicKey);
    this.privateKey = EncryptKeyPair.convertPrivateKeyToCurve(signingKeyPair.fullPrivateKey);
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

  factory(): EncryptKeyPairFactory {
    return {
      publicKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getPublicKey(encoding),
      privateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getPrivateKey(encoding),
      chainCode: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => this.getChainCode(encoding),
      derivationPath: this.derivationPath,
    };
  }
}
