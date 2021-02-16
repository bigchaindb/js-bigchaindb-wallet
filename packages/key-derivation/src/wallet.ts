import { generateMnemonic, mnemonicToSeedSync, validateMnemonic, wordlists } from 'bip39';
import { Ed25519Sha256 } from 'crypto-conditions';
import { EncryptKeyPair } from './encrypt-key-pair';
import { HARDENED_OFFSET, KeyDerivation } from './key-derivation';
import { SignKeyPair } from './sign-key-pair';
import {
  Chain,
  DerivatedKeyPair,
  DerivationKeyPairMap,
  KeyEncodingMap,
  KeyPairDerivationOptions,
  SignKeyPairFactory,
} from './types';

const ENTROPY_BITS = 256;
const INVALID_SEED = 'Invalid seed (must be a Buffer or hex string)';
const INVALID_MNEMONIC = 'Invalid mnemonic (see bip39)';
const INVALID_LANGUAGE = (language: string) => `${language} is not listed in bip39 module`;

// export type KeyEncoding = keyof KeyEncodingMap;
// export type EncodedKey<K extends keyof KeyEncodingMap = 'default'> = ReturnType<KeyEncodingMap[K]>;

export class BigChainWallet {
  private _seedHex: string;
  // TODO: networkUrl: string;

  // MNEMONIC
  static createMnemonic(
    strength: number = ENTROPY_BITS,
    language = 'english',
    rngFn?: (size: number) => Buffer | undefined,
  ): string {
    if (language && !Object.prototype.hasOwnProperty.call(wordlists, language)) {
      throw new TypeError(INVALID_LANGUAGE(language));
    }
    const wordlist = wordlists[language];
    return generateMnemonic(strength || ENTROPY_BITS, rngFn, wordlist);
  }

  static validateMnemonic(mnemonic: string, language = 'english'): boolean {
    if (language && !Object.prototype.hasOwnProperty.call(wordlists, language)) {
      throw new TypeError(INVALID_LANGUAGE(language));
    }
    if (mnemonic?.trim().split(/\s+/g).length < 12) {
      return false;
    }
    const wordlist = wordlists[language];
    return validateMnemonic(mnemonic, wordlist);
  }

  static createSeed(mnemonic: string, password: string = undefined, language = 'english'): Buffer {
    if (!BigChainWallet.validateMnemonic(mnemonic, language)) {
      throw new Error(INVALID_MNEMONIC);
    }
    return mnemonicToSeedSync(mnemonic, password);
  }

  static fromMnemonic(mnemonic: string, password: string = undefined, language = 'english'): BigChainWallet {
    const seedHex = BigChainWallet.createSeed(mnemonic, password, language).toString('hex');
    return new BigChainWallet(seedHex);
  }

  static fromSeed(seed: string | Buffer): BigChainWallet {
    let seedHex: string;
    if (Buffer.isBuffer(seed)) {
      seedHex = seed.toString('hex');
    } else if (typeof seed === 'string') {
      seedHex = seed;
    } else {
      throw new TypeError(INVALID_SEED);
    }
    return new BigChainWallet(seedHex);
  }

  static masterKeyPairFactory<P extends keyof DerivationKeyPairMap>(
    type: P,
    seed: string,
  ): ReturnType<DerivationKeyPairMap[P]> {
    const derivationKeyPairMap: DerivationKeyPairMap = {
      sign: () => SignKeyPair.getMasterKeyPair(seed).factory(),
      encrypt: () => EncryptKeyPair.getMasterKeyPair(seed).factory(),
    };
    return derivationKeyPairMap[type]() as ReturnType<DerivationKeyPairMap[P]>;
  }

  static derivatedKeyPairFactoryFromSeed<P extends keyof DerivationKeyPairMap>(
    type: P,
    seed: string,
    options: KeyPairDerivationOptions,
  ): ReturnType<DerivationKeyPairMap[P]> {
    const derivationKeyPairMap: DerivationKeyPairMap = {
      sign: () => SignKeyPair.getDerivatedKeyPair(seed, options).factory(),
      encrypt: () => EncryptKeyPair.getDerivatedKeyPair(seed, options).factory(),
    };
    return derivationKeyPairMap[type]() as ReturnType<DerivationKeyPairMap[P]>;
  }

  static derivatedKeyPairFactory<P extends keyof DerivationKeyPairMap>(
    type: P,
    derivatedKeyPair: DerivatedKeyPair,
  ): ReturnType<DerivationKeyPairMap[P]> {
    const derivationKeyPairMap: DerivationKeyPairMap = {
      sign: () => SignKeyPair.fromDerivatedKeyPair(derivatedKeyPair).factory(),
      encrypt: () => EncryptKeyPair.fromDerivatedKeyPair(derivatedKeyPair).factory(),
    };
    return derivationKeyPairMap[type]() as ReturnType<DerivationKeyPairMap[P]>;
  }

  // Go deeper in derivationPath after `m/44'/822'/accountId'`
  static getDerivatedKeyPair<P extends keyof DerivationKeyPairMap = 'sign'>(
    type: P,
    signKeyPair: SignKeyPairFactory,
    index: number,
    chain: Chain = 0,
  ): ReturnType<DerivationKeyPairMap[P]> {
    const { privateKey, chainCode, derivationPath } = signKeyPair;
    const segments = [index, chain];
    const derivatedKeyPair = segments.reduce(
      (parentKeys, segment) => KeyDerivation.childKeyDerivation(parentKeys, segment + HARDENED_OFFSET),
      {
        key: privateKey(),
        chainCode: chainCode(),
        derivationPath: `${derivationPath}/${chain}'/${index}'`,
      },
    );
    return BigChainWallet.derivatedKeyPairFactory<P>(type, derivatedKeyPair);
  }

  constructor(seedHex: string) {
    this._seedHex = seedHex;
  }

  getMasterKeyPair<P extends keyof DerivationKeyPairMap = 'sign'>(type: P): ReturnType<DerivationKeyPairMap[P]> {
    return BigChainWallet.masterKeyPairFactory<P>(type, this._seedHex);
  }

  getDerivatedKeyPair<P extends keyof DerivationKeyPairMap = 'sign'>(
    type: P,
    options: KeyPairDerivationOptions = {},
  ): ReturnType<DerivationKeyPairMap[P]> {
    return BigChainWallet.derivatedKeyPairFactoryFromSeed<P>(type, this._seedHex, options);
  }

  getDerivedPublicKey<K extends keyof KeyEncodingMap = 'default', P extends keyof DerivationKeyPairMap = 'sign'>(
    type: P,
    options: KeyPairDerivationOptions = {},
    encoding?: K,
  ) {
    return this.getDerivatedKeyPair(type, options).publicKey<K>(encoding);
  }

  getDerivedPrivateKey<K extends keyof KeyEncodingMap = 'default', P extends keyof DerivationKeyPairMap = 'sign'>(
    type: P,
    options: KeyPairDerivationOptions = {},
    encoding?: K,
  ) {
    return this.getDerivatedKeyPair(type, options).privateKey<K>(encoding);
  }

  getDerivedChainCode<K extends keyof KeyEncodingMap = 'default', P extends keyof DerivationKeyPairMap = 'sign'>(
    type: P,
    options: KeyPairDerivationOptions = {},
    encoding?: K,
  ) {
    return this.getDerivatedKeyPair(type, options).chainCode<K>(encoding);
  }

  getDerivedFullPrivateKey<K extends keyof KeyEncodingMap = 'default', P extends keyof DerivationKeyPairMap = 'sign'>(
    type: P,
    options: KeyPairDerivationOptions = {},
    encoding?: K,
  ) {
    if (type !== 'sign') {
      throw new Error('Full private key is only supported for type sign');
    }
    return this.getDerivatedKeyPair(type, options).fullPrivateKey<K>(encoding);
  }

  signTransaction(): (
    transaction: Record<string, unknown>,
    input: Record<string, unknown>,
    transactionHash: string,
  ) => string {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    return function sign(
      _transaction: Record<string, unknown>,
      _input: Record<string, unknown>,
      transactionHash: string,
    ) {
      // TODO: retrieve proper key based on input, transaction ?
      //! cast cheat due to crypto-conditions lib
      const privateKeyBuffer = (self.getDerivedPrivateKey('sign') as unknown) as string;
      const ed25519Fulfillment = new Ed25519Sha256();
      ed25519Fulfillment.sign(Buffer.from(transactionHash, 'hex'), privateKeyBuffer);
      const fulfillmentUri = ed25519Fulfillment.serializeUri();
      return fulfillmentUri;
    };
  }
}
