import { derivePath, getMasterKeyFromSeed, getPublicKey } from 'ed25519-hd-key';
import { bufferToUint8Array, convertPrivateKey, convertPublicKey, encodeKey, KeyEncodingMap } from './utils';
import * as bip39 from 'bip39';
import { Ed25519Sha256 } from 'crypto-conditions';

const ENTROPY_BITS = 256;
const INVALID_SEED = 'Invalid seed (must be a Buffer or hex string)';
const INVALID_MNEMONIC = 'Invalid mnemonic (see bip39)';
const INVALID_LANGUAGE = (language: string) => `${language} is not listed in bip39 module`;

export const BIG_CHAIN_PATH = `m/44'/822'`;

export type KeyEncoding = keyof KeyEncodingMap;
export type KeyPair = {
  publicKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => ReturnType<KeyEncodingMap[K]>;
  privateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => ReturnType<KeyEncodingMap[K]>;
};
export type EncodedKey<K extends keyof KeyEncodingMap = 'default'> = ReturnType<KeyEncodingMap[K]>;

export type Chain = 0 | 1;

export class BigChainWallet {
  private _seedHex: string;
  // TODO: networkUrl: string;

  static createMnemonic(
    strength: number = ENTROPY_BITS,
    language = 'english',
    rngFn?: (size: number) => Buffer | undefined,
  ): string {
    if (language && !Object.prototype.hasOwnProperty.call(bip39.wordlists, language)) {
      throw new TypeError(INVALID_LANGUAGE(language));
    }
    const wordlist = bip39.wordlists[language];
    return bip39.generateMnemonic(strength || ENTROPY_BITS, rngFn, wordlist);
  }

  static validateMnemonic(mnemonic: string, language = 'english'): boolean {
    if (language && !Object.prototype.hasOwnProperty.call(bip39.wordlists, language)) {
      throw new TypeError(INVALID_LANGUAGE(language));
    }
    if (mnemonic?.trim().split(/\s+/g).length < 12) {
      return false;
    }
    const wordlist = bip39.wordlists[language];
    return bip39.validateMnemonic(mnemonic, wordlist);
  }

  static createSeed(mnemonic: string, password: string = undefined, language = 'english'): Buffer {
    if (!BigChainWallet.validateMnemonic(mnemonic, language)) {
      throw new Error(INVALID_MNEMONIC);
    }
    return bip39.mnemonicToSeedSync(mnemonic, password);
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

  constructor(seedHex: string) {
    this._seedHex = seedHex;
  }

  encodeKey<K extends keyof KeyEncodingMap>(
    key: Uint8Array,
    encoding: K = 'default' as K,
    type?: 'secret',
  ): EncodedKey<K> {
    return encodeKey(key, encoding, type);
  }

  getMasterKey() {
    return getMasterKeyFromSeed(this._seedHex);
  }

  getMasterKeyPair(): KeyPair {
    const { key } = getMasterKeyFromSeed(this._seedHex);
    const uInt8Key = bufferToUint8Array(key);

    const publicKey = <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) =>
      this.encodeKey(getPublicKey(uInt8Key as Buffer, false), encoding);
    const privateKey = <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) =>
      this.encodeKey(uInt8Key, encoding, 'secret');
    return { publicKey, privateKey };
  }

  derive(derivationPath: string): Uint8Array {
    const data = derivePath(derivationPath, this._seedHex);
    return bufferToUint8Array(data.key);
  }

  getAccountKey(account: number) {
    return this.derive(`${BIG_CHAIN_PATH}/${account}'`);
  }

  getAccountChildKey(account: number, index: number, chain: Chain = 0) {
    return this.derive(`${BIG_CHAIN_PATH}/${account}'/${chain}'/${index}'`);
  }

  getKeyPairFromDerivedKey(key: Uint8Array): KeyPair {
    const publicKey = <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) =>
      this.encodeKey(getPublicKey(key as Buffer, false), encoding);
    const privateKey = <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) =>
      this.encodeKey(key, encoding, 'secret');
    return { publicKey, privateKey };
  }

  getKeyPair(account?: number, index?: number, chain: Chain = 0) {
    let key: Uint8Array;
    if (typeof account == 'number' && typeof index === 'number') {
      key = this.getAccountChildKey(account, index, chain);
    } else if (typeof account == 'number') {
      key = this.getAccountKey(account);
    } else {
      key = this.derive(BIG_CHAIN_PATH);
    }
    return this.getKeyPairFromDerivedKey(key);
  }

  getPublicKey<K extends keyof KeyEncodingMap = 'default'>(account?: number, encoding?: K) {
    return this.getKeyPair(account).publicKey<K>(encoding);
  }

  getPrivateKey<K extends keyof KeyEncodingMap = 'default'>(account?: number, encoding?: K) {
    return this.getKeyPair(account).privateKey<K>(encoding);
  }

  getFullPrivateKey<K extends keyof KeyEncodingMap = 'default'>(account?: number, encoding?: K) {
    const privKey = this.getKeyPair(account).privateKey();
    const pubKey = this.getKeyPair(account).publicKey();
    const key = new Uint8Array(privKey.length + pubKey.length);
    key.set(privKey);
    key.set(pubKey, privKey.length);
    return this.encodeKey<K>(key, encoding, 'secret');
  }

  getDHKeyPair(account?: number, index?: number, chain: Chain = 0): KeyPair {
    const keyPair = this.getKeyPair(account, index, chain);
    const publicKeyBuffer = convertPublicKey(keyPair.publicKey());
    const privateKeyBuffer = convertPrivateKey(keyPair.privateKey());

    const publicKey = <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) =>
      this.encodeKey(publicKeyBuffer, encoding);
    const privateKey = <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) =>
      this.encodeKey(privateKeyBuffer, encoding, 'secret');
    return { publicKey, privateKey };
  }

  getDHPublicKey<K extends keyof KeyEncodingMap = 'default'>(account?: number, encoding?: K) {
    const publicKeyBuffer = convertPublicKey(this.getKeyPair(account).publicKey());
    return this.encodeKey<K>(publicKeyBuffer, encoding);
  }

  getDHPrivateKey<K extends keyof KeyEncodingMap = 'default'>(account?: number, encoding?: K) {
    const privateKeyBuffer = convertPrivateKey(this.getFullPrivateKey(account) as Uint8Array);
    return this.encodeKey<K>(privateKeyBuffer, encoding);
  }

  signTransaction() {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    return function sign(
      _transaction: Record<string, unknown>,
      _input: Record<string, unknown>,
      transactionHash: string,
    ) {
      // TODO: retrieve proper key based on input, transaction ?
      //! cast cheat due to crypto-conditions
      const privateKeyBuffer = (self.getPrivateKey() as unknown) as string;
      const ed25519Fulfillment = new Ed25519Sha256();
      ed25519Fulfillment.sign(Buffer.from(transactionHash, 'hex'), privateKeyBuffer);
      const fulfillmentUri = ed25519Fulfillment.serializeUri();
      return fulfillmentUri;
    };
  }
}
