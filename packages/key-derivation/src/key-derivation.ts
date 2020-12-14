import * as bip39 from 'bip39';
import { Ed25519Sha256 } from 'crypto-conditions';
import { derivePath, getMasterKeyFromSeed, getPublicKey } from 'ed25519-hd-key';
import { bufferToUint8Array, convertPublicKey, convertPrivateKey, keyFactory } from './utils';

const ENTROPY_BITS = 256;
const INVALID_SEED = 'Invalid seed (must be a Buffer or hex string)';
const INVALID_MNEMONIC = 'Invalid mnemonic (see bip39)';
const INVALID_LANGUAGE = (language: string) => `${language} is not listed in bip39 module`;

export const BIG_CHAIN_PATH = "m/44'/822'";

export type KeyOutput = undefined | 'base58' | 'hex' | 'pem';

export type KeyPair = {
  publicKey: (output?: KeyOutput) => string | Uint8Array;
  privateKey: (output?: KeyOutput) => string | Uint8Array;
};

export type KeyFactory = (key: Uint8Array, output?: KeyOutput, type?: string) => string | Uint8Array;

type Chain = 0 | 1;

export class BigChainWallet {
  private _seedHex: string;
  // TODO: networkUrl: string;

  static createMnemonic(
    strength: number = ENTROPY_BITS,
    language = 'english',
    rngFn?: (size: number) => Buffer | undefined,
  ) {
    if (language && !Object.prototype.hasOwnProperty.call(bip39.wordlists, language)) {
      throw new TypeError(INVALID_LANGUAGE(language));
    }
    const wordlist = bip39.wordlists[language];
    return bip39.generateMnemonic(strength || ENTROPY_BITS, rngFn, wordlist);
  }

  static validateMnemonic(mnemonic: string, language = 'english') {
    if (language && !Object.prototype.hasOwnProperty.call(bip39.wordlists, language)) {
      throw new TypeError(INVALID_LANGUAGE(language));
    }
    if (mnemonic?.trim().split(/\s+/g).length < 12) {
      return false;
    }
    const wordlist = bip39.wordlists[language];
    return bip39.validateMnemonic(mnemonic, wordlist);
  }

  static createSeed(mnemonic: string, password: string = undefined, language = 'english') {
    if (!BigChainWallet.validateMnemonic(mnemonic, language)) {
      throw new Error(INVALID_MNEMONIC);
    }
    return bip39.mnemonicToSeedSync(mnemonic, password);
  }

  static fromMnemonic(mnemonic: string, password: string = undefined, language = 'english') {
    const seedHex = BigChainWallet.createSeed(mnemonic, password, language).toString('hex');
    return new BigChainWallet(seedHex);
  }

  static fromSeed(seed: string | Buffer) {
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

  getMasterKey() {
    return getMasterKeyFromSeed(this._seedHex);
  }

  getMasterKeyPair(): KeyPair {
    const { key } = getMasterKeyFromSeed(this._seedHex);
    const uInt8Key = bufferToUint8Array(key);
    const publicKey = (output?: KeyOutput) => keyFactory(getPublicKey(uInt8Key as Buffer, false), output);
    const privateKey = (output?: KeyOutput) => keyFactory(uInt8Key, output, 'secret');
    return { publicKey, privateKey };
  }

  derive(derivationPath: string): Uint8Array {
    const data = derivePath(derivationPath, this._seedHex);
    const uInt8Key = bufferToUint8Array(data.key);
    return uInt8Key;
  }

  getAccountKey(account: number) {
    return this.derive(`${BIG_CHAIN_PATH}/${account}'`);
  }

  getAccountChildKey(account: number, index: number, chain: Chain = 0) {
    return this.derive(`${BIG_CHAIN_PATH}/${account}'/${chain}'/${index}'`);
  }

  getKeyPairFromDerivedKey(key: Uint8Array): KeyPair {
    // const uInt8Key = bufferToUint8Array(key);
    const publicKey = (output?: KeyOutput) => keyFactory(getPublicKey(key as Buffer, false), output);
    const privateKey = (output?: KeyOutput) => keyFactory(key, output, 'secret');
    return { publicKey, privateKey };
  }

  getKeyPair(account?: number, index?: number, chain: Chain = 0): KeyPair {
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

  getPublicKey(account?: number, output?: KeyOutput) {
    return this.getKeyPair(account).publicKey(output);
  }

  getPrivateKey(account?: number, output?: KeyOutput) {
    return this.getKeyPair(account).privateKey(output);
  }

  getFullPrivateKey(account?: number, output?: KeyOutput) {
    const privKey = this.getKeyPair(account).privateKey() as Uint8Array;
    const pubKey = this.getKeyPair(account).publicKey() as Uint8Array;
    const key = new Uint8Array(privKey.length + pubKey.length);
    key.set(privKey);
    key.set(pubKey, privKey.length);
    // const key = Buffer.concat([privKey, pubKey], privKey.length + pubKey.length);
    return keyFactory(key, output, 'secret');
  }

  getDHKeyPair(account?: number): KeyPair {
    const keyPair = this.getKeyPair(account);
    const publicKeyBuffer = convertPublicKey(keyPair.publicKey() as Uint8Array);
    const privateKeyBuffer = convertPrivateKey(keyPair.privateKey() as Uint8Array);
    const publicKey = (output?: KeyOutput) => keyFactory(publicKeyBuffer, output);
    const privateKey = (output?: KeyOutput) => keyFactory(privateKeyBuffer, output, 'secret');
    return { publicKey, privateKey };
  }

  getDHPublicKey(account?: number, output?: KeyOutput) {
    const publicKeyBuffer = convertPublicKey(this.getKeyPair(account).publicKey() as Uint8Array);
    return keyFactory(publicKeyBuffer, output);
  }

  getDHPrivateKey(account?: number, output?: KeyOutput) {
    const privateKeyBuffer = convertPrivateKey(this.getFullPrivateKey(account) as Uint8Array);
    return keyFactory(privateKeyBuffer, output);
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
      const privateKeyBuffer = self.getPrivateKey() as string;
      const ed25519Fulfillment = new Ed25519Sha256();
      ed25519Fulfillment.sign(Buffer.from(transactionHash, 'hex'), privateKeyBuffer);
      const fulfillmentUri = ed25519Fulfillment.serializeUri();
      return fulfillmentUri;
    };
  }
}
