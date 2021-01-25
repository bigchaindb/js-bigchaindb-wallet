import { sign, SignKeyPair } from 'tweetnacl';
import { decodeBase64 } from 'tweetnacl-util';

export class Sign {
  static readonly publicKeyLength = sign.publicKeyLength;
  static readonly privateKeyLength = sign.secretKeyLength;
  static readonly signatureLength = sign.signatureLength;

  readonly name: 'NACLSIGN';
  publicKey?: Uint8Array | undefined;
  privateKey?: Uint8Array | undefined;

  static createKeyPair(seed?: Uint8Array): SignKeyPair {
    return seed ? sign.keyPair.fromSeed(seed) : sign.keyPair();
  }

  static sign(msg: Uint8Array, privateKey: Uint8Array): Uint8Array {
    return sign(msg, privateKey);
  }

  static signature(msg: Uint8Array, privateKey: Uint8Array): Uint8Array {
    return sign.detached(msg, privateKey);
  }

  static open(signedMsg: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return sign.open(signedMsg, publicKey);
  }

  static verify(msg: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    return sign.detached.verify(msg, signature, publicKey);
  }

  constructor(keyPair: { publicKey?: string | Uint8Array | undefined; privateKey?: string | Uint8Array | undefined }) {
    const { publicKey, privateKey } = keyPair;
    this.publicKey = typeof publicKey === 'string' ? decodeBase64(publicKey) : publicKey;
    this.privateKey = typeof privateKey === 'string' ? decodeBase64(privateKey) : privateKey;
  }

  sign(msg: Uint8Array) {
    if (!this.privateKey) {
      throw new Error('Private key is missing');
    }
    return Sign.sign(msg, this.privateKey);
  }

  signature(msg: Uint8Array) {
    if (!this.privateKey) {
      throw new Error('Private key is missing');
    }
    return Sign.signature(msg, this.privateKey);
  }

  open(signedMsg: Uint8Array) {
    if (!this.publicKey) {
      throw new Error('Public key is missing');
    }
    return Sign.open(signedMsg, this.publicKey);
  }

  verify(msg: Uint8Array, signature: Uint8Array) {
    if (!this.publicKey) {
      throw new Error('Public key is missing');
    }
    return Sign.verify(msg, signature, this.publicKey);
  }
}
