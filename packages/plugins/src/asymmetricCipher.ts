import { Cipher, CipherType } from '@s1seven/js-bigchain-wallet-types';
import { box, randomBytes } from 'tweetnacl';
import { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } from 'tweetnacl-util';

export class AsymmetricCipher implements Cipher {
  name: 'NACLBOX';
  type: CipherType = 'asymmetric';
  sharedSecret: Uint8Array;

  static createKeyPair() {
    return box.keyPair();
  }

  static createSharedKey(secretKey: Uint8Array, publicKey: Uint8Array) {
    return box.before(publicKey, secretKey);
  }

  static newNonce() {
    return randomBytes(box.nonceLength);
  }

  static encrypt(json: Record<string, unknown>, secretOrSharedKey: Uint8Array, key?: Uint8Array) {
    const nonce = this.newNonce();
    const messageUint8 = decodeUTF8(JSON.stringify(json));
    const encrypted = key
      ? box(messageUint8, nonce, key, secretOrSharedKey)
      : box.after(messageUint8, nonce, secretOrSharedKey);

    const fullMessage = new Uint8Array(nonce.length + encrypted.length);
    fullMessage.set(nonce);
    fullMessage.set(encrypted, nonce.length);

    const base64FullMessage = encodeBase64(fullMessage);
    return base64FullMessage;
  }

  static decrypt(messageWithNonce: string, secretOrSharedKey: Uint8Array, key?: Uint8Array): Record<string, unknown> {
    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
    const nonce = messageWithNonceAsUint8Array.slice(0, box.nonceLength);
    const message = messageWithNonceAsUint8Array.slice(box.nonceLength, messageWithNonce.length);

    const decrypted = key
      ? box.open(message, nonce, key, secretOrSharedKey)
      : box.open.after(message, nonce, secretOrSharedKey);

    if (!decrypted) {
      throw new Error('Could not decrypt message');
    }

    const base64DecryptedMessage = encodeUTF8(decrypted);
    return JSON.parse(base64DecryptedMessage);
  }

  constructor(privateKey: Uint8Array, theirPublicKey: Uint8Array) {
    this.sharedSecret = AsymmetricCipher.createSharedKey(privateKey, theirPublicKey);
  }

  encrypt(json: Record<string, unknown>) {
    return new Promise<string>((resolve, reject) => {
      try {
        const encrypted = AsymmetricCipher.encrypt(json, this.sharedSecret);
        resolve(encrypted);
      } catch (e) {
        reject(e);
      }
    });
  }

  decrypt(messageWithNonce: string) {
    return new Promise<Record<string, unknown>>((resolve, reject) => {
      try {
        const decrypted = AsymmetricCipher.decrypt(messageWithNonce, this.sharedSecret);
        resolve(decrypted);
      } catch (e) {
        reject(e);
      }
    });
  }
}
