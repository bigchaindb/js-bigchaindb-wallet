import { Cipher, CipherType } from '@s1seven/js-bigchaindb-wallet-types';
import { box, randomBytes } from 'tweetnacl';
import { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } from 'tweetnacl-util';

export class AsymmetricCipher implements Cipher {
  name: 'NACLBOX';
  type: CipherType = 'asymmetric';
  sharedKey: Uint8Array;

  static createKeyPair() {
    return box.keyPair();
  }

  static createSharedKey(secretKey: Uint8Array, publicKey: Uint8Array) {
    return box.before(publicKey, secretKey);
  }

  static newNonce() {
    return randomBytes(box.nonceLength);
  }

  static encrypt<T = Record<string, unknown>>(payload: T, secretOrSharedKey: Uint8Array, key?: Uint8Array): string {
    const nonce = this.newNonce();
    const messageUint8 = decodeUTF8(JSON.stringify(payload));
    const encrypted = key
      ? box(messageUint8, nonce, key, secretOrSharedKey)
      : box.after(messageUint8, nonce, secretOrSharedKey);

    const fullMessage = new Uint8Array(nonce.length + encrypted.length);
    fullMessage.set(nonce);
    fullMessage.set(encrypted, nonce.length);

    const base64FullMessage = encodeBase64(fullMessage);
    return base64FullMessage;
  }

  static decrypt<T = Record<string, unknown>>(
    messageWithNonce: string,
    secretOrSharedKey: Uint8Array,
    key?: Uint8Array,
  ): T {
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
    this.sharedKey = AsymmetricCipher.createSharedKey(privateKey, theirPublicKey);
  }

  encrypt<T = Record<string, unknown>>(payload: T) {
    return new Promise<string>((resolve, reject) => {
      try {
        const encrypted = AsymmetricCipher.encrypt<T>(payload, this.sharedKey);
        resolve(encrypted);
      } catch (e) {
        reject(e);
      }
    });
  }

  decrypt<T = Record<string, unknown>>(messageWithNonce: string) {
    return new Promise<T>((resolve, reject) => {
      try {
        const decrypted = AsymmetricCipher.decrypt<T>(messageWithNonce, this.sharedKey);
        resolve(decrypted);
      } catch (e) {
        reject(e);
      }
    });
  }
}
