import { Cipher, CipherType } from '@s1seven/js-bigchain-wallet-types';
import { secretbox, randomBytes } from 'tweetnacl';
import { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } from 'tweetnacl-util';

export default class SymmetricCipher implements Cipher {
  name: 'NACLSECRETBOX';
  type: CipherType = 'symmetric';
  _secret: string;

  static newNonce() {
    return randomBytes(secretbox.nonceLength);
  }

  static createSecret() {
    return encodeBase64(randomBytes(secretbox.keyLength));
  }

  static encrypt(json: Record<string, unknown>, key: string) {
    const keyUint8Array = decodeBase64(key);
    const nonce = this.newNonce();
    const messageUint8 = decodeUTF8(JSON.stringify(json));
    const box = secretbox(messageUint8, nonce, keyUint8Array);
    const fullMessage = new Uint8Array(nonce.length + box.length);
    fullMessage.set(nonce);
    fullMessage.set(box, nonce.length);
    const base64FullMessage = encodeBase64(fullMessage);
    return base64FullMessage;
  }

  static decrypt(messageWithNonce: string, key: string): Record<string, unknown> {
    const keyUint8Array = decodeBase64(key);
    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
    const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);
    const message = messageWithNonceAsUint8Array.slice(secretbox.nonceLength, messageWithNonce.length);

    const decrypted = secretbox.open(message, nonce, keyUint8Array);
    if (!decrypted) {
      throw new Error('Could not decrypt message');
    }
    const base64DecryptedMessage = encodeUTF8(decrypted);
    return JSON.parse(base64DecryptedMessage);
  }

  constructor(secret: string) {
    this._secret = secret;
  }

  encrypt(json: Record<string, unknown>) {
    return new Promise<string>((resolve, reject) => {
      try {
        const encrypted = SymmetricCipher.encrypt(json, this._secret);
        resolve(encrypted);
      } catch (e) {
        reject(e);
      }
    });
  }

  decrypt(messageWithNonce: string) {
    return new Promise<Record<string, unknown>>((resolve, reject) => {
      try {
        const decrypted = SymmetricCipher.decrypt(messageWithNonce, this._secret);
        resolve(decrypted);
      } catch (e) {
        reject(e);
      }
    });
  }
}
