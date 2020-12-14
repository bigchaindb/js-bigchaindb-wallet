import { Cipher, CipherType } from '@s1seven/js-bigchain-wallet-types';
import { secretbox, randomBytes } from 'tweetnacl';
import { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } from 'tweetnacl-util';

export class SymmetricCipher implements Cipher {
  name: 'NACLSECRETBOX';
  type: CipherType = 'symmetric';
  secret: Uint8Array;

  static newNonce() {
    return randomBytes(secretbox.nonceLength);
  }

  static createSecret(type?: 'string') {
    const randomInt = randomBytes(secretbox.keyLength);
    return type ? encodeBase64(randomInt) : randomInt;
  }

  static encrypt(json: Record<string, unknown>, key: Uint8Array) {
    const nonce = this.newNonce();
    const messageUint8 = decodeUTF8(JSON.stringify(json));
    const box = secretbox(messageUint8, nonce, key);
    const fullMessage = new Uint8Array(nonce.length + box.length);
    fullMessage.set(nonce);
    fullMessage.set(box, nonce.length);
    const base64FullMessage = encodeBase64(fullMessage);
    return base64FullMessage;
  }

  static decrypt(messageWithNonce: string, key: Uint8Array): Record<string, unknown> {
    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
    const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);
    const message = messageWithNonceAsUint8Array.slice(secretbox.nonceLength, messageWithNonce.length);

    const decrypted = secretbox.open(message, nonce, key);
    if (!decrypted) {
      throw new Error('Could not decrypt message');
    }
    const base64DecryptedMessage = encodeUTF8(decrypted);
    return JSON.parse(base64DecryptedMessage);
  }

  constructor(secret: string | Uint8Array) {
    if (typeof secret === 'string') {
      this.secret = decodeBase64(secret);
    } else {
      this.secret = secret;
    }
  }

  encrypt(json: Record<string, unknown>) {
    return new Promise<string>((resolve, reject) => {
      try {
        const encrypted = SymmetricCipher.encrypt(json, this.secret);
        resolve(encrypted);
      } catch (e) {
        reject(e);
      }
    });
  }

  decrypt(messageWithNonce: string) {
    return new Promise<Record<string, unknown>>((resolve, reject) => {
      try {
        const decrypted = SymmetricCipher.decrypt(messageWithNonce, this.secret);
        resolve(decrypted);
      } catch (e) {
        reject(e);
      }
    });
  }
}
