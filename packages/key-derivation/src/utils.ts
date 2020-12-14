import * as base58 from 'bs58';
import * as ed2curve from 'ed2curve';
import { encodeBase64 } from 'tweetnacl-util';

export function bufferToUint8Array(buffer: Buffer) {
  return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength / Uint8Array.BYTES_PER_ELEMENT);
}

export function toPem(base64Key: string, type?: string) {
  if (type === 'secret') {
    return `-----BEGIN EC PRIVATE KEY-----
${base64Key}
-----END EC PRIVATE KEY-----
`;
  }
  return `-----BEGIN PUBLIC KEY-----
${base64Key}
-----END PUBLIC KEY-----
`;
}

export function uint8ArrayToHexString(byteArray: Uint8Array) {
  return Array.prototype.map
    .call(byteArray, function (byte: number) {
      return ('0' + (byte & 0xff).toString(16)).slice(-2);
    })
    .join('');
}

export function keyFactory(
  key: Uint8Array,
  output?: undefined | 'base58' | 'hex' | 'pem',
  type?: string,
): string | Uint8Array {
  switch (output) {
    case 'hex':
      return uint8ArrayToHexString(key);
    case 'base58':
      return base58.encode(key);
    case 'pem':
      return toPem(encodeBase64(key), type);
    default:
      return key;
  }
}

export function convertPublicKey(publicKey: Uint8Array): Uint8Array {
  return ed2curve.convertPublicKey(publicKey);
}

export function convertPrivateKey(privateKey: Uint8Array): Uint8Array {
  return ed2curve.convertSecretKey(privateKey);
}

export function convertKeyPair(keyPair: {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const { publicKey, privateKey } = keyPair;
  return { publicKey: convertPublicKey(publicKey), privateKey: convertPrivateKey(privateKey) };
}
