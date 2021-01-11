import * as base58 from 'bs58';
import { KeyEncodingMap } from './types';
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

export function uint8ArrayToHexString(byteArray: Uint8Array): string {
  return Array.prototype.map
    .call(byteArray, function (byte: number) {
      return ('0' + (byte & 0xff).toString(16)).slice(-2);
    })
    .join('');
}

export const derivationPathRegex = new RegExp("^m(\\/[0-9]+')+$");

export const replaceDerive = (val: string) => val.replace("'", '');

export function isValidDerivationPath(path: string) {
  if (!derivationPathRegex.test(path)) {
    return false;
  }
  return !path
    .split('/')
    .slice(1)
    .map(replaceDerive)
    .some((val) => isNaN(parseInt(val, 10)));
}

export function encodeKey<K extends keyof KeyEncodingMap>(
  key: Uint8Array,
  output: K,
  type?: 'secret',
): ReturnType<KeyEncodingMap[K]> {
  const keyEncodingMap: KeyEncodingMap = {
    hex: () => uint8ArrayToHexString(key),
    base58: () => base58.encode(key) as string,
    base64: () => encodeBase64(key),
    buffer: () => Buffer.from(key),
    pem: () => toPem(encodeBase64(key), type),
    default: () => key,
  };
  return keyEncodingMap[output]() as ReturnType<KeyEncodingMap[K]>;
}
