import * as base58 from 'bs58';
import { createPublicKey, createPrivateKey, KeyObject } from 'crypto';
import { KeyEncodingMap, KeyPairType } from './types';
import { asn1, ASN1Class, ASN1Type } from './asn1';
import { ByteStringBuffer } from './bytestring-buffer';
import { oids } from './oids';
import { encodeBase64 } from 'tweetnacl-util';

export function isEqualBuffer(buf1: Buffer, buf2: Buffer): boolean {
  if (buf1.length !== buf2.length) {
    return false;
  }
  for (let i = 0; i < buf1.length; i++) {
    if (buf1[i] !== buf2[i]) {
      return false;
    }
  }
  return true;
}

export function base58Decode(options: {
  decode?: (string: string) => Buffer;
  keyMaterial: string;
  type: KeyPairType;
}): Buffer {
  let bytes: Buffer;
  const { decode = base58.decode as (string: string) => Buffer, keyMaterial, type } = options;
  try {
    bytes = decode(keyMaterial);
  } catch (e) {
    // do nothing
    // the bs58 implementation throws, forge returns undefined
    // this helper throws when no result is produced
  }
  if (bytes === undefined) {
    throw new TypeError(`The ${type} key material must be Base58 encoded.`);
  }
  return bytes;
}

export function base58Encode(options: {
  encode?: (buffer: Buffer | number[] | Uint8Array) => string;
  keyMaterial: Buffer | number[] | Uint8Array;
  type: KeyPairType;
}): string {
  let base58Key: string;
  const { encode = base58.encode as (buffer: Buffer | number[] | Uint8Array) => string, keyMaterial, type } = options;
  try {
    base58Key = encode(keyMaterial);
  } catch (e) {
    // do nothing
    // the bs58 implementation throws, forge returns undefined
    // this helper throws when no result is produced
  }
  if (base58Key === undefined) {
    throw new TypeError(`The ${type} key material must be Bytes Buffer.`);
  }
  return base58Key;
}

export function bufferToUint8Array(buffer: Buffer): Uint8Array {
  return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength / Uint8Array.BYTES_PER_ELEMENT);
}

export function uint8ArrayToHexString(byteArray: Uint8Array): string {
  return Array.prototype.map
    .call(byteArray, function (byte: number) {
      return ('0' + (byte & 0xff).toString(16)).slice(-2);
    })
    .join('');
}

export function toUint8Array(content: string | Buffer | Uint8Array, encoding: BufferEncoding = 'hex'): Uint8Array {
  let bytes: Uint8Array;
  if (Buffer.isBuffer(content)) {
    bytes = bufferToUint8Array(content);
  } else if (typeof content === 'string') {
    bytes = bufferToUint8Array(Buffer.from(content, encoding));
  }
  return bytes;
}

export const derivationPathRegex = new RegExp("^m(\\/[0-9]+')+$");

export const replaceDerive = (val: string): string => val.replace("'", '');

export function isValidDerivationPath(path: string): boolean {
  if (!derivationPathRegex.test(path)) {
    return false;
  }
  return !path
    .split('/')
    .slice(1)
    .map(replaceDerive)
    .some((val) => isNaN(parseInt(val, 10)));
}

export function privateKeyDerEncode(options: { privateKeyBytes?: Buffer; seedBytes?: Buffer }): Buffer {
  // TODO: FIX issue with X25519, this converter (all keys are the same)
  const { privateKeyBytes, seedBytes } = options;
  if (!(privateKeyBytes || seedBytes)) {
    throw new TypeError('`privateKeyBytes` or `seedBytes` is required.');
  }
  if (!privateKeyBytes && !(Buffer.isBuffer(seedBytes) && seedBytes.length === 32)) {
    throw new TypeError('`seedBytes` must be a 32 byte Buffer.');
  }
  if (!seedBytes && !(Buffer.isBuffer(privateKeyBytes) && privateKeyBytes.length === 64)) {
    throw new TypeError('`privateKeyBytes` must be a 64 byte Buffer.');
  }

  let p: Buffer;
  if (seedBytes) {
    p = seedBytes;
  } else {
    // extract the first 32 bytes of the 64 byte private key representation
    p = Buffer.from(privateKeyBytes.buffer, privateKeyBytes.byteOffset, 32);
  }
  const keyBuffer = new ByteStringBuffer(p);
  const asn1Key = asn1.create(ASN1Class.UNIVERSAL, ASN1Type.OCTETSTRING, false, keyBuffer.getBytes());
  const a = asn1.create(ASN1Class.UNIVERSAL, ASN1Type.SEQUENCE, true, [
    asn1.create(ASN1Class.UNIVERSAL, ASN1Type.INTEGER, false, asn1.integerToDer(0).getBytes()),
    // privateKeyAlgorithm
    asn1.create(ASN1Class.UNIVERSAL, ASN1Type.SEQUENCE, true, [
      asn1.create(ASN1Class.UNIVERSAL, ASN1Type.OID, false, asn1.oidToDer(oids.EdDSA25519).getBytes()),
    ]),
    // private key
    asn1.create(ASN1Class.UNIVERSAL, ASN1Type.OCTETSTRING, false, asn1.toDer(asn1Key).getBytes()),
  ]);

  const privateKeyDer = asn1.toDer(a);
  return Buffer.from(privateKeyDer.getBytes(), 'binary');
}

export function publicKeyDerEncode(options: { publicKeyBytes: Buffer }): Buffer {
  const { publicKeyBytes } = options;
  if (!(Buffer.isBuffer(publicKeyBytes) && publicKeyBytes.length === 32)) {
    throw new TypeError('`publicKeyBytes` must be a 32 byte Buffer.');
  }
  // add a zero byte to the front of the publicKeyBytes, this results in
  // the bitstring being 256 bits vs. 170 bits (without padding)
  const zeroBuffer = Buffer.from(new Uint8Array([0]));
  const keyBuffer = new ByteStringBuffer(Buffer.concat([zeroBuffer, publicKeyBytes]));
  const a = asn1.create(ASN1Class.UNIVERSAL, ASN1Type.SEQUENCE, true, [
    asn1.create(ASN1Class.UNIVERSAL, ASN1Type.SEQUENCE, true, [
      asn1.create(ASN1Class.UNIVERSAL, ASN1Type.OID, false, asn1.oidToDer(oids.EdDSA25519).getBytes()),
    ]),
    // public key
    asn1.create(ASN1Class.UNIVERSAL, ASN1Type.BITSTRING, false, keyBuffer.getBytes()),
  ]);

  const publicKeyDer = asn1.toDer(a);
  return Buffer.from(publicKeyDer.getBytes(), 'binary');
}

export function toDer(key: Buffer, type?: KeyPairType): Buffer {
  return type === 'private'
    ? privateKeyDerEncode({ privateKeyBytes: key })
    : publicKeyDerEncode({ publicKeyBytes: key });
}

export function publicKeyToKeyObject(options: {
  publicKeyBytes: Buffer;
  format?: 'der' | 'pem';
  type?: 'spki';
}): KeyObject {
  const { format = 'der', publicKeyBytes, type = 'spki' } = options;
  return createPublicKey({
    key: publicKeyDerEncode({ publicKeyBytes }),
    format,
    type,
  });
}

export function privateKeyToKeyObject(options: {
  privateKeyBytes?: Buffer;
  seedBytes?: Buffer;
  format?: 'der' | 'pem';
  type?: 'pkcs8' | 'sec1';
}): KeyObject {
  const { format = 'der', privateKeyBytes, seedBytes, type = 'pkcs8' } = options;
  return createPrivateKey({
    key: privateKeyDerEncode({ privateKeyBytes, seedBytes }),
    format,
    type,
  });
}

export function toKeyObject(key: Buffer, type?: KeyPairType, outputType?: 'pkcs8' | 'sec1'): KeyObject {
  if (type === 'private') {
    return key.length === 32
      ? privateKeyToKeyObject({ seedBytes: key, type: outputType || 'pkcs8' })
      : privateKeyToKeyObject({ privateKeyBytes: key, type: outputType || 'pkcs8' });
  }
  return publicKeyToKeyObject({ publicKeyBytes: key });
}

export function toPem(key: Buffer, type?: KeyPairType, outputType?: 'pkcs8' | 'sec1'): string {
  if (type === 'private') {
    return key.length === 32
      ? (privateKeyToKeyObject({ seedBytes: key, type: outputType || 'pkcs8' }).export({
          format: 'pem',
          type: outputType || 'pkcs8',
        }) as string)
      : (privateKeyToKeyObject({ privateKeyBytes: key, type: outputType || 'pkcs8' }).export({
          format: 'pem',
          type: outputType || 'pkcs8',
        }) as string);
  }

  return publicKeyToKeyObject({ publicKeyBytes: key }).export({ format: 'pem', type: 'spki' }) as string;
}

export function encodeKey<K extends keyof KeyEncodingMap>(
  key: Uint8Array,
  output: K,
  type?: KeyPairType,
  outputType?: 'pkcs8' | 'sec1',
): ReturnType<KeyEncodingMap[K]> {
  const keyEncodingMap: KeyEncodingMap = {
    hex: () => uint8ArrayToHexString(key),
    // base32: () => 'TODO',
    base58: () => base58.encode(Buffer.from(key)) as string,
    base64: () => encodeBase64(key),
    buffer: () => Buffer.from(key),
    pem: () => toPem(Buffer.from(key), type, outputType),
    der: () => toDer(Buffer.from(key), type),
    keyObject: () => toKeyObject(Buffer.from(key), type, outputType),
    default: () => key,
  };

  return keyEncodingMap[output]() as ReturnType<KeyEncodingMap[K]>;
}
