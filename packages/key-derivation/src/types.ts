import { KeyObject } from 'crypto';

export type Encoding = 'hex' | 'base58' | 'base64' | 'buffer' | 'der' | 'pem' | 'default';

export type KeyEncodingMap = {
  hex: () => string;
  // base32: () => string;
  base58: () => string;
  base64: () => string;
  buffer: () => Buffer;
  pem: () => string;
  der: () => Buffer;
  keyObject: () => KeyObject;
  default: () => Uint8Array;
};

export type KeyPairType = 'public' | 'private' | `fingerprint's`;

export type KeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

export type DerivedKeyPair = {
  key: Uint8Array;
  chainCode: Uint8Array;
  derivationPath: string;
};

export type Chain = 0 | 1;

export type KeyPairDerivationOptions = {
  account?: number;
  index?: number;
  chain?: Chain;
};

export type KeyPairFactory = {
  publicKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => ReturnType<KeyEncodingMap[K]>;
  privateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => ReturnType<KeyEncodingMap[K]>;
  chainCode: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => ReturnType<KeyEncodingMap[K]>;
  fullPrivateKey?: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => ReturnType<KeyEncodingMap[K]>;
  type: string;
  id?: string;
  controller?: string;
};

export type KeyPairObject = {
  publicKey: Uint8Array;
  privateKey?: Uint8Array;
  chainCode: Uint8Array;
  type: string;
  id?: string;
  controller?: string;
};

export type SignKeyPairFactory = KeyPairFactory & {
  fullPrivateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => ReturnType<KeyEncodingMap[K]>;
  fingerprint: () => string;
  derivationPath: string;
};

export type SignKeyPairObject = KeyPairObject & {
  fullPrivateKey?: Uint8Array;
  fingerprint: string;
  derivationPath: string;
};

export type EncryptKeyPairFactory = KeyPairFactory & {
  fingerprint: () => string;
  derivationPath: string;
};

export type EncryptKeyPairObject = KeyPairObject & {
  fingerprint: string;
  derivationPath: string;
};

export type DerivationKeyPairMap = {
  sign: () => SignKeyPairFactory;
  encrypt: () => EncryptKeyPairFactory;
};
