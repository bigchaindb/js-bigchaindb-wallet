export type Encoding = 'hex' | 'base58' | 'base64' | 'buffer' | 'pem' | 'default';

export type KeyEncodingMap = {
  hex: () => string;
  base58: () => string;
  base64: () => string;
  buffer: () => Buffer;
  pem: () => string;
  default: () => Uint8Array;
};

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
};

export type SignKeyPairFactory = KeyPairFactory & {
  fullPrivateKey: <K extends keyof KeyEncodingMap = 'default'>(encoding?: K) => ReturnType<KeyEncodingMap[K]>;
  derivationPath: string;
};

export type EncryptKeyPairFactory = KeyPairFactory & {
  derivationPath: string;
};

export type DerivationKeyPairMap = {
  sign: () => SignKeyPairFactory;
  encrypt: () => EncryptKeyPairFactory;
};
