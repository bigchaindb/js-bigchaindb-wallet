import { decode, sign, verify, JsonWebTokenError } from 'jwt-ed25519-tn';
import { Cipher } from '@bigchaindb/js-bigchaindb-wallet-types';
import { BigChainWallet } from '@bigchaindb/js-bigchaindb-key-derivation';

// const PRIVATE_KEY_SIZE = 64;
// const PUBLIC_KEY_SIZE = 32;
const INVALID_KEY = 'Invalid key (must be a Buffer, Uint8Array or hex string)';
const INVALID_CIPHER = 'Invalid cipher (must be type symmetric or asymmetric)';
const MISSING_CIPHER_INSTANCE = 'Register a cipher before calling this method';
const MISSING_KEY = 'Missing key (should have publicKey and privateKey)';

export type Algorithm =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'Ed25519'
  | 'none';

export type Verification = {
  iat: number;
  iss: string;
  nbf?: number;
  exp?: number;
  aud?: string;
  jti?: string;
  sub?: string;
  [key: string]: any;
};

export type VerificationOptions = {
  algorithm?: Algorithm;
  // timestamp in seconds
  clockTimestamp?: number;
  ignoreNotBefore?: boolean;
  clockTolerance?: number;
  ignoreExpiration?: boolean;
  audience?: string | string[];
  issuer?: string;
  subject?: string;
  jwtid?: string;
  maxAge?: string | number;
  [key: string]: any;
};

export type SignOptions = {
  subject?: string;
  issuer?: string;
  expiresIn?: number | string;
  notBefore?: number | string;
  audience?: string | string[];
  algorithm?: Algorithm;
  header?: Record<string, unknown>;
  encoding?: string;
  jwtid?: string;
  noTimestamp?: boolean;
  keyid?: string;
  mutatePayload?: boolean;
};

export type DecodedToken<T = Record<string, unknown>> = {
  headers: {
    alg: string;
    type: string;
    [key: string]: string;
  };
  payload: T & Verification;
  signature: string;
};

export type BaseTokenPayload = {
  jwt: string;
  [key: string]: unknown;
};

export class TokenService {
  _algorithm = 'Ed25519';
  _issuer = 'BigChainDB';
  private _publicKey: Buffer;
  private _privateKey: Buffer;
  private _cipher: Cipher;

  static fromSeed(seed: string | Buffer, accountIndex?: number) {
    const wallet = BigChainWallet.fromSeed(seed);
    const keyPair = wallet.getDerivatedKeyPair('sign', { account: accountIndex });
    const privateKey = keyPair.fullPrivateKey('buffer');
    const publicKey = keyPair.publicKey('buffer');
    return new TokenService({ publicKey, privateKey });
  }

  static fromKeyPair(keyPair: { publicKey: Uint8Array | Buffer | string; privateKey: Uint8Array | Buffer | string }) {
    if (
      !Object.prototype.hasOwnProperty.call(keyPair, 'publicKey') ||
      !Object.prototype.hasOwnProperty.call(keyPair, 'privateKey')
    ) {
      throw new TypeError(MISSING_KEY);
    }

    Object.keys(keyPair).forEach((key) => {
      if (typeof keyPair[key] === 'string') {
        keyPair[key] = Buffer.from(keyPair[key], 'hex');
      } else if (keyPair[key] instanceof Uint8Array) {
        keyPair[key] = Buffer.from(keyPair[key]);
      } else if (!Buffer.isBuffer(keyPair[key])) {
        throw new TypeError(INVALID_KEY);
      }
    });

    return new TokenService({
      publicKey: keyPair.publicKey as Buffer,
      privateKey: keyPair.privateKey as Buffer,
    });
  }

  constructor(setup: { publicKey: Buffer; privateKey: Buffer; cipher?: Cipher }) {
    const { publicKey, privateKey, cipher } = setup;
    this._publicKey = publicKey;
    this._privateKey = privateKey;
    if (cipher) {
      this.cipher = cipher;
    }
  }

  get algorithm() {
    return this._algorithm;
  }

  get issuer() {
    return this._issuer;
  }

  set issuer(value) {
    this._issuer = value;
  }

  get cipher() {
    return this._cipher;
  }

  set cipher(value: Cipher) {
    this._cipher = value;
  }

  validateCipher() {
    if (!this.cipher || !this.cipher.type) {
      throw new Error(MISSING_CIPHER_INSTANCE);
    }
  }

  sign<T = Record<string, unknown>>(payload: T, options: SignOptions = {}): string {
    const { subject = 'transaction', issuer = this.issuer } = options;
    //? TODO: use keyid field to match specific algorithm
    return sign(payload, { key: this._privateKey, algorithm: this.algorithm }, { issuer, subject, ...options });
  }

  async encrypt<T = BaseTokenPayload>(payload: T): Promise<string> {
    this.validateCipher();
    if (this.cipher.type === 'asymmetric') {
      return this.cipher.encrypt<T>(payload, this.cipher.sharedKey);
    } else if (this.cipher.type === 'symmetric') {
      return this.cipher.encrypt<T>(payload, this.cipher.secret);
    }
    throw new Error(INVALID_CIPHER);
  }

  async produce<T = Record<string, unknown>>(payload: T, options?: SignOptions): Promise<string> {
    this.validateCipher();
    const jwt = this.sign<T>(payload, options);
    return this.encrypt<BaseTokenPayload>({ jwt });
  }

  decode<T = Record<string, unknown>>(jwt: string): DecodedToken<T> {
    return decode(jwt, { complete: true }) as DecodedToken<T>;
  }

  async decrypt<T = BaseTokenPayload>(encryptedPayload: string): Promise<T> {
    this.validateCipher();
    if (this.cipher.type === 'asymmetric') {
      return this.cipher.decrypt<T>(encryptedPayload, this.cipher.sharedKey);
    } else if (this.cipher.type === 'symmetric') {
      return this.cipher.decrypt<T>(encryptedPayload, this.cipher.secret);
    }
    throw new Error(INVALID_CIPHER);
  }

  async verify<T = Record<string, unknown>>(jwt: string, options: VerificationOptions = {}): Promise<Verification & T> {
    return new Promise((resolve, reject) => {
      verify(
        jwt,
        { key: this._publicKey, algorithm: this.algorithm },
        options,
        (err: typeof JsonWebTokenError, res: T & Verification) => (err ? reject(err) : resolve(res)),
      );
    });
  }

  async consume<T = Record<string, unknown>>(
    encryptedJwt: string,
    options?: VerificationOptions,
  ): Promise<Verification & T> {
    const { jwt } = await this.decrypt<BaseTokenPayload>(encryptedJwt);
    return this.verify<T>(jwt, options);
  }
}
