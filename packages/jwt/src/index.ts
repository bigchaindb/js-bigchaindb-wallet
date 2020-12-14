import { decode, sign, verify, JsonWebTokenError } from 'jwt-ed25519-tn';
import { Cipher } from '@s1seven/js-bigchain-wallet-types';
import { BigChainWallet } from '@s1seven/js-bigchain-key-derivation';

// const PRIVATE_KEY_SIZE = 64;
// const PUBLIC_KEY_SIZE = 32;
const INVALID_KEY = 'Invalid key (must be a Buffer, Uint8Array or hex string)';
const INVALID_CIPHER = 'Invalid cipher (must be type symmetric or asymmetric)';
const MISSING_CIPHER_INSTANCE = 'Register a cipher before calling this method';
const MISSING_KEY = 'Missing key (should have publicKey and privateKey)';

export type Verification = {
  iat: number;
  iss: string;
  nbf?: any;
  exp?: any;
  aud?: string;
  jti?: string;
  sub?: string;
  [key: string]: any;
};

export type SignOptions = {
  subject?: string;
  issuer?: string;
  expiresIn?: number | string;
  notBefore?: number | string;
  audience?: string | string[];
  algorithm?:
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
  header?: Record<string, unknown>;
  encoding?: string;
  jwtid?: string;
  noTimestamp?: boolean;
  keyid?: string;
  mutatePayload?: boolean;
};

export class TokenService {
  _algorithm = 'Ed25519';
  _issuer = 'BigChainDB';
  _publicKey: Buffer;
  _privateKey: Buffer;
  _cipher: Cipher;

  static fromSeed(seed: string | Buffer, accountIndex?: number) {
    const wallet = BigChainWallet.fromSeed(seed);
    const keyPair = wallet.getKeyPair(accountIndex);
    const privateKey = wallet.getFullPrivateKey(accountIndex) as Uint8Array;
    const publicKey = keyPair.publicKey() as Uint8Array;
    return new TokenService({ publicKey: Buffer.from(publicKey), privateKey: Buffer.from(privateKey) });
    // return new TokenService({ publicKey, privateKey });
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
        keyPair[key] = Buffer.from(keyPair[key], 'hex') as Buffer;
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

  sign(content: Record<string, unknown>, options: SignOptions = {}): string {
    const { subject = 'transaction', issuer = this.issuer } = options;
    //? TODO: use keyid field to match specific algorithm
    return sign(content, { key: this._privateKey, algorithm: this.algorithm }, { ...options, issuer, subject });
  }

  async encrypt(token: string) {
    this.validateCipher();
    if (this.cipher.type === 'asymmetric') {
      return this.cipher.encrypt({ token }, this.cipher.sharedSecret);
    } else if (this.cipher.type === 'symmetric') {
      return this.cipher.encrypt({ token }, this.cipher.secret);
    }
    throw new Error(INVALID_CIPHER);
  }

  async produce(content: { claim: any; [key: string]: any }, options?: SignOptions) {
    this.validateCipher();
    const token = this.sign(content, options);
    return this.encrypt(token);
  }

  decode(token: string) {
    return decode(token, { complete: true });
  }

  async decrypt(encryptedToken: string): Promise<{ token: string; [key: string]: unknown }> {
    this.validateCipher();
    if (this.cipher.type === 'asymmetric') {
      return (await this.cipher.decrypt(encryptedToken, this.cipher.sharedSecret)) as {
        token: string;
        [key: string]: unknown;
      };
    } else if (this.cipher.type === 'symmetric') {
      return (await this.cipher.decrypt(encryptedToken, this.cipher.secret)) as {
        token: string;
        [key: string]: unknown;
      };
    }
    throw new Error(INVALID_CIPHER);
  }

  async verify(token: string): Promise<Verification> {
    return new Promise((resolve, reject) => {
      verify(
        token,
        { key: this._publicKey, algorithm: this.algorithm },
        (err: typeof JsonWebTokenError, res: Verification) => (err ? reject(err) : resolve(res)),
      );
    });
  }

  async consume(encryptedToken: string) {
    const { token } = await this.decrypt(encryptedToken);
    return this.verify(token);
  }
}
