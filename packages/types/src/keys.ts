export enum KeyType {
  plaintextKey = 'plaintextKey',
  // TODO: trezor = "trezor",
}

export interface BaseKey {
  extra?: any;
  path?: string;
  publicKey: string;
  // if the network is not set, the key is assumed to be on Networks.PUBLIC
  network?: string;
  type: KeyType | string;
}

/**
 * All key types (ledgers, plaintext keys, etc.) should use the same Key shape.
 * That way, plugins don't have to know what key type there is, they just work
 * the same on all of them.
 *
 * `privateKey` is always required regardless of key types. If the key type
 * doesn't have any secrets (like a ledger key), this should be an empty string.
 *
 * `extra` is an arbitrary store of additional metadata, to be used as an escape
 * hatch to support any exotic key type in the future.
 */
export interface Key extends BaseKey {
  id: string;
  privateKey: string;
}

export interface UnstoredKey extends BaseKey {
  id?: string;
  privateKey: string;
}

/**
 * The encrypted key is the exact same shape as the key, minus secret
 * information and plus encrypted information.
 */
export interface EncryptedKey {
  encryptedBlob: string;
  encrypterName: string;
  id: string;
  salt: string;
}

/**
 * Metadata about the key and when it was changed.
 */
export interface KeyMetadata {
  id: string;
}

export interface EncryptParams {
  key: Key;
  password: string;
}

export interface DecryptParams {
  encryptedKey: EncryptedKey;
  password: string;
}

/**
 * This is the export interface that an encryption plugin must implement.
 *
 * example encrypters:
 *  - identity encrypterName (does nothing, ok to use for Ledger / Trezor)
 *  - scrypt password + nacl box (what StellarX uses)
 *  - scrypt password and then xor with Stellar key (what Keybase does)
 * https://keybase.io/docs/crypto/local-key-security
 */
export interface Encrypter {
  name: string;

  /**
   * Encrypt a raw, unencrypted key.
   */
  encryptKey(params: EncryptParams): Promise<EncryptedKey>;

  /**
   * Decrypt an encrypted key. If the password doesn't properly encrypt the key,
   * it should throw an error. Please make sure the error message is descriptive
   * and user-friendly.
   */
  decryptKey(params: DecryptParams): Promise<Key>;
}
