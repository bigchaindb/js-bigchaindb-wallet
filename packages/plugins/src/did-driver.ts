import {
  BigChainWallet,
  DerivatedKeyPair,
  EncryptKeyPair,
  KeyPairDerivationOptions,
  SignKeyPair,
  SignKeyPairFactory,
} from '@bigchaindb/wallet-hd';
import LRU from 'lru-cache';
import { constants as securityConstants } from 'security-context';

export type DidDocPublicKey = {
  id: string;
  type: string; // 'Ed25519VerificationKey2018'
  controller: string;
  publicKeyBase58?: string;
  publicKeyBase64?: string;
};

export type DidDocKeyAgreement = {
  id: string;
  type: string; //  'X25519KeyAgreementKey2019'
  controller: string;
  publicKeyBase58: string;
  publicKeyBase64?: string;
};

export type DidDocKeyPair = {
  id: string;
  type: string; // 'Ed25519VerificationKey2018' | 'X25519KeyAgreementKey2019
  controller: string;
  publicKeyBase58?: string;
  publicKeyBase64?: string;
  privateKeyBase58?: string;
  privateKeyBase64?: string;
};

export type DidDoc = {
  '@context': securityConstants.SECURITY_CONTEXT_V2_URL;
  id: string;
  publicKey: DidDocPublicKey[];
  authentication: string[];
  assertionMethod: string[];
  capabilityDelegation: string[];
  capabilityInvocation: string[];
  keyAgreement: DidDocKeyAgreement[];
  keys?: DidDocKeyPair[];
};

export type DidDocFragment = { '@context': securityConstants.SECURITY_CONTEXT_V2_URL } & (
  | DidDocPublicKey
  | DidDocKeyAgreement
);

function getKey(options: { didDoc: DidDoc; keyIdFragment: string }): DidDocFragment {
  const { didDoc, keyIdFragment } = options;
  // Determine if the key id fragment belongs to the "main" public key,
  // or the keyAgreement key
  const keyId = `${didDoc.id}#${keyIdFragment}`;
  const publicKey = didDoc.publicKey[0];
  if (publicKey.id === keyId) {
    return {
      '@context': securityConstants.SECURITY_CONTEXT_V2_URL,
      ...publicKey,
    };
  }
  return {
    '@context': securityConstants.SECURITY_CONTEXT_V2_URL,
    ...didDoc.keyAgreement[0],
  };
}

export class DidDriver {
  method: string;
  private _cache: LRU<string, Promise<DidDoc>>;

  constructor({ maxCacheSize = 100 } = {}) {
    // used by did-io to register drivers
    this.method = 'key';
    this._cache = new LRU({ max: maxCacheSize });
  }

  async get(options: { did?: string; url?: string } = {}): Promise<DidDoc | DidDocFragment> {
    const { url } = options;
    let { did } = options;
    did = did || url;
    if (!did) {
      throw new TypeError('"did" must be a string.');
    }

    const [didAuthority, keyIdFragment] = did.split('#');
    let addedToCache = false;
    let promise = this._cache.get(didAuthority);
    if (!promise) {
      const fingerprint = didAuthority.substr(`did:${this.method}:`.length);
      const signKeyPair = SignKeyPair.fromFingerprint(fingerprint);
      promise = this.keyToDidDoc({ signKeyPair });
      this._cache.set(didAuthority, promise);
      addedToCache = true;
    }

    let didDoc: DidDoc;
    try {
      didDoc = await promise;
    } catch (e) {
      if (addedToCache) {
        this._cache.del(didAuthority);
      }
      throw e;
    }

    if (keyIdFragment) {
      return getKey({ didDoc, keyIdFragment });
    }
    return didDoc;
  }

  generate(
    options: {
      keyType?: string;
      derivationOptions?: KeyPairDerivationOptions;
      seed?: string;
      derivatedKeyPair?: DerivatedKeyPair;
    } = {},
  ): Promise<DidDoc> {
    const { keyType = SignKeyPair.suite, seed, derivationOptions, derivatedKeyPair } = options;
    if (keyType === SignKeyPair.suite) {
      let signKeyPairFactory: SignKeyPairFactory;
      if (seed && !derivationOptions) {
        signKeyPairFactory = BigChainWallet.masterKeyPairFactory('sign', seed);
      } else if (seed && derivationOptions) {
        signKeyPairFactory = BigChainWallet.derivatedKeyPairFactoryFromSeed('sign', seed, derivationOptions);
      } else if (derivatedKeyPair) {
        signKeyPairFactory = BigChainWallet.derivatedKeyPairFactory('sign', derivatedKeyPair);
      } else {
        signKeyPairFactory = SignKeyPair.generate().factory();
      }

      const signKeyPair = SignKeyPair.fromFactory(signKeyPairFactory);
      return this.keyToDidDoc({ signKeyPair });
    } else {
      throw new TypeError(`Unsupported Key type ${keyType}`);
    }
  }

  async keyToDidDoc(options: { signKeyPair?: SignKeyPair; derivatedKeyPair?: DerivatedKeyPair }): Promise<DidDoc> {
    const { signKeyPair, derivatedKeyPair } = options;
    let edKeyPair: SignKeyPair;
    if (derivatedKeyPair) {
      edKeyPair = SignKeyPair.fromDerivatedKeyPair(derivatedKeyPair);
    } else if (signKeyPair) {
      edKeyPair = signKeyPair;
    } else if (!signKeyPair && !derivatedKeyPair) {
      throw new TypeError('`signKeyPair` or `derivatedKeyPair` is required.');
    }
    const did = `did:key:${edKeyPair.getFingerprint()}`;
    const keyId = `${did}#${edKeyPair.getFingerprint()}`;
    const dhKeyPair = EncryptKeyPair.fromSignKeyPair(edKeyPair);
    dhKeyPair.id = `${did}#${dhKeyPair.getFingerprint()}`;

    const didDocPublicKey = {
      id: keyId,
      type: edKeyPair.type,
      controller: did,
      publicKeyBase58: edKeyPair.getPublicKey('base58'),
      publicKeyBase64: edKeyPair.getPublicKey('base64'),
    };
    const didDocKeyAgreement = {
      id: dhKeyPair.id,
      type: dhKeyPair.type,
      controller: did,
      publicKeyBase58: dhKeyPair.getPublicKey('base58'),
      publicKeyBase64: dhKeyPair.getPublicKey('base64'),
    };

    const didDoc: DidDoc = {
      '@context': ['https://w3id.org/did/v0.11'],
      id: did,
      publicKey: [didDocPublicKey],
      authentication: [keyId],
      assertionMethod: [keyId],
      capabilityDelegation: [keyId],
      capabilityInvocation: [keyId],
      keyAgreement: [didDocKeyAgreement],
    };

    Object.defineProperty(didDoc, 'keys', {
      value: {
        [keyId]: {
          ...didDocPublicKey,
          privateKeyBase58: edKeyPair.getFullPrivateKey('base58'),
          privateKeyBase64: edKeyPair.getFullPrivateKey('base64'),
        },
        [dhKeyPair.id]: {
          ...didDocKeyAgreement,
          privateKeyBase58: dhKeyPair.getPrivateKey('base58'),
          privateKeyBase64: dhKeyPair.getPrivateKey('base64'),
        },
      },
      enumerable: false,
    });

    return didDoc;
  }

  computeKeyId(key: EncryptKeyPair | SignKeyPair): string {
    return `did:${this.method}:${key.getFingerprint()}#${key.getFingerprint()}`;
  }
}
