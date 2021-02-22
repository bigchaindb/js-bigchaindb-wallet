import {
  BigChainWallet,
  BIG_CHAIN_DERIVATION_PATH,
  DerivatedKeyPair,
  ED25519_CURVE,
  EncryptKeyPair,
  EncryptKeyPairFactory,
  HARDENED_OFFSET,
  KeyDerivation,
  SignKeyPair,
  SignKeyPairFactory,
  uint8ArrayToHexString,
  X25519_CURVE,
} from '../src';
import cases from './fixtures/cases';
import vectors from './fixtures/vectors';

const assertKeypair = (actualKeypair: SignKeyPairFactory, expectedPublicKey: string, expectedPrivateKey: string) => {
  expect(actualKeypair.publicKey('base58')).toEqual(expectedPublicKey);
  expect(actualKeypair.privateKey('base58')).toEqual(expectedPrivateKey);
};

const assertChildKeypair = (
  actualKeypair: SignKeyPairFactory | EncryptKeyPairFactory,
  expectedKeyPair: SignKeyPairFactory | EncryptKeyPairFactory,
) => {
  const { publicKey, privateKey } = expectedKeyPair;
  expect(actualKeypair.publicKey('hex')).toEqual(publicKey('hex'));
  expect(actualKeypair.privateKey('hex')).toEqual(privateKey('hex'));
};

const specTestCase = (num: number) => () => {
  const testCase = cases[num];
  const seedHex = BigChainWallet.createSeed(testCase.mnemonic, testCase.passPhrase).toString('hex');
  const wallet = BigChainWallet.fromSeed(seedHex);

  it('should derives expected parent key', () => {
    const { key } = new KeyDerivation(seedHex).getBaseKey();
    const masterKey = uint8ArrayToHexString(key);
    expect(masterKey).toEqual(testCase.parentKey);
  });

  it('should derives expected account level keys', () => {
    testCase.keyPairs.forEach(([publicKey, privateKey], index) => {
      const derivatedSignKeyPair = wallet.getDerivatedKeyPair('sign', { account: index });
      // const derivatedEncryptKeyPair = wallet.getDerivatedKeyPair('encrypt', { account: index });
      assertKeypair(derivatedSignKeyPair, publicKey, privateKey);
    });
  });

  it('should derives expected index level keys', () => {
    testCase.keyPairs.forEach((_, index) => {
      const childIndex = 1;
      const derivatedSignKeyPair = wallet.getDerivatedKeyPair('sign', { account: index });
      const derivatedChildSignKeyPair = BigChainWallet.getDerivatedKeyPair('sign', derivatedSignKeyPair, childIndex);

      const derivatedEncryptKeyPair = wallet.getDerivatedKeyPair('encrypt', { account: index });
      const derivatedChildEncryptKeyPair = BigChainWallet.getDerivatedKeyPair(
        'encrypt',
        derivatedEncryptKeyPair,
        // derivatedSignKeyPair,
        childIndex,
      );
      // TODO: test encrypteKeyPair from sign key pair

      const expectedSignKeyPair = SignKeyPair.fromDerivatedKeyPair(
        KeyDerivation.derivePath(`${BIG_CHAIN_DERIVATION_PATH}/${index}'/0'/${childIndex}'`, seedHex, 'sign'),
      ).factory();

      const expectedEncryptKeyPair = EncryptKeyPair.fromDerivatedKeyPair(
        KeyDerivation.derivePath(`${BIG_CHAIN_DERIVATION_PATH}/${index}'/0'/${childIndex}'`, seedHex, 'encrypt'),
      ).factory();

      assertChildKeypair(derivatedChildSignKeyPair, expectedSignKeyPair);
      assertChildKeypair(derivatedChildEncryptKeyPair, expectedEncryptKeyPair);
    });
  });

  it('should throw a type error when creating key pair with no public key', () => {
    expect(() => new SignKeyPair({})).toThrow(new TypeError('The "publicKey" property is required.'));
    expect(() => new EncryptKeyPair({})).toThrow(new TypeError('The "publicKey" property is required.'));
  });

  it('should throw a type error when creating key pair from invalid derivated key pair', () => {
    const invalidChainCode = new Uint8Array();
    const invalidKey = new Uint8Array();
    const derivationPath = `${BIG_CHAIN_DERIVATION_PATH}/0'/0'/0'`;
    expect(() =>
      SignKeyPair.fromDerivatedKeyPair({
        key: invalidKey,
        chainCode: invalidChainCode,
        curve: X25519_CURVE,
        derivationPath,
        depth: 5,
      }),
    ).toThrow(new TypeError(`'curve' must be ${ED25519_CURVE}.`));

    expect(() =>
      SignKeyPair.fromDerivatedKeyPair({
        key: invalidKey,
        chainCode: invalidChainCode,
        curve: ED25519_CURVE,
        derivationPath,
        depth: 5,
      }),
    ).toThrow(new TypeError(`Key should be ${KeyDerivation.keyLength} bytes length`));

    expect(() =>
      EncryptKeyPair.fromDerivatedKeyPair({
        key: invalidKey,
        chainCode: invalidChainCode,
        curve: ED25519_CURVE,
        derivationPath,
        depth: 5,
      }),
    ).toThrow(new TypeError(`Key should be ${KeyDerivation.keyLength} bytes length`));
  });

  it('should throw a type error when creating encrypt key pair from invalid sign key pair', () => {
    const signKeyPair = new SignKeyPair({ publicKey: new Uint8Array() });
    expect(() => EncryptKeyPair.fromSignKeyPair(signKeyPair)).toThrow(
      new TypeError(`PublicKey should be ${SignKeyPair.publicKeyLength} bytes length`),
    );
  });

  it('should throw a type error when generating key pair from invalid secret | seed', () => {
    const invalidSeed = 'invalid-seed';
    const invalidSecret = 'invalid-secret';
    expect(() => SignKeyPair.generate({ seed: invalidSeed, encoding: 'utf-8' })).toThrow(
      new TypeError(`Seed should be ${SignKeyPair.seedLength} bytes length`),
    );

    expect(() => SignKeyPair.generate({ secretKey: invalidSecret, encoding: 'utf-8' })).toThrow(
      new TypeError(`SecretKey should be ${SignKeyPair.fullPrivateKeyLength} bytes length`),
    );

    expect(() => EncryptKeyPair.generate({ secretKey: invalidSecret, encoding: 'utf-8' })).toThrow(
      new TypeError(`SecretKey should be ${EncryptKeyPair.privateKeyLength} bytes length`),
    );
  });

  it('should throw a type error when creating key pair from invalid fingerprint', () => {
    const invalidFingerprint = 'invalid-fingerprint';
    expect(() => SignKeyPair.fromFingerprint(invalidFingerprint)).toThrow(
      new Error('`fingerprint` must be a multibase encoded string.'),
    );
    expect(() => EncryptKeyPair.fromFingerprint(invalidFingerprint)).toThrow(
      new Error('`fingerprint` must be a multibase encoded string.'),
    );
  });

  it(`should convert Ed's signing keys to curve`, () => {
    const signKeyPairFactory = wallet.getDerivatedKeyPair('sign');
    const signPublicKeyHex = signKeyPairFactory.publicKey('hex');
    const signPrivateKeyHex = signKeyPairFactory.privateKey('hex');
    const encryptKeyPairFactory = wallet.getDerivatedKeyPair('encrypt');
    const encryptPublicKeyHex = encryptKeyPairFactory.publicKey('hex');
    const encryptPrivateKeyHex = encryptKeyPairFactory.privateKey('hex');

    expect(signPublicKeyHex).toEqual(testCase.conversions.sign[0]);
    expect(signPrivateKeyHex).toEqual(testCase.conversions.sign[1]);
    expect(encryptPublicKeyHex).toEqual(testCase.conversions.curve[0]);
    expect(encryptPrivateKeyHex).toEqual(testCase.conversions.curve[1]);
  });

  it(`should create key Pairs from fingerprint`, () => {
    const signKeyPairFactory = wallet.getDerivatedKeyPair('sign');
    const signFingerprint = signKeyPairFactory.fingerprint();
    const signKeyPair2 = SignKeyPair.fromFingerprint(signFingerprint);
    const signFingerprintValid = SignKeyPair.verifyFingerprint(signFingerprint, signKeyPair2.getPublicKey('base58'));
    const encryptKeyPairFactory = wallet.getDerivatedKeyPair('encrypt');
    const encryptFingerprint = encryptKeyPairFactory.fingerprint();
    const encryptKeyPair2 = EncryptKeyPair.fromFingerprint(encryptFingerprint);
    const encryptFingerprintValid = EncryptKeyPair.verifyFingerprint(
      encryptFingerprint,
      encryptKeyPair2.getPublicKey('base58'),
    );

    expect(signFingerprint).toEqual(testCase.fingerprints.sign);
    expect(encryptFingerprint).toEqual(testCase.fingerprints.curve);
    expect(signKeyPair2.getPublicKey('base58')).toEqual(signKeyPairFactory.publicKey('base58'));
    expect(signFingerprintValid.valid).toBeTruthy();
    expect(encryptKeyPair2.getPublicKey('base58')).toEqual(encryptKeyPairFactory.publicKey('base58'));
    expect(encryptFingerprintValid.valid).toBeTruthy();
  });

  it(`should convert key Pairs to DER`, () => {
    const signKeyPairFactory = wallet.getDerivatedKeyPair('sign');
    const signPublicKeyDer = signKeyPairFactory.publicKey('der');
    const signPrivateKeyDer = signKeyPairFactory.privateKey('der');
    const encryptKeyPairFactory = wallet.getDerivatedKeyPair('encrypt');
    const encryptPublicKeyDer = encryptKeyPairFactory.publicKey('der');
    // const encryptPrivateKeyDer = encryptKeyPairFactory.privateKey('der');

    expect(signPublicKeyDer.toString('hex')).toEqual(testCase.der.sign[0]);
    expect(signPrivateKeyDer.toString('hex')).toEqual(testCase.der.sign[1]);
    expect(encryptPublicKeyDer.toString('hex')).toEqual(testCase.der.curve[0]);
    // expect(encryptPrivateKeyDer.toString('hex')).toEqual(testCase.der.curve[1]);
  });

  it(`should convert key Pairs to KeyObject`, () => {
    const signKeyPairFactory = wallet.getDerivatedKeyPair('sign');
    const signPublicKeyObject = signKeyPairFactory.publicKey('keyObject');
    const signPrivateKeyObject = signKeyPairFactory.privateKey('keyObject');
    const encryptKeyPairFactory = wallet.getDerivatedKeyPair('encrypt');
    const encryptPublicKeyObject = encryptKeyPairFactory.publicKey('keyObject');
    // const encryptPrivateKeyObject = encryptKeyPairFactory.privateKey('keyObject');

    expect(signPublicKeyObject.type).toEqual('public');
    expect(signPrivateKeyObject.type).toEqual('private');
    expect(encryptPublicKeyObject.type).toEqual('public');
    // expect(encryptPrivateKeyObject.type).toEqual('private');
  });

  it(`should convert key Pairs to PEM`, () => {
    const signKeyPairFactory = wallet.getDerivatedKeyPair('sign');
    const signPublicKeyPem = signKeyPairFactory.publicKey('pem');
    const signPrivateKeyPem = signKeyPairFactory.privateKey('pem');
    const encryptKeyPairFactory = wallet.getDerivatedKeyPair('encrypt');
    const encryptPublicKeyPem = encryptKeyPairFactory.publicKey('pem');
    // const encryptPrivateKeyPem = encryptKeyPairFactory.privateKey('pem');

    expect(signPublicKeyPem).toEqual(testCase.pem.sign[0]);
    expect(signPrivateKeyPem).toEqual(testCase.pem.sign[1]);
    expect(encryptPublicKeyPem).toEqual(testCase.pem.curve[0]);
    // expect(encryptPrivateKeyPem).toEqual(testCase.pem.curve[1]);
  });
};

const specTestVector = (num: number) => () => {
  const testCase = vectors[num];
  const { seed: seedHex, vector } = testCase;
  let derivatedKeyPair = new KeyDerivation(seedHex).getMasterKey('sign');

  it(`should create master key from seed - [Chain m]`, () => {
    const { chainCode, key } = derivatedKeyPair;
    expect(uint8ArrayToHexString(chainCode)).toEqual(testCase.chainCode);
    expect(uint8ArrayToHexString(key)).toEqual(testCase.key);
    expect(uint8ArrayToHexString(SignKeyPair.getPublicKey(key))).toEqual(testCase.publicKey);
  });

  vector.forEach((subVector) => {
    it(`should create child key from ${subVector.path}`, () => {
      const { chainCode, key } = KeyDerivation.derivePath(subVector.path, seedHex, 'sign');
      derivatedKeyPair = KeyDerivation.childKeyDerivation(derivatedKeyPair, subVector.index, HARDENED_OFFSET);

      expect({
        index: subVector.index,
        path: subVector.path,
        key: uint8ArrayToHexString(derivatedKeyPair.key),
        chainCode: uint8ArrayToHexString(derivatedKeyPair.chainCode),
        publicKey: uint8ArrayToHexString(SignKeyPair.getPublicKey(derivatedKeyPair.key)),
      }).toEqual(subVector);

      expect({
        index: subVector.index,
        path: subVector.path,
        key: uint8ArrayToHexString(key),
        chainCode: uint8ArrayToHexString(chainCode),
        publicKey: uint8ArrayToHexString(SignKeyPair.getPublicKey(key)),
      }).toEqual(subVector);
    });
  });
};

describe('KeyDerivation', function () {
  describe('Test Case 1', specTestCase(0));
  describe('Test Case 2', specTestCase(1));
  describe('Test Case 3', specTestCase(2));
  describe('Test Case 4', specTestCase(3));
  describe('Test Case 5 - Ed25519 - vector1', specTestVector(0));
  describe('Test Case 6 - Ed25519 - vector2', specTestVector(1));

});
