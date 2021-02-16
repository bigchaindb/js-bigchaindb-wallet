import {
  BigChainWallet,
  BIG_CHAIN_DERIVATION_PATH,
  EncryptKeyPair,
  EncryptKeyPairFactory,
  KeyDerivation,
  SignKeyPair,
  SignKeyPairFactory,
  uint8ArrayToHexString,
} from '../src';
import cases from './fixtures/cases';

const assertKeypair = (actualKeypair: SignKeyPairFactory, expectedPublicKey: string, expectedPrivateKey: string) => {
  expect(actualKeypair.publicKey('base58')).toEqual(expectedPublicKey);
  expect(actualKeypair.privateKey('base58')).toEqual(expectedPrivateKey);
};

const assertChildKeypair = (
  actualKeypair: SignKeyPairFactory | EncryptKeyPairFactory,
  expectedKeyPair: SignKeyPair | EncryptKeyPair,
) => {
  const { publicKey, privateKey } = expectedKeyPair;
  expect(actualKeypair.publicKey('hex')).toEqual(uint8ArrayToHexString(publicKey));
  expect(actualKeypair.privateKey('hex')).toEqual(uint8ArrayToHexString(privateKey));
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

  it('should derives expected child keys', () => {
    testCase.keyPairs.forEach(([publicKey, privateKey], index) => {
      const derivatedSignKeyPair = wallet.getDerivatedKeyPair('sign', { account: index });
      assertKeypair(derivatedSignKeyPair, publicKey, privateKey);

      const childIndex = 1;
      const derivatedChildSignKeyPair = BigChainWallet.getDerivatedKeyPair('sign', derivatedSignKeyPair, childIndex);
      const derivatedChildEncryptKeyPair = BigChainWallet.getDerivatedKeyPair(
        'encrypt',
        derivatedSignKeyPair,
        childIndex,
      );
      const expectedChildKeyPair = KeyDerivation.derivePath(
        `${BIG_CHAIN_DERIVATION_PATH}/${index}'/${childIndex}'/0'`,
        seedHex,
      );

      assertChildKeypair(derivatedChildSignKeyPair, SignKeyPair.fromDerivatedKeyPair(expectedChildKeyPair));
      assertChildKeypair(derivatedChildEncryptKeyPair, EncryptKeyPair.fromDerivatedKeyPair(expectedChildKeyPair));
    });
  });

  it('should throw a type error when creating key pair with no public key', () => {
    expect(() => new SignKeyPair({})).toThrow(new TypeError('The "publicKey" property is required.'));
    expect(() => new EncryptKeyPair({})).toThrow(new TypeError('The "publicKey" property is required.'));
  });

  it('should throw a type error when creating key pair from invalid derived key pair', () => {
    const invalidChainCode = new Uint8Array();
    const invalidKey = new Uint8Array();
    const derivationPath = `${BIG_CHAIN_DERIVATION_PATH}/${0}'/${0}'/0'`;
    expect(() =>
      SignKeyPair.fromDerivatedKeyPair({ key: invalidKey, chainCode: invalidChainCode, derivationPath }),
    ).toThrow(new TypeError(`Key should be ${KeyDerivation.keyLength} bytes length`));

    expect(() =>
      EncryptKeyPair.fromDerivatedKeyPair({ key: invalidKey, chainCode: invalidChainCode, derivationPath }),
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

describe('KeyDerivation', function () {
  describe('Test Case 1', specTestCase(0));
  describe('Test Case 2', specTestCase(1));
  describe('Test Case 3', specTestCase(2));
  describe('Test Case 4', specTestCase(3));
});
