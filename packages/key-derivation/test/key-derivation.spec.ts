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
      const derivedSignKeyPair = wallet.getDerivedKeyPair('sign', { account: index });
      assertKeypair(derivedSignKeyPair, publicKey, privateKey);

      const childIndex = 1;
      const derivedChildSignKeyPair = BigChainWallet.getDerivedKeyPair('sign', derivedSignKeyPair, childIndex);
      const derivedChildEncryptKeyPair = BigChainWallet.getDerivedKeyPair('encrypt', derivedSignKeyPair, childIndex);
      const expectedChildKeyPair = KeyDerivation.derivePath(
        `${BIG_CHAIN_DERIVATION_PATH}/${index}'/${childIndex}'/0'`,
        seedHex,
      );

      assertChildKeypair(derivedChildSignKeyPair, new SignKeyPair(expectedChildKeyPair));
      assertChildKeypair(derivedChildEncryptKeyPair, new EncryptKeyPair(expectedChildKeyPair));
    });
  });

  it(`should convert Ed's signing keys to curve`, () => {
    const signKeyPair = wallet.getDerivedKeyPair('sign');
    const signPublicKeyHex = signKeyPair.publicKey('hex');
    const signPrivateKeyHex = signKeyPair.privateKey('hex');
    const encryptKeyPair = wallet.getDerivedKeyPair('encrypt');
    const encryptPublicKeyHex = encryptKeyPair.publicKey('hex');
    const encryptPrivateKeyHex = encryptKeyPair.privateKey('hex');

    expect(signPublicKeyHex).toEqual(testCase.conversions.sign[0]);
    expect(signPrivateKeyHex).toEqual(testCase.conversions.sign[1]);
    expect(encryptPublicKeyHex).toEqual(testCase.conversions.curve[0]);
    expect(encryptPrivateKeyHex).toEqual(testCase.conversions.curve[1]);
  });
};

describe('KeyDerivation', function () {
  describe('Test Case 1', specTestCase(0));
  describe('Test Case 2', specTestCase(1));
  describe('Test Case 3', specTestCase(2));
  describe('Test Case 4', specTestCase(3));
});
