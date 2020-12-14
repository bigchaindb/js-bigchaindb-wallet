import { BigChainWallet, KeyPair, BIG_CHAIN_PATH, uint8ArrayToHexString } from '../src';
import cases from './fixtures/cases';

const assertKeypair = (actualKeypair: KeyPair, expectedPublicKey: string, expectedPrivateKey: string) => {
  expect(actualKeypair.publicKey('base58')).toEqual(expectedPublicKey);
  expect(actualKeypair.privateKey('base58')).toEqual(expectedPrivateKey);
};

const specTestCase = (num: number) => () => {
  const testCase = cases[num];
  const wallet = BigChainWallet.fromMnemonic(testCase.mnemonic, testCase.passPhrase);

  it('derives expected parent key', () => {
    const masterKey = uint8ArrayToHexString(wallet.derive(BIG_CHAIN_PATH));
    expect(masterKey).toEqual(testCase.parentKey);
  });

  it('derives expected child keys', () => {
    testCase.keyPairs.forEach(([publicKey, privateKey], index) =>
      assertKeypair(wallet.getKeypair(index), publicKey, privateKey),
    );
  });

  it("convert signing keys to Edward's curve", () => {
    const keyPair = wallet.getKeypair();
    const publicKeyHex = keyPair.publicKey('hex');
    const privateKeyHex = keyPair.privateKey('hex');
    expect(publicKeyHex).toEqual(testCase.conversions.sign[0]);
    expect(privateKeyHex).toEqual(testCase.conversions.sign[1]);

    const curveKeyPair = wallet.getDHKeyPair();
    const curvePublicKeyHex = curveKeyPair.publicKey('hex');
    const curvePrivateKeyHex = curveKeyPair.privateKey('hex');
    expect(curvePublicKeyHex).toEqual(testCase.conversions.curve[0]);
    expect(curvePrivateKeyHex).toEqual(testCase.conversions.curve[1]);
  });
};

describe('KeyDerivation', function () {
  describe('Test Case 1', specTestCase(0));
  describe('Test Case 2', specTestCase(1));
  describe('Test Case 3', specTestCase(2));
  describe('Test Case 4', specTestCase(3));
});
