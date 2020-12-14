import { BigChainWallet, KeyPair, BIG_CHAIN_PATH } from '../src';
import cases from './fixtures/cases';

const assertKeypair = (actualKeypair: KeyPair, expectedPublicKey: string, expectedPrivateKey: string) => {
  expect(actualKeypair.publicKey('base58')).toEqual(expectedPublicKey);
  expect(actualKeypair.privateKey('base58')).toEqual(expectedPrivateKey);
};

const specTestCase = (num: number) => () => {
  const testCase = cases[num];
  const wallet = BigChainWallet.fromMnemonic(testCase.mnemonic, testCase.passPhrase);

  it('derives expected parent key', () => {
    expect(wallet.derive(BIG_CHAIN_PATH).toString('hex')).toEqual(testCase.parentKey);
  });

  it('derives expected child keys', () => {
    testCase.keyPairs.forEach(([publicKey, privateKey], index) =>
      assertKeypair(wallet.getKeypair(index), publicKey, privateKey),
    );
  });
  //? TODO: test conversion to ed's curves
};

describe('KeyDerivation', function () {
  describe('Test Case 1', specTestCase(0));
  describe('Test Case 2', specTestCase(1));
  describe('Test Case 3', specTestCase(2));
  describe('Test Case 4', specTestCase(3));
});
