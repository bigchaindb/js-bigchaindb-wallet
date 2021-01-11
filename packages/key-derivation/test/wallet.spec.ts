import * as bip39 from 'bip39';
import { BigChainWallet } from '../src';

const MNEMONIC_ENGLISH =
  'pride gaze casino bread mail huge embark grief poverty anger kid entry either movie hen that flee sea birth good frequent endless globe ordinary';
const MNEMONIC_FRENCH =
  'étonnant stimulus gicler fébrile flexion caresser biberon érosion kiosque copie hérisson graduel atrium néfaste outil géranium alpaga banlieue spatial balancer manquant cerise mascotte unanime';

const FROM_MNEMONIC_ENGLISH_PUBLIC_KEY_0 = '5P6b3kUKpBfVWMfJEg5XTtXy37etSKcmw36DUEf3iiLJ';
const FROM_MNEMONIC_ENGLISH_SECRET_KEY_0 = '9ddiuq7RJRT3huGVxm57RTTU6BYDjDJMWuMyB6wLzjy3';

describe('BigChainWallet', () => {
  describe('fromMnemonic', () => {
    it('creates wallet from mnemonic with defaults', () => {
      const wallet = BigChainWallet.fromMnemonic(MNEMONIC_ENGLISH);
      expect(wallet.getDerivedPublicKey('sign', { account: 0 }, 'base58')).toEqual(FROM_MNEMONIC_ENGLISH_PUBLIC_KEY_0);
      expect(wallet.getDerivedPrivateKey('sign', { account: 0 }, 'base58')).toEqual(FROM_MNEMONIC_ENGLISH_SECRET_KEY_0);
    });

    it('creates wallet from mnemonic with specific language', () => {
      const expectedPublic = '2bvbLAMa9LfqhFYYe1Z1UuWMfyz85AvBCgDEHfJvvhpm';
      const expectedPrivateKey = 'DuSEXvGzetvccnQ3s3i38hkbWTBW7C5Ge3uHcFWBiXGR';
      const wallet = BigChainWallet.fromMnemonic(MNEMONIC_FRENCH, undefined, 'french');
      expect(wallet.getDerivedPublicKey('sign', { account: 0 }, 'base58')).toEqual(expectedPublic);
      expect(wallet.getDerivedPrivateKey('sign', { account: 0 }, 'base58')).toEqual(expectedPrivateKey);
    });

    it('creates wallet from mnemonic with password', () => {
      const expectedPublic = '4q8r4XZHQnVWStT9Dqcu5ZgAGWeifvi2tgHyRQn9D6ph';
      const expectedPrivateKey = 'DeGbUWgb3bhk4XEWtaZxyPgmsBoE5vvGugCapHVmnNpK';
      const wallet = BigChainWallet.fromMnemonic(MNEMONIC_ENGLISH, 'password');
      expect(wallet.getDerivedPublicKey('sign', { account: 0 }, 'base58')).toEqual(expectedPublic);
      expect(wallet.getDerivedPrivateKey('sign', { account: 0 }, 'base58')).toEqual(expectedPrivateKey);
    });

    it('creates wallet from mnemonic with password AND specific language', () => {
      const expectedPublic = 'FwHieS1ZR2KbYv3cXwp4QwcbB6vYA7w26GXocFSYBr2m';
      const expectedPrivateKey = 'RZKRJr7fYqfnd3QprMcVDbaMAbHxF8SNmmCrTKVjAqu';
      const wallet = BigChainWallet.fromMnemonic(MNEMONIC_FRENCH, 'motdepasse', 'french');
      expect(wallet.getDerivedPublicKey('sign', { account: 0 }, 'base58')).toEqual(expectedPublic);
      expect(wallet.getDerivedPrivateKey('sign', { account: 0 }, 'base58')).toEqual(expectedPrivateKey);
    });

    const expectInvalidMnemonicFailure = (mnemonic?: string, password?: string, language?: string) => {
      expect(() => BigChainWallet.fromMnemonic(mnemonic, password, language)).toThrow(
        new Error('Invalid mnemonic (see bip39)'),
      );
    };

    it('empty mnemonic throws', () => {
      expectInvalidMnemonicFailure();
      expectInvalidMnemonicFailure('');
      expectInvalidMnemonicFailure(null);
      expectInvalidMnemonicFailure(undefined, 'password', 'italian');
      expectInvalidMnemonicFailure('', 'password', 'italian');
    });

    it('invalid mnemonic throws', () => {
      expectInvalidMnemonicFailure('phrase'); // short
      expectInvalidMnemonicFailure('bigchain'); // invalid word AND short
    });
  });

  describe('fromSeed', () => {
    it('creates wallet from seed hex string', () => {
      const seedHex = BigChainWallet.createSeed(MNEMONIC_ENGLISH).toString('hex');
      const wallet = BigChainWallet.fromSeed(seedHex);
      expect(wallet.getDerivedPublicKey('sign', { account: 0 }, 'base58')).toEqual(FROM_MNEMONIC_ENGLISH_PUBLIC_KEY_0);
      expect(wallet.getDerivedPrivateKey('sign', { account: 0 }, 'base58')).toEqual(FROM_MNEMONIC_ENGLISH_SECRET_KEY_0);
    });

    it('creates wallet from seed Buffer', () => {
      const seedBuffer = BigChainWallet.createSeed(MNEMONIC_ENGLISH);
      const wallet = BigChainWallet.fromSeed(seedBuffer);
      expect(wallet.getDerivedPublicKey('sign', { account: 0 }, 'base58')).toEqual(FROM_MNEMONIC_ENGLISH_PUBLIC_KEY_0);
      expect(wallet.getDerivedPrivateKey('sign', { account: 0 }, 'base58')).toEqual(FROM_MNEMONIC_ENGLISH_SECRET_KEY_0);
    });
  });

  describe('generateMnemonic', () => {
    describe('entropy', () => {
      const assertInvalidEntropy = (entropy?: number) => {
        expect(() => BigChainWallet.createMnemonic(entropy)).toThrow(new TypeError('Invalid entropy'));
      };

      it('generates a 24 word seed by default', () => {
        const mnemonic = BigChainWallet.createMnemonic();
        expect(mnemonic.split(' ').length).toEqual(24);
      });

      it('generates a 12 word seed for 128 bits entropy', () => {
        const mnemonic = BigChainWallet.createMnemonic(128);
        expect(mnemonic.split(' ').length).toEqual(12);
      });

      it('rejects entropy if not a multiple of 32', () => {
        assertInvalidEntropy(129);
        assertInvalidEntropy(200);
      });

      it('rejects entropy if out of range [128 - 256]', () => {
        assertInvalidEntropy(129);
        assertInvalidEntropy(257);
      });
    });

    describe('language', () => {
      it('supports bip39 languages', () => {
        const chineseWordlist = bip39.wordlists['chinese_traditional'];
        const mnemonic = BigChainWallet.createMnemonic(0, 'chinese_traditional');

        const mnemonicWords = mnemonic.split(' ');
        expect(mnemonicWords.length).toEqual(24);

        const wordsInDict = mnemonicWords.filter((w) => chineseWordlist.indexOf(w) !== -1);
        expect(wordsInDict.length).toEqual(24);
      });

      it('supports french language', () => {
        const frenchWordlist = bip39.wordlists['french'];
        const mnemonic = BigChainWallet.createMnemonic(null, 'french');

        const mnemonicWords = mnemonic.split(' ');
        expect(mnemonicWords.length).toEqual(24);

        const wordsInDict = mnemonicWords.filter((w) => frenchWordlist.indexOf(w) !== -1);
        expect(wordsInDict.length).toEqual(24);
      });

      it('rejects unsupported bip39 languages with meaningful message', () => {
        expect(() => BigChainWallet.createMnemonic(0, 'toki_pona')).toThrow(
          new TypeError('toki_pona is not listed in bip39 module'),
        );
      });
    });
  });

  describe('validateMnemonic', () => {
    const validate = BigChainWallet.validateMnemonic;

    it('passes valid mnemonic input', () => {
      // 24 word
      expect(validate(MNEMONIC_ENGLISH)).toBeTruthy();
      // 12 word
      expect(validate(BigChainWallet.createMnemonic(128))).toBeTruthy();
    });

    it('rejects empty mnemonic input', () => {
      // assert.equal(validate(), false);
      expect(validate(null)).toBeFalsy();
      expect(validate('')).toBeFalsy();
      expect(validate('', 'french')).toBeFalsy();
      expect(validate(null, 'french')).toBeFalsy();
    });

    it('rejects short mnemonic input', () => {
      expect(validate('phrase')).toBeFalsy();
      expect(validate('phrase mass barrel')).toBeFalsy();
      expect(validate('phrase mass barrel', 'english')).toBeFalsy();
    });

    it('rejects mnemonic with word not in wordlist', () => {
      const mnemonic = MNEMONIC_ENGLISH.split(' ').slice(1);
      mnemonic.push('bigchaindb');
      expect(validate(mnemonic.join(' '))).toBeFalsy();
    });

    it("rejects mnemonic input that isn't a multiple of 32 bits", () => {
      // 23 words
      const twentyThreeWords = BigChainWallet.createMnemonic().split(' ').slice(1).join(' ');
      expect(twentyThreeWords.split(' ').length).toEqual(23);
      expect(validate(twentyThreeWords)).toBeFalsy();
    });
  });
});
