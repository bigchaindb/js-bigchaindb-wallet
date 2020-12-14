import { BigChainWallet } from '@s1seven/js-bigchain-key-derivation';
import { AsymmetricCipher, SymmetricCipher } from '@s1seven/js-bigchain-wallet-plugins';
import { TokenService } from '../src';

describe('TokenService', function () {
  it('Should throw error if no cipher is assigned', async () => {
    const mnemonic = BigChainWallet.createMnemonic();
    const seed = BigChainWallet.createSeed(mnemonic);
    const tokenService = TokenService.fromSeed(seed);
    const claim = 'myclaim';

    await expect(
      async () =>
        await tokenService.produce({
          claim,
        }),
    ).rejects.toThrow(new Error('Register a cipher before calling this method'));
  });

  it('Should sign - verify a token using symmetric cipher', async () => {
    const mnemonic = BigChainWallet.createMnemonic();
    const seed = BigChainWallet.createSeed(mnemonic);
    const secret = SymmetricCipher.createSecret();
    const tokenService = TokenService.fromSeed(seed);
    tokenService.cipher = new SymmetricCipher(secret);

    const claim = 'myclaim';
    const encryptedToken = await tokenService.produce({
      claim,
    });
    const payload = await tokenService.consume(encryptedToken);
    
    expect(payload.claim).toEqual(claim);
  });

  it('Should sign - verify a token using asymmetric cipher', async () => {
    const mnemonic = BigChainWallet.createMnemonic();
    const seed = BigChainWallet.createSeed(mnemonic);
    const keyPairA = AsymmetricCipher.createKeyPair();
    const keyPairB = AsymmetricCipher.createKeyPair();
    const tokenService = TokenService.fromSeed(seed);
    tokenService.cipher = new AsymmetricCipher(keyPairA.secretKey, keyPairB.publicKey);

    const claim = 'myclaim';
    const encryptedToken = await tokenService.produce({
      claim,
    });
    // tokenService.cipher = new AsymmetricCipher(keyPairB.secretKey, keyPairA.publicKey);
    const payload = await tokenService.consume(encryptedToken);

    expect(payload.claim).toEqual(claim);
  });
});
