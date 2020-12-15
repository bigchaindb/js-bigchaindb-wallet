import { BigChainWallet } from '@s1seven/js-bigchaindb-key-derivation';
import { AsymmetricCipher, SymmetricCipher } from '@s1seven/js-bigchaindb-wallet-plugins';
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

  it('Should sign - verify a token using symmetric cipher for encrypt/decrypt', async () => {
    const mnemonic = BigChainWallet.createMnemonic();
    const seed = BigChainWallet.createSeed(mnemonic);
    const secret = SymmetricCipher.createSecret();
    const tokenService = TokenService.fromSeed(seed);
    tokenService.cipher = new SymmetricCipher(secret);

    type TokenPayload = {
      claim: string;
      randomData: string;
    };
    const claim = 'myclaim';
    const encryptedToken = await tokenService.produce<TokenPayload>({
      claim,
      randomData: 'test',
    });
    const payload = await tokenService.consume<TokenPayload>(encryptedToken);
    expect(payload.claim).toEqual(claim);
  });

  it('Should sign - verify a token using asymmetric cipher for encrypt/decrypt', async () => {
    const mnemonic = BigChainWallet.createMnemonic();
    const seed = BigChainWallet.createSeed(mnemonic);
    const keyPairA = AsymmetricCipher.createKeyPair();
    const keyPairB = AsymmetricCipher.createKeyPair();
    const tokenService = TokenService.fromSeed(seed);
    tokenService.cipher = new AsymmetricCipher(keyPairA.secretKey, keyPairB.publicKey);

    type TokenPayload = {
      claim: string;
    };
    const claim = 'myclaim';
    const encryptedToken = await tokenService.produce<TokenPayload>({
      claim,
    });
    // tokenService.cipher = new AsymmetricCipher(keyPairB.secretKey, keyPairA.publicKey);
    const payload = await tokenService.consume<TokenPayload>(encryptedToken);
    expect(payload.claim).toEqual(claim);
  });
});
