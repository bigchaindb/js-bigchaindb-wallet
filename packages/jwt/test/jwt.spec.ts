import { BigChainWallet } from '@bigchaindb/wallet-hd';
import { AsymmetricCipher, SymmetricCipher } from '@bigchaindb/wallet-plugins';
import { TokenService } from '../src';

const createTokenService = () => {
  const mnemonic = BigChainWallet.createMnemonic();
  const seed = BigChainWallet.createSeed(mnemonic);
  return TokenService.fromSeed(seed);
};

type TokenPayload = {
  claim: string;
  randomData?: string;
};

describe('TokenService', function () {
  it('Should throw error if no cipher is assigned', async () => {
    const tokenService = createTokenService();
    const claim = 'myclaim';
    await expect(
      async () =>
        await tokenService.produce({
          claim,
        }),
    ).rejects.toThrow(new Error('Register a cipher before calling this method'));
  });

  it('Should sign - verify a token using symmetric cipher for encrypt/decrypt', async () => {
    const tokenService = createTokenService();
    const secret = SymmetricCipher.createSecret();
    tokenService.cipher = new SymmetricCipher(secret);

    const claim = 'myclaim';
    const encryptedToken = await tokenService.produce<TokenPayload>({
      claim,
      randomData: 'test',
    });
    const payload = await tokenService.consume<TokenPayload>(encryptedToken);
    expect(payload.claim).toEqual(claim);
  });

  it('Should sign - verify a token using asymmetric cipher for encrypt/decrypt', async () => {
    const tokenService = createTokenService();
    const keyPairA = AsymmetricCipher.createKeyPair();
    const keyPairB = AsymmetricCipher.createKeyPair();
    tokenService.cipher = new AsymmetricCipher(keyPairA.secretKey, keyPairB.publicKey);

    const claim = 'myclaim';
    const encryptedToken = await tokenService.produce<TokenPayload>({
      claim,
    });
    // tokenService.cipher = new AsymmetricCipher(keyPairB.secretKey, keyPairA.publicKey);
    const payload = await tokenService.consume<TokenPayload>(encryptedToken);
    expect(payload.claim).toEqual(claim);
  });

  it('Should sign - verify a token using sign / verify options', async () => {
    const tokenService = createTokenService();
    const secret = SymmetricCipher.createSecret();
    tokenService.cipher = new SymmetricCipher(secret);

    const claim = 'myclaim';
    const options = { issuer: 'test_issuer' };
    const encryptedToken = await tokenService.produce<TokenPayload>(
      {
        claim,
        randomData: 'test',
      },
      options,
    );
    const decryptedJWT = await tokenService.decrypt(encryptedToken);
    const decodedToken = tokenService.decode(decryptedJWT.jwt);
    expect(decodedToken.payload.iss).toEqual(options.issuer);

    const payload = await tokenService.consume<TokenPayload>(encryptedToken, options);
    expect(payload.claim).toEqual(claim);
  });

  it('Should throw an error during verification when a token uses invalid issuer', async () => {
    const tokenService = createTokenService();
    const secret = SymmetricCipher.createSecret();
    tokenService.cipher = new SymmetricCipher(secret);

    const claim = 'myclaim';
    const encryptedToken = await tokenService.produce<TokenPayload>(
      {
        claim,
        randomData: 'test',
      },
      { issuer: 'invalid_issuer' },
    );
    await expect(
      async () => await tokenService.consume<TokenPayload>(encryptedToken, { issuer: 'test_issuer' }),
    ).rejects.toThrow(new Error('jwt issuer invalid. expected: test_issuer'));
  });
});
