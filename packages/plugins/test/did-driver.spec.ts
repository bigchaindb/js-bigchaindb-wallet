import { BigChainWallet, BIG_CHAIN_DERIVATION_PATH, KeyDerivation } from '@bigchaindb/wallet-hd';
import { DidDriver } from '../src/did-driver';
import { cases } from './fixtures/did-driver';

describe('DID Driver', function () {
  const mnemonic = 'bread supply coyote spend grocery scan usage survey print token brother crew';
  const seedHex = BigChainWallet.createSeed(mnemonic).toString('hex');

  it('Should generate DID doc from seed', async () => {
    const didDriver = new DidDriver();
    const didDoc = await didDriver.generate({ seed: seedHex });
    expect(didDoc).toEqual(cases.fromSeed.didDoc);
    expect(didDoc.keys).toEqual(cases.fromSeed.didDocKeys);
  });

  it('Should generate DID doc from derived key pair', async () => {
    const derivatedKeyPair = KeyDerivation.derivePath(`${BIG_CHAIN_DERIVATION_PATH}/1'/1'/0'`, seedHex);
    const didDriver = new DidDriver();
    const didDoc = await didDriver.generate({ derivatedKeyPair });
    expect(didDoc).toEqual(cases.fromDerivatedKeyPair.didDoc);
    expect(didDoc.keys).toEqual(cases.fromDerivatedKeyPair.didDocKeys);
  });

  it('Should get DID doc fragment from DID', async () => {
    const didDriver = new DidDriver();
    const did = cases.fromSeed.didDoc.publicKey[0].id;
    const didDoc = await didDriver.get({ did });
    expect(didDoc).toEqual(cases.fromDidWithFragment);
  });

  it('Should get full DID doc from DID Authority', async () => {
    const didDriver = new DidDriver();
    const did = cases.fromSeed.didDoc.id;
    const didDoc = await didDriver.get({ did });
    expect(didDoc).toEqual(cases.fromDidAuthority);
  });
});
