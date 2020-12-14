import AsymmetricCipher from '../src/asymmetricCipher';

describe('AsymmetricCipher', function () {
  it('Encrypt - decrypt from static methods', () => {
    const obj = { hello: 'world' };
    const keyPairA = AsymmetricCipher.createKeyPair();
    const keyPairB = AsymmetricCipher.createKeyPair();
    const sharedA = AsymmetricCipher.createSharedKey(keyPairA.secretKey, keyPairB.publicKey);
    const encrypted = AsymmetricCipher.encrypt(obj, sharedA);
    const sharedB = AsymmetricCipher.createSharedKey(keyPairB.secretKey, keyPairA.publicKey);
    const decrypted = AsymmetricCipher.decrypt(encrypted, sharedB);
    expect(decrypted).toEqual(obj);
  });

  it('Encrypt - decrypt from prototype methods', async () => {
    const obj = { hello: 'world' };
    const keyPairA = AsymmetricCipher.createKeyPair();
    const keyPairB = AsymmetricCipher.createKeyPair();
    const aymmetricCipherA = new AsymmetricCipher(keyPairA.secretKey, keyPairB.publicKey);
    const encrypted = await aymmetricCipherA.encrypt(obj);
    const aymmetricCipherB = new AsymmetricCipher(keyPairB.secretKey, keyPairA.publicKey);
    const decrypted = await aymmetricCipherB.decrypt(encrypted);
    expect(decrypted).toEqual(obj);
  });
});
