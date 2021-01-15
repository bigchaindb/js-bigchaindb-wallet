import { decodeUTF8, encodeUTF8 } from 'tweetnacl-util';
import { Sign } from '../src/sign';

describe('Sign', function () {
  it('Should sign - verify from static methods', () => {
    const msgString = JSON.stringify({ hello: 'world' });
    const msg = decodeUTF8(msgString);

    const keyPair = Sign.createKeyPair();
    const signedMsg = Sign.sign(msg, keyPair.secretKey);
    const openedSignedMsg = Sign.open(signedMsg, keyPair.publicKey);
    const signature = Sign.signature(msg, keyPair.secretKey);
    const verify = Sign.verify(msg, signature, keyPair.publicKey);

    expect(encodeUTF8(openedSignedMsg)).toEqual(msgString);
    expect(verify).toBeTruthy();
  });

  it('Should sign - verify from prototype methods', async () => {
    const msgString = JSON.stringify({ hello: 'world' });
    const msg = decodeUTF8(msgString);

    const keyPair = Sign.createKeyPair();
    const instance = new Sign({ publicKey: keyPair.publicKey, privateKey: keyPair.secretKey });
    const signedMsg = instance.sign(msg);
    const openedSignedMsg = instance.open(signedMsg);
    const signature = instance.signature(msg);
    const verify = instance.verify(msg, signature);

    expect(encodeUTF8(openedSignedMsg)).toEqual(msgString);
    expect(verify).toBeTruthy();
  });
});
