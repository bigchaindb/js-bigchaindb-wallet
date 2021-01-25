# `key-derivation`

Heavily inspired by [stellar-hd-wallet](https://github.com/chatch/stellar-hd-wallet).
Complies to [BIP44] and [SLIP10].

## Usage

### TODO: DEMONSTRATE API

```
const BigChainWallet = require('@s1seven/js-bigchain-key-derivation');

```

## TODOs

### Account discovery

In an extra module ?

- implement account discovery :
- [BIP44 spec](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#account-discovery)
- [oip-hdmw](https://oipwg.github.io/oip-hdmw/Account.js.html)
- [bip32-utils](https://github.com/oipwg/bip32-utils/blob/master/chain.js)
- With a query like :

```ts
async accountDiscovery(account: number | string, index: number, attempt = 0): Promise<boolean> {
  const conn = new Connection(this.networkUrl);
  const publicKey = this.getPublicKey(index, 'base58');
  // ? only check unspent ?
  const unspentTransactions = await conn.listOutputs(publicKey, false);
  const spentTransactions = await conn.listOutputs(publicKey, true);
  const transactions = [...unspentTransactions, ...spentTransactions];
  if (transactions.length) {
    return false;
  }
  if (!transactions.length) {
    return this.accountDiscovery(account, (index += 1), (attempt += 1));
  }
  if (attempt === 20) {
    return true;
  }
  return false;
}
```

- add third property if keypair has unspent transaction ?
- check that previous account has transaction history

### DER / KeyObject / PEM encoding

- Add missing alg to export as DER/PEM/Keyobject X25519 private key

[bip44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
[slip10]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
