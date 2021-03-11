# JS-BigChainDB-wallets

[![lerna](https://img.shields.io/badge/maintained%20with-lerna-cc00ff.svg)](https://lerna.js.org/)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

This repository contains a suite of components and modules to ease the creation of wallets for BigChainDB.

## List of packages

- [Key-Derivation](https://github.com/bigchaindb/js-bigchaindb-wallet/tree/master/packages/key-derivation#readme)
- [Plugins](https://github.com/bigchaindb/js-bigchaindb-wallet/tree/master/packages/plugins#readme)
- [Types](https://github.com/bigchaindb/js-bigchaindb-wallet/tree/master/packages/types#readme)
- [JWT](https://github.com/bigchaindb/js-bigchaindb-wallet/tree/master/packages/jwt#readme)

## TODOs

- Implement Key-store package

  - Store encrypted seeds + derivated full privateKey + transactions linked to derivated publicKey

  - support attachement of default | custom encryption plugin (following the plugins API)

  - support attachement of default | custom storage (create default : LocalStorage for browser and MemoryStorage + FileStorage for node)

  - allow encrypted file export ( encrypted using custom secret key ? )