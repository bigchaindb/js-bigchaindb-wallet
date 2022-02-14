export const cases = {
  fromSeed: {
    didDoc: {
      '@context': ['https://w3id.org/did/v0.11'],
      id: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
      publicKey: [
        {
          id: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
          type: 'Ed25519VerificationKey2018',
          controller: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
          publicKeyBase58: 'B8UAa4DWGppYwKzTrhu7iCJkRvHU9vQGTyJVY4E27goD',
          publicKeyBase64: 'ln6mhnFyENBbNuoqWvdbnvvT7qKNmAABnoeCkBUinFQ=',
        },
      ],
      authentication: [
        'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
      ],
      assertionMethod: [
        'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
      ],
      capabilityDelegation: [
        'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
      ],
      capabilityInvocation: [
        'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
      ],
      keyAgreement: [
        {
          id: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6LSpouJakfanDWpA3t4GwMf8CP6WxBnjWTx2H6p35LMVrNa',
          type: 'X25519KeyAgreementKey2019',
          controller: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
          publicKeyBase58: 'E8j94Srigko54fWHkHqhocAcfoeg2uHo9JP8YcgpnUbp',
          publicKeyBase64: 'wyKkcq015jrUE5xns7M+5dP/UUco4qL7PZ0CRA6/nEc=',
        },
      ],
    },
    didDocKeys: {
      'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab': {
        id: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
        type: 'Ed25519VerificationKey2018',
        controller: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
        publicKeyBase58: 'B8UAa4DWGppYwKzTrhu7iCJkRvHU9vQGTyJVY4E27goD',
        publicKeyBase64: 'ln6mhnFyENBbNuoqWvdbnvvT7qKNmAABnoeCkBUinFQ=',
        privateKeyBase58: '5ezrYcGHiuVD6AYKjcteyiZnxcfbNDigZ5EAAF2DRLwiLqy3JLwRwvRC3m8VvB6uyTNnn4tZrZGvjorP3H9su4jd',
        privateKeyBase64: '6NXoz1PnhD43MF4j7YzFCr+jp8Nohga/a2HsyS/E2VOWfqaGcXIQ0Fs26ipa91ue+9Puoo2YAAGeh4KQFSKcVA==',
      },
      'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6LSpouJakfanDWpA3t4GwMf8CP6WxBnjWTx2H6p35LMVrNa': {
        id: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6LSpouJakfanDWpA3t4GwMf8CP6WxBnjWTx2H6p35LMVrNa',
        type: 'X25519KeyAgreementKey2019',
        controller: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
        publicKeyBase58: 'E8j94Srigko54fWHkHqhocAcfoeg2uHo9JP8YcgpnUbp',
        publicKeyBase64: 'wyKkcq015jrUE5xns7M+5dP/UUco4qL7PZ0CRA6/nEc=',
        privateKeyBase58: '8Zq3FDpYRTBTncHrxxag6f83umXUpNooq8zfMyjD8Fib',
        privateKeyBase64: 'cGq2QDvatNAvydFNNpX/7nJLfB1Aj0G3jDstj/SxnXw=',
      },
    },
  },
  fromDerivatedKeyPair: {
    didDoc: {
      '@context': ['https://w3id.org/did/v0.11'],
      id: 'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
      publicKey: [
        {
          id: 'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
          type: 'Ed25519VerificationKey2018',
          controller: 'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
          publicKeyBase58: '2UB6L1jHe7RRHxidChCd3o5tW3SD16Y4xK5rdTUGYNnG',
          publicKeyBase64: 'FdHHmJuJuleK1ngqnDJq3YQC6CrwX6FdCu/1PYvgul0=',
        },
      ],
      authentication: [
        'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
      ],
      assertionMethod: [
        'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
      ],
      capabilityDelegation: [
        'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
      ],
      capabilityInvocation: [
        'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
      ],
      keyAgreement: [
        {
          id: 'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6LSeA22bArDLqnYXwicUFzhqXwQvHNBTGxT5bvNccXMsN37',
          type: 'X25519KeyAgreementKey2019',
          controller: 'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
          publicKeyBase58: '3Uqs4s3MFP4oSZLqwcUkWwiw58q4kfnJCdCh89sq9zGM',
          publicKeyBase64: 'JNlONiOOoUU+qGaeRjnAbF0BX5MVasbJQB3bFvCK534=',
        },
      ],
    },
    didDocKeys: {
      'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe': {
        id: 'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
        type: 'Ed25519VerificationKey2018',
        controller: 'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
        publicKeyBase58: '2UB6L1jHe7RRHxidChCd3o5tW3SD16Y4xK5rdTUGYNnG',
        publicKeyBase64: 'FdHHmJuJuleK1ngqnDJq3YQC6CrwX6FdCu/1PYvgul0=',
        privateKeyBase58: '4MgzjsSasEtFNb7kzf1sF2zyH2MY6D5NioxifGKEdGPvxRfc7NQGXKuXFkdboHw6XyDZCHAzHj79xwtL7wEj9rTN',
        privateKeyBase64: 'p+SVMggbYa/X7StUvHkM74IRAlWpb20HGCcbfTf6nRgV0ceYm4m6V4rWeCqcMmrdhALoKvBfoV0K7/U9i+C6XQ==',
      },
      'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6LSeA22bArDLqnYXwicUFzhqXwQvHNBTGxT5bvNccXMsN37': {
        id: 'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe#z6LSeA22bArDLqnYXwicUFzhqXwQvHNBTGxT5bvNccXMsN37',
        type: 'X25519KeyAgreementKey2019',
        controller: 'did:key:z6MkfvS8vFyiyeutQTZKtGATttdtKci4QynReKznTjSHTbZe',
        publicKeyBase58: '3Uqs4s3MFP4oSZLqwcUkWwiw58q4kfnJCdCh89sq9zGM',
        publicKeyBase64: 'JNlONiOOoUU+qGaeRjnAbF0BX5MVasbJQB3bFvCK534=',
        privateKeyBase58: 'Fb9kg3qqcBLp6xAmMuXEcq8Q77q3sbVMLAmrQbtJPwnU',
        privateKeyBase64: '2MNC8m4CjtyijqAzxblfVTGt8lPyZ0HVfo64e0D8p0U=',
      },
    },
  },
  fromDidWithFragment: {
    '@context': 'https://w3id.org/security/v2',
    id: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
    type: 'Ed25519VerificationKey2018',
    controller: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
    publicKeyBase58: 'B8UAa4DWGppYwKzTrhu7iCJkRvHU9vQGTyJVY4E27goD',
    publicKeyBase64: 'ln6mhnFyENBbNuoqWvdbnvvT7qKNmAABnoeCkBUinFQ=',
  },
  fromDidAuthority: {
    '@context': ['https://w3id.org/did/v0.11'],
    id: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
    publicKey: [
      {
        id: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
        type: 'Ed25519VerificationKey2018',
        controller: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
        publicKeyBase58: 'B8UAa4DWGppYwKzTrhu7iCJkRvHU9vQGTyJVY4E27goD',
        publicKeyBase64: 'ln6mhnFyENBbNuoqWvdbnvvT7qKNmAABnoeCkBUinFQ=',
      },
    ],
    authentication: [
      'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
    ],
    assertionMethod: [
      'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
    ],
    capabilityDelegation: [
      'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
    ],
    capabilityInvocation: [
      'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
    ],
    keyAgreement: [
      {
        id: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab#z6LSpouJakfanDWpA3t4GwMf8CP6WxBnjWTx2H6p35LMVrNa',
        type: 'X25519KeyAgreementKey2019',
        controller: 'did:key:z6MkpajDAJTwcNK23pqAYGrxZHrkFVZKZoed9zDRNLC32uab',
        publicKeyBase58: 'E8j94Srigko54fWHkHqhocAcfoeg2uHo9JP8YcgpnUbp',
        publicKeyBase64: 'wyKkcq015jrUE5xns7M+5dP/UUco4qL7PZ0CRA6/nEc=',
      },
    ],
  },
};
