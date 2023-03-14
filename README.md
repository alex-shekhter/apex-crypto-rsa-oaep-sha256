# apex-crypto-rsa-oaep-sha256

The purpose of this project is to provide working implementation of the RSAES-OAEP (PKCS#1 v2) encryption and decryption using Salesforce Apex programming language.

This project also has a few shell scripts (tested only in MAC OS X with Mac Port) to simplify key generation and testing.

The Apex code is based on the following gists:

 * [karmats](https://gist.github.com/karmats/4270441be5a34fff7062)
 * [nikitakarpenkov](https://gist.github.com/nikitakarpenkov/7a39c5cd6170dbcac74cf797d03e60f7)
 * [vasudevanselvaganesh](https://gist.github.com/vasudevanselvaganesh/7a817e58a5c703ece149da70cbb1553a)

## Repository structure

The `force-app` direcory uses standard SF layout and has Apex classes.

```
./force-app/main/default/classes/CryptoRSA_1_v2.cls
./force-app/main/default/classes/CryptoRSA_1_v2_Test.cls
```

The `scripts` directory has some useful sheel scripts which simplifying creation of the keys and their usage.

```
./scripts/prep_modulus_exponents.sh
./scripts/generate_keys.sh
./scripts/encrypt.sh
./scripts/cat_mod_exponents.sh
./scripts/decrypt.sh
```

## Future

RSA OAEP decryption implementation is very expensive from the CPU time POV and therefore can lead to the Governor Limits violations. It might be interesting to try to play with `BigInt` class
from the [mattandeil repository](https://github.com/mattandneil/apex-rsa-sha-512/blob/master/CryptoRsaSha512.cls)

