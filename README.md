# common-good-storage - offchain signing

```sh
$ cargo run --quiet client-propose-deal \
  sr25519:554b6fc625fbea8f56eb56262d92ccb083fd6eaaf5ee9a966eaab4db2062f4d0 \
  abcd
public key: 143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559
deal:       abcd
signed:     ec975e3564e5803727d90314603a02fc4640a7643943cf96d94babf893b4d15815bf00aeeb61730f5c14c92fe44df09469b5c661102e91026b20a0e64b0bde80
```

and if we take that clients public key (143fa...) and the signed abcd "document" (ec975...) to the next phase with the arguments:

1. client_key sr25519:143fa...
1. miner_key sr25519:e5be9a.... (this is the well-known //Alice secret seed)
1. same original document abcd masquerading as comm_p
1. the signature from the first step ec975...

```sh
$ cargo run --quiet miner-verify-publish \
  sr25519:143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559 \
  sr25519:e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a \
  abcd \
  ec975e3564e5803727d90314603a02fc4640a7643943cf96d94babf893b4d15815bf00aeeb61730f5c14c92fe44df09469b5c661102e91026b20a0e64b0bde80
deal:   abcdec975e3564e5803727d90314603a02fc4640a7643943cf96d94babf893b4d15815bf00aeeb61730f5c14c92fe44df09469b5c661102e91026b20a0e64b0bde80
signed: 3855ab55fb8ae603944e52451de7d91f417a2e174b77737ef70dc7a4d36d634cea23f80e1c84ceabfac582e09842dc18881598052ad6c38ad588c36f1bddc682

```
This is just the basic `sign(sign(b"abcd", client_key), miner_key)`, don't really know about the multisig sr25519 yet. 
The `deal:` in the output is the `b"abcd".iter().chain(signature_by_client)` and `signed ` is the outer signature for it.

