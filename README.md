# common-good-storage - offchain signing

## Client propose a deal

```sh
# Args:
#    client_key: AnyKey,     // client's private key
#    comm_p: AnyHex,         // lets just pretend this is the commP cid
#    padded_piece_size: u64, // size of the payload and any padding to construct the binary merkle trie https://spec.filecoin.io/systems/filecoin_files/piece/pieces.png
#    miner: AnyKey,          // miner's public key i.e. 32 bytes
#    start_block: u64, // this type needs to match frame_system::BlockNumber defined in runtime
#    end_block: u64,   // frame_support::pallet_prelude::BlockNumberFor

$ cargo run --quiet client-propose-deal \
  sr25519:554b6fc625fbea8f56eb56262d92ccb083fd6eaaf5ee9a966eaab4db2062f4d0 \
  abcd \
  128 \
  sr25519:d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d \
  10000 \
  20000

client public key:   143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559
deal proposal:       DealProposal { comm_p: abcd, padded_piece_size: 128, client: 143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559, miner: d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d, start_block: 10000, end_block: 20000 }
signature:           723b1464b81d02b0e285471e5e1181357d6e6ddb91c26f4ccccc71432a74bd6b59f89c829ba03a827121aefacd64f9dc2bcf2fdec245b380009943bf2a335786
```

and if we take that clients public key (143fa...) and the signed deal proposal (723b14...) to the next phase with the arguments:

```sh
# Args:
#     client: AnyKey,          // client's public key
#     miner_key: AnyKey,       // miner's private key
#     comm_p: AnyHex,          // same as previous step
#     padded_piece_size: u64,  // same as previous step
#     start_block: u64,        // same as previous step
#     end_block: u64,          // same as previous step
#     signature: AnyHex,       // the signature from the client in the previous step

$ cargo run --quiet miner-verify-publish \
  sr25519:143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559 \
  sr25519:e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a \
  abcd \
  128 \
  10000 \
  20000 \
  723b1464b81d02b0e285471e5e1181357d6e6ddb91c26f4ccccc71432a74bd6b59f89c829ba03a827121aefacd64f9dc2bcf2fdec245b380009943bf2a335786

deal proposal:   DealProposal { comm_p: abcd, padded_piece_size: 128, client: 143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559, miner: d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d, start_block: 10000, end_block: 20000 }
deal:            08abcd800000000000000080143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a55980d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d1027000000000000204e000000000000723b1464b81d02b0e285471e5e1181357d6e6ddb91c26f4ccccc71432a74bd6b59f89c829ba03a827121aefacd64f9dc2bcf2fdec245b380009943bf2a335786
signature:       8e7fee67658439454d4f5df4b3321c26a8d6f0e94fe10e95a399e8aa1e825251a4fff66bd19ba23c62964c8b8fc2e69b3bb986a7f829126dfc950d6871d31b84
```

Publishable deal is just a basic `sign(sign(encoded(deal_proposal), client_key), miner_key)` which does not use aggregate signatures.
The `deal:` in the output is the `deal_proposal.encode().chain(signature_by_client)` where deal_proposal is SCALE encoded and `signature` is the outer signature for it.
