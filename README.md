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

client public key:   sr25519:143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559
deal proposal:       DealProposal { comm_p: AnyHex(abcd), padded_piece_size: 128, client: sr25519:143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559, miner: sr25519:d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d, start_block: 10000, end_block: 20000 }
signature:           c8a66dce56b233f903c1196174e673bf0fd01d305b1f806350c598d6580b865cc9967b960f8e4ae314194ad33ab012201f9a58b9f10be8613cf907bc0fd8df82
```

and if we take that clients public key (143fa...) and the signed deal proposal (c8a66...) to the next phase with the arguments:

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
  c8a66dce56b233f903c1196174e673bf0fd01d305b1f806350c598d6580b865cc9967b960f8e4ae314194ad33ab012201f9a58b9f10be8613cf907bc0fd8df82

deal proposal:   DealProposal { comm_p: AnyHex(abcd), padded_piece_size: 128, client: sr25519:143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559, miner: sr25519:d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d, start_block: 10000, end_block: 20000 }
deal:            08abcd800000000000000000143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a55900d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d1027000000000000204e000000000000c8a66dce56b233f903c1196174e673bf0fd01d305b1f806350c598d6580b865cc9967b960f8e4ae314194ad33ab012201f9a58b9f10be8613cf907bc0fd8df82
signature:       dea33232885f0716e39fe1c3e54c1eb7ce818aad17551cee7bc4f7d2c5c492235a0fccdc92c4be1bfd44b4c05e02e03a98c5b0150e0410b6970674e3e1a87f84
```

Publishable deal is just a basic `sign(sign(encoded(deal_proposal), client_key), miner_key)` which does not use aggregate signatures.
The `deal:` in the output is the `deal_proposal.encode().chain(signature_by_client)` where deal_proposal is SCALE encoded and `signature` is the outer signature for it.
