use codec::{Decode, Encode};
use std::fmt;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "cli-example",
    about = "Example code to handle off-chain deal signing"
)]
struct Opts {
    #[structopt(subcommand)]
    command: Command,
}

mod client_propose_deal;
use client_propose_deal::ClientProposeDeal;

mod miner_verify_publish;
use miner_verify_publish::MinerVerifyPublish;

mod hex_io;
pub(crate) use hex_io::{AnyHex, AnyKey, HexString};

#[derive(Debug, StructOpt)]
enum Command {
    /// Generate a signed deal proposal by the client to the specific miner.
    ClientProposeDeal(ClientProposeDeal),
    /// Verify a previously client generated deal proposal by a miner, generating a on-chain
    /// publishable deal description.
    MinerVerifyPublish(MinerVerifyPublish),
}

static SIMPLE_PROPOSAL_CONTEXT: &[u8] = b"example starts: proposal";
static SIMPLE_DEAL_CONTEXT: &[u8] = b"example continues: deal";

fn main() {
    run(Opts::from_args())
}

fn run(opts: Opts) {
    let res: Result<Box<dyn fmt::Display>, Box<dyn std::error::Error>> = match opts.command {
        Command::ClientProposeDeal(cpd) => cpd
            .run()
            .map(|pd| Box::new(pd) as Box<dyn fmt::Display>)
            .map_err(Box::from),
        Command::MinerVerifyPublish(mvp) => mvp
            .run()
            .map(|pd| Box::new(pd) as Box<dyn fmt::Display>)
            .map_err(Box::from),
    };

    match res {
        Ok(d) => println!("{}", d),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Encode, Decode)]
struct DealProposal {
    comm_p: AnyHex,
    // size of the payload and any padding to construct the binary merkle trie https://spec.filecoin.io/systems/filecoin_files/piece/pieces.png
    padded_piece_size: u64,
    // Public key - AccountId - https://substrate.dev/docs/en/knowledgebase/integrate/subkey#generating-keys
    client: AnyKey,
    // Public key i.e. 32 bytes
    miner: AnyKey,
    // this type needs to match frame_system::BlockNumber defined in runtime
    start_block: u64,
    // frame_support::pallet_prelude::BlockNumberFor
    end_block: u64,
}

#[cfg(test)]
mod tests {
    use super::{AnyHex, AnyKey, ClientProposeDeal, DealProposal, MinerVerifyPublish};
    use crate::client_propose_deal::ProposableDeal;
    use std::str::FromStr;

    #[test]
    fn example_client_propose_deal_sr25519() {
        let client_sk = "sr25519:554b6fc625fbea8f56eb56262d92ccb083fd6eaaf5ee9a966eaab4db2062f4d0";
        let miner_pk = "sr25519:d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
        let cmd = ClientProposeDeal {
            client_key: AnyKey::from_str(client_sk).unwrap(),
            comm_p: AnyHex::from_str("abcd").unwrap(),
            padded_piece_size: 128,
            miner: AnyKey::from_str(miner_pk).unwrap(),
            start_block: 10_000,
            end_block: 20_000,
        };

        cmd.run().unwrap();
    }

    #[test]
    fn example_client_propose_deal_bls12() {
        let client_sk = "bls12:3a6ec3badbbad93a25bd57a612f2875acef3cca518247a8534643a4ddb4fdc3e";
        let miner_pk = "bls12:81e8e7ccd05c30ac0c41e5fe8aa63a6e6f5dde28d0485592a2bcd84493496dba5c8752d46933339914f91f62af812351";
        let cmd = ClientProposeDeal {
            client_key: AnyKey::from_str(client_sk).unwrap(),
            comm_p: AnyHex::from_str("abcd").unwrap(),
            padded_piece_size: 128,
            miner: AnyKey::from_str(miner_pk).unwrap(),
            start_block: 10_000,
            end_block: 20_000,
        };

        cmd.run().unwrap();
    }

    #[test]
    fn proposable_deal_formatting_sr25519() {
        let client_pk = "sr25519:143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559";
        let miner_pk = "sr25519:d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
        let sig = AnyHex::from_str("72d2df2584b12d4cbea791edd85346ac786c5640730b7ad6ae1f532444f06a307c440874fb8b844e481152192d71f594f4db5812549af90bfa107379f93a8881").unwrap();
        let expected = "\
client public key:   143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559
deal proposal:       DealProposal { comm_p: AnyHex(abcd), padded_piece_size: 128, client: Sr25519, miner: Sr25519, start_block: 10000, end_block: 20000 }
signature:           72d2df2584b12d4cbea791edd85346ac786c5640730b7ad6ae1f532444f06a307c440874fb8b844e481152192d71f594f4db5812549af90bfa107379f93a8881
";

        let resp = ProposableDeal {
            deal_proposal: DealProposal {
                comm_p: AnyHex::from_str("abcd").unwrap(),
                padded_piece_size: 128,
                client: AnyKey::from_str(client_pk).unwrap(),
                miner: AnyKey::from_str(miner_pk).unwrap(),
                start_block: 10_000,
                end_block: 20_000,
            },
            signature: sig.0,
        };

        assert_eq!(expected, &format!("{}", resp));
    }

    #[test]
    fn proposable_deal_formatting_bls12() {
        use bls_signatures::Serialize;
        use std::convert::TryInto;
        let client_sk = "bls12:3a6ec3badbbad93a25bd57a612f2875acef3cca518247a8534643a4ddb4fdc3e";
        let miner_pk = "bls12:81e8e7ccd05c30ac0c41e5fe8aa63a6e6f5dde28d0485592a2bcd84493496dba5c8752d46933339914f91f62af812351";
        let sig = AnyHex::from_str("b66b31cd722ad9b686e41eae5ccc352cb57ce7455c45f49302568ebe3fb1331eb9c0dc38f60db2d990f4f53952a5fdeb0d71fe76e7048210ec7b60f62765738e01aaf1bb4fca405adb01f4a252842c6cc92a1154c2d0c6d570d5fee93067f970").unwrap();
        let expected = "\
client public key:   81e8e7ccd05c30ac0c41e5fe8aa63a6e6f5dde28d0485592a2bcd84493496dba5c8752d46933339914f91f62af812351
deal proposal:       DealProposal { comm_p: AnyHex(abcd), padded_piece_size: 128, client: Bls12, miner: Bls12, start_block: 10000, end_block: 20000 }
signature:           b66b31cd722ad9b686e41eae5ccc352cb57ce7455c45f49302568ebe3fb1331eb9c0dc38f60db2d990f4f53952a5fdeb0d71fe76e7048210ec7b60f62765738e01aaf1bb4fca405adb01f4a252842c6cc92a1154c2d0c6d570d5fee93067f970
";

        let client_pk = match AnyKey::from_str(client_sk) {
            Ok(AnyKey::BlsPrivate(bytes)) => bls_signatures::PrivateKey::from_bytes(&bytes)
                .unwrap()
                .public_key()
                .as_bytes(),
            x => unreachable!("{:?}", x),
        };

        let resp = ProposableDeal {
            deal_proposal: DealProposal {
                comm_p: AnyHex::from_str("abcd").unwrap(),
                padded_piece_size: 128,
                client: AnyKey::BlsPublic(client_pk.try_into().unwrap()),
                miner: AnyKey::from_str(miner_pk).unwrap(),
                start_block: 10_000,
                end_block: 20_000,
            },
            signature: sig.0,
        };

        assert_eq!(expected, &format!("{}", resp));
    }

    #[test]
    fn example_miner_verify_publish() {
        let client_pk = "sr25519:143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559";
        let miner_sk = "sr25519:e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";
        let sig = "46b26683b7e8706f2ae42ea950de63fdd7ee00f4f4dbdac4c328c33dfe2f4643e77d20bb706fde456e543b872bb5c7691728585a5337423ceb749ee7d3751a8f";

        let cmd = MinerVerifyPublish {
            client: AnyKey::from_str(client_pk).unwrap(),
            miner_key: AnyKey::from_str(miner_sk).unwrap(),
            comm_p: AnyHex::from_str("abcd").unwrap(),
            padded_piece_size: 128,
            start_block: 10_000,
            end_block: 20_000,
            signature: AnyHex::from_str(sig).unwrap(),
        };

        cmd.run().unwrap();
    }

    #[test]
    fn example_miner_verify_publish_bls12() {
        use bls_signatures::Serialize;
        use std::convert::TryInto;

        let client_sk = "bls12:3a6ec3badbbad93a25bd57a612f2875acef3cca518247a8534643a4ddb4fdc3e";

        let miner_sk = "bls12:93383d7666256663e092709cf19ca215d4e26355af1152a80955d34ea796a431";
        let miner_sk = AnyKey::from_str(miner_sk).unwrap();

        // TODO: writing the operations back to back highlights that we should have a strongly typed
        // layer above the cmdline operation level.

        let client_pk = AnyKey::BlsPublic(
            bls_signatures::PrivateKey::from_bytes(AnyKey::from_str(client_sk).unwrap().as_ref())
                .unwrap()
                .public_key()
                .as_bytes()
                .try_into()
                .unwrap(),
        );

        let cmd = ClientProposeDeal {
            client_key: AnyKey::from_str(client_sk).unwrap(),
            comm_p: AnyHex::from_str("abcd").unwrap(),
            padded_piece_size: 128,
            miner: AnyKey::BlsPublic(
                bls_signatures::PrivateKey::from_bytes(miner_sk.as_ref())
                    .unwrap()
                    .public_key()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            ),
            start_block: 10_000,
            end_block: 20_000,
        };

        let sig = cmd.run().unwrap().signature;

        let cmd = MinerVerifyPublish {
            client: client_pk,
            miner_key: miner_sk,
            comm_p: AnyHex::from_str("abcd").unwrap(),
            padded_piece_size: 128,
            start_block: 10_000,
            end_block: 20_000,
            signature: AnyHex(sig),
        };

        cmd.run().unwrap();
    }

    #[test]
    fn cannot_publish_invalid_signature_based_deal() {
        let client_pk = "sr25519:143fa4ecea108937a2324d36ee4cbce3c6f3a08b0499b276cd7adb7a7631a559";
        let miner_sk = "sr25519:e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";
        // last char changed
        let sig = "46b26683b7e8706f2ae42ea950de63fdd7ee00f4f4dbdac4c328c33dfe2f4643e77d20bb706fde456e543b872bb5c7691728585a5337423ceb749ee7d3751a8d";

        let cmd = MinerVerifyPublish {
            client: AnyKey::from_str(client_pk).unwrap(),
            miner_key: AnyKey::from_str(miner_sk).unwrap(),
            comm_p: AnyHex::from_str("abcd").unwrap(),
            padded_piece_size: 128,
            start_block: 10_000,
            end_block: 20_000,
            signature: AnyHex::from_str(sig).unwrap(),
        };

        let err = cmd.run().unwrap_err();
        assert!(
            matches!(
                err,
                crate::miner_verify_publish::ProposalVerifyError::InvalidSignature
            ),
            "{:?}",
            err
        );
    }

    #[test]
    fn propose_and_verify_publish() {
        let client_sk = "sr25519:554b6fc625fbea8f56eb56262d92ccb083fd6eaaf5ee9a966eaab4db2062f4d0";

        let miner_sk = "sr25519:e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";
        let miner_pk = "sr25519:d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

        let cmd = ClientProposeDeal {
            client_key: AnyKey::from_str(client_sk).unwrap(),
            comm_p: AnyHex::from_str("abcd").unwrap(),
            padded_piece_size: 128,
            miner: AnyKey::from_str(miner_pk).unwrap(),
            start_block: 10_000,
            end_block: 20_000,
        };

        let proposable = cmd.run().unwrap();

        let cmd = MinerVerifyPublish {
            client: proposable.deal_proposal.client,
            miner_key: AnyKey::from_str(miner_sk).unwrap(),
            comm_p: proposable.deal_proposal.comm_p,
            padded_piece_size: proposable.deal_proposal.padded_piece_size,
            start_block: proposable.deal_proposal.start_block,
            end_block: proposable.deal_proposal.end_block,
            signature: AnyHex(proposable.signature),
        };

        cmd.run().unwrap();
    }
}
