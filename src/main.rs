use codec::{Decode, Encode};
use std::fmt;
use std::str::FromStr;
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

#[derive(Debug, StructOpt)]
enum Command {
    // TODO: some fields are omitted in this phase
    // VerifiedDeal: bool,    indicate that the deal counts towards verified client total
    // StoragePricePerEpoch abi.TokenAmount
    // ProviderCollateral abi.TokenAmount
    // ClientCollateral   abi.TokenAmount
    /// This is signed by the client
    ClientProposeDeal(ClientProposeDeal),
    MinerVerifyPublish(MinerVerifyPublish),
}

#[derive(Debug, StructOpt)]
struct ClientProposeDeal {
    // client's private key
    client_key: AnyKey,
    // lets just pretend this is the commP cid
    comm_p: AnyHex,
    // size of the payload and any padding to construct the binary merkle trie https://spec.filecoin.io/systems/filecoin_files/piece/pieces.png
    padded_piece_size: u64,
    // miner's public key i.e. 32 bytes
    miner: AnyKey,
    // this type needs to match frame_system::BlockNumber defined in runtime
    start_block: u64,
    // frame_support::pallet_prelude::BlockNumberFor
    end_block: u64,
}

#[derive(Debug)]
enum DealProposeError {
    // none at this time before we add key types
}

impl fmt::Display for DealProposeError {
    fn fmt(&self, _fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        unreachable!()
    }
}

impl std::error::Error for DealProposeError {}

#[derive(Debug, StructOpt)]
struct MinerVerifyPublish {
    // client's public key
    client: AnyKey,
    // miner's private key
    miner_key: AnyKey,
    comm_p: AnyHex,
    padded_piece_size: u64,
    start_block: u64,
    end_block: u64,
    signature: AnyHex,
}

#[derive(Debug)]
enum ProposalVerifyError {
    InvalidSignature,
}

impl fmt::Display for ProposalVerifyError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ProposalVerifyError::*;
        match self {
            // not sure if the nested reason matters?
            InvalidSignature => write!(fmt, "Invalid client signature"),
        }
    }
}

impl std::error::Error for ProposalVerifyError {}

static SIMPLE_PROPOSAL_CONTEXT: &[u8] = b"example starts: proposal";
static SIMPLE_DEAL_CONTEXT: &[u8] = b"example continues: deal";

fn main() {
    run(Opts::from_args())
}

#[derive(Debug)]
struct ProposableDeal {
    deal_proposal: DealProposal,
    signature: schnorrkel::sign::Signature,
}

impl fmt::Display for ProposableDeal {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            fmt,
            "client public key:   {:?}",
            HexString(self.deal_proposal.client.as_ref())
        )?;
        writeln!(fmt, "deal proposal:       {:?}", self.deal_proposal)?;
        writeln!(
            fmt,
            "signature:           {:?}",
            HexString(&self.signature.to_bytes()[..])
        )
    }
}

impl ClientProposeDeal {
    fn run(self) -> Result<ProposableDeal, DealProposeError> {
        match self {
            ClientProposeDeal {
                client_key: AnyKey::Sr25519(client_sk),
                comm_p,
                padded_piece_size,
                miner,
                start_block,
                end_block,
            } => {
                let kp = schnorrkel::keys::MiniSecretKey::from_bytes(&client_sk[..])
                    .expect("SecretKey needs 32 bytes, cannot fail")
                    .expand(schnorrkel::keys::ExpansionMode::Ed25519)
                    .to_keypair();

                let deal_proposal = DealProposal {
                    comm_p,
                    padded_piece_size,
                    client: AnyKey::Sr25519(kp.public.to_bytes()),
                    miner,
                    start_block,
                    end_block,
                };

                let signature = kp.sign_simple(SIMPLE_PROPOSAL_CONTEXT, &deal_proposal.encode());

                let resp = ProposableDeal {
                    deal_proposal,
                    signature,
                };

                Ok(resp)
            }
        }
    }
}

#[derive(Debug)]
struct PublishableDeal {
    deal_proposal: DealProposal,
    serialized_deal: Vec<u8>,
    deal_signature: schnorrkel::sign::Signature,
}

impl fmt::Display for PublishableDeal {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "deal proposal:   {:?}", self.deal_proposal)?;
        writeln!(
            fmt,
            "deal:            {:?}",
            HexString(self.serialized_deal.as_slice())
        )?;
        writeln!(
            fmt,
            "signature:       {:?}",
            HexString(&self.deal_signature.to_bytes()[..])
        )
    }
}

impl MinerVerifyPublish {
    fn run(self) -> Result<PublishableDeal, ProposalVerifyError> {
        match self {
            MinerVerifyPublish {
                client: AnyKey::Sr25519(client_pk_arr),
                miner_key: AnyKey::Sr25519(miner_sk_arr),
                comm_p,
                padded_piece_size,
                start_block,
                end_block,
                signature: AnyHex(orig_signature),
            } => {
                let signature = schnorrkel::sign::Signature::from_bytes(&orig_signature[..])
                    .expect("Signature conversion failed");

                let client_pk = schnorrkel::keys::PublicKey::from_bytes(&client_pk_arr[..])
                    .expect("PublicKey conversion failed for client_key");

                let miner_kp = schnorrkel::keys::MiniSecretKey::from_bytes(&miner_sk_arr[..])
                    .expect("SecretKey conversion failed for miner_key")
                    .expand(schnorrkel::keys::ExpansionMode::Ed25519)
                    .to_keypair();

                let deal_proposal = DealProposal {
                    comm_p,
                    padded_piece_size,
                    client: AnyKey::Sr25519(client_pk_arr),
                    miner: AnyKey::Sr25519(miner_kp.public.to_bytes()),
                    start_block,
                    end_block,
                };

                client_pk
                    .verify_simple(SIMPLE_PROPOSAL_CONTEXT, &deal_proposal.encode(), &signature)
                    .map_err(|_| ProposalVerifyError::InvalidSignature)?;

                // now we indicate intent to accept deal to the client

                // and publish the deal

                let deal = {
                    // just concatenate these together
                    let mut deal = Vec::<u8>::with_capacity(
                        deal_proposal.encode().len() + orig_signature.len(),
                    );
                    deal.extend(deal_proposal.encode());
                    deal.extend(&orig_signature[..]);
                    deal
                };

                let deal_sig = miner_kp.sign_simple(SIMPLE_DEAL_CONTEXT, &deal);

                let resp = PublishableDeal {
                    deal_proposal,
                    serialized_deal: deal,
                    deal_signature: deal_sig,
                };

                Ok(resp)
            }
        }
    }
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

#[derive(Encode, Decode)]
enum AnyKey {
    Sr25519([u8; 32]),
}

impl FromStr for AnyKey {
    type Err = InvalidTaggedHex;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::FromHex;
        let pos = s
            .bytes()
            .position(|ch| ch == b':')
            .ok_or(InvalidTaggedHex::MissingSeparator)?;

        let (prefix, hex) = (&s[..pos], &s[(pos + 1)..]);

        let key = match prefix {
            "sr25519" => AnyKey::Sr25519(<[u8; 32]>::from_hex(hex)?),
            x => return Err(InvalidTaggedHex::InvalidPrefix(x.to_owned())),
        };

        Ok(key)
    }
}

impl AsRef<[u8]> for AnyKey {
    fn as_ref(&self) -> &[u8] {
        // this method is ... not great if the input was a minisecretkey, but then again, we are
        // reading all of them on the command line at the moment.
        match self {
            AnyKey::Sr25519(x) => x,
        }
    }
}

impl fmt::Debug for AnyKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnyKey::Sr25519(_) => write!(fmt, "Sr25519"),
        }
    }
}

#[derive(Debug)]
enum InvalidTaggedHex {
    MissingSeparator,
    InvalidPrefix(String),
    InvalidHex(hex::FromHexError),
}

impl From<hex::FromHexError> for InvalidTaggedHex {
    fn from(e: hex::FromHexError) -> Self {
        InvalidTaggedHex::InvalidHex(e)
    }
}

impl fmt::Display for InvalidTaggedHex {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InvalidTaggedHex::*;
        match self {
            MissingSeparator => write!(fmt, "value is missing the type:hex separator ':'"),
            InvalidPrefix(p) => write!(fmt, "unsupported type: {:?}", p),
            InvalidHex(e) => write!(fmt, "invalid hex: {}", e),
        }
    }
}

#[derive(Debug)]
enum AnySignature {
    Sr25519([u8; 64]),
}

impl FromStr for AnySignature {
    type Err = InvalidTaggedHex;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::FromHex;
        let pos = s
            .bytes()
            .position(|ch| ch == b':')
            .ok_or(InvalidTaggedHex::MissingSeparator)?;

        let (prefix, hex) = (&s[..pos], &s[(pos + 1)..]);

        let key = match prefix {
            "sr25519" => AnySignature::Sr25519(<[u8; 64]>::from_hex(hex)?),
            x => return Err(InvalidTaggedHex::InvalidPrefix(x.to_owned())),
        };

        Ok(key)
    }
}

#[derive(Encode, Decode)]
struct AnyHex(Vec<u8>);

impl AsRef<[u8]> for AnyHex {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl FromStr for AnyHex {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::FromHex;
        Ok(AnyHex(Vec::from_hex(s)?))
    }
}

impl fmt::Debug for AnyHex {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "AnyHex({:?})", HexString(&self.0))
    }
}

/// Separating this from AnyHex in order to handle the key material the same way.
struct HexString<'a>(&'a [u8]);

impl fmt::Debug for HexString<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(fmt, "{:02x}", b)?
        }
        Ok(())
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
    use super::{
        AnyHex, AnyKey, ClientProposeDeal, DealProposal, MinerVerifyPublish, ProposableDeal,
    };
    use std::str::FromStr;

    #[test]
    fn example_client_propose_deal() {
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
    fn proposable_deal_formatting() {
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
            signature: schnorrkel::sign::Signature::from_bytes(sig.as_ref()).unwrap(),
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
            matches!(err, super::ProposalVerifyError::InvalidSignature),
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
            signature: AnyHex(proposable.signature.to_bytes().to_vec()),
        };

        cmd.run().unwrap();
    }
}
