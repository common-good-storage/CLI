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
    // this is signed by the client
    ClientProposeDeal {
        client_key: AnyKey,
        // lets just pretend this is the commP cid
        comm_p: AnyHex,
        /*
        commP: (), // root cid for the file
        padded_piece_size: u64,
        verified_deal: bool,
        client: (), // address
        miner: (),  // address
        price_per_epoch: u64,
        clent_collateral: u64,
        miner_collateral: u64,
        */
    },
    MinerVerifyPublish {
        client_key: AnyKey,
        miner_key: AnyKey,
        comm_p: AnyHex,
        signature: AnyHex,
    },
}

static SIMPLE_PROPOSAL_CONTEXT: &[u8] = b"example starts: proposal";
static SIMPLE_DEAL_CONTEXT: &[u8] = b"example continues: deal";

fn main() {
    run(Opts::from_args())
}

fn run(opts: Opts) {
    match opts.command {
        Command::ClientProposeDeal {
            client_key: AnyKey::Sr25519(client_sk),
            comm_p,
        } => {
            // lets just sign the fake cid
            let kp = schnorrkel::keys::MiniSecretKey::from_bytes(&client_sk[..])
                .expect("SecretKey conversion failed")
                .expand(schnorrkel::keys::ExpansionMode::Ed25519)
                .to_keypair();

            let signature = kp
                .sign_simple(SIMPLE_PROPOSAL_CONTEXT, comm_p.as_ref())
                .to_bytes();

            println!("public key: {:?}", HexString(&kp.public.to_bytes()));
            println!("deal:       {:?}", HexString(comm_p.as_ref()));
            println!("signed:     {:?}", HexString(&signature));
        }
        Command::MinerVerifyPublish {
            client_key: AnyKey::Sr25519(client_pk),
            miner_key: AnyKey::Sr25519(miner_sk),
            comm_p,
            signature: AnyHex(orig_signature),
        } => {
            let signature = schnorrkel::sign::Signature::from_bytes(&orig_signature[..])
                .expect("Signature conversion failed");

            let client_pk = schnorrkel::keys::PublicKey::from_bytes(&client_pk[..])
                .expect("PublicKey conversion failed for client_key");

            let miner_sk = schnorrkel::keys::MiniSecretKey::from_bytes(&miner_sk[..])
                .expect("SecretKey conversion failed for miner_key")
                .expand(schnorrkel::keys::ExpansionMode::Ed25519);

            client_pk
                .verify_simple(SIMPLE_PROPOSAL_CONTEXT, comm_p.as_ref(), &signature)
                .expect("Invalid signature");

            // now we indicate intent to accept deal to the client

            // and publish the deal

            let deal = {
                // just concatenate these together
                let mut deal =
                    Vec::<u8>::with_capacity(comm_p.as_ref().len() + orig_signature.len());
                deal.extend(comm_p.as_ref());
                deal.extend(&orig_signature[..]);
                deal
            };

            let deal_sig = miner_sk
                .to_keypair()
                .sign_simple(SIMPLE_DEAL_CONTEXT, &deal)
                .to_bytes();

            println!("deal:   {:?}", HexString(deal.as_slice()));
            println!("signed: {:?}", HexString(&deal_sig[..]));
        }
    }
}

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
