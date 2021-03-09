///! Command for the miner response to a client initiated deal proposal. After this command has
///! executed successfully, the deal would be ready to be published on-chain by the miner.
use super::{
    AnyHex, AnyKey, DealProposal, HexString, SIMPLE_DEAL_CONTEXT, SIMPLE_PROPOSAL_CONTEXT,
};
use codec::Encode;
use std::fmt;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub(crate) struct MinerVerifyPublish {
    /// Clients public key, "key_type:hex", e.g. "sr25519:{64 hex}".
    pub client: AnyKey,
    /// Miners private key, "key_type:hex", e.g. "sr25519:{64 hex}".
    pub miner_key: AnyKey,
    /// The padded payload CID; any hex content will do for this example.
    pub comm_p: AnyHex,
    /// Miners public key, "key_type:hex", e.g. "sr25519:{64 hex}".
    pub padded_piece_size: u64,
    /// BlockNumber to start the deal.
    pub start_block: u64,
    /// BlockNumber to end the deal.
    pub end_block: u64,
    /// Clients signature for the deal proposal.
    pub signature: AnyHex,
}

impl MinerVerifyPublish {
    pub(crate) fn run(self) -> Result<PublishableDeal, ProposalVerifyError> {
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

#[derive(Debug)]
pub(crate) enum ProposalVerifyError {
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

#[derive(Debug)]
pub(crate) struct PublishableDeal {
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
