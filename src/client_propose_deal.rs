///! Command for the deal initiation proposal made by the client, off-chain.
use super::{AnyHex, AnyKey, DealProposal, HexString, SIMPLE_PROPOSAL_CONTEXT};
use codec::Encode;
use std::fmt;
use structopt::StructOpt;

// TODO: some fields are omitted in this phase
// VerifiedDeal: bool,    indicate that the deal counts towards verified client total
// StoragePricePerEpoch abi.TokenAmount
// ProviderCollateral abi.TokenAmount
// ClientCollateral   abi.TokenAmount
#[derive(Debug, StructOpt)]
pub(crate) struct ClientProposeDeal {
    // client's private key
    pub client_key: AnyKey,
    // lets just pretend this is the commP cid
    pub comm_p: AnyHex,
    // size of the payload and any padding to construct the binary merkle trie https://spec.filecoin.io/systems/filecoin_files/piece/pieces.png
    pub padded_piece_size: u64,
    // miner's public key i.e. 32 bytes
    pub miner: AnyKey,
    // this type needs to match frame_system::BlockNumber defined in runtime
    pub start_block: u64,
    // frame_support::pallet_prelude::BlockNumberFor
    pub end_block: u64,
}

#[derive(Debug)]
pub(crate) enum DealProposeError {
    // none at this time before we add key types
}

impl fmt::Display for DealProposeError {
    fn fmt(&self, _fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        unreachable!()
    }
}

impl std::error::Error for DealProposeError {}

#[derive(Debug)]
pub(crate) struct ProposableDeal {
    pub deal_proposal: DealProposal,
    // this should become vec<u8> or similar when we extend
    pub signature: schnorrkel::sign::Signature,
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
    pub(crate) fn run(self) -> Result<ProposableDeal, DealProposeError> {
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
