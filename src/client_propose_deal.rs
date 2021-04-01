///! Command for the deal initiation proposal made by the client, off-chain.
use super::{
    AnyHex, AnyPrivateKey, AnyPublicKey, DealProposal, ProposableDeal, SIMPLE_PROPOSAL_CONTEXT,
};
use bls_signatures::Serialize;
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
    /// Clients private key, "key_type:hex", e.g. "sr25519:{64 hex}".
    pub client_key: AnyPrivateKey,
    /// The padded payload CID; any hex content will do for this example.
    pub comm_p: AnyHex,
    /// Size of the payload with fr32 padding. Any u64 will do.
    // size of the payload and any padding to construct the binary merkle trie https://spec.filecoin.io/systems/filecoin_files/piece/pieces.png
    pub padded_piece_size: u64,
    /// Miners public key, "key_type:hex", e.g. "sr25519:{64 hex}".
    // miner's public key i.e. 32 bytes
    pub miner: AnyPublicKey,
    /// BlockNumber to start the deal.
    // this type needs to match frame_system::BlockNumber defined in runtime
    pub start_block: u64,
    /// BlockNumber to end the deal.
    // frame_support::pallet_prelude::BlockNumberFor
    pub end_block: u64,
}

#[derive(Debug)]
pub(crate) enum DealProposeError {
    InvalidKeyCombination,
}

impl fmt::Display for DealProposeError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("Invalid combination of key types")
    }
}

impl std::error::Error for DealProposeError {}

impl ClientProposeDeal {
    pub(crate) fn run(self) -> Result<ProposableDeal, DealProposeError> {
        match self {
            ClientProposeDeal {
                client_key: AnyPrivateKey::Sr25519(client_sk),
                comm_p,
                padded_piece_size,
                miner: AnyPublicKey::Sr25519(miner_pk),
                start_block,
                end_block,
            } => {
                let kp = schnorrkel::keys::MiniSecretKey::from_bytes(&client_sk[..])
                    .expect("SecretKey needs 32 bytes, cannot fail")
                    .expand(schnorrkel::keys::ExpansionMode::Ed25519)
                    .to_keypair();

                // TODO: start < end

                let deal_proposal = DealProposal {
                    comm_p: comm_p.as_ref().to_vec(),
                    padded_piece_size,
                    client: kp.public.to_bytes().to_vec(),
                    miner: miner_pk.to_vec(),
                    start_block,
                    end_block,
                };

                let signature = kp
                    .sign_simple(SIMPLE_PROPOSAL_CONTEXT, &deal_proposal.encode())
                    .to_bytes()
                    .to_vec();

                let resp = ProposableDeal {
                    deal_proposal,
                    signature,
                };

                Ok(resp)
            }
            ClientProposeDeal {
                client_key: AnyPrivateKey::Bls(client_sk),
                comm_p,
                padded_piece_size,
                miner: AnyPublicKey::Bls(miner_pk),
                start_block,
                end_block,
            } => {
                let sk = bls_signatures::PrivateKey::from_bytes(&client_sk)
                    .expect("SecretKey is valid, cannot fail");

                let pk = sk.public_key().as_bytes();

                // TODO: start < end

                let deal_proposal = DealProposal {
                    comm_p: comm_p.as_ref().to_vec(),
                    padded_piece_size,
                    client: pk,
                    miner: miner_pk.to_vec(),
                    start_block,
                    end_block,
                };

                let doc = deal_proposal.encode();

                let signed = {
                    // Per https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.2
                    // prefix the document with the public key in order to get unique messages for
                    // each key
                    let mut buffer = sk.public_key().as_bytes();
                    buffer.extend(doc);
                    buffer
                };

                let signature = sk.sign(&signed).as_bytes();

                let resp = ProposableDeal {
                    deal_proposal,
                    signature,
                };

                Ok(resp)
            }
            _ => Err(DealProposeError::InvalidKeyCombination),
        }
    }
}
