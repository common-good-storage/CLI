///! Command for the miner response to a client initiated deal proposal. After this command has
///! executed successfully, the deal would be ready to be published on-chain by the miner.
use super::{
    AnyHex, AnyPrivateKey, AnyPublicKey, DealProposal, PublishableDeal, SIMPLE_DEAL_CONTEXT,
    SIMPLE_PROPOSAL_CONTEXT,
};
use codec::Encode;
use std::fmt;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub(crate) struct MinerVerifyPublish {
    /// Clients public key, "key_type:hex", e.g. "sr25519:{64 hex}".
    pub client: AnyPublicKey,
    /// Miners private key, "key_type:hex", e.g. "sr25519:{64 hex}".
    pub miner_key: AnyPrivateKey,
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
                client: AnyPublicKey::Sr25519(client_pk_arr),
                miner_key: AnyPrivateKey::Sr25519(miner_sk_arr),
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

                // TODO: same verification for the deal which was done already by client

                let deal_proposal = DealProposal {
                    comm_p: comm_p.as_ref().to_vec(),
                    padded_piece_size,
                    client: client_pk_arr.to_vec(),
                    miner: miner_kp.public.to_bytes().to_vec(),
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
                    // FIXME: this encodes the proposal twice
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
                    deal_signature: deal_sig.to_bytes().to_vec(),
                };

                Ok(resp)
            }
            MinerVerifyPublish {
                client: AnyPublicKey::Bls(client_pk_arr),
                miner_key: AnyPrivateKey::Bls(miner_sk_arr),
                comm_p,
                padded_piece_size,
                start_block,
                end_block,
                signature: AnyHex(client_signature),
            } => {
                use bls_signatures::Serialize;

                let client_pk = bls_signatures::PublicKey::from_bytes(&client_pk_arr)
                    .expect("key conversion shouldn't fail");
                let miner_sk = bls_signatures::PrivateKey::from_bytes(&miner_sk_arr)
                    .expect("key conversion shouldn't fail");
                let client_signature = bls_signatures::Signature::from_bytes(&client_signature)
                    .map_err(|_| ProposalVerifyError::InvalidSignature)?;

                let miner_pk = miner_sk.public_key();

                let deal_proposal = DealProposal {
                    comm_p: comm_p.as_ref().to_vec(),
                    padded_piece_size,
                    client: client_pk_arr.to_vec(),
                    miner: miner_pk.as_bytes().to_vec(),
                    start_block,
                    end_block,
                };

                let deal_encoded = deal_proposal.encode();

                let client_message = {
                    // https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.2
                    let mut buffer = client_pk.as_bytes();
                    buffer.extend(&deal_encoded);
                    buffer
                };

                if !client_pk.verify(client_signature, &client_message) {
                    return Err(ProposalVerifyError::InvalidSignature);
                }

                let miner_message = {
                    let mut buffer = miner_sk.public_key().as_bytes();
                    buffer.extend(&deal_encoded);
                    buffer
                };

                let miner_signature = miner_sk.sign(&miner_message);

                assert!(miner_pk.verify(miner_signature, &miner_message));

                // aggregated signatures cannot contain signatures of the same document, which is
                // why the signed document/message is prefixed with signers public key. See more in https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.2
                let multisig = bls_signatures::aggregate(&[client_signature, miner_signature])
                    .expect("multisig construction failed");

                assert_eq!(false, client_pk.verify(multisig, &client_message));
                assert_eq!(false, miner_pk.verify(multisig, &miner_message));

                assert!(bls_signatures::verify(
                    &multisig,
                    &[
                        bls_signatures::hash(&client_message),
                        bls_signatures::hash(&miner_message)
                    ],
                    &[client_pk, miner_pk],
                ));

                Ok(PublishableDeal {
                    deal_proposal,
                    serialized_deal: deal_encoded,
                    deal_signature: multisig.as_bytes(),
                })
            }
            _ => return Err(ProposalVerifyError::InvalidKeyCombination),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ProposalVerifyError {
    InvalidSignature,
    InvalidKeyCombination,
}

impl fmt::Display for ProposalVerifyError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ProposalVerifyError::*;
        match self {
            // not sure if the nested reason matters?
            InvalidSignature => write!(fmt, "Invalid client signature"),
            InvalidKeyCombination => write!(fmt, "Invalid or unsupported key combination"),
        }
    }
}

impl std::error::Error for ProposalVerifyError {}
