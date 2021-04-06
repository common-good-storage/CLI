///! Separated module for bls as the signed message prepending requires additional work.
use bls_signatures::{hash, PrivateKey, PublicKey, Serialize, Signature};

pub(crate) fn sign(sk: &PrivateKey, deal_proposal: &[u8]) -> Signature {
    let mut signed = Vec::new();
    prepend_public_key(&sk.public_key(), deal_proposal, &mut signed);
    sk.sign(signed)
}

pub(crate) fn verify(pk: &PublicKey, sig: Signature, deal_proposal: &[u8]) -> bool {
    let mut signed = Vec::new();
    prepend_public_key(&pk, deal_proposal, &mut signed);
    pk.verify(sig, &signed)
}

pub(crate) fn verify_aggregate(sig: &Signature, message: &[u8], keys: &[PublicKey]) -> bool {
    let mut v = Vec::new();

    let hashes = keys
        .iter()
        .map(|pk| {
            prepend_public_key(pk, message, &mut v);
            hash(&v)
        })
        .collect::<Vec<_>>();

    bls_signatures::verify(&sig, &hashes, &keys)
}

fn prepend_public_key(pk: &PublicKey, message: &[u8], v: &mut Vec<u8>) {
    v.clear();
    if let Some(needed) = (48 + message.len()).checked_sub(v.capacity()) {
        v.reserve(needed);
    }

    // Per https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.2
    // prefix the document with the public key in order to get unique messages for
    // each key
    v.extend(pk.as_bytes());
    v.extend(message);
}
