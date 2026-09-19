//! Revocation lists: what an account has revoked, and the one principal allowed to say so
//! (docs/design/revocation.md).
//!
//! The runtime's allowlist is the authoritative revocation and it needs none of this: a revoked device stops being
//! answered the moment a person clicks. A list exists for the PUBLISHERS the runtime cannot reach any other way, such
//! as a box connector, which grants its stream key to anything with a valid certificate and would otherwise go on
//! granting to a revoked device until that device's certificate expired. A publisher verifies a list itself, rotates
//! its key, and refuses to grant the new one to anything the list names.
//!
//! Signing is `may_revoke`'s: granted only by the root and renewed only by the root, so exactly one principal can sign
//! a list that verifies. Two signers would race on `version` and the loser's revocation would be refused as stale,
//! which is the worst way a revocation can fail.

use std::collections::HashSet;

use sha2::{Digest, Sha256};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Certificate, CertificateBody, RevocationBody, RevocationList};

use crate::{ChainError, Identity, PublicKey, account_id, principal_id, verify, verify_chain};

const REVOCATION_LABEL: &[u8] = b"wmlhub/revocation/v1\0";

/// The most entries one list may carry, principals and certificates together. A list that needs more is a device
/// inventory rather than a revocation, and a publisher holds the whole of it in memory for as long as it runs.
pub const MAX_REVOKED: usize = 256;
/// The largest encoded list body accepted, checked before anything in it is decoded. Every entry is 32 bytes and two
/// of framing, so a full list is a little under 9 KiB; this leaves room and no more.
pub const MAX_REVOCATION_BYTES: usize = 16 << 10;
/// How far ahead of a holder's own clock a list's `version` may be. The same minute `seal` allows a command's time:
/// a signer with a fast clock costs at most that, rather than locking the account out of revoking until its clock is
/// reached.
pub const MAX_FUTURE_MS: u64 = 60_000;

/// Why a list was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationError {
    /// the body is over its size, does not decode, holds more than [`MAX_REVOKED`] entries, or an entry is not 32 bytes
    Malformed,
    /// signed for a different account
    WrongAccount,
    /// the signer's chain did not verify
    Chain(ChainError),
    /// the signer's leaf does not carry `may_revoke`
    NotRevoker,
    /// the signer is named by the list the holder already has: a revoked revoker signs nothing
    SignerRevoked,
    /// the signature does not verify under the signer's leaf key
    Signature,
    /// more than [`MAX_FUTURE_MS`] ahead of the holder's clock
    FromTheFuture,
    /// at or below the version the holder already has
    Stale,
}

/// A list that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    pub version: u64,
    /// the principal id of whoever signed it
    pub signer: [u8; 32],
    principals: HashSet<[u8; 32]>,
    certificates: HashSet<[u8; 32]>,
}

impl Revoked {
    /// Does this list revoke anything in `chain`?
    ///
    /// A chain is revoked if ANY certificate in it is: a revoked delegate vouches for nothing, so the devices it paired
    /// fall with it, and those are exactly the ones in doubt when the delegate is the thing that was lost. A renewal is
    /// revoked when the certificate it renews is, since it re-grants exactly those terms. A certificate that does not
    /// decode counts as revoked: a publisher asking this is deciding whether to hand over a key, and "I could not tell"
    /// is not a yes.
    pub fn revokes(&self, chain: &[Certificate]) -> bool {
        chain.iter().any(|cert| {
            let Ok(body) = CertificateBody::decode(cert.body.as_slice()) else { return true };
            let principal = match <[u8; 32]>::try_from(body.subject.as_slice()) {
                Ok(subject) => principal_id(&subject),
                Err(_) => return true,
            };
            self.principals.contains(&principal)
                || self.certificates.contains(&certificate_hash(cert))
                || body.renews.as_ref().is_some_and(|previous| self.certificates.contains(&certificate_hash(previous)))
        })
    }

    /// Does this list revoke anything `older` did not? A publisher rotates its key only then: re-signing the same
    /// entries is how a revoker keeps a list fresh, and rotating on every re-sign would make every device ask for
    /// the key again every day for nothing. A list that REMOVES entries adds nobody to exclude, so it is not a
    /// reason to rotate either.
    pub fn adds_to(&self, older: Option<&Revoked>) -> bool {
        match older {
            None => !self.is_empty(),
            Some(older) => {
                !self.principals.is_subset(&older.principals) || !self.certificates.is_subset(&older.certificates)
            }
        }
    }

    /// How many entries it holds.
    pub fn len(&self) -> usize {
        self.principals.len() + self.certificates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a certificate is revoked BY: SHA-256 of its body exactly as transmitted, which is also exactly what was
/// signed, so it names one certificate and cannot be made to name another.
pub fn certificate_hash(cert: &Certificate) -> [u8; 32] {
    Sha256::digest(&cert.body).into()
}

/// Sign a list as `signer`, whose chain to the root is `chain` (leaf first) and must carry `may_revoke`.
pub fn sign_revocations(
    signer: &Identity,
    chain: &[Certificate],
    account: [u8; 32],
    version: u64,
    principals: &[[u8; 32]],
    certificates: &[[u8; 32]],
) -> RevocationList {
    let body = RevocationBody {
        account: account.to_vec(),
        version,
        principals: principals.iter().map(|p| p.to_vec()).collect(),
        certificates: certificates.iter().map(|c| c.to_vec()).collect(),
    }
    .encode_to_vec();
    let signature = signer.sign(REVOCATION_LABEL, &body);
    RevocationList { body, signature, chain: chain.to_vec() }
}

/// Verify a list for the account whose root is `root`, at `now_ms`, against the list the holder already has.
///
/// Cheap checks first and the signer's chain and signature last, so a list that is refused for its shape, its
/// account or its version costs nothing to refuse. `held` is not optional in spirit: pass the list you already apply,
/// because a list signed by a principal that list revokes must be refused, and a version at or below it is stale.
pub fn verify_revocations(
    root: &PublicKey,
    list: &RevocationList,
    now_ms: u64,
    held: Option<&Revoked>,
) -> Result<Revoked, RevocationError> {
    if list.body.len() > MAX_REVOCATION_BYTES {
        return Err(RevocationError::Malformed);
    }
    let body = RevocationBody::decode(list.body.as_slice()).map_err(|_| RevocationError::Malformed)?;
    if body.principals.len() + body.certificates.len() > MAX_REVOKED {
        return Err(RevocationError::Malformed);
    }
    let entry = |bytes: &Vec<u8>| <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| RevocationError::Malformed);
    let principals = body.principals.iter().map(entry).collect::<Result<HashSet<_>, _>>()?;
    let certificates = body.certificates.iter().map(entry).collect::<Result<HashSet<_>, _>>()?;
    if body.account.as_slice() != account_id(root) {
        return Err(RevocationError::WrongAccount);
    }
    if body.version > now_ms.saturating_add(MAX_FUTURE_MS) {
        return Err(RevocationError::FromTheFuture);
    }
    if held.is_some_and(|h| body.version <= h.version) {
        return Err(RevocationError::Stale);
    }

    let verified = verify_chain(root, &list.chain, now_ms).map_err(RevocationError::Chain)?;
    if !verified.leaf.may_revoke {
        return Err(RevocationError::NotRevoker);
    }
    // The case this exists for: `may_revoke` moved to a new runtime after the old one was lost, the new holder's first
    // list names the old one, and from then on the old one's signature must count for nothing even though its
    // certificate still verifies.
    if held.is_some_and(|h| h.revokes(&list.chain)) {
        return Err(RevocationError::SignerRevoked);
    }
    verify(&verified.leaf_key, REVOCATION_LABEL, &list.body, &list.signature)
        .map_err(|_| RevocationError::Signature)?;
    Ok(Revoked { version: body.version, signer: verified.principal, principals, certificates })
}

#[cfg(test)]
mod tests;
