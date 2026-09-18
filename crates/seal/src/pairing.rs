//! Sealing what a device is given when it is paired (docs/design/pairing.md).
//!
//! The certificate in it is public, but the account's channel key is not: channel names are an HMAC under it, so a
//! hub that could read a pairing slot would otherwise learn the name of every stream the account uses. So the whole
//! answer is sealed to the agreement key the offer carried, which means only the device that made the offer can read
//! it — and if a hub substituted that key, the person's fingerprint comparison is what catches it.
//!
//! This is HPKE with its own label, not the command path: neither side has a certificate for the other yet, which is
//! the entire situation pairing exists to fix.

use hpke::Deserializable;
use hpke::kem::X25519HkdfSha256;
use wmlhub_keys::MAX_CHAIN;
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{PairedWith, Sealed};

use crate::{AgreementKey, OpenError, SealError, hpke_open_raw, hpke_seal_raw};

const PAIRING_INFO_LABEL: &[u8] = b"wmlhub/pairing-answer/v1\0";

/// Seal what a newly paired device needs, to the agreement key its offer carried.
pub fn seal_pairing_answer(offered_agreement_key: &[u8; 32], paired: &PairedWith) -> Result<Vec<u8>, SealError> {
    hpke_seal_raw(PAIRING_INFO_LABEL, offered_agreement_key, &paired.encode_to_vec()).map_err(SealError::Hpke)
}

/// Open it, with the agreement key the offer was made with. The chain is checked for shape only: whether it verifies
/// is the caller's business, since only the caller knows which principal it expects to be named.
pub fn open_pairing_answer(agreement: &AgreementKey, sealed: &[u8]) -> Result<PairedWith, OpenError> {
    let plaintext = hpke_open_raw(PAIRING_INFO_LABEL, agreement, sealed)?;
    let paired = PairedWith::decode(plaintext.as_slice()).map_err(|_| OpenError::Malformed)?;
    if paired.account_root.len() != 32 || paired.channel_key.len() != 32 {
        return Err(OpenError::Malformed);
    }
    if paired.chain.is_empty() || paired.chain.len() > MAX_CHAIN {
        return Err(OpenError::Malformed);
    }
    Ok(paired)
}

/// The encapsulated key of a sealed answer, so a caller can refuse a malformed one before decrypting.
pub(crate) fn enc_of(sealed: &Sealed) -> Result<<X25519HkdfSha256 as hpke::Kem>::EncappedKey, OpenError> {
    <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&sealed.enc).map_err(|_| OpenError::Malformed)
}
