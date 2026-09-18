//! The pairing code a person carries, and the fingerprint they compare (docs/design/pairing.md).
//!
//! The hub cannot mint a device, because it never sees a signing key. What a hub in the middle CAN do is swap the
//! keys in a pairing slot and get itself paired, and the only thing standing in the way is a human comparing one
//! fingerprint on two screens. So both live here, beside the keys they describe, rather than in whichever UI happens
//! to show them.

use sha2::{Digest, Sha256};

const CODE_LABEL: &[u8] = b"wmlhub/pairing-code/v1\0";
const FINGERPRINT_LABEL: &[u8] = b"wmlhub/pairing/v1\0";

/// Characters of a pairing code. Crockford's base32 alphabet: no I, L, O or U, so nothing reads as something else
/// over a phone or off a terminal.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters in a pairing code, at 5 bits each: 40 bits, which is not worth grinding inside a slot's ten minutes
/// and against a hub that rate-limits, and is short enough that a person will type it rather than give up.
pub const CODE_CHARS: usize = 8;

/// A pairing code: what the person carries from the new device to the one that can issue a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCode(String);

impl PairingCode {
    /// A fresh code from the operating system's random source.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; CODE_CHARS];
        getrandom::fill(&mut bytes)?;
        let text = bytes.iter().map(|b| ALPHABET[usize::from(b % 32)] as char).collect();
        Ok(Self(text))
    }

    /// The code as a person reads it. Groups of four are the UI's business, not this type's.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Read a code back, however it was typed: lower case, and the confusable characters Crockford maps (I and L to
    /// 1, O to 0) are accepted, because a person reading one aloud is exactly when that happens.
    pub fn parse(typed: &str) -> Option<Self> {
        let text: String = typed
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| match c.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            })
            .collect();
        if text.len() != CODE_CHARS || !text.bytes().all(|b| ALPHABET.contains(&b)) {
            return None;
        }
        Some(Self(text))
    }

    /// What the hub is told. The hub never learns the code itself, so slots it leaks are of no use to anyone.
    pub fn hash(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(CODE_LABEL);
        hash.update(self.0.as_bytes());
        hash.finalize().into()
    }
}

/// What the person compares on both screens: the offered keys, and nothing else.
///
/// A hub that substitutes its own keys changes this, which is the whole of pairing's security. Rendering is the UI's
/// (words on a phone, hex on a terminal), so this hands back the digest and a hex form, and stays out of it.
pub fn fingerprint(identity_key: &[u8; 32], agreement_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FINGERPRINT_LABEL);
    hash.update(identity_key);
    hash.update(agreement_key);
    hash.finalize().into()
}

/// Characters of the hex fingerprint: 48 bits, which is what a person will actually compare character by character.
pub const FINGERPRINT_CHARS: usize = 12;

/// The fingerprint as a person reads it where words are wrong: a connector printing to a terminal, a log.
pub fn fingerprint_hex(identity_key: &[u8; 32], agreement_key: &[u8; 32]) -> String {
    crate::hex(&fingerprint(identity_key, agreement_key)[..FINGERPRINT_CHARS / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_eight_readable_characters_and_hashes_to_something_else() {
        let code = PairingCode::generate().unwrap();
        assert_eq!(code.as_str().len(), CODE_CHARS);
        assert!(code.as_str().bytes().all(|b| ALPHABET.contains(&b)), "{}", code.as_str());
        assert_ne!(code.hash().as_slice(), code.as_str().as_bytes(), "the hub is told the hash, never the code");
        assert_eq!(code.hash(), PairingCode::parse(code.as_str()).unwrap().hash(), "the same code, the same hash");
    }

    #[test]
    fn two_codes_differ() {
        let (one, two) = (PairingCode::generate().unwrap(), PairingCode::generate().unwrap());
        assert_ne!(one, two);
        assert_ne!(one.hash(), two.hash());
    }

    #[test]
    fn a_code_is_read_back_however_a_person_typed_it() {
        let code = PairingCode::parse("0123ABCD").unwrap();
        for typed in
            ["0123abcd", "0123 ABCD", "0123-abcd", " 0123abcd ", "o123abcd", "0i23abcd".replace('i', "I").as_str()]
        {
            assert_eq!(PairingCode::parse(typed), Some(code.clone()), "{typed}");
        }
        // O reads as 0 and I as 1, which is the whole point of the alphabet
        assert_eq!(PairingCode::parse("O123ABCD"), Some(code.clone()));
        assert_eq!(PairingCode::parse("0L23ABCD".replace('L', "l").as_str()), PairingCode::parse("0123ABCD"));
    }

    #[test]
    fn what_is_not_a_code_is_refused() {
        for typed in ["", "0123ABC", "0123ABCDE", "0123ABCU", "!@£$%^&*"] {
            assert_eq!(PairingCode::parse(typed), None, "{typed:?}");
        }
    }

    #[test]
    fn a_fingerprint_covers_both_keys_and_nothing_else() {
        let (identity, agreement) = ([1u8; 32], [2u8; 32]);
        let base = fingerprint(&identity, &agreement);
        assert_ne!(base, fingerprint(&[3; 32], &agreement), "another identity key");
        assert_ne!(base, fingerprint(&identity, &[4; 32]), "another agreement key");
        assert_ne!(base, fingerprint(&agreement, &identity), "the same keys the other way round");
        assert_eq!(fingerprint_hex(&identity, &agreement).len(), FINGERPRINT_CHARS);
        assert!(fingerprint_hex(&identity, &agreement).starts_with(&crate::hex(&base[..1])));
    }
}
