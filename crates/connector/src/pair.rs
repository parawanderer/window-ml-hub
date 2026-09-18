//! Pairing a connector: the half that runs on the box (docs/design/pairing.md, option C).
//!
//! The box has keys and nothing else. It chooses a code, shows the code and the fingerprint of its own keys, and
//! leaves an offer with the hub under the hash of that code. A person carries the code to a device that may pair,
//! compares the fingerprint on both screens, and leaves a sealed answer in the same slot.
//!
//! The comparison is the whole of the security. A hub cannot mint a certificate, but it can substitute the keys in
//! the offer it is holding, and then it is the hub that gets paired. So this prints the fingerprint of what it
//! actually offered, and refuses an answer that does not name its own keys — the second check is not what protects
//! the account (a hub that substituted the keys would simply keep the certificate) but it turns a subtle failure
//! into a loud one.

use std::fmt;
use std::time::Duration;

use wmlhub_client::{ClientError, Pairing};
use wmlhub_keys::pairing::{PairingCode, fingerprint_hex};
use wmlhub_keys::{ChainError, MAX_LABEL_BYTES, principal_id, verify_chain};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{PairedWith, PairingAnswer, PairingOffer, Role};
use wmlhub_seal::{OpenError, open_pairing_answer};

use crate::state::Keys;

/// How long a connector waits to be paired. The hub holds a slot for ten minutes (`wmlhub::pairing::SLOT_LIFETIME`),
/// so waiting longer would be waiting for a slot that no longer exists.
pub const PAIRING_WINDOW: Duration = Duration::from_secs(10 * 60);

/// The role a box connector asks to be, and the only role it accepts a certificate for. A connector that logged in
/// as something else would be asking for powers its own design says it must not hold.
pub const ROLE: Role = Role::BoxConnector;

#[derive(Debug)]
pub enum PairError {
    Random(getrandom::Error),
    /// the label is longer than a certificate may carry
    Label(usize),
    /// the hub refused the offer, or the socket failed
    Hub(ClientError),
    /// nobody answered inside the window the hub holds a slot for
    TimedOut,
    /// what was left in the slot is not a `PairingAnswer`
    Malformed,
    /// it did not open with the key the offer carried: the answer was sealed for somebody else
    Sealed(OpenError),
    /// the chain does not verify to the account root that came with it
    Chain(ChainError),
    /// the certificate names another principal, so this connector was not what got paired
    NotMine,
    /// the certificate names another agreement key, so nothing sealed to this connector would ever open
    NotMyAgreementKey,
    /// the certificate was issued for another role
    WrongRole(Role),
}

/// An offer this connector has made, or is about to: the code and fingerprint to show, and the wait for an answer.
pub struct Offer<'a> {
    keys: &'a Keys,
    code: PairingCode,
    offer: Vec<u8>,
}

impl<'a> Offer<'a> {
    /// Choose a code and build the offer. Nothing has been sent yet, so a caller shows the code and the fingerprint
    /// before it waits.
    pub fn new(keys: &'a Keys, label: &str, now_ms: u64) -> Result<Self, PairError> {
        if label.len() > MAX_LABEL_BYTES {
            return Err(PairError::Label(label.len()));
        }
        let code = PairingCode::generate().map_err(PairError::Random)?;
        let offer = PairingOffer {
            identity_key: keys.identity.public().to_vec(),
            agreement_key: keys.agreement.public().to_vec(),
            role: ROLE as i32,
            label: label.to_owned(),
            offered_at_ms: now_ms,
        }
        .encode_to_vec();
        Ok(Self { keys, code, offer })
    }

    /// The code the person carries to a device that may pair.
    pub fn code(&self) -> &str {
        self.code.as_str()
    }

    /// The fingerprint of the keys in this offer, which is what the person compares on both screens.
    pub fn fingerprint(&self) -> String {
        fingerprint_hex(&self.keys.identity.public(), &self.keys.agreement.public())
    }

    /// Leave the offer with the hub. Separate from the wait so that a hub that cannot be reached is an error before
    /// anybody is told to carry a code to another room.
    pub async fn leave(&self, url: &str) -> Result<Left<'_>, PairError> {
        let pairing = Pairing::offer(url, &self.code.hash(), self.offer.clone()).await.map_err(PairError::Hub)?;
        Ok(Left { offer: self, pairing })
    }
}

/// An offer the hub is now holding, waiting for somebody to answer it.
pub struct Left<'a> {
    offer: &'a Offer<'a>,
    pairing: Pairing,
}

impl Left<'_> {
    /// Wait for an answer, then check that what came back is for this connector and verifies to the account root
    /// inside it.
    pub async fn answer(&mut self, window: Duration, now_ms: impl Fn() -> u64) -> Result<PairedWith, PairError> {
        let answer = match tokio::time::timeout(window, self.pairing.answer()).await {
            Ok(answer) => answer.map_err(PairError::Hub)?,
            Err(_) => return Err(PairError::TimedOut),
        };
        let answer = PairingAnswer::decode(answer.as_slice()).map_err(|_| PairError::Malformed)?;
        let paired = open_pairing_answer(&self.offer.keys.agreement, &answer.sealed).map_err(PairError::Sealed)?;
        self.check(&paired, now_ms())?;
        Ok(paired)
    }

    /// What a connector refuses to store: anything it could not then log in with, so the failure is here rather than
    /// at a hub that can only say the hello did not verify.
    fn check(&self, paired: &PairedWith, now_ms: u64) -> Result<(), PairError> {
        let keys = self.offer.keys;
        let root: [u8; 32] = paired.account_root.as_slice().try_into().map_err(|_| PairError::Malformed)?;
        let verified = verify_chain(&root, &paired.chain, now_ms).map_err(PairError::Chain)?;
        if verified.principal != principal_id(&keys.identity.public()) {
            return Err(PairError::NotMine);
        }
        if verified.leaf.agreement_key != keys.agreement.public() {
            return Err(PairError::NotMyAgreementKey);
        }
        if verified.leaf.role() != ROLE {
            return Err(PairError::WrongRole(verified.leaf.role()));
        }
        Ok(())
    }
}

impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(e) => write!(f, "no random source: {e}"),
            Self::Label(len) => write!(f, "the label is {len} bytes; a certificate carries at most {MAX_LABEL_BYTES}"),
            Self::Hub(ClientError::Transport(e)) => write!(f, "cannot reach the hub: {e}"),
            Self::Hub(ClientError::Refused(e)) => {
                write!(f, "the hub refused the offer: {:?} {}", e.code(), e.message)
            }
            Self::Hub(e) => write!(f, "the hub: {e:?}"),
            Self::TimedOut => write!(f, "nobody paired it within {} minutes", PAIRING_WINDOW.as_secs() / 60),
            Self::Malformed => write!(f, "what was left in the pairing slot is not an answer"),
            Self::Sealed(e) => write!(f, "the answer was not sealed to this connector's key: {e:?}"),
            Self::Chain(e) => write!(f, "the certificate does not verify to the account root it came with: {e:?}"),
            Self::NotMine => {
                write!(f, "the certificate names another principal: this connector was not what got paired")
            }
            Self::NotMyAgreementKey => {
                write!(f, "the certificate names another agreement key, so nothing sealed to it would open")
            }
            Self::WrongRole(role) => write!(f, "the certificate was issued for {role:?}, not {ROLE:?}"),
        }
    }
}
