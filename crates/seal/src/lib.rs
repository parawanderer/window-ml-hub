//! Sealed, signed commands and results between two principals (docs/design/end-to-end-crypto.md §Commands and
//! results; the wire format is `proto/wmlhub/v1/seal.proto`).
//!
//! A command is signed by the sender's leaf identity, carries the sender's certificate chain, and is sealed with HPKE
//! (RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM) to the recipient's agreement key, with
//! both principal ids in the HPKE info. The recipient opens it and checks, in this order, each step no more expensive
//! than it needs to be for what came before: sizes, decryption, the chain to the account root, that the chain's leaf
//! is the sender the hub stamped, the signature, that the body is from that sender and to this recipient, the clock
//! window, the scope, and finally that the nonce is new. Only an authenticated, in-window command can occupy the
//! replay window, and a full window refuses rather than forgets.
//!
//! The hub never runs any of this. What it could do to a sealed command (drop it, delay it, replay it, deliver it to
//! the wrong principal, claim another sender) each ends in one of the refusals in [`OpenError`].

use std::collections::{HashSet, VecDeque};

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use wmlhub_keys::{ChainError, Identity, PublicKey, principal_id, sign_command, verify_chain, verify_command};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Certificate, CertificateBody, CommandBody, Sealed, SignedCommand};

/// A principal id: SHA-256 of its Ed25519 identity key.
pub type PrincipalId = [u8; 32];

/// The largest encoded `Sealed` accepted: what fits in an envelope payload.
pub const MAX_SEALED_BYTES: usize = 1 << 20;
/// Bytes of a command nonce.
pub const NONCE_BYTES: usize = 16;
/// How far a command's clock may be from the recipient's, either way.
pub const CLOCK_WINDOW_MS: u64 = 60_000;
/// Nonces one recipient remembers at once. Past it, new commands are refused until old nonces age out: forgetting a
/// nonce still inside its window would let that command be replayed.
pub const MAX_REPLAY_ENTRIES: usize = 65_536;

const SEAL_INFO_LABEL: &[u8] = b"wmlhub/seal/v1\0";

/// An X25519 key agreement key pair: what a principal's certificate binds as `agreement_key`, and what commands to it
/// are sealed to.
pub struct AgreementKey {
    secret: <X25519HkdfSha256 as hpke::Kem>::PrivateKey,
    public: [u8; 32],
}

impl AgreementKey {
    /// A fresh key pair from the operating system's random source.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)?;
        Ok(Self::from_seed(&seed))
    }

    /// A key pair derived from 32 bytes of seed (RFC 9180 DeriveKeyPair). Deterministic: for tests and vectors.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (secret, public) = X25519HkdfSha256::derive_keypair(seed);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&public.to_bytes());
        Self { secret, public: bytes }
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

/// Who is sending: the leaf identity that signs, and the chain that proves it belongs to the account.
pub struct Sender<'a> {
    pub identity: &'a Identity,
    /// leaf first, as `verify_chain` takes it
    pub chain: &'a [Certificate],
}

/// Where a command goes: the recipient's principal id and the agreement key its certificate binds.
#[derive(Debug, Clone, Copy)]
pub struct Recipient {
    pub principal: PrincipalId,
    pub agreement_key: [u8; 32],
}

/// Sealing failed. Only the random source or an HPKE internal failure can cause it.
#[derive(Debug)]
pub enum SealError {
    Random(getrandom::Error),
    Hpke(hpke::HpkeError),
}

/// Seal a command needing `scope` to `to`. Returns the encoded `Sealed` and the nonce its result will answer.
pub fn seal_command(
    from: &Sender,
    to: &Recipient,
    scope: &str,
    body: &[u8],
    now_ms: u64,
) -> Result<(Vec<u8>, [u8; NONCE_BYTES]), SealError> {
    seal(from, to, scope, body, &[], now_ms)
}

/// Seal the result of the command whose nonce is `answers` back to its sender.
pub fn seal_result(
    from: &Sender,
    to: &Recipient,
    answers: &[u8; NONCE_BYTES],
    body: &[u8],
    now_ms: u64,
) -> Result<Vec<u8>, SealError> {
    seal(from, to, "", body, answers, now_ms).map(|(sealed, _)| sealed)
}

fn seal(
    from: &Sender,
    to: &Recipient,
    scope: &str,
    body: &[u8],
    answers: &[u8],
    now_ms: u64,
) -> Result<(Vec<u8>, [u8; NONCE_BYTES]), SealError> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(SealError::Random)?;
    let sender = principal_id(&from.identity.public());
    let command = CommandBody {
        from: sender.to_vec(),
        to: to.principal.to_vec(),
        scope: scope.to_owned(),
        nonce: nonce.to_vec(),
        time_ms: now_ms,
        body: body.to_vec(),
        answers: answers.to_vec(),
    }
    .encode_to_vec();
    let signed =
        SignedCommand { signature: sign_command(from.identity, &command), body: command, chain: from.chain.to_vec() }
            .encode_to_vec();
    let sealed = hpke_seal(&sender, to, &signed).map_err(SealError::Hpke)?;
    Ok((sealed, nonce))
}

fn hpke_seal(sender: &PrincipalId, to: &Recipient, plaintext: &[u8]) -> Result<Vec<u8>, hpke::HpkeError> {
    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&to.agreement_key)?;
    let (enc, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        &info(sender, &to.principal),
        plaintext,
        &[],
    )?;
    Ok(Sealed { enc: enc.to_bytes().to_vec(), ciphertext }.encode_to_vec())
}

fn info(from: &PrincipalId, to: &PrincipalId) -> Vec<u8> {
    let mut info = Vec::with_capacity(SEAL_INFO_LABEL.len() + 64);
    info.extend_from_slice(SEAL_INFO_LABEL);
    info.extend_from_slice(from);
    info.extend_from_slice(to);
    info
}

/// Why a sealed command was refused. Precise for logs and tests; what a runtime tells the sender is its own business.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// over [`MAX_SEALED_BYTES`]
    TooLarge,
    /// a layer did not decode, or a field has the wrong length or shape
    Malformed,
    /// not sealed to this recipient's key, not sealed between this sender and this recipient, or altered
    Decrypt,
    /// the sender's certificate chain does not verify to the account root
    Chain(ChainError),
    /// the chain's leaf, or the body's `from`, is not the sender the hub delivered it from
    NotSender,
    /// the signature does not verify under the chain's leaf key
    Signature,
    /// the body names another recipient
    NotForMe,
    /// the command's clock is more than [`CLOCK_WINDOW_MS`] from this recipient's
    Clock,
    /// a command whose sender's certificate does not grant its scope
    Scope,
    /// this nonce from this sender was already accepted
    Replay,
    /// the replay window is full of live nonces; try again once they age out
    Busy,
}

/// An opened, verified command or result.
#[derive(Debug, Clone)]
pub struct Opened {
    pub from: PrincipalId,
    /// empty on a result
    pub scope: String,
    pub nonce: [u8; NONCE_BYTES],
    pub time_ms: u64,
    pub body: Vec<u8>,
    /// the nonce of the command this answers; `None` on a command
    pub answers: Option<[u8; NONCE_BYTES]>,
    /// the sender's leaf certificate, for anything further the recipient decides by (its role, its label)
    pub leaf: CertificateBody,
}

/// A principal receiving commands: its keys, the account it belongs to, and the nonces it has accepted.
pub struct Receiver {
    principal: PrincipalId,
    agreement: AgreementKey,
    account_root: PublicKey,
    replay: ReplayWindow,
}

impl Receiver {
    pub fn new(identity_public: &PublicKey, agreement: AgreementKey, account_root: PublicKey) -> Self {
        Self { principal: principal_id(identity_public), agreement, account_root, replay: ReplayWindow::default() }
    }

    /// Open `sealed`, which the hub delivered from `sender` (`Envelope.sender`), at this recipient's wall clock
    /// `now_ms`. A command is accepted at most once.
    pub fn open(&mut self, sender: &[u8], sealed: &[u8], now_ms: u64) -> Result<Opened, OpenError> {
        if sealed.len() > MAX_SEALED_BYTES {
            return Err(OpenError::TooLarge);
        }
        let sender: PrincipalId = sender.try_into().map_err(|_| OpenError::NotSender)?;
        let sealed = Sealed::decode(sealed).map_err(|_| OpenError::Malformed)?;
        let enc =
            <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&sealed.enc).map_err(|_| OpenError::Malformed)?;
        let plaintext = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &self.agreement.secret,
            &enc,
            &info(&sender, &self.principal),
            &sealed.ciphertext,
            &[],
        )
        .map_err(|_| OpenError::Decrypt)?;

        let signed = SignedCommand::decode(plaintext.as_slice()).map_err(|_| OpenError::Malformed)?;
        let verified = verify_chain(&self.account_root, &signed.chain, now_ms).map_err(OpenError::Chain)?;
        if verified.principal != sender {
            return Err(OpenError::NotSender);
        }
        verify_command(&verified.leaf_key, &signed.body, &signed.signature).map_err(|_| OpenError::Signature)?;

        let body = CommandBody::decode(signed.body.as_slice()).map_err(|_| OpenError::Malformed)?;
        if body.from != sender {
            return Err(OpenError::NotSender);
        }
        if body.to != self.principal {
            return Err(OpenError::NotForMe);
        }
        let nonce: [u8; NONCE_BYTES] = body.nonce.as_slice().try_into().map_err(|_| OpenError::Malformed)?;
        if body.time_ms.abs_diff(now_ms) > CLOCK_WINDOW_MS {
            return Err(OpenError::Clock);
        }
        let answers = match (body.answers.is_empty(), body.scope.is_empty()) {
            // a command names the scope it needs, and the sender's certificate must grant it
            (true, false) => {
                if !verified.leaf.scopes.contains(&body.scope) {
                    return Err(OpenError::Scope);
                }
                None
            }
            // a result names the command it answers and needs no scope
            (false, true) => Some(body.answers.as_slice().try_into().map_err(|_| OpenError::Malformed)?),
            _ => return Err(OpenError::Malformed),
        };
        self.replay.admit(sender, nonce, now_ms)?;
        Ok(Opened {
            from: sender,
            scope: body.scope,
            nonce,
            time_ms: body.time_ms,
            body: body.body,
            answers,
            leaf: verified.leaf,
        })
    }
}

/// The nonces accepted recently, per sender. A nonce is kept until its command could no longer pass the clock check:
/// a command accepted at `now` carries a time no later than `now + CLOCK_WINDOW_MS`, which passes the check up to and
/// including `now + 2 * CLOCK_WINDOW_MS`. So the nonce is forgotten only after that millisecond.
struct ReplayWindow {
    capacity: usize,
    seen: HashSet<(PrincipalId, [u8; NONCE_BYTES])>,
    /// in arrival order, with the time each may be forgotten
    order: VecDeque<(u64, (PrincipalId, [u8; NONCE_BYTES]))>,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::with_capacity(MAX_REPLAY_ENTRIES)
    }
}

impl ReplayWindow {
    fn with_capacity(capacity: usize) -> Self {
        Self { capacity, seen: HashSet::new(), order: VecDeque::new() }
    }

    fn admit(&mut self, from: PrincipalId, nonce: [u8; NONCE_BYTES], now_ms: u64) -> Result<(), OpenError> {
        // Arrival order is forget order only while the clock runs forwards; a clock stepped back keeps entries longer
        // than needed, never shorter.
        while let Some(&(forget_at, key)) = self.order.front() {
            if forget_at > now_ms {
                break;
            }
            self.order.pop_front();
            self.seen.remove(&key);
        }
        let key = (from, nonce);
        if self.seen.contains(&key) {
            return Err(OpenError::Replay);
        }
        if self.seen.len() >= self.capacity {
            return Err(OpenError::Busy);
        }
        self.seen.insert(key);
        self.order.push_back((now_ms.saturating_add(2 * CLOCK_WINDOW_MS + 1), key));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
