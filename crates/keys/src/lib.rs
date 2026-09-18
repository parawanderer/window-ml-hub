//! Identities, certificate chains and the signed hello (docs/design/end-to-end-crypto.md §Identities and §Accounts).
//!
//! The hub uses the verifying half: [`verify_chain`] and [`verify_hello`], with public keys only. Clients and tests use
//! the signing half: [`Identity`], [`issue`], [`sign_hello`]. Encryption is not here: the hub never encrypts or
//! decrypts anything.
//!
//! Every signature is over a domain-separation label followed by the exact bytes, so a signature made for one purpose
//! (a certificate) can never be replayed as another (a hello).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Certificate, CertificateBody, Role};

/// An Ed25519 public key.
pub type PublicKey = [u8; 32];

/// The longest chain accepted: a leaf issued by the root, or by one delegate the root allowed to pair.
pub const MAX_CHAIN: usize = 2;

/// The longest a certificate may be valid for. Every certificate carries a real window, so an account nobody is
/// watching stops being reachable on its own: a device that is never renewed loses access, which is the one form of
/// revocation that needs no list, no hub and nobody online. Renewal is a command the root or a `may_pair` delegate
/// answers while the device is still on the runtime's allowlist, so revoking is simply not renewing.
///
/// 90 days is chosen for what it costs when it is wrong: a device that has been away longer re-pairs, which is a
/// minute with the person present, and a device that is stolen is useless within a quarter even if every other
/// mechanism failed.
pub const MAX_CERTIFICATE_MS: u64 = 90 * 24 * 60 * 60 * 1_000;

/// Scopes a box connector's certificate may never carry: it relays one machine's telemetry and answers a few
/// commands about it. Nothing about that involves approving anything or driving a session.
pub const BOX_CONNECTOR_FORBIDS: [&str; 2] = [scope::APPROVE, "control"];

/// Scopes only the account root may grant. Answering a run's gates, driving a machine, and administering the
/// account's devices are things a person decides at the root, not powers a paired device passes on: a phone that may
/// approve a click should not thereby be able to pair another phone (window-ml `docs/spec/CHAT_PAGE.md` §Pairing).
pub const NEVER_DELEGABLE: [&str; 3] = [scope::APPROVE, "control", "admin"];

/// The largest encoded certificate body accepted. Checked before decoding: a hello is read before its sender is
/// authenticated, so nothing in it may cost more than its size allows. A body with every field at its limit is about
/// 750 bytes.
pub const MAX_CERT_BYTES: usize = 1024;
/// The largest encoded body of a RENEWAL, which carries the certificate it renews: another whole body, its signature
/// and the framing around them, on top of a body of its own. Renewals never nest ([`verify_chain`] refuses a
/// predecessor that is itself one), so this is the ceiling rather than one step of many.
pub const MAX_RENEWING_CERT_BYTES: usize = 2 * MAX_CERT_BYTES + 128;
/// The most scopes one certificate may carry. Attenuation compares each against the issuer's, so this bounds that too.
pub const MAX_SCOPES: usize = 16;
/// The longest scope name.
pub const MAX_SCOPE_BYTES: usize = 32;
/// The longest label.
pub const MAX_LABEL_BYTES: usize = 64;

/// The scope names runtimes know today (window-ml docs/spec/RUNTIME_HUB.md §Principals and scopes). The set is open:
/// a certificate may carry a name that is not here, and it verifies.
pub mod scope {
    pub const VIEW: &str = "view";
    pub const DRIVE: &str = "drive";
    pub const APPROVE: &str = "approve";
    pub const SCREEN: &str = "screen";
    pub const DESKTOP: &str = "desktop";
}

const CERT_LABEL: &[u8] = b"wmlhub/cert/v1\0";
const HELLO_LABEL: &[u8] = b"wmlhub/hello/v1\0";
const COMMAND_LABEL: &[u8] = b"wmlhub/command/v1\0";
const GRANT_LABEL: &[u8] = b"wmlhub/grant/v1\0";
const STREAM_LABEL: &[u8] = b"wmlhub/stream/v1\0";

/// An Ed25519 identity key held in memory: for clients, tools and tests. (The extension keeps its keys as
/// non-extractable WebCrypto keys instead; this type is never how a browser holds one.)
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    /// A fresh identity from the operating system's random source.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    /// An identity from a 32-byte seed. Deterministic: for tests and vectors.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { key: SigningKey::from_bytes(&seed) }
    }

    /// The public key.
    pub fn public(&self) -> PublicKey {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, label: &[u8], message: &[u8]) -> Vec<u8> {
        let mut signed = Vec::with_capacity(label.len() + message.len());
        signed.extend_from_slice(label);
        signed.extend_from_slice(message);
        self.key.sign(&signed).to_bytes().to_vec()
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", hex(&self.public()))
    }
}

/// A principal's id: SHA-256 of its identity public key.
pub fn principal_id(key: &PublicKey) -> [u8; 32] {
    Sha256::digest(key).into()
}

/// An account's id: SHA-256 of its root public key.
pub fn account_id(root: &PublicKey) -> [u8; 32] {
    Sha256::digest(root).into()
}

/// What a certificate grants its subject.
#[derive(Debug, Clone)]
pub struct CertSpec {
    pub subject: PublicKey,
    pub agreement_key: [u8; 32],
    pub role: Role,
    pub scopes: Vec<String>,
    pub may_pair: bool,
    /// May sign the account's revocation lists. Only the root may grant it, and only one principal may hold it
    /// (docs/design/revocation.md); [`verify_chain`] refuses it on anything a delegate issued.
    pub may_revoke: bool,
    pub not_before_ms: u64,
    /// 0 means no expiry
    pub not_after_ms: u64,
    pub label: String,
}

/// Issue a certificate for `spec`, signed by `issuer` (the account root, or a principal allowed to pair).
/// Issue a certificate, or say why not.
///
/// It refuses what every verifier would: a certificate is checked here for the rules that do not depend on the chain
/// it will be presented in, so a caller learns at issuance rather than at somebody else's verifier. What it cannot
/// see from here — that the issuer may delegate at all, that scopes only narrow — `verify_chain` does.
pub fn issue(issuer: &Identity, spec: &CertSpec) -> Result<Certificate, ChainError> {
    if spec.not_before_ms == 0 || spec.not_after_ms == 0 {
        return Err(ChainError::Unbounded);
    }
    if spec.not_after_ms <= spec.not_before_ms || spec.not_after_ms - spec.not_before_ms > MAX_CERTIFICATE_MS {
        return Err(ChainError::TooLong);
    }
    if spec.role == Role::BoxConnector
        && (spec.may_pair || spec.may_revoke || spec.scopes.iter().any(|s| BOX_CONNECTOR_FORBIDS.contains(&s.as_str())))
    {
        return Err(ChainError::RoleNotPermitted);
    }
    Ok(sign_certificate(issuer, spec))
}

pub(crate) fn sign_certificate(issuer: &Identity, spec: &CertSpec) -> Certificate {
    let body = CertificateBody {
        subject: spec.subject.to_vec(),
        agreement_key: spec.agreement_key.to_vec(),
        issuer: issuer.public().to_vec(),
        role: spec.role as i32,
        scopes: spec.scopes.clone(),
        may_pair: spec.may_pair,
        may_revoke: spec.may_revoke,
        not_before_ms: spec.not_before_ms,
        not_after_ms: spec.not_after_ms,
        label: spec.label.clone(),
        renews: None,
    }
    .encode_to_vec();
    let signature = issuer.sign(CERT_LABEL, &body);
    Certificate { body, signature }
}

/// Renew `previous`: the same certificate with a later window, signed by `issuer`.
///
/// This is deliberately not `issue` with the old fields copied by the caller. Renewal is the one operation a
/// delegate may perform for scopes it could not itself grant, and what buys that is the predecessor travelling with
/// it, so the new body is built HERE from the old one rather than by somebody who might get a field wrong. The field
/// that matters most is `agreement_key`: it is where sealed commands go, and a renewal free to change it could
/// redirect everything sealed to an approver into a key the renewer holds.
///
/// Renaming a device is therefore not a renewal. `label` travels unchanged like everything else, and a new name is a
/// fresh issuance by whoever may grant those scopes.
pub fn renew(
    issuer: &Identity,
    previous: &Certificate,
    not_before_ms: u64,
    not_after_ms: u64,
) -> Result<Certificate, ChainError> {
    let before = decode_body(&previous.body)?;
    if before.renews.is_some() {
        return Err(ChainError::BadRenewal);
    }
    if not_before_ms == 0 || not_after_ms == 0 {
        return Err(ChainError::Unbounded);
    }
    if not_after_ms <= not_before_ms || not_after_ms - not_before_ms > MAX_CERTIFICATE_MS {
        return Err(ChainError::TooLong);
    }
    let body = CertificateBody {
        issuer: issuer.public().to_vec(),
        not_before_ms,
        not_after_ms,
        renews: Some(previous.clone()),
        ..before
    }
    .encode_to_vec();
    let signature = issuer.sign(CERT_LABEL, &body);
    Ok(Certificate { body, signature })
}

/// Why a chain was refused. Deliberately coarse on the wire (the hub answers `UNAUTHENTICATED`), precise here for
/// logs and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// no certificates, or more than [`MAX_CHAIN`]
    Length,
    /// a certificate or key did not decode, a key is not 32 bytes, or a body, scope list, scope name or label is
    /// over its limit or a scope name has a character outside `a-z 0-9 . _ -`
    Malformed,
    /// a signature does not verify under its issuer's key
    Signature,
    /// a certificate's issuer is not the next certificate's subject, or the last is not issued by the root
    Issuer,
    /// an intermediate certificate lacks `may_pair`
    NotDelegated,
    /// a certificate is not yet valid, or has expired
    Expired,
    /// a certificate outlives its issuer's certificate
    OutlivesIssuer,
    /// a certificate grants a scope its issuer's certificate does not hold
    ScopeWidened,
    /// the root key appears as a certificate subject
    RootAsSubject,
    /// a certificate has no validity window: both `not_before_ms` and `not_after_ms` are required
    Unbounded,
    /// a certificate is valid for longer than [`MAX_CERTIFICATE_MS`]
    TooLong,
    /// a certificate grants its role something that role may never hold (a box connector that may pair or approve)
    RoleNotPermitted,
    /// a delegate issued a scope only the root may grant ([`NEVER_DELEGABLE`]), or `may_revoke`
    NotDelegable,
    /// a certificate claims to RENEW one that the root did not sign, that is itself a renewal, or whose terms it
    /// does not repeat exactly
    BadRenewal,
}

/// A chain that verified: who the principal is and what its leaf certificate says.
#[derive(Debug, Clone)]
pub struct Verified {
    pub account: [u8; 32],
    pub principal: [u8; 32],
    pub leaf_key: PublicKey,
    pub leaf: CertificateBody,
}

/// Verify `chain` (leaf first) up to `root` at time `now_ms`. Public keys only.
pub fn verify_chain(root: &PublicKey, chain: &[Certificate], now_ms: u64) -> Result<Verified, ChainError> {
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err(ChainError::Length);
    }
    let bodies: Vec<CertificateBody> = chain.iter().map(|c| decode_body(&c.body)).collect::<Result<_, _>>()?;

    for (i, (cert, body)) in chain.iter().zip(&bodies).enumerate() {
        let subject = key32(&body.subject)?;
        let issuer = key32(&body.issuer)?;
        key32(&body.agreement_key)?;
        if subject == *root {
            return Err(ChainError::RootAsSubject);
        }
        let parent = bodies.get(i + 1);
        let expected_issuer = match parent {
            Some(p) => key32(&p.subject)?,
            None => *root,
        };
        if issuer != expected_issuer {
            return Err(ChainError::Issuer);
        }
        verify(&issuer, CERT_LABEL, &cert.body, &cert.signature).map_err(|_| ChainError::Signature)?;
        // A real window on every certificate, so expiry is the revocation that works with nobody online.
        if body.not_before_ms == 0 || body.not_after_ms == 0 {
            return Err(ChainError::Unbounded);
        }
        if body.not_after_ms <= body.not_before_ms || body.not_after_ms - body.not_before_ms > MAX_CERTIFICATE_MS {
            return Err(ChainError::TooLong);
        }
        if now_ms < body.not_before_ms || now_ms > body.not_after_ms {
            return Err(ChainError::Expired);
        }
        if body.role() == Role::BoxConnector
            && (body.may_pair || body.scopes.iter().any(|s| BOX_CONNECTOR_FORBIDS.contains(&s.as_str())))
        {
            return Err(ChainError::RoleNotPermitted);
        }
        // A renewal re-issues what the root already granted this subject, unchanged but for its window, so it is
        // exempt from the two rules below that keep a delegate from granting more than it holds. Verified first,
        // because what it is exempt from depends on it being a real one.
        let renewed = match &body.renews {
            None => false,
            Some(previous) => {
                verify_renewal(root, body, previous)?;
                true
            }
        };
        if let Some(p) = parent {
            if !p.may_pair {
                return Err(ChainError::NotDelegated);
            }
            // A renewal is bound by this too, which is what collapses the root's part in renewal to one visit per
            // account per window (its own certificate) rather than one per device.
            if body.not_after_ms > p.not_after_ms {
                return Err(ChainError::OutlivesIssuer);
            }
            // `may_revoke` is never delegated and never renewed by a delegate either. "A renewal grants nothing new"
            // is false for this one field, because its whole value is that exactly one principal holds it: keeping a
            // second holder alive is how two signers happen, and two signers race on a per-account monotonic
            // `version` with the loser's revocation refused as stale (docs/design/revocation.md).
            if body.may_revoke {
                return Err(ChainError::NotDelegable);
            }
            if !renewed {
                if body.scopes.iter().any(|s| !p.scopes.contains(s)) {
                    return Err(ChainError::ScopeWidened);
                }
                // Issued by a delegate rather than by the root: the powers a person decides at the root do not travel.
                if body.scopes.iter().any(|s| NEVER_DELEGABLE.contains(&s.as_str())) {
                    return Err(ChainError::NotDelegable);
                }
            }
        }
    }

    let leaf = bodies.into_iter().next().expect("chain is not empty");
    let leaf_key = key32(&leaf.subject)?;
    Ok(Verified { account: account_id(root), principal: principal_id(&leaf_key), leaf_key, leaf })
}

/// The bytes a principal signs to answer a challenge. Binds the hub's name (so another hub's challenge cannot be
/// passed along), the nonce (so it cannot be replayed), and who is logging in as what, into which account.
pub fn hello_transcript(hub: &str, nonce: &[u8], principal: &[u8], role: Role, account: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(4 + hub.len() + 4 + nonce.len() + 4 + principal.len() + 4 + 32);
    t.extend_from_slice(&len32(hub.len()).to_be_bytes());
    t.extend_from_slice(hub.as_bytes());
    t.extend_from_slice(&len32(nonce.len()).to_be_bytes());
    t.extend_from_slice(nonce);
    t.extend_from_slice(&len32(principal.len()).to_be_bytes());
    t.extend_from_slice(principal);
    t.extend_from_slice(&(role as i32).to_be_bytes());
    t.extend_from_slice(account);
    t
}

/// Sign an encoded `CommandBody` (a command or a result) with the sender's leaf identity.
pub fn sign_command(leaf: &Identity, body: &[u8]) -> Vec<u8> {
    leaf.sign(COMMAND_LABEL, body)
}

/// Verify a command or result signature made by `leaf_key`.
pub fn verify_command(leaf_key: &PublicKey, body: &[u8], signature: &[u8]) -> Result<(), BadSignature> {
    verify(leaf_key, COMMAND_LABEL, body, signature)
}

/// Sign an encoded `GrantBody` (a stream key handed to a device) with the publisher's leaf identity.
pub fn sign_grant(leaf: &Identity, body: &[u8]) -> Vec<u8> {
    leaf.sign(GRANT_LABEL, body)
}

/// Verify a grant signature made by `leaf_key`.
pub fn verify_grant(leaf_key: &PublicKey, body: &[u8], signature: &[u8]) -> Result<(), BadSignature> {
    verify(leaf_key, GRANT_LABEL, body, signature)
}

/// Sign a published stream frame's header and ciphertext with the publisher's leaf identity.
pub fn sign_stream(leaf: &Identity, signed_bytes: &[u8]) -> Vec<u8> {
    leaf.sign(STREAM_LABEL, signed_bytes)
}

/// Verify a stream frame signature made by `leaf_key`.
pub fn verify_stream(leaf_key: &PublicKey, signed_bytes: &[u8], signature: &[u8]) -> Result<(), BadSignature> {
    verify(leaf_key, STREAM_LABEL, signed_bytes, signature)
}

/// Sign a hello transcript with the leaf identity.
pub fn sign_hello(leaf: &Identity, transcript: &[u8]) -> Vec<u8> {
    leaf.sign(HELLO_LABEL, transcript)
}

/// Verify a hello signature made by `leaf_key`.
pub fn verify_hello(leaf_key: &PublicKey, transcript: &[u8], signature: &[u8]) -> Result<(), BadSignature> {
    verify(leaf_key, HELLO_LABEL, transcript, signature)
}

/// A signature did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadSignature;

fn verify(key: &PublicKey, label: &[u8], message: &[u8], signature: &[u8]) -> Result<(), BadSignature> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| BadSignature)?;
    let signature = Signature::from_slice(signature).map_err(|_| BadSignature)?;
    let mut signed = Vec::with_capacity(label.len() + message.len());
    signed.extend_from_slice(label);
    signed.extend_from_slice(message);
    key.verify_strict(&signed, &signature).map_err(|_| BadSignature)
}

/// Check a certificate that claims to renew `previous`.
///
/// The exemption a renewal buys is from `ScopeWidened` and `NotDelegable`, which are the two rules that make
/// delegation safe, so it is bought strictly: the predecessor has to be the ACCOUNT ROOT's own signature over
/// exactly these terms.
fn verify_renewal(root: &PublicKey, body: &CertificateBody, previous: &Certificate) -> Result<(), ChainError> {
    let before = decode_body(&previous.body)?;
    // Renewals do not chain. Without this a delegate could renew its own renewal, and the predecessor would stop
    // being the root's word about anything.
    if before.renews.is_some() {
        return Err(ChainError::BadRenewal);
    }
    // Signed by the root and saying so. Under a delegate this would be a delegate certifying its own authority.
    if key32(&before.issuer)? != *root {
        return Err(ChainError::BadRenewal);
    }
    verify(root, CERT_LABEL, &previous.body, &previous.signature).map_err(|_| ChainError::BadRenewal)?;
    // The predecessor's own window is NOT checked: an expired predecessor is the normal case, and is the point.
    //
    // Everything else must be equal, and it is compared as a WHOLE rather than field by field, so a field added to
    // `CertificateBody` later is covered by this rule until somebody deliberately exempts it here. Scopes compare in
    // order, which `renew` gives for free by copying them and a hand-built renewal has no reason to disturb.
    let expected = CertificateBody {
        issuer: body.issuer.clone(),
        not_before_ms: body.not_before_ms,
        not_after_ms: body.not_after_ms,
        renews: body.renews.clone(),
        ..before
    };
    if expected != *body {
        return Err(ChainError::BadRenewal);
    }
    Ok(())
}

/// Decode a certificate body, refusing anything over its bounds before any of it is compared or verified.
fn decode_body(bytes: &[u8]) -> Result<CertificateBody, ChainError> {
    if bytes.len() > MAX_RENEWING_CERT_BYTES {
        return Err(ChainError::Malformed);
    }
    let body = CertificateBody::decode(bytes).map_err(|_| ChainError::Malformed)?;
    // Only a renewal has any business being larger than a certificate, because only a renewal carries another one.
    if body.renews.is_none() && bytes.len() > MAX_CERT_BYTES {
        return Err(ChainError::Malformed);
    }
    let name_ok = |s: &String| {
        (1..=MAX_SCOPE_BYTES).contains(&s.len())
            && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    };
    if body.scopes.len() > MAX_SCOPES || !body.scopes.iter().all(name_ok) || body.label.len() > MAX_LABEL_BYTES {
        return Err(ChainError::Malformed);
    }
    Ok(body)
}

fn key32(bytes: &[u8]) -> Result<[u8; 32], ChainError> {
    bytes.try_into().map_err(|_| ChainError::Malformed)
}

/// Lengths in a transcript are u32; a hub name, nonce or principal id is never near that.
fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Lowercase hex, for ids in logs and file names.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub mod pairing;

#[cfg(test)]
mod tests;
