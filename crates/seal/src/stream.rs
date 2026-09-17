//! Published streams: session events and telemetry, encrypted under a stream key and signed by the publisher
//! (docs/design/end-to-end-crypto.md §Published streams).
//!
//! A stream key is symmetric, so every subscriber holding it could encrypt a frame; the publisher's signature is what
//! stops a compromised phone forging the runtime's events to the other devices. The signature covers a header binding
//! the frame to its publisher, channel, key and counter, and that header is also the AEAD's associated data, so a hub
//! that moves a frame to another channel, renumbers it, or splices one frame's ciphertext onto another's header is
//! caught before anything decrypts.
//!
//! The key reaches each device as a [`Grant`], sealed exactly as a command is but under its own labels. The publisher
//! wraps its own key, so a grant also carries the publisher's certificate chain: that is how a subscriber learns the
//! key that signs the stream.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use wmlhub_keys::{PublicKey, principal_id, sign_grant, sign_stream, verify_grant, verify_stream};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{GrantBody, SignedGrant, StreamFrame};

use crate::{NONCE_BYTES, OpenError, PrincipalId, Receiver, Recipient, SealError, Sender, hpke_seal};

/// The largest encoded `StreamFrame` accepted, matching what an envelope payload may carry.
pub const MAX_STREAM_FRAME_BYTES: usize = 1 << 20;
/// Bytes of an AES-GCM nonce.
const FRAME_NONCE_BYTES: usize = 12;
/// Bytes of a stream key id.
const KEY_ID_BYTES: usize = 8;

const GRANT_INFO_LABEL: &[u8] = b"wmlhub/keygrant/v1\0";
const KEY_ID_LABEL: &[u8] = b"wmlhub/streamkey-id/v1\0";
const CHANNEL_LABEL: &[u8] = b"wmlhub/channel/v1\0";

/// Bytes of a channel name.
pub const CHANNEL_BYTES: usize = 16;

/// A stream's symmetric key. The publisher chooses it, rotates it, and wraps it to every device allowed to read.
#[derive(Clone)]
pub struct StreamKey {
    key: [u8; 32],
    id: [u8; KEY_ID_BYTES],
}

impl StreamKey {
    /// A fresh key from the operating system's random source.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        Ok(Self::from_bytes(key))
    }

    pub fn from_bytes(key: [u8; 32]) -> Self {
        let mut hash = Sha256::new();
        hash.update(KEY_ID_LABEL);
        hash.update(key);
        let digest = hash.finalize();
        let mut id = [0u8; KEY_ID_BYTES];
        id.copy_from_slice(&digest[..KEY_ID_BYTES]);
        Self { key, id }
    }

    /// Which key a frame names. Derived from the key, so a publisher and a subscriber agree on it with no extra state.
    pub fn id(&self) -> [u8; KEY_ID_BYTES] {
        self.id
    }
}

/// What the publisher signs and the AEAD binds: the frame's place in the world. The channel, key id and counter are
/// each load-bearing (moving, relabelling or renumbering a frame stops it verifying). The publisher id and the
/// associated data are not, today: a frame is verified with the publisher key its grant carried, before it is
/// decrypted, so nothing could attribute a frame elsewhere or decrypt one unverified. They are here because both are
/// free and both stop being redundant the moment a reader resolves a key from the frame rather than from a grant.
fn header(publisher: &PrincipalId, channel: &[u8], key_id: &[u8; KEY_ID_BYTES], counter: u64, nonce: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(32 + 2 + channel.len() + KEY_ID_BYTES + 8 + FRAME_NONCE_BYTES);
    header.extend_from_slice(publisher);
    header.extend_from_slice(&u16::try_from(channel.len()).unwrap_or(u16::MAX).to_be_bytes());
    header.extend_from_slice(channel);
    header.extend_from_slice(key_id);
    header.extend_from_slice(&counter.to_be_bytes());
    header.extend_from_slice(nonce);
    header
}

/// Encrypt and sign one batch for `channel`. `counter` is the publisher's own count for that channel, from 1, and
/// never repeats across key rotations.
pub fn seal_frame(
    publisher: &Sender,
    channel: &[u8],
    key: &StreamKey,
    counter: u64,
    batch: &[u8],
) -> Result<Vec<u8>, SealError> {
    let me = principal_id(&publisher.identity.public());
    let mut nonce = [0u8; FRAME_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(SealError::Random)?;
    let header = header(&me, channel, &key.id, counter, &nonce);
    let cipher = Aes256Gcm::new_from_slice(&key.key).expect("a stream key is 32 bytes");
    let ciphertext = cipher
        .encrypt(&Nonce::try_from(&nonce[..]).map_err(|_| SealError::Aead)?, Payload { msg: batch, aad: &header })
        .map_err(|_| SealError::Aead)?;
    let mut signed = header;
    signed.extend_from_slice(&ciphertext);
    let signature = sign_stream(publisher.identity, &signed);
    Ok(StreamFrame { key_id: key.id.to_vec(), counter, nonce: nonce.to_vec(), ciphertext, signature }.encode_to_vec())
}

/// A stream key handed to one device, opened and verified.
#[derive(Debug, Clone)]
pub struct Grant {
    pub publisher: PrincipalId,
    /// the publisher's identity key: what its frames are verified with
    pub publisher_key: PublicKey,
    pub channel: Vec<u8>,
    pub key_id: [u8; KEY_ID_BYTES],
    pub key: [u8; 32],
    /// the first counter this key covers
    pub from_counter: u64,
}

/// Wrap `key` for one device. The publisher signs and seals it; `from_counter` is the first counter the key covers.
pub fn wrap_key(
    publisher: &Sender,
    to: &Recipient,
    channel: &[u8],
    key: &StreamKey,
    from_counter: u64,
    now_ms: u64,
) -> Result<Vec<u8>, SealError> {
    let me = principal_id(&publisher.identity.public());
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(SealError::Random)?;
    let body = GrantBody {
        from: me.to_vec(),
        to: to.principal.to_vec(),
        nonce: nonce.to_vec(),
        time_ms: now_ms,
        channel: channel.to_vec(),
        key_id: key.id.to_vec(),
        key: key.key.to_vec(),
        from_counter,
    }
    .encode_to_vec();
    let signed =
        SignedGrant { signature: sign_grant(publisher.identity, &body), body, chain: publisher.chain.to_vec() }
            .encode_to_vec();
    hpke_seal(GRANT_INFO_LABEL, &me, to, &signed).map_err(SealError::Hpke)
}

/// Open a wrapped stream key the hub delivered from `sender`. Checked exactly as a command is: sealed to this device,
/// a chain to the account root whose leaf is that sender, the publisher's signature, addressed here, inside the clock
/// window, and its nonce not seen before.
pub fn open_grant(receiver: &mut Receiver, sender: &[u8], sealed: &[u8], now_ms: u64) -> Result<Grant, OpenError> {
    let sender: PrincipalId = sender.try_into().map_err(|_| OpenError::NotSender)?;
    let plaintext = receiver.unseal(GRANT_INFO_LABEL, &sender, sealed)?;
    let signed = SignedGrant::decode(plaintext.as_slice()).map_err(|_| OpenError::Malformed)?;
    let verified = receiver.check_chain(&sender, &signed.chain, now_ms)?;
    verify_grant(&verified.leaf_key, &signed.body, &signed.signature).map_err(|_| OpenError::Signature)?;

    let body = GrantBody::decode(signed.body.as_slice()).map_err(|_| OpenError::Malformed)?;
    let key: [u8; 32] = body.key.as_slice().try_into().map_err(|_| OpenError::Malformed)?;
    let key_id: [u8; KEY_ID_BYTES] = body.key_id.as_slice().try_into().map_err(|_| OpenError::Malformed)?;
    if StreamKey::from_bytes(key).id != key_id {
        return Err(OpenError::Malformed);
    }
    receiver.check_addressing(&sender, &body.from, &body.to, &body.nonce, body.time_ms, now_ms)?;
    Ok(Grant {
        publisher: sender,
        publisher_key: verified.leaf_key,
        channel: body.channel,
        key_id,
        key,
        from_counter: body.from_counter,
    })
}

/// An account-wide key for naming channels. Kept with the account's other secrets and never sent to the hub.
#[derive(Clone)]
pub struct ChannelKey([u8; 32]);

impl ChannelKey {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        Ok(Self(key))
    }

    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// The channel a stream of `what` (a session hash, a box id) travels on: HMAC-SHA256 under this account's channel
    /// key, truncated to 16 bytes. The hub routes by this and learns nothing from it: it cannot tell which session a
    /// channel belongs to, or that two accounts are watching the same box (docs/PROTOCOL.md §What the hub can see).
    /// `purpose` separates the streams of one subject, so a session's events and its keys are different channels.
    pub fn channel(&self, purpose: &str, what: &[u8]) -> [u8; CHANNEL_BYTES] {
        use hmac::{KeyInit, Mac};
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes a key of any length");
        mac.update(CHANNEL_LABEL);
        mac.update(purpose.as_bytes());
        mac.update(&[0]);
        mac.update(what);
        let tag = mac.finalize().into_bytes();
        let mut channel = [0u8; CHANNEL_BYTES];
        channel.copy_from_slice(&tag[..CHANNEL_BYTES]);
        channel
    }
}

/// Why a published frame was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// over [`MAX_STREAM_FRAME_BYTES`]
    TooLarge,
    /// did not decode, or a field has the wrong length
    Malformed,
    /// no key with this frame's id: the subscriber has not been granted it (yet)
    UnknownKey,
    /// not signed by this stream's publisher for this channel, counter and key
    Signature,
    /// the key does not open it, or the header it was sealed under is not the one delivered
    Decrypt,
    /// a counter this reader has already passed: the hub replayed or reordered the stream
    OutOfOrder { last: u64, counter: u64 },
}

/// One batch, opened.
#[derive(Debug, Clone)]
pub struct Published {
    pub counter: u64,
    /// counters between the last frame and this one that never arrived (telemetry may be dropped; session events are
    /// not, so anything but 0 there means the ring was truncated or the hub dropped something)
    pub skipped: u64,
    pub batch: Vec<u8>,
}

/// One subscriber's view of one stream: whose it is, which channel, the keys it has been granted, and how far it has
/// read.
pub struct StreamReader {
    publisher: PrincipalId,
    publisher_key: PublicKey,
    channel: Vec<u8>,
    keys: HashMap<[u8; KEY_ID_BYTES], [u8; 32]>,
    last: u64,
}

impl StreamReader {
    /// A reader for the stream a grant is for. Its publisher, channel and signing key come from the grant, which was
    /// verified when it was opened, so a reader can never be pointed at a stream by the hub.
    pub fn new(grant: &Grant) -> Self {
        let mut reader = Self {
            publisher: grant.publisher,
            publisher_key: grant.publisher_key,
            channel: grant.channel.clone(),
            keys: HashMap::new(),
            last: 0,
        };
        reader.add_key(grant);
        reader
    }

    /// Take another key for this stream: a rotation, or the previous key for reading further back in the ring. A grant
    /// for another stream is ignored.
    pub fn add_key(&mut self, grant: &Grant) -> bool {
        if grant.publisher != self.publisher || grant.channel != self.channel {
            return false;
        }
        self.keys.insert(grant.key_id, grant.key);
        true
    }

    /// Where this reader has read to. A resubscribe should ask the hub for what follows.
    pub fn counter(&self) -> u64 {
        self.last
    }

    /// Start again from `counter`, after a backfill that begins further back than this reader has read.
    pub fn rewind_to(&mut self, counter: u64) {
        self.last = counter;
    }

    /// Verify and decrypt one published frame.
    pub fn open(&mut self, frame: &[u8]) -> Result<Published, StreamError> {
        if frame.len() > MAX_STREAM_FRAME_BYTES {
            return Err(StreamError::TooLarge);
        }
        let frame = StreamFrame::decode(frame).map_err(|_| StreamError::Malformed)?;
        let key_id: [u8; KEY_ID_BYTES] = frame.key_id.as_slice().try_into().map_err(|_| StreamError::Malformed)?;
        if frame.nonce.len() != FRAME_NONCE_BYTES {
            return Err(StreamError::Malformed);
        }
        let key = *self.keys.get(&key_id).ok_or(StreamError::UnknownKey)?;

        let header = header(&self.publisher, &self.channel, &key_id, frame.counter, &frame.nonce);
        let mut signed = header.clone();
        signed.extend_from_slice(&frame.ciphertext);
        verify_stream(&self.publisher_key, &signed, &frame.signature).map_err(|_| StreamError::Signature)?;
        if frame.counter <= self.last {
            return Err(StreamError::OutOfOrder { last: self.last, counter: frame.counter });
        }

        let cipher = Aes256Gcm::new_from_slice(&key).expect("a stream key is 32 bytes");
        let batch = cipher
            .decrypt(
                &Nonce::try_from(&frame.nonce[..]).map_err(|_| StreamError::Malformed)?,
                Payload { msg: &frame.ciphertext, aad: &header },
            )
            .map_err(|_| StreamError::Decrypt)?;
        let skipped = frame.counter - self.last - 1;
        self.last = frame.counter;
        Ok(Published { counter: frame.counter, skipped, batch })
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
