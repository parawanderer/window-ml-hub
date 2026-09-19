//! The hub half of a connector: publishing what the box said, and answering the one command devices ask of it.
//!
//! One websocket carries both, so one loop owns it. It waits on two things at once — a frame from the box side, and
//! whatever the hub has to say — and whichever arrives first is served with the other still waiting. That is only
//! sound because `Client::next` is safe to drop: what it has read stays read (`self.pending`), and the one thing a
//! dropped call can lose is a pong it was about to send, which costs nothing here because the hub's idle timeout
//! counts any traffic and a frame arriving is this connector about to send some.
//!
//! The duplicate check lives here rather than beside the box, because a frame is only a duplicate once it has
//! actually been published: the box side hands frames over and the hub can still refuse them.

use std::collections::{HashSet, VecDeque};
use std::io;

use tokio::sync::{mpsc, watch};
use wmlhub_box::read;
use wmlhub_client::{Client, ClientError, Event};
use wmlhub_keys::revocation::RevocationError;
use wmlhub_keys::{hex, verify_chain};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Error as HubError, Kind, Presence, RevocationList, StreamRef, error::Code};
use wmlhub_seal::{ChannelKey, Recipient, Sender, StreamKey};

use crate::grant::{is_grant, refusal, wrap_for};
use crate::relay::{Channels, Relay, RelayError, Relayed};
use crate::revoked::Revocations;
use crate::state::State;

/// The purpose a revoker's list is published under, keyed like every other channel (`ChannelKey::channel`), with the
/// revoker's principal id as the subject.
pub const REVOCATIONS_PURPOSE: &str = "revocations";

/// Frames remembered for the duplicate check. A backfill longer than this would republish, so it is sized well past
/// what a reconnect asks for: a box sends a few frames a second, and this covers minutes of them.
pub const DEDUPE_FRAMES: usize = 4_096;

/// Why publishing stopped. Every one of these is the caller's to fix, because the caller owns the certificate and
/// the handshake.
#[derive(Debug)]
pub enum ServeError {
    /// the hub connection failed, or the hub closed it
    Hub(ClientError),
    /// the hub refused something about this connection (not a throttle, which is not an end)
    Refused(HubError),
    /// sealing or publishing a frame failed
    Publish(RelayError),
    /// the box side stopped, so there is nothing left to publish
    BoxGone,
    /// who is revoked could not be written down. That stops the connector rather than being logged past: a restart
    /// would forget, and grant its key to devices the account has revoked.
    State(io::Error),
}

/// What this connector did while it was up, for the caller's logs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Served {
    pub published: u64,
    /// frames the box replayed that had already been published
    pub duplicates: u64,
    /// devices handed the stream key
    pub granted: u64,
    /// commands that were not `box.grant`, or not asked in a way that could be answered
    pub refused: u64,
    /// grants refused because the list names the asker, or because it has gone stale
    pub revoked: u64,
    /// revocation lists applied, and how many of them rotated the key
    pub lists: u64,
    pub rotations: u64,
}

/// One box's traffic on one hub connection: published, and granted to whoever may read it.
pub struct Serving<'a> {
    relay: Relay<'a>,
    channels: Channels,
    publisher: Sender<'a>,
    channel_key: &'a ChannelKey,
    revocations: Revocations,
    /// where who-is-revoked is written down
    state: &'a State,
    /// the hashes of frames published recently, oldest first
    seen: VecDeque<u64>,
    seen_set: HashSet<u64>,
    /// the newest `at_ms` published, which is what the box side resumes from
    published: watch::Sender<Option<u64>>,
    counts: Served,
}

/// What a `Serving` needs about the account's revocations: the channel key their channels are named under, what
/// this connector already knew (`State::revocations`), and where to write down what it learns.
pub struct Revoking<'a> {
    pub channel_key: &'a ChannelKey,
    pub revocations: Revocations,
    pub state: &'a State,
}

impl<'a> Serving<'a> {
    pub fn new(
        publisher: Sender<'a>,
        key: StreamKey,
        channels: Channels,
        revoking: Revoking<'a>,
        published: watch::Sender<Option<u64>>,
    ) -> Self {
        Self {
            relay: Relay::new(Sender { identity: publisher.identity, chain: publisher.chain }, key, channels.clone()),
            channels,
            publisher,
            channel_key: revoking.channel_key,
            revocations: revoking.revocations,
            state: revoking.state,
            seen: VecDeque::new(),
            seen_set: HashSet::new(),
            published,
            counts: Served::default(),
        }
    }

    /// What this connector has done so far.
    pub fn counts(&self) -> &Served {
        &self.counts
    }

    /// Publish and answer until the hub connection fails or the box side stops.
    pub async fn run(
        &mut self,
        client: &mut Client,
        frames: &mut mpsc::Receiver<Vec<u8>>,
        now_ms: &impl Fn() -> u64,
    ) -> ServeError {
        // A connection starts by reading every revoker it knows of, from the ring: a list published while this
        // connector was away arrives before it has granted anything on this connection.
        let revokers: Vec<[u8; 32]> = self.revocations.revokers().copied().collect();
        for revoker in revokers {
            if let Err(e) = self.follow(client, &revoker).await {
                return e;
            }
        }
        loop {
            // Whichever comes first. The loser is dropped, which is why neither may hold state of its own: a frame
            // taken off the channel and then dropped would be a frame nobody published.
            let next = tokio::select! {
                frame = frames.recv() => Next::Frame(frame),
                event = client.next() => Next::Hub(event.map(Box::new)),
            };
            let outcome = match next {
                Next::Frame(Some(frame)) => self.publish(client, &frame).await,
                Next::Frame(None) => return ServeError::BoxGone,
                Next::Hub(Ok(event)) => self.event(client, *event, now_ms()).await,
                Next::Hub(Err(e)) => return ServeError::Hub(e),
            };
            if let Err(e) = outcome {
                return e;
            }
        }
    }

    /// Publish one frame unless it has been published already. `run` calls this for every frame the box side hands
    /// over; it is public so a caller that drives the loop itself (a test, a different binary) can too.
    pub async fn publish(&mut self, client: &mut Client, frame: &[u8]) -> Result<(), ServeError> {
        let digest = hash(frame);
        if self.seen_set.contains(&digest) {
            self.counts.duplicates += 1;
            return Ok(());
        }
        match self.relay.frame(client, frame).await {
            Ok(Relayed::Consumed) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(ServeError::Publish(e)),
        }
        self.remember(digest);
        self.counts.published += 1;
        if let Some(at_ms) = read(frame).at_ms {
            // a box whose clock stepped back would otherwise pin the resume point to a future it never reaches
            let newest = self.published.borrow().map_or(at_ms, |last| last.max(at_ms));
            let _ = self.published.send(Some(newest));
        }
        Ok(())
    }

    /// What the hub had to say: a command, a revoker coming online, or a list one of them published.
    async fn event(&mut self, client: &mut Client, event: Event, now_ms: u64) -> Result<(), ServeError> {
        match event {
            Event::Command(asked) => {
                // Revocations are checked only for the one command this connector answers, so a command it does not
                // know stays silent however the account's list stands.
                if is_grant(&asked) {
                    if let Err(why) = self.revocations.may_grant(&asked.chain, now_ms) {
                        tracing::warn!(device = %hex(&asked.from), ?why, "not granting the stream key");
                        self.counts.revoked += 1;
                        if let Ok(agreement_key) = <[u8; 32]>::try_from(asked.leaf.agreement_key.as_slice()) {
                            let to = Recipient { principal: asked.from, agreement_key };
                            client.result(&to, &asked.nonce, &refusal(&why)).await.map_err(ServeError::Hub)?;
                        }
                        return Ok(());
                    }
                }
                let key_from = self.relay.key_from();
                let wrapped =
                    match wrap_for(&asked, &self.publisher, self.relay.key(), &self.channels, key_from, now_ms) {
                        Ok(Ok(wrapped)) => wrapped,
                        Ok(Err(refused)) => {
                            tracing::info!(?refused, "a command this connector does not answer");
                            self.counts.refused += 1;
                            return Ok(());
                        }
                        Err(e) => return Err(ServeError::Publish(RelayError::Seal(e))),
                    };
                for grant in wrapped {
                    client.direct(asked.from, Kind::Command, grant).await.map_err(ServeError::Hub)?;
                }
                self.counts.granted += 1;
                tracing::info!(device = %wmlhub_keys::hex(&asked.from), "granted the stream key");
                Ok(())
            }
            // A throttle is the hub asking this connector to slow down, not an end: it keeps publishing and the hub
            // reads it more slowly. Anything else it says about this connection is the end of it.
            Event::Error(e) if e.code() == Code::Throttled => {
                tracing::warn!("the hub is throttling this account");
                Ok(())
            }
            Event::Error(e) => Err(ServeError::Refused(e)),
            Event::Presence(presence) => self.presence(client, presence, now_ms).await,
            Event::Published { stream, payload, .. } => self.list(&stream, &payload, now_ms),
            _ => Ok(()),
        }
    }

    /// A principal of the account came online. If its chain says it may sign revocation lists, this connector
    /// follows its channel from now on, and the freshness floor is armed for good.
    ///
    /// The chain is verified here rather than taken from the hub, which only relays it. Believing a hub that claimed
    /// a revoker would cost nothing but strictness, but there is no reason to believe it.
    async fn presence(&mut self, client: &mut Client, presence: Presence, now_ms: u64) -> Result<(), ServeError> {
        if !presence.online || presence.chain.is_empty() {
            return Ok(());
        }
        let Ok(verified) = verify_chain(self.revocations.root(), &presence.chain, now_ms) else { return Ok(()) };
        if !verified.leaf.may_revoke || presence.principal != verified.principal {
            return Ok(());
        }
        if self.revocations.saw_revoker(verified.principal, now_ms) {
            self.state.write_revokers(&self.revocations).map_err(ServeError::State)?;
            tracing::info!(revoker = %hex(&verified.principal), "following the account's revocation list");
            self.follow(client, &verified.principal).await?;
        }
        Ok(())
    }

    /// A list published on a revoker's channel: applied if it verifies, written down, and the key rotated if it names
    /// somebody new. A list that does not verify changes nothing, and an older one arriving again from the ring's
    /// backfill is expected and quiet.
    fn list(&mut self, stream: &StreamRef, payload: &[u8], now_ms: u64) -> Result<(), ServeError> {
        let Ok(publisher) = <[u8; 32]>::try_from(stream.publisher.as_slice()) else { return Ok(()) };
        if !self.revocations.revokers().any(|r| *r == publisher)
            || stream.channel != self.revocations_channel(&publisher)
        {
            return Ok(());
        }
        let Ok(list) = RevocationList::decode(payload) else {
            tracing::warn!(revoker = %hex(&publisher), "a revocation list that does not decode");
            return Ok(());
        };
        match self.revocations.apply(&list, now_ms) {
            Ok(applied) => {
                self.state.write_revocation_list(&list).map_err(ServeError::State)?;
                self.state.write_revokers(&self.revocations).map_err(ServeError::State)?;
                self.counts.lists += 1;
                if applied.rotate {
                    let key = StreamKey::generate().map_err(|e| ServeError::State(io::Error::other(e.to_string())))?;
                    self.relay.rotate(key);
                    self.counts.rotations += 1;
                    tracing::info!("the revocation list names somebody new: rotated the stream key");
                }
                Ok(())
            }
            Err(RevocationError::Stale) => Ok(()),
            Err(e) => {
                tracing::warn!(revoker = %hex(&publisher), error = ?e, "a revocation list that does not verify");
                Ok(())
            }
        }
    }

    /// Subscribe to a revoker's list.
    async fn follow(&mut self, client: &mut Client, revoker: &[u8; 32]) -> Result<(), ServeError> {
        let channel = self.revocations_channel(revoker);
        client.subscribe(revoker, &channel, None).await.map_err(ServeError::Hub)
    }

    fn revocations_channel(&self, revoker: &[u8; 32]) -> Vec<u8> {
        self.channel_key.channel(REVOCATIONS_PURPOSE, revoker).to_vec()
    }

    fn remember(&mut self, digest: u64) {
        self.seen.push_back(digest);
        self.seen_set.insert(digest);
        if self.seen.len() > DEDUPE_FRAMES {
            if let Some(gone) = self.seen.pop_front() {
                self.seen_set.remove(&gone);
            }
        }
    }
}

enum Next {
    Frame(Option<Vec<u8>>),
    /// boxed: an `Event` carries an opened command, and the frame beside it is a pointer
    Hub(Result<Box<Event>, ClientError>),
}

/// FNV-1a: a duplicate check over bytes that are identical or not at all, so this needs to be fast rather than
/// cryptographic. A collision would drop one frame of telemetry, and the bytes come from a box the connector is
/// already trusting to tell it the truth.
fn hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}
