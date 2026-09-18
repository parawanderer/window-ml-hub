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

use tokio::sync::{mpsc, watch};
use wmlhub_box::read;
use wmlhub_client::{Client, ClientError, Event};
use wmlhub_proto::v1::{Error as HubError, Kind, error::Code};
use wmlhub_seal::{Sender, StreamKey};

use crate::grant::wrap_for;
use crate::relay::{Channels, Relay, RelayError, Relayed};

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
}

/// One box's traffic on one hub connection: published, and granted to whoever may read it.
pub struct Serving<'a> {
    relay: Relay<'a>,
    channels: Channels,
    key: &'a StreamKey,
    publisher: Sender<'a>,
    /// the hashes of frames published recently, oldest first
    seen: VecDeque<u64>,
    seen_set: HashSet<u64>,
    /// the newest `at_ms` published, which is what the box side resumes from
    published: watch::Sender<Option<u64>>,
    counts: Served,
}

impl<'a> Serving<'a> {
    pub fn new(
        publisher: Sender<'a>,
        key: &'a StreamKey,
        channels: Channels,
        published: watch::Sender<Option<u64>>,
    ) -> Self {
        Self {
            relay: Relay::new(Sender { identity: publisher.identity, chain: publisher.chain }, key, channels.clone()),
            channels,
            key,
            publisher,
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

    /// What the hub had to say. A connector subscribes to nothing, so almost all of it is somebody else's business.
    async fn event(&mut self, client: &mut Client, event: Event, now_ms: u64) -> Result<(), ServeError> {
        match event {
            Event::Command(asked) => {
                let wrapped = match wrap_for(&asked, &self.publisher, self.key, &self.channels, now_ms) {
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
            _ => Ok(()),
        }
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
