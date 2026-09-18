//! Staying connected to a box: reconnecting when the stream ends, asking for what was missed, and publishing each
//! frame exactly once (docs/design/box-connector.md §Reading the stream).
//!
//! A box restarts, a network blinks, a laptop sleeps. What the connector must not do on the way back is publish the
//! same frame twice: it asks for a backfill covering the gap, and the box replays frames it already relayed. There is
//! no frame id to compare, so recently published frames are remembered by hash — the bytes are identical on replay,
//! since nothing between the box and here re-encodes them, which is the same property the whole design rests on.

use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use wmlhub_box::read;
use wmlhub_client::Client;

use crate::events::{Events, IngestError};
use crate::http::Target;
use crate::relay::{Relay, RelayError, Relayed};

/// Frames remembered for the duplicate check. A backfill longer than this would republish, so it is sized well past
/// what a reconnect asks for: a box sends a few frames a second, and this covers minutes of them.
pub const DEDUPE_FRAMES: usize = 4_096;
/// Asked for on top of the measured gap, to cover the clock skew between a box and this connector.
pub const BACKFILL_SLACK: Duration = Duration::from_secs(30);
/// The longest a reconnect waits, reached by doubling from the first.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);
const FIRST_BACKOFF: Duration = Duration::from_millis(500);

#[derive(Debug)]
pub enum ConnectorError {
    /// the hub connection failed: the caller reconnects it, since it owns the certificate and the handshake
    Hub(RelayError),
}

/// What one pass over a box's stream did, for the caller's logs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pass {
    pub published: u64,
    /// frames the box replayed that had already been published
    pub duplicates: u64,
    /// frames the connector consumed (a `hello`, which belongs to its own connection)
    pub consumed: u64,
}

/// One box, relayed for as long as the hub connection lasts.
pub struct Connector<'a> {
    target: Target,
    relay: Relay<'a>,
    /// the hashes of frames published recently, oldest first
    seen: VecDeque<u64>,
    seen_set: HashSet<u64>,
    /// the newest `at_ms` published, which is what a reconnect asks to resume from
    last_at_ms: Option<u64>,
}

impl<'a> Connector<'a> {
    pub fn new(target: Target, relay: Relay<'a>) -> Self {
        Self { target, relay, seen: VecDeque::new(), seen_set: HashSet::new(), last_at_ms: None }
    }

    /// Read this box until the hub connection fails, reconnecting to the box for as long as that takes. Returns only
    /// when publishing fails, because that is the caller's to fix; a box that goes away is this loop's own business.
    pub async fn run(&mut self, client: &mut Client, now_ms: impl Fn() -> u64) -> ConnectorError {
        let mut backoff = FIRST_BACKOFF;
        loop {
            match self.pass(client, &now_ms).await {
                Ok(pass) => {
                    // any progress at all means the box is there, so the next outage starts from the short wait
                    if pass.published > 0 || pass.consumed > 0 {
                        backoff = FIRST_BACKOFF;
                    }
                }
                Err(Passed::Hub(e)) => return ConnectorError::Hub(e),
                // A box that went away is this loop's own business: it waits and asks again. A caller that wants to
                // say so in a log drives `pass` itself, which hands the error back.
                Err(Passed::Box(_)) => {}
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// One connection to the box, from its hello to whatever ends it.
    pub async fn pass(&mut self, client: &mut Client, now_ms: &impl Fn() -> u64) -> Result<Pass, Passed> {
        let since = self.since(now_ms());
        let mut events = Events::open(&self.target, since).await.map_err(Passed::Box)?;
        let mut pass = Pass::default();
        loop {
            let frame = match events.next_frame().await {
                Ok(frame) => frame,
                // the stream ended or failed: the pass is over, and what it did still counts
                Err(e) => return if pass == Pass::default() { Err(Passed::Box(e)) } else { Ok(pass) },
            };
            match self.frame(client, &frame).await.map_err(Passed::Hub)? {
                Some(Relayed::Consumed) => pass.consumed += 1,
                Some(_) => pass.published += 1,
                None => pass.duplicates += 1,
            }
        }
    }

    /// Publish one frame unless it has been published already. `None` means it was a duplicate.
    async fn frame(&mut self, client: &mut Client, frame: &[u8]) -> Result<Option<Relayed>, RelayError> {
        let digest = hash(frame);
        if self.seen_set.contains(&digest) {
            return Ok(None);
        }
        let landed = self.relay.frame(client, frame).await?;
        self.remember(digest);
        if let Some(at_ms) = read(frame).at_ms {
            // a box whose clock stepped back would otherwise pin the resume point to a future it never reaches
            self.last_at_ms = Some(self.last_at_ms.map_or(at_ms, |last| last.max(at_ms)));
        }
        Ok(Some(landed))
    }

    /// How far back to ask the box to replay: the gap since the newest frame published, and some slack.
    fn since(&self, now_ms: u64) -> Option<u64> {
        let last = self.last_at_ms?;
        let gap = now_ms.saturating_sub(last);
        Some(gap.saturating_add(BACKFILL_SLACK.as_millis() as u64))
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

/// Which side of the connector a pass failed on: a box that went away is ordinary, a hub that refused is not.
#[derive(Debug)]
pub enum Passed {
    Box(IngestError),
    Hub(RelayError),
}

/// FNV-1a over the frame's bytes: a duplicate check, not a signature, and the frames it compares are ones the
/// publisher already signed.
fn hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
