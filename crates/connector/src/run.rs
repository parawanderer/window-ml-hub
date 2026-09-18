//! Staying connected to a box: reconnecting when the stream ends, and asking for what was missed
//! (docs/design/box-connector.md §Reading the stream).
//!
//! A box restarts, a network blinks, a laptop sleeps. What the connector must not do on the way back is publish the
//! same frame twice, so it asks for a backfill covering the gap and the box replays frames it has already seen. The
//! duplicate check is on the publishing side (`crate::serve`), because it belongs with the thing that knows what was
//! published: this side hands frames over, and a frame handed over is not yet a frame that landed.
//!
//! This side owns no hub connection at all. It reads and forwards, with the channel's own backpressure as its only
//! limit, and learns where to resume from a watch the publisher writes. Two halves rather than one loop because one
//! websocket has to carry both what this publishes and what devices ask of it, and a loop that is waiting on a box
//! is not reading its hub.

use std::time::Duration;

use tokio::sync::{mpsc, watch};
use wmlhub_box::{Route, route};

use crate::events::{Events, IngestError};
use crate::http::Target;

/// Frames waiting to be published. A full channel stops this side reading the box, which is the right way round: a
/// hub that cannot keep up should slow the connector down rather than fill its memory.
pub const PENDING_FRAMES: usize = 256;
/// Asked for on top of the measured gap, to cover the clock skew between a box and this connector.
pub const BACKFILL_SLACK: Duration = Duration::from_secs(30);
/// The longest a reconnect waits, reached by doubling from the first.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);
const FIRST_BACKOFF: Duration = Duration::from_millis(500);

/// What one pass over a box's stream did, for the caller's logs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pass {
    /// frames handed to the publishing side; how many of them were new is its business
    pub forwarded: u64,
    /// frames this connector consumed (a `hello`, which belongs to its own connection)
    pub consumed: u64,
}

/// Why reading a box stopped.
#[derive(Debug)]
pub enum ConnectorError {
    /// the publishing side is gone, so there is nobody to hand frames to
    Stopped,
}

/// One box, read for as long as somebody is publishing what it says.
pub struct Connector {
    target: Target,
    frames: mpsc::Sender<Vec<u8>>,
    /// the newest `at_ms` PUBLISHED, which is what a reconnect asks to resume from. Written by the publisher, because
    /// a frame this side handed over and the hub never took is a frame the box must be asked for again.
    published: watch::Receiver<Option<u64>>,
}

impl Connector {
    pub fn new(target: Target, frames: mpsc::Sender<Vec<u8>>, published: watch::Receiver<Option<u64>>) -> Self {
        Self { target, frames, published }
    }

    /// Read this box for as long as the publishing side is there, reconnecting to the box for as long as that takes.
    pub async fn run(&mut self, now_ms: impl Fn() -> u64) -> ConnectorError {
        let mut backoff = FIRST_BACKOFF;
        loop {
            match self.pass(&now_ms).await {
                Ok(pass) => {
                    // any progress at all means the box is there, so the next outage starts from the short wait
                    if pass.forwarded > 0 || pass.consumed > 0 {
                        backoff = FIRST_BACKOFF;
                    }
                }
                Err(Passed::Stopped) => return ConnectorError::Stopped,
                // A box that went away is this loop's own business: it waits and asks again. A caller that wants to
                // say so in a log drives `pass` itself, which hands the error back.
                Err(Passed::Box(_)) => {}
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// One connection to the box, from its hello to whatever ends it.
    pub async fn pass(&mut self, now_ms: &impl Fn() -> u64) -> Result<Pass, Passed> {
        let since = self.since(now_ms());
        let mut events = Events::open(&self.target, since).await.map_err(Passed::Box)?;
        let mut pass = Pass::default();
        loop {
            let frame = match events.next_frame().await {
                Ok(frame) => frame,
                // the stream ended or failed: the pass is over, and what it did still counts
                Err(e) => return if pass == Pass::default() { Err(Passed::Box(e)) } else { Ok(pass) },
            };
            // a hello belongs to this connection and is never relayed as another's
            if route(&frame).0 == Route::Consume {
                pass.consumed += 1;
                continue;
            }
            self.frames.send(frame).await.map_err(|_| Passed::Stopped)?;
            pass.forwarded += 1;
        }
    }

    /// How far back to ask the box to replay: the gap since the newest frame published, and some slack.
    fn since(&self, now_ms: u64) -> Option<u64> {
        let last = (*self.published.borrow())?;
        let gap = now_ms.saturating_sub(last);
        Some(gap.saturating_add(BACKFILL_SLACK.as_millis() as u64))
    }
}

/// Which side of the connector a pass failed on: a box that went away is ordinary, a publisher that stopped is not.
#[derive(Debug)]
pub enum Passed {
    Box(IngestError),
    Stopped,
}
