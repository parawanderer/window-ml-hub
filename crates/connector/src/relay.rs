//! Publishing a box's frames on the two channels the relay protocol needs (docs/design/box-connector.md
//! §Consequence for the relay protocol).
//!
//! `KIND_TELEMETRY` is coalesced and dropped oldest-first, which is right for samples and wrong for edges, so an
//! edge rides `KIND_SESSION_EVENTS` (lossless, ordered, and a subscriber that falls behind resyncs from the ring)
//! and a sample rides telemetry with a coalesce key. Each channel has its own counter, because a subscriber checks
//! a stream's order against the publisher's own count rather than against the hub's `seq`.

use wmlhub_box::{Route, route};
use wmlhub_client::{Client, ClientError};
use wmlhub_proto::v1::Kind;
use wmlhub_seal::{SealError, Sender, StreamKey, seal_frame};

/// The two channels one box publishes on. Both are keyed names (`ChannelKey::channel`), so the hub cannot tell which
/// box a channel belongs to.
#[derive(Debug, Clone)]
pub struct Channels {
    pub edge: Vec<u8>,
    pub sample: Vec<u8>,
}

/// What became of one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relayed {
    /// the connector's own: a `hello` belongs to the connection it arrived on
    Consumed,
    /// published on the lossless channel, with the counter it carried
    Edge { counter: u64 },
    /// published on the sample channel; an empty coalesce key is one that may never be superseded
    Sample { counter: u64, coalesce: &'static [u8] },
}

#[derive(Debug)]
pub enum RelayError {
    Seal(SealError),
    Client(ClientError),
}

/// One box's traffic, sealed and published.
pub struct Relay<'a> {
    publisher: Sender<'a>,
    key: &'a StreamKey,
    channels: Channels,
    edge_counter: u64,
    sample_counter: u64,
}

impl<'a> Relay<'a> {
    pub fn new(publisher: Sender<'a>, key: &'a StreamKey, channels: Channels) -> Self {
        Self { publisher, key, channels, edge_counter: 0, sample_counter: 0 }
    }

    /// Where this frame went, without publishing it: what the connector logs, and what the tests assert on.
    pub fn route(frame: &[u8]) -> Relayed {
        match route(frame).0 {
            Route::Consume => Relayed::Consumed,
            Route::Edge => Relayed::Edge { counter: 0 },
            Route::Sample { coalesce } => Relayed::Sample { counter: 0, coalesce },
        }
    }

    /// Seal one frame and publish it on the channel its kind belongs to. The frame's bytes are sealed as they came.
    pub async fn frame(&mut self, client: &mut Client, frame: &[u8]) -> Result<Relayed, RelayError> {
        match Self::route(frame) {
            Relayed::Consumed => Ok(Relayed::Consumed),
            Relayed::Edge { .. } => {
                self.edge_counter += 1;
                let sealed = self.seal(&self.channels.edge.clone(), self.edge_counter, frame)?;
                client
                    .publish(&self.channels.edge, Kind::SessionEvents, sealed.into())
                    .await
                    .map_err(RelayError::Client)?;
                Ok(Relayed::Edge { counter: self.edge_counter })
            }
            Relayed::Sample { coalesce, .. } => {
                self.sample_counter += 1;
                let sealed = self.seal(&self.channels.sample.clone(), self.sample_counter, frame)?;
                client
                    .publish_coalesced(&self.channels.sample, Kind::Telemetry, sealed.into(), coalesce)
                    .await
                    .map_err(RelayError::Client)?;
                Ok(Relayed::Sample { counter: self.sample_counter, coalesce })
            }
        }
    }

    fn seal(&self, channel: &[u8], counter: u64, frame: &[u8]) -> Result<Vec<u8>, RelayError> {
        seal_frame(&self.publisher, channel, self.key, counter, frame).map_err(RelayError::Seal)
    }
}
