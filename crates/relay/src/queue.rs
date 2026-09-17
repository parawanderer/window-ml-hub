//! One connection's outbound queue, where backpressure is decided by kind (docs/PROTOCOL.md §Two ways to send).
//!
//! - Session events and direct envelopes are never dropped. Past their bound the connection is a slow consumer and
//!   is closed; it resubscribes from its position.
//! - Telemetry is coalesced: a queued envelope on the same stream with the same non-empty `coalesce` is replaced.
//!   Past its bound the oldest telemetry is dropped, counted per stream, and a `Gap` goes out before that stream's
//!   next delivered envelope.

use std::collections::{HashMap, VecDeque};

use wmlhub_proto::v1::{self, Envelope, Frame, Kind, frame::Body};

use crate::StreamKey;
use crate::limits::Limits;

/// The queue refused an item because the connection is too far behind; the caller closes it.
#[derive(Debug, PartialEq, Eq)]
pub struct SlowConsumer;

#[derive(Debug)]
struct Item {
    frame: Frame,
    bytes: usize,
    /// set for telemetry: which stream, for coalescing, drops and gaps
    telemetry: Option<StreamKey>,
    session_event: bool,
}

/// Dropped telemetry on one stream, waiting to be reported.
#[derive(Debug, Default)]
struct Dropped {
    epoch: u64,
    count: u64,
}

#[derive(Debug, Default)]
pub(crate) struct Outbound {
    items: VecDeque<Item>,
    bytes: usize,
    session_events: usize,
    telemetry: usize,
    dropped: HashMap<StreamKey, Dropped>,
}

impl Outbound {
    /// Queue a control frame or a direct envelope: never dropped.
    pub(crate) fn push_frame(&mut self, frame: Frame, limits: &Limits) -> Result<(), SlowConsumer> {
        let bytes = encoded_len(&frame);
        self.push(Item { frame, bytes, telemetry: None, session_event: false }, limits)
    }

    /// Queue a published envelope of `key`'s stream, applying the policy of its kind.
    pub(crate) fn push_published(
        &mut self,
        key: &StreamKey,
        env: Envelope,
        limits: &Limits,
    ) -> Result<(), SlowConsumer> {
        let kind = env.kind();
        let frame = Frame { body: Some(Body::Envelope(env)) };
        let bytes = encoded_len(&frame);
        if kind != Kind::Telemetry {
            return self
                .push(Item { frame, bytes, telemetry: None, session_event: kind == Kind::SessionEvents }, limits);
        }
        if let Some(i) = self.coalesce_target(key, &frame) {
            let old = std::mem::replace(
                &mut self.items[i],
                Item { frame, bytes, telemetry: Some(key.clone()), session_event: false },
            );
            self.bytes = self.bytes - old.bytes + bytes;
            return self.check_bytes(limits);
        }
        while self.telemetry >= limits.queue_telemetry.max(1) {
            self.drop_oldest_telemetry();
        }
        self.push(Item { frame, bytes, telemetry: Some(key.clone()), session_event: false }, limits)
    }

    /// Take queued frames, oldest first, up to about `budget` bytes (always at least one frame when any is queued).
    /// A `Gap` is emitted immediately before the first envelope of a stream that lost telemetry.
    pub(crate) fn take(&mut self, budget: usize) -> Vec<Frame> {
        let mut out = Vec::new();
        let mut spent = 0;
        while let Some(item) = self.items.front() {
            if !out.is_empty() && spent + item.bytes > budget {
                break;
            }
            let item = self.items.pop_front().expect("front exists");
            self.bytes -= item.bytes;
            if item.session_event {
                self.session_events -= 1;
            }
            if let Some(key) = &item.telemetry {
                self.telemetry -= 1;
                if let Some(d) = self.dropped.remove(key) {
                    let resume_seq = match &item.frame.body {
                        Some(Body::Envelope(e)) => e.seq,
                        _ => 0,
                    };
                    out.push(Frame {
                        body: Some(Body::Gap(v1::Gap {
                            stream: Some(key.to_ref()),
                            epoch: d.epoch,
                            dropped: d.count,
                            resume_seq,
                        })),
                    });
                }
            }
            spent += item.bytes;
            out.push(item.frame);
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    fn push(&mut self, item: Item, limits: &Limits) -> Result<(), SlowConsumer> {
        if item.session_event {
            if self.session_events >= limits.queue_session_events {
                return Err(SlowConsumer);
            }
            self.session_events += 1;
        }
        if item.telemetry.is_some() {
            self.telemetry += 1;
        }
        self.bytes += item.bytes;
        self.items.push_back(item);
        self.check_bytes(limits)
    }

    fn check_bytes(&self, limits: &Limits) -> Result<(), SlowConsumer> {
        if self.bytes > limits.queue_bytes { Err(SlowConsumer) } else { Ok(()) }
    }

    fn coalesce_target(&self, key: &StreamKey, frame: &Frame) -> Option<usize> {
        let Some(Body::Envelope(new)) = &frame.body else { return None };
        if new.coalesce.is_empty() {
            return None;
        }
        self.items.iter().position(|it| {
            it.telemetry.as_ref() == Some(key)
                && matches!(&it.frame.body, Some(Body::Envelope(old)) if old.coalesce == new.coalesce)
        })
    }

    fn drop_oldest_telemetry(&mut self) {
        let Some(i) = self.items.iter().position(|it| it.telemetry.is_some()) else { return };
        let item = self.items.remove(i).expect("position is in range");
        self.bytes -= item.bytes;
        self.telemetry -= 1;
        let key = item.telemetry.expect("telemetry item");
        let epoch = match &item.frame.body {
            Some(Body::Envelope(e)) => e.epoch,
            _ => 0,
        };
        let d = self.dropped.entry(key).or_default();
        d.epoch = epoch;
        d.count += 1;
    }
}

fn encoded_len(frame: &Frame) -> usize {
    use wmlhub_proto::prost::Message;
    frame.encoded_len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(channel: &[u8]) -> StreamKey {
        StreamKey { publisher: b"rt".to_vec(), channel: channel.to_vec() }
    }

    fn env(kind: Kind, seq: u64, coalesce: &[u8]) -> Envelope {
        Envelope {
            kind: kind as i32,
            seq,
            epoch: 9,
            coalesce: coalesce.to_vec(),
            payload: vec![1; 8],
            ..Default::default()
        }
    }

    fn seqs(frames: &[Frame]) -> Vec<String> {
        frames
            .iter()
            .map(|f| match &f.body {
                Some(Body::Envelope(e)) => format!("e{}", e.seq),
                Some(Body::Gap(g)) => format!("gap{}@{}", g.dropped, g.resume_seq),
                other => format!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn telemetry_with_the_same_coalesce_key_replaces_in_place() {
        let limits = Limits::default();
        let mut q = Outbound::default();
        q.push_published(&key(b"box"), env(Kind::Telemetry, 1, b"sample"), &limits).unwrap();
        q.push_published(&key(b"box"), env(Kind::Telemetry, 2, b"info"), &limits).unwrap();
        q.push_published(&key(b"box"), env(Kind::Telemetry, 3, b"sample"), &limits).unwrap();
        assert_eq!(seqs(&q.take(usize::MAX)), ["e3", "e2"]);
    }

    #[test]
    fn empty_coalesce_never_coalesces_and_other_streams_never_do() {
        let limits = Limits::default();
        let mut q = Outbound::default();
        q.push_published(&key(b"a"), env(Kind::Telemetry, 1, b""), &limits).unwrap();
        q.push_published(&key(b"a"), env(Kind::Telemetry, 2, b""), &limits).unwrap();
        q.push_published(&key(b"b"), env(Kind::Telemetry, 3, b"s"), &limits).unwrap();
        q.push_published(&key(b"a"), env(Kind::Telemetry, 4, b"s"), &limits).unwrap();
        assert_eq!(seqs(&q.take(usize::MAX)), ["e1", "e2", "e3", "e4"]);
    }

    #[test]
    fn telemetry_past_its_bound_drops_oldest_and_reports_a_gap() {
        let limits = Limits { queue_telemetry: 2, ..Limits::default() };
        let mut q = Outbound::default();
        for seq in 1..=5 {
            q.push_published(&key(b"box"), env(Kind::Telemetry, seq, b""), &limits).unwrap();
        }
        assert_eq!(seqs(&q.take(usize::MAX)), ["gap3@4", "e4", "e5"]);
        // reported once
        q.push_published(&key(b"box"), env(Kind::Telemetry, 6, b""), &limits).unwrap();
        assert_eq!(seqs(&q.take(usize::MAX)), ["e6"]);
    }

    #[test]
    fn telemetry_pressure_never_drops_a_session_event() {
        let limits = Limits { queue_telemetry: 1, ..Limits::default() };
        let mut q = Outbound::default();
        q.push_published(&key(b"s"), env(Kind::SessionEvents, 1, b""), &limits).unwrap();
        q.push_published(&key(b"box"), env(Kind::Telemetry, 1, b""), &limits).unwrap();
        q.push_published(&key(b"box"), env(Kind::Telemetry, 2, b""), &limits).unwrap();
        assert_eq!(seqs(&q.take(usize::MAX)), ["e1", "gap1@2", "e2"]);
    }

    #[test]
    fn session_events_past_their_bound_are_a_slow_consumer() {
        let limits = Limits { queue_session_events: 2, ..Limits::default() };
        let mut q = Outbound::default();
        q.push_published(&key(b"s"), env(Kind::SessionEvents, 1, b""), &limits).unwrap();
        q.push_published(&key(b"s"), env(Kind::SessionEvents, 2, b""), &limits).unwrap();
        assert_eq!(q.push_published(&key(b"s"), env(Kind::SessionEvents, 3, b""), &limits), Err(SlowConsumer));
    }

    #[test]
    fn bytes_past_their_bound_are_a_slow_consumer() {
        let limits = Limits { queue_bytes: 40, ..Limits::default() };
        let mut q = Outbound::default();
        let big = Frame { body: Some(Body::Envelope(Envelope { payload: vec![0; 64], ..Default::default() })) };
        assert_eq!(q.push_frame(big, &limits), Err(SlowConsumer));
    }

    #[test]
    fn take_respects_the_budget_but_always_makes_progress() {
        let limits = Limits::default();
        let mut q = Outbound::default();
        for seq in 1..=3 {
            q.push_published(&key(b"s"), env(Kind::SessionEvents, seq, b""), &limits).unwrap();
        }
        assert_eq!(seqs(&q.take(1)), ["e1"]);
        assert_eq!(q.len(), 2);
        assert_eq!(seqs(&q.take(usize::MAX)), ["e2", "e3"]);
        assert!(q.is_empty());
    }
}
