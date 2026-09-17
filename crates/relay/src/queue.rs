//! One connection's outbound queue, where backpressure is decided by kind (docs/PROTOCOL.md §Two ways to send).
//!
//! - Session events and direct envelopes are never dropped. Past their bound the connection is a slow consumer and
//!   is closed; it resubscribes from its position.
//! - Telemetry is coalesced: a queued envelope on the same stream with the same non-empty `coalesce` is superseded.
//!   Past its bound the oldest telemetry is dropped, counted per stream, and a `Gap` goes out before that stream's
//!   next delivered envelope.
//! - Every published stream is delivered in `seq` order. Coalescing removes the superseded envelope and appends the
//!   new one (replacing it in place put a newer seq ahead of an older one), and a repeated `Subscribe` purges what is
//!   queued for the stream before its backfill (otherwise both arrive). The model checker's order invariant found
//!   both.

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
    /// set for a published envelope of either kind: the stream it belongs to
    stream: Option<StreamKey>,
    telemetry: bool,
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
        self.push(Item { frame, bytes, stream: None, telemetry: false, session_event: false }, limits)
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
        let telemetry = kind == Kind::Telemetry;
        let item =
            Item { frame, bytes, stream: Some(key.clone()), telemetry, session_event: kind == Kind::SessionEvents };
        if !telemetry {
            return self.push(item, limits);
        }
        if let Some(i) = self.coalesce_target(key, &item.frame) {
            let old = self.items.remove(i).expect("position is in range");
            self.bytes -= old.bytes;
            self.telemetry -= 1;
        }
        while self.telemetry >= limits.queue_telemetry.max(1) {
            self.drop_oldest_telemetry();
        }
        self.push(item, limits)
    }

    /// Remove everything queued for `key`'s stream and forget its unreported drops: the subscription is being
    /// replaced (a repeated `Subscribe`, whose backfill resends what the ring holds) or ended (`Unsubscribe`).
    pub(crate) fn purge_stream(&mut self, key: &StreamKey) {
        let (mut bytes, mut session, mut telemetry) = (0, 0, 0);
        self.items.retain(|it| {
            let keep = it.stream.as_ref() != Some(key);
            if !keep {
                bytes += it.bytes;
                session += usize::from(it.session_event);
                telemetry += usize::from(it.telemetry);
            }
            keep
        });
        self.bytes -= bytes;
        self.session_events -= session;
        self.telemetry -= telemetry;
        self.dropped.remove(key);
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
            self.session_events -= usize::from(item.session_event);
            if item.telemetry {
                self.telemetry -= 1;
                let key = item.stream.as_ref().expect("a telemetry item belongs to a stream");
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

    /// Internal consistency, for the model checker: the counters agree with the items, and the bounds hold.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn check(&self, limits: &Limits) -> Result<(), String> {
        let bytes: usize = self.items.iter().map(|i| i.bytes).sum();
        let session = self.items.iter().filter(|i| i.session_event).count();
        let telemetry = self.items.iter().filter(|i| i.telemetry).count();
        if bytes != self.bytes || session != self.session_events || telemetry != self.telemetry {
            return Err(format!(
                "queue counters drifted: bytes {} vs {bytes}, session {} vs {session}, telemetry {} vs {telemetry}",
                self.bytes, self.session_events, self.telemetry
            ));
        }
        if self.bytes > limits.queue_bytes
            || self.session_events > limits.queue_session_events
            || self.telemetry > limits.queue_telemetry.max(1)
        {
            return Err(format!(
                "queue over its bounds: {} bytes, {session} session, {telemetry} telemetry",
                self.bytes
            ));
        }
        Ok(())
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
        self.telemetry += usize::from(item.telemetry);
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
            it.telemetry
                && it.stream.as_ref() == Some(key)
                && matches!(&it.frame.body, Some(Body::Envelope(old)) if old.coalesce == new.coalesce)
        })
    }

    fn drop_oldest_telemetry(&mut self) {
        let Some(i) = self.items.iter().position(|it| it.telemetry) else { return };
        let item = self.items.remove(i).expect("position is in range");
        self.bytes -= item.bytes;
        self.telemetry -= 1;
        let key = item.stream.expect("a telemetry item belongs to a stream");
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
    fn telemetry_with_the_same_coalesce_key_supersedes_and_order_is_kept() {
        let limits = Limits::default();
        let mut q = Outbound::default();
        q.push_published(&key(b"box"), env(Kind::Telemetry, 1, b"sample"), &limits).unwrap();
        q.push_published(&key(b"box"), env(Kind::Telemetry, 2, b"info"), &limits).unwrap();
        q.push_published(&key(b"box"), env(Kind::Telemetry, 3, b"sample"), &limits).unwrap();
        // seq 1 is superseded; 2 still goes before 3 (replacing in place delivered 3 then 2)
        assert_eq!(seqs(&q.take(usize::MAX)), ["e2", "e3"]);
        q.check(&limits).unwrap();
    }

    #[test]
    fn purging_a_stream_removes_only_its_items_and_keeps_the_counters_true() {
        let limits = Limits { queue_telemetry: 1, ..Limits::default() };
        let mut q = Outbound::default();
        q.push_published(&key(b"a"), env(Kind::SessionEvents, 1, b""), &limits).unwrap();
        q.push_published(&key(b"b"), env(Kind::SessionEvents, 1, b""), &limits).unwrap();
        q.push_published(&key(b"a"), env(Kind::Telemetry, 2, b""), &limits).unwrap();
        q.push_published(&key(b"a"), env(Kind::Telemetry, 3, b""), &limits).unwrap(); // drops 2: a Gap is owed on a
        q.push_frame(Frame { body: Some(Body::Ping(v1::Ping { nonce: 1 })) }, &limits).unwrap();
        q.purge_stream(&key(b"a"));
        q.check(&limits).unwrap();
        let left = q.take(usize::MAX);
        assert_eq!(left.len(), 2, "b's envelope and the ping remain");
        assert!(left.iter().all(|f| !matches!(f.body, Some(Body::Gap(_)))), "no Gap for a purged stream");
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
