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
//!
//! Items are ENCODED frames (`Bytes`, length prefix included), with the few facts the queue decides on (stream, kind,
//! seq, epoch, coalesce key) kept beside them. A published envelope's bytes are shared with the ring and with every
//! other subscriber; nothing here decodes or re-encodes one.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use wmlhub_proto::bytes::Bytes;
use wmlhub_proto::encode_frame;
use wmlhub_proto::v1::{self, Frame, Kind, frame::Body};

use crate::StreamKey;
use crate::limits::Limits;
use crate::ring::Entry;

/// The queue refused an item because the connection is too far behind; the caller closes it.
#[derive(Debug, PartialEq, Eq)]
pub struct SlowConsumer;

#[derive(Debug)]
struct Item {
    wire: Bytes,
    /// set for a published envelope of either kind: the stream it belongs to
    stream: Option<Arc<StreamKey>>,
    seq: u64,
    epoch: u64,
    coalesce: Bytes,
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
    dropped: HashMap<Arc<StreamKey>, Dropped>,
}

impl Outbound {
    /// Queue a control frame or a direct envelope: never dropped. Encoded here, once.
    pub(crate) fn push_frame(&mut self, frame: &Frame, limits: &Limits) -> Result<(), SlowConsumer> {
        let item = Item {
            wire: encode_frame(frame),
            stream: None,
            seq: 0,
            epoch: 0,
            coalesce: Bytes::new(),
            telemetry: false,
            session_event: false,
        };
        self.push(item, limits)
    }

    /// Queue a published envelope of `stream`, applying the policy of its kind. `entry` is shared, not copied.
    pub(crate) fn push_published(
        &mut self,
        stream: &Arc<StreamKey>,
        kind: Kind,
        epoch: u64,
        entry: &Entry,
        limits: &Limits,
    ) -> Result<(), SlowConsumer> {
        let telemetry = kind == Kind::Telemetry;
        let item = Item {
            wire: entry.wire.clone(),
            stream: Some(stream.clone()),
            seq: entry.seq,
            epoch,
            coalesce: entry.coalesce.clone(),
            telemetry,
            session_event: kind == Kind::SessionEvents,
        };
        if !telemetry {
            return self.push(item, limits);
        }
        if let Some(i) = self.coalesce_target(stream, &item.coalesce) {
            let old = self.items.remove(i).expect("position is in range");
            self.bytes -= old.wire.len();
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
            let keep = it.stream.as_deref() != Some(key);
            if !keep {
                bytes += it.wire.len();
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
    pub(crate) fn take(&mut self, budget: usize) -> Vec<Bytes> {
        let mut out = Vec::new();
        let mut spent = 0;
        while let Some(item) = self.items.front() {
            if !out.is_empty() && spent + item.wire.len() > budget {
                break;
            }
            let item = self.items.pop_front().expect("front exists");
            self.bytes -= item.wire.len();
            self.session_events -= usize::from(item.session_event);
            if item.telemetry {
                self.telemetry -= 1;
                let key = item.stream.as_ref().expect("a telemetry item belongs to a stream");
                if let Some(d) = self.dropped.remove(key) {
                    let gap =
                        v1::Gap { stream: Some(key.to_ref()), epoch: d.epoch, dropped: d.count, resume_seq: item.seq };
                    out.push(encode_frame(&Frame { body: Some(Body::Gap(gap)) }));
                }
            }
            spent += item.wire.len();
            out.push(item.wire);
        }
        out
    }

    /// Internal consistency, for the model checker: the counters agree with the items, and the bounds hold.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn check(&self, limits: &Limits) -> Result<(), String> {
        let bytes: usize = self.items.iter().map(|i| i.wire.len()).sum();
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
        self.bytes += item.wire.len();
        self.items.push_back(item);
        if self.bytes > limits.queue_bytes { Err(SlowConsumer) } else { Ok(()) }
    }

    fn coalesce_target(&self, stream: &StreamKey, coalesce: &Bytes) -> Option<usize> {
        if coalesce.is_empty() {
            return None;
        }
        self.items
            .iter()
            .position(|it| it.telemetry && it.stream.as_deref() == Some(stream) && it.coalesce == *coalesce)
    }

    fn drop_oldest_telemetry(&mut self) {
        let Some(i) = self.items.iter().position(|it| it.telemetry) else { return };
        let item = self.items.remove(i).expect("position is in range");
        self.bytes -= item.wire.len();
        self.telemetry -= 1;
        let key = item.stream.expect("a telemetry item belongs to a stream");
        let d = self.dropped.entry(key).or_default();
        d.epoch = item.epoch;
        d.count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wmlhub_proto::v1::Envelope;

    fn key(channel: &[u8]) -> Arc<StreamKey> {
        Arc::new(StreamKey { publisher: b"rt".to_vec(), channel: channel.to_vec() })
    }

    fn entry(kind: Kind, seq: u64, coalesce: &[u8]) -> (Kind, Entry) {
        let env = Envelope {
            kind: kind as i32,
            seq,
            epoch: 9,
            coalesce: Bytes::copy_from_slice(coalesce),
            payload: vec![1; 8].into(),
            ..Default::default()
        };
        let wire = encode_frame(&Frame { body: Some(Body::Envelope(env)) });
        (kind, Entry { seq, wire, coalesce: Bytes::copy_from_slice(coalesce) })
    }

    fn push(q: &mut Outbound, k: &Arc<StreamKey>, e: (Kind, Entry), limits: &Limits) -> Result<(), SlowConsumer> {
        q.push_published(k, e.0, 9, &e.1, limits)
    }

    fn seqs(wires: &[Bytes]) -> Vec<String> {
        wires
            .iter()
            .map(|w| match wmlhub_proto::decode_frames(w, usize::MAX).unwrap().remove(0).body {
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
        let b = key(b"box");
        push(&mut q, &b, entry(Kind::Telemetry, 1, b"sample"), &limits).unwrap();
        push(&mut q, &b, entry(Kind::Telemetry, 2, b"info"), &limits).unwrap();
        push(&mut q, &b, entry(Kind::Telemetry, 3, b"sample"), &limits).unwrap();
        // seq 1 is superseded; 2 still goes before 3 (replacing in place delivered 3 then 2)
        assert_eq!(seqs(&q.take(usize::MAX)), ["e2", "e3"]);
        q.check(&limits).unwrap();
    }

    #[test]
    fn a_queued_published_envelope_shares_its_bytes() {
        let limits = Limits::default();
        let (mut q1, mut q2) = (Outbound::default(), Outbound::default());
        let e = entry(Kind::SessionEvents, 1, b"");
        push(&mut q1, &key(b"s"), e.clone(), &limits).unwrap();
        push(&mut q2, &key(b"s"), e.clone(), &limits).unwrap();
        let (a, b) = (q1.take(usize::MAX).remove(0), q2.take(usize::MAX).remove(0));
        assert_eq!(a.as_ptr(), e.1.wire.as_ptr());
        assert_eq!(b.as_ptr(), e.1.wire.as_ptr());
    }

    #[test]
    fn purging_a_stream_removes_only_its_items_and_keeps_the_counters_true() {
        let limits = Limits { queue_telemetry: 1, ..Limits::default() };
        let mut q = Outbound::default();
        let (a, b) = (key(b"a"), key(b"b"));
        push(&mut q, &a, entry(Kind::SessionEvents, 1, b""), &limits).unwrap();
        push(&mut q, &b, entry(Kind::SessionEvents, 1, b""), &limits).unwrap();
        push(&mut q, &a, entry(Kind::Telemetry, 2, b""), &limits).unwrap();
        push(&mut q, &a, entry(Kind::Telemetry, 3, b""), &limits).unwrap(); // drops 2: a Gap is owed on a
        q.push_frame(&Frame { body: Some(Body::Ping(v1::Ping { nonce: 1 })) }, &limits).unwrap();
        q.purge_stream(&a);
        q.check(&limits).unwrap();
        let left = q.take(usize::MAX);
        assert_eq!(left.len(), 2, "b's envelope and the ping remain");
        assert!(seqs(&left).iter().all(|s| !s.starts_with("gap")), "no Gap for a purged stream");
    }

    #[test]
    fn empty_coalesce_never_coalesces_and_other_streams_never_do() {
        let limits = Limits::default();
        let mut q = Outbound::default();
        let (a, b) = (key(b"a"), key(b"b"));
        push(&mut q, &a, entry(Kind::Telemetry, 1, b""), &limits).unwrap();
        push(&mut q, &a, entry(Kind::Telemetry, 2, b""), &limits).unwrap();
        push(&mut q, &b, entry(Kind::Telemetry, 3, b"s"), &limits).unwrap();
        push(&mut q, &a, entry(Kind::Telemetry, 4, b"s"), &limits).unwrap();
        assert_eq!(seqs(&q.take(usize::MAX)), ["e1", "e2", "e3", "e4"]);
    }

    #[test]
    fn telemetry_past_its_bound_drops_oldest_and_reports_a_gap() {
        let limits = Limits { queue_telemetry: 2, ..Limits::default() };
        let mut q = Outbound::default();
        let b = key(b"box");
        for seq in 1..=5 {
            push(&mut q, &b, entry(Kind::Telemetry, seq, b""), &limits).unwrap();
        }
        assert_eq!(seqs(&q.take(usize::MAX)), ["gap3@4", "e4", "e5"]);
        // reported once
        push(&mut q, &b, entry(Kind::Telemetry, 6, b""), &limits).unwrap();
        assert_eq!(seqs(&q.take(usize::MAX)), ["e6"]);
    }

    #[test]
    fn telemetry_pressure_never_drops_a_session_event() {
        let limits = Limits { queue_telemetry: 1, ..Limits::default() };
        let mut q = Outbound::default();
        let (s, b) = (key(b"s"), key(b"box"));
        push(&mut q, &s, entry(Kind::SessionEvents, 1, b""), &limits).unwrap();
        push(&mut q, &b, entry(Kind::Telemetry, 1, b""), &limits).unwrap();
        push(&mut q, &b, entry(Kind::Telemetry, 2, b""), &limits).unwrap();
        assert_eq!(seqs(&q.take(usize::MAX)), ["e1", "gap1@2", "e2"]);
    }

    #[test]
    fn session_events_past_their_bound_are_a_slow_consumer() {
        let limits = Limits { queue_session_events: 2, ..Limits::default() };
        let mut q = Outbound::default();
        let s = key(b"s");
        push(&mut q, &s, entry(Kind::SessionEvents, 1, b""), &limits).unwrap();
        push(&mut q, &s, entry(Kind::SessionEvents, 2, b""), &limits).unwrap();
        assert_eq!(push(&mut q, &s, entry(Kind::SessionEvents, 3, b""), &limits), Err(SlowConsumer));
    }

    #[test]
    fn bytes_past_their_bound_are_a_slow_consumer() {
        let limits = Limits { queue_bytes: 40, ..Limits::default() };
        let mut q = Outbound::default();
        let big = Frame { body: Some(Body::Envelope(Envelope { payload: vec![0; 64].into(), ..Default::default() })) };
        assert_eq!(q.push_frame(&big, &limits), Err(SlowConsumer));
    }

    #[test]
    fn take_respects_the_budget_but_always_makes_progress() {
        let limits = Limits::default();
        let mut q = Outbound::default();
        let s = key(b"s");
        for seq in 1..=3 {
            push(&mut q, &s, entry(Kind::SessionEvents, seq, b""), &limits).unwrap();
        }
        assert_eq!(seqs(&q.take(1)), ["e1"]);
        assert_eq!(q.len(), 2);
        assert_eq!(seqs(&q.take(usize::MAX)), ["e2", "e3"]);
        assert!(q.is_empty());
    }
}
