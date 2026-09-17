//! One stream's ring: the bounded recent history a subscriber backfills from (docs/PROTOCOL.md §Streams, rings
//! and resuming). A cache, never the authority.
//!
//! Entries are ENCODED frames. A published envelope is stamped and encoded exactly once, here, and the same bytes are
//! retained, fanned out to every subscriber and replayed to every backfill, shared by reference count. Before this, a
//! publish cloned its envelope (payload included) once per subscriber and every connection re-encoded it.

use std::collections::VecDeque;

use wmlhub_proto::bytes::Bytes;
use wmlhub_proto::encode_frame;
use wmlhub_proto::v1::{Envelope, Frame, Kind, Position, frame::Body};

/// A published envelope as it travels: its seq, its encoded frame, and its coalesce key (kept beside the bytes so a
/// queue never decodes a frame to coalesce it).
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) seq: u64,
    pub(crate) wire: Bytes,
    pub(crate) coalesce: Bytes,
}

#[derive(Debug)]
pub(crate) struct Ring {
    pub(crate) kind: Kind,
    pub(crate) epoch: u64,
    /// the seq of the newest envelope ever published, retained or not
    pub(crate) seq: u64,
    entries: VecDeque<Entry>,
    /// encoded bytes retained: what the account's ring budget counts
    pub(crate) bytes: usize,
    /// logical clock of the last publish, for choosing which idle stream to evict
    pub(crate) touched: u64,
}

/// What a subscriber gets: the entries to send, and whether its record has a gap before them.
#[derive(Debug)]
pub(crate) struct Backfill {
    pub(crate) entries: Vec<Entry>,
    pub(crate) truncated: bool,
}

/// What a publish did to the ring's memory.
#[derive(Debug)]
pub(crate) struct Published {
    pub(crate) entry: Entry,
    pub(crate) added: usize,
    pub(crate) freed: usize,
}

impl Ring {
    pub(crate) fn new(kind: Kind, epoch: u64, touched: u64) -> Self {
        Self { kind, epoch, seq: 0, entries: VecDeque::new(), bytes: 0, touched }
    }

    /// Stamp `env` with this ring's epoch and next seq, encode it once, retain it (evicting past `capacity`), and
    /// return the entry every subscriber will share.
    pub(crate) fn publish(&mut self, mut env: Envelope, capacity: usize, touched: u64) -> Published {
        self.seq += 1;
        env.seq = self.seq;
        env.epoch = self.epoch;
        self.touched = touched;
        let coalesce = env.coalesce.clone();
        let wire = encode_frame(&Frame { body: Some(Body::Envelope(env)) });
        let entry = Entry { seq: self.seq, wire, coalesce };
        // Under test and fuzzing, prove the metadata kept beside the bytes says what the bytes say. Once, here: `Bytes`
        // is immutable, so an entry that was right when it was made stays right.
        #[cfg(any(test, feature = "testing"))]
        if let Err(e) = self.verify_entry(&entry) {
            panic!("{e}");
        }
        let (mut added, mut freed) = (0, 0);
        if capacity > 0 {
            added = entry.wire.len();
            self.bytes += added;
            self.entries.push_back(entry.clone());
            while self.entries.len() > capacity {
                freed += self.evict_oldest();
            }
        }
        Published { entry, added, freed }
    }

    /// Drop the oldest retained entry; the bytes freed.
    pub(crate) fn evict_oldest(&mut self) -> usize {
        match self.entries.pop_front() {
            Some(e) => {
                self.bytes -= e.wire.len();
                e.wire.len()
            }
            None => 0,
        }
    }

    /// Everything after `since`. `truncated` is true when entries between `since` (or the stream's start) and the
    /// first one returned are no longer retained.
    pub(crate) fn backfill(&self, since: Option<&Position>) -> Backfill {
        let after = match since {
            Some(p) if p.epoch == self.epoch => p.seq,
            _ => 0,
        };
        let first_retained = self.entries.front().map_or(self.seq + 1, |e| e.seq);
        let entries: Vec<Entry> = self.entries.iter().filter(|e| e.seq > after).cloned().collect();
        let stale_epoch = since.is_some_and(|p| p.epoch != self.epoch && p.seq > 0);
        Backfill { truncated: first_retained > after + 1 || stale_epoch, entries }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Internal consistency, for the model checker: bytes agree with the entries, seqs strictly increase and end at
    /// or before `seq`, and the capacity holds. (What each entry's bytes say is verified when it is made.)
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn check(&self, capacity: usize) -> Result<(), String> {
        let bytes: usize = self.entries.iter().map(|e| e.wire.len()).sum();
        if bytes != self.bytes {
            return Err(format!("ring bytes drifted: {} vs {bytes}", self.bytes));
        }
        if self.entries.len() > capacity {
            return Err(format!("ring over capacity: {} > {capacity}", self.entries.len()));
        }
        let mut last = 0;
        for e in &self.entries {
            if e.seq <= last || e.seq > self.seq {
                return Err(format!("ring entry out of order: seq {} after {last}", e.seq));
            }
            last = e.seq;
        }
        Ok(())
    }

    /// An entry's bytes decode to exactly one envelope carrying its own seq, this ring's epoch and kind, and its
    /// recorded coalesce key.
    #[cfg(any(test, feature = "testing"))]
    fn verify_entry(&self, e: &Entry) -> Result<(), String> {
        let frames = wmlhub_proto::decode_frames(&e.wire, usize::MAX).map_err(|x| format!("ring entry: {x}"))?;
        let [Frame { body: Some(Body::Envelope(env)) }] = frames.as_slice() else {
            return Err("ring entry is not exactly one envelope frame".into());
        };
        if env.seq != e.seq || env.epoch != self.epoch || env.kind != self.kind as i32 || env.coalesce != e.coalesce {
            return Err(format!(
                "ring entry {} mislabelled: bytes say seq {} epoch {} kind {}",
                e.seq, env.seq, env.epoch, env.kind
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(n: usize) -> Envelope {
        Envelope { kind: Kind::SessionEvents as i32, payload: vec![0; n].into(), ..Default::default() }
    }

    fn filled(capacity: usize, count: usize) -> Ring {
        let mut r = Ring::new(Kind::SessionEvents, 42, 0);
        for i in 0..count {
            r.publish(env(10), capacity, i as u64);
        }
        r
    }

    fn seqs(b: &Backfill) -> Vec<u64> {
        b.entries.iter().map(|e| e.seq).collect()
    }

    #[test]
    fn publish_stamps_encodes_once_and_evicts_past_capacity() {
        let r = filled(3, 5);
        assert_eq!(r.seq, 5);
        r.check(3).unwrap();
        let b = r.backfill(None);
        assert_eq!(seqs(&b), [3, 4, 5]);
    }

    #[test]
    fn the_retained_entry_and_the_fanned_out_entry_share_bytes() {
        let mut r = Ring::new(Kind::SessionEvents, 1, 0);
        let p = r.publish(env(64), 4, 0);
        let retained = r.backfill(None).entries.remove(0);
        assert_eq!(p.entry.wire.as_ptr(), retained.wire.as_ptr(), "one encoding, shared");
        assert_eq!(p.added, p.entry.wire.len());
    }

    #[test]
    fn a_fresh_subscriber_to_a_full_history_is_not_truncated() {
        let b = filled(10, 4).backfill(None);
        assert_eq!(seqs(&b), [1, 2, 3, 4]);
        assert!(!b.truncated);
    }

    #[test]
    fn a_fresh_subscriber_after_eviction_is_truncated() {
        assert!(filled(3, 5).backfill(None).truncated);
    }

    #[test]
    fn resuming_within_the_ring_sends_only_what_is_newer() {
        let b = filled(3, 5).backfill(Some(&Position { epoch: 42, seq: 3 }));
        assert_eq!(seqs(&b), [4, 5]);
        assert!(!b.truncated);
    }

    #[test]
    fn resuming_from_before_the_ring_is_truncated() {
        let b = filled(3, 5).backfill(Some(&Position { epoch: 42, seq: 1 }));
        assert_eq!(seqs(&b), [3, 4, 5]);
        assert!(b.truncated);
    }

    #[test]
    fn resuming_at_the_head_sends_nothing_and_is_not_truncated() {
        let b = filled(3, 5).backfill(Some(&Position { epoch: 42, seq: 5 }));
        assert!(b.entries.is_empty());
        assert!(!b.truncated);
    }

    #[test]
    fn a_position_from_another_epoch_gets_everything_marked_truncated() {
        let b = filled(10, 2).backfill(Some(&Position { epoch: 7, seq: 2 }));
        assert_eq!(seqs(&b), [1, 2]);
        assert!(b.truncated);
    }

    #[test]
    fn an_unretained_kind_keeps_seq_but_no_history() {
        let r = filled(0, 3);
        assert_eq!(r.seq, 3);
        assert!(r.is_empty());
        assert!(r.backfill(None).truncated);
    }
}
