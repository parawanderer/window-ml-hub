//! One stream's ring: the bounded recent history a subscriber backfills from (docs/PROTOCOL.md §Streams, rings
//! and resuming). A cache, never the authority.

use std::collections::VecDeque;

use wmlhub_proto::v1::{Envelope, Kind, Position};

#[derive(Debug)]
pub(crate) struct Ring {
    pub(crate) kind: Kind,
    pub(crate) epoch: u64,
    /// the seq of the newest envelope ever published, retained or not
    pub(crate) seq: u64,
    entries: VecDeque<Envelope>,
    pub(crate) bytes: usize,
    /// logical clock of the last publish, for choosing which idle stream to evict
    pub(crate) touched: u64,
}

/// What a subscriber gets: the envelopes to send, and whether its record has a gap before them.
#[derive(Debug)]
pub(crate) struct Backfill {
    pub(crate) envelopes: Vec<Envelope>,
    pub(crate) truncated: bool,
}

impl Ring {
    pub(crate) fn new(kind: Kind, epoch: u64, touched: u64) -> Self {
        Self { kind, epoch, seq: 0, entries: VecDeque::new(), bytes: 0, touched }
    }

    /// Stamp `env` with this ring's epoch and next seq, retain a copy (evicting past `capacity`), and return it.
    /// Returns the bytes evicted so the account's byte budget can be kept.
    pub(crate) fn publish(&mut self, mut env: Envelope, capacity: usize, touched: u64) -> (Envelope, usize) {
        self.seq += 1;
        env.seq = self.seq;
        env.epoch = self.epoch;
        self.touched = touched;
        let mut freed = 0;
        if capacity > 0 {
            self.bytes += env.payload.len();
            self.entries.push_back(env.clone());
            while self.entries.len() > capacity {
                freed += self.evict_oldest();
            }
        }
        (env, freed)
    }

    /// Drop the oldest retained envelope; the payload bytes freed.
    pub(crate) fn evict_oldest(&mut self) -> usize {
        match self.entries.pop_front() {
            Some(e) => {
                self.bytes -= e.payload.len();
                e.payload.len()
            }
            None => 0,
        }
    }

    /// Everything after `since`. `truncated` is true when envelopes between `since` (or the stream's start) and the
    /// first one returned are no longer retained.
    pub(crate) fn backfill(&self, since: Option<&Position>) -> Backfill {
        let after = match since {
            Some(p) if p.epoch == self.epoch => p.seq,
            _ => 0,
        };
        let first_retained = self.entries.front().map_or(self.seq + 1, |e| e.seq);
        let envelopes: Vec<Envelope> = self.entries.iter().filter(|e| e.seq > after).cloned().collect();
        let stale_epoch = since.is_some_and(|p| p.epoch != self.epoch && p.seq > 0);
        Backfill { truncated: first_retained > after + 1 || stale_epoch, envelopes }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Internal consistency, for the model checker: bytes agree with the entries, seqs strictly increase and end at
    /// or before `seq`, every entry carries this ring's epoch and kind, and the capacity holds.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn check(&self, capacity: usize) -> Result<(), String> {
        let bytes: usize = self.entries.iter().map(|e| e.payload.len()).sum();
        if bytes != self.bytes {
            return Err(format!("ring bytes drifted: {} vs {bytes}", self.bytes));
        }
        if self.entries.len() > capacity {
            return Err(format!("ring over capacity: {} > {capacity}", self.entries.len()));
        }
        let mut last = 0;
        for e in &self.entries {
            if e.seq <= last || e.seq > self.seq || e.epoch != self.epoch || e.kind != self.kind as i32 {
                return Err(format!("ring entry out of order or mislabelled: seq {} after {last}", e.seq));
            }
            last = e.seq;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(n: usize) -> Envelope {
        Envelope { kind: Kind::SessionEvents as i32, payload: vec![0; n], ..Default::default() }
    }

    fn filled(capacity: usize, count: usize) -> Ring {
        let mut r = Ring::new(Kind::SessionEvents, 42, 0);
        for i in 0..count {
            r.publish(env(10), capacity, i as u64);
        }
        r
    }

    fn seqs(b: &Backfill) -> Vec<u64> {
        b.envelopes.iter().map(|e| e.seq).collect()
    }

    #[test]
    fn publish_stamps_seq_and_epoch_and_evicts_past_capacity() {
        let r = filled(3, 5);
        assert_eq!(r.seq, 5);
        assert_eq!(r.bytes, 30);
        let b = r.backfill(None);
        assert_eq!(seqs(&b), [3, 4, 5]);
        assert!(b.envelopes.iter().all(|e| e.epoch == 42));
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
        assert!(b.envelopes.is_empty());
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
