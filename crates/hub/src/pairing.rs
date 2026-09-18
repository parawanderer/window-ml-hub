//! Pairing slots: the hub's only unauthenticated write (docs/design/pairing.md).
//!
//! A slot holds two blobs the hub does not read — an offer from a principal that has no certificate yet, and the
//! answer a device with a certificate puts back — keyed by SHA-256 of a pairing code the hub never sees. The person
//! carries the code between the two devices, and compares a fingerprint of the offered keys on both screens, which is
//! what stops a hub substituting its own keys and pairing itself.
//!
//! Everything here is bounded, because it is the one thing a stranger can make the hub remember: a short life, a
//! global cap, one answer per slot, and a size limit on each blob. A slot is a promise to hold two blobs for ten
//! minutes, not storage.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a slot lives if nobody collects it.
pub const SLOT_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Slots open at once, across every account and address.
pub const MAX_SLOTS: usize = 1_024;
/// The largest offer accepted: two keys, a role, a label.
pub const MAX_OFFER_BYTES: usize = 512;
/// The largest answer accepted: a sealed certificate and the account root it chains to.
pub const MAX_ANSWER_BYTES: usize = 4 << 10;

/// Why a slot operation was refused. Each is answered the same way on the wire, so a stranger cannot tell a hit from
/// a miss by the reply it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    /// no slot with that code hash, or it expired
    Unknown,
    /// a slot with that code hash is already open
    Taken,
    /// an offer or answer past its size limit, or a code hash that is not 32 bytes
    TooLarge,
    /// the hub is holding as many slots as it will
    Full,
    /// this slot already has an answer; a second would let a hub choose which certificate a device gets
    Answered,
}

#[derive(Debug, Clone)]
struct Slot {
    offer: Vec<u8>,
    answer: Option<Vec<u8>>,
    expires: Instant,
}

/// Every slot the hub is holding.
#[derive(Debug, Default)]
pub struct Slots {
    open: HashMap<[u8; 32], Slot>,
}

impl Slots {
    /// Hold an offer under `code_hash`. Refused if one is already open under it, which is what stops a hub (or
    /// anyone) pointing two devices at one slot.
    pub fn offer(&mut self, code_hash: &[u8], offer: Vec<u8>, now: Instant) -> Result<(), SlotError> {
        let key = Self::key(code_hash)?;
        if offer.len() > MAX_OFFER_BYTES {
            return Err(SlotError::TooLarge);
        }
        self.forget_expired(now);
        if self.open.contains_key(&key) {
            return Err(SlotError::Taken);
        }
        if self.open.len() >= MAX_SLOTS {
            return Err(SlotError::Full);
        }
        self.open.insert(key, Slot { offer, answer: None, expires: now + SLOT_LIFETIME });
        Ok(())
    }

    /// The offer in a slot, for a device that knows the code. Reading it does not consume the slot: the same device
    /// reads it, shows the fingerprint, and comes back with an answer.
    pub fn offered(&mut self, code_hash: &[u8], now: Instant) -> Result<Vec<u8>, SlotError> {
        let key = Self::key(code_hash)?;
        self.forget_expired(now);
        self.open.get(&key).map(|slot| slot.offer.clone()).ok_or(SlotError::Unknown)
    }

    /// Put the answer back. Only the first is taken: a second answer would let whoever posted it choose which
    /// certificate the new principal ends up with.
    pub fn answer(&mut self, code_hash: &[u8], answer: Vec<u8>, now: Instant) -> Result<(), SlotError> {
        let key = Self::key(code_hash)?;
        if answer.len() > MAX_ANSWER_BYTES {
            return Err(SlotError::TooLarge);
        }
        self.forget_expired(now);
        let slot = self.open.get_mut(&key).ok_or(SlotError::Unknown)?;
        if slot.answer.is_some() {
            return Err(SlotError::Answered);
        }
        slot.answer = Some(answer);
        Ok(())
    }

    /// Collect the answer, which deletes the slot: it has done its work, and nothing is served twice.
    pub fn collect(&mut self, code_hash: &[u8], now: Instant) -> Result<Vec<u8>, SlotError> {
        let key = Self::key(code_hash)?;
        self.forget_expired(now);
        let answer = self.open.get(&key).ok_or(SlotError::Unknown)?.answer.clone().ok_or(SlotError::Unknown)?;
        self.open.remove(&key);
        Ok(answer)
    }

    /// Drop a slot: the peer that offered it has gone, so nothing is waiting for the answer any more.
    pub fn forget(&mut self, code_hash: &[u8]) {
        if let Ok(key) = Self::key(code_hash) {
            self.open.remove(&key);
        }
    }

    /// How many slots are held, for the tests and the logs.
    pub fn held(&self) -> usize {
        self.open.len()
    }

    fn key(code_hash: &[u8]) -> Result<[u8; 32], SlotError> {
        code_hash.try_into().map_err(|_| SlotError::TooLarge)
    }

    fn forget_expired(&mut self, now: Instant) {
        self.open.retain(|_, slot| slot.expires > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: [u8; 32] = [7; 32];
    const OTHER: [u8; 32] = [8; 32];

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn an_offer_is_held_read_answered_and_collected_once() {
        let (mut slots, at) = (Slots::default(), now());
        slots.offer(&CODE, b"keys".to_vec(), at).unwrap();
        assert_eq!(slots.offered(&CODE, at).unwrap(), b"keys", "reading does not consume it");
        assert_eq!(slots.offered(&CODE, at).unwrap(), b"keys");
        assert_eq!(slots.collect(&CODE, at).unwrap_err(), SlotError::Unknown, "nothing to collect yet");
        slots.answer(&CODE, b"cert".to_vec(), at).unwrap();
        assert_eq!(slots.collect(&CODE, at).unwrap(), b"cert");
        assert_eq!(slots.collect(&CODE, at).unwrap_err(), SlotError::Unknown, "and never twice");
        assert_eq!(slots.held(), 0);
    }

    #[test]
    fn a_code_in_use_cannot_be_taken_over() {
        // Two devices on one slot is how a hub would pair itself instead of the device in front of the person.
        let (mut slots, at) = (Slots::default(), now());
        slots.offer(&CODE, b"mine".to_vec(), at).unwrap();
        assert_eq!(slots.offer(&CODE, b"theirs".to_vec(), at).unwrap_err(), SlotError::Taken);
        assert_eq!(slots.offered(&CODE, at).unwrap(), b"mine");
    }

    #[test]
    fn only_the_first_answer_is_taken() {
        let (mut slots, at) = (Slots::default(), now());
        slots.offer(&CODE, b"keys".to_vec(), at).unwrap();
        slots.answer(&CODE, b"first".to_vec(), at).unwrap();
        assert_eq!(slots.answer(&CODE, b"second".to_vec(), at).unwrap_err(), SlotError::Answered);
        assert_eq!(slots.collect(&CODE, at).unwrap(), b"first");
    }

    #[test]
    fn a_slot_is_forgotten_when_its_time_is_up() {
        let (mut slots, at) = (Slots::default(), now());
        slots.offer(&CODE, b"keys".to_vec(), at).unwrap();
        let later = at + SLOT_LIFETIME + Duration::from_millis(1);
        assert_eq!(slots.offered(&CODE, later).unwrap_err(), SlotError::Unknown);
        assert_eq!(slots.held(), 0, "and it is not merely hidden");
        // the edge is still inside
        let mut slots = Slots::default();
        slots.offer(&CODE, b"keys".to_vec(), at).unwrap();
        assert!(slots.offered(&CODE, at + SLOT_LIFETIME - Duration::from_millis(1)).is_ok());
    }

    #[test]
    fn the_hub_holds_only_so_many_and_expiry_makes_room() {
        let (mut slots, at) = (Slots::default(), now());
        for i in 0..MAX_SLOTS {
            let mut code = [0u8; 32];
            code[..8].copy_from_slice(&(i as u64).to_be_bytes());
            slots.offer(&code, b"keys".to_vec(), at).unwrap();
        }
        assert_eq!(slots.offer(&OTHER, b"keys".to_vec(), at).unwrap_err(), SlotError::Full);
        let later = at + SLOT_LIFETIME + Duration::from_millis(1);
        assert!(slots.offer(&OTHER, b"keys".to_vec(), later).is_ok(), "the old ones aged out");
        assert_eq!(slots.held(), 1);
    }

    #[test]
    fn a_blob_past_its_limit_is_refused_before_it_is_held() {
        let (mut slots, at) = (Slots::default(), now());
        assert_eq!(
            slots.offer(&CODE, vec![0; MAX_OFFER_BYTES + 1], at).unwrap_err(),
            SlotError::TooLarge,
            "an offer is two keys, a role and a label"
        );
        assert_eq!(slots.held(), 0);
        slots.offer(&CODE, b"keys".to_vec(), at).unwrap();
        assert_eq!(slots.answer(&CODE, vec![0; MAX_ANSWER_BYTES + 1], at).unwrap_err(), SlotError::TooLarge);
        assert_eq!(slots.collect(&CODE, at).unwrap_err(), SlotError::Unknown, "and nothing was stored");
    }

    #[test]
    fn a_code_hash_of_the_wrong_length_is_refused() {
        let (mut slots, at) = (Slots::default(), now());
        assert_eq!(slots.offer(&[1, 2, 3], b"keys".to_vec(), at).unwrap_err(), SlotError::TooLarge);
        assert_eq!(slots.offered(&[1, 2, 3], at).unwrap_err(), SlotError::TooLarge);
    }
}
