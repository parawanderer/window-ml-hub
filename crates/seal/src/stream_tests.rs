//! What a hub, or a device holding the stream key, could do to a published stream, and what stops each.

use super::*;
use crate::tests::{Account, NOW};
use crate::{AgreementKey, open_pairing_answer, seal_command, seal_pairing_answer, seal_result};
use wmlhub_keys::{MAX_CHAIN, scope};

const CHANNEL: &[u8] = b"ch-42";

/// A publisher (the runtime), a key, and a subscriber (the phone) that has been granted it.
fn stream(a: &Account, key: &StreamKey) -> StreamReader {
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, key, 1, NOW).unwrap();
    let grant = open_grant(&mut a.phone_receiver(), &a.runtime.id(), &wrapped, NOW).unwrap();
    StreamReader::new(&grant)
}

fn frame(a: &Account, key: &StreamKey, counter: u64, batch: &[u8]) -> Vec<u8> {
    seal_frame(&a.runtime.sender(), CHANNEL, key, counter, batch).unwrap()
}

// ------------------------------ what works ------------------------------

#[test]
fn a_subscriber_granted_the_key_reads_the_stream_in_order() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let mut reader = stream(&a, &key);
    for n in 1..=3u64 {
        let opened = reader.open(&frame(&a, &key, n, format!("batch {n}").as_bytes())).unwrap();
        assert_eq!(opened.counter, n);
        assert_eq!(opened.skipped, 0);
        assert_eq!(opened.batch, format!("batch {n}").into_bytes());
    }
    assert_eq!(reader.counter(), 3);
}

#[test]
fn a_grant_carries_the_publisher_the_channel_and_the_key_that_signs_it() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, &key, 7, NOW).unwrap();
    let grant = open_grant(&mut a.phone_receiver(), &a.runtime.id(), &wrapped, NOW).unwrap();
    assert_eq!(grant.publisher, a.runtime.id());
    assert_eq!(grant.publisher_key, a.runtime.identity.public());
    assert_eq!(grant.channel, CHANNEL);
    assert_eq!(grant.key_id, key.id());
    assert_eq!(grant.from_counter, 7);
}

#[test]
fn a_rotation_is_read_by_a_subscriber_holding_both_keys_and_the_old_ring_still_opens() {
    let (a, old) = (Account::new(1), StreamKey::generate().unwrap());
    let mut reader = stream(&a, &old);
    let first = frame(&a, &old, 1, b"before");
    reader.open(&first).unwrap();

    let new = StreamKey::generate().unwrap();
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, &new, 2, NOW).unwrap();
    let grant = open_grant(&mut a.phone_receiver(), &a.runtime.id(), &wrapped, NOW).unwrap();
    assert!(reader.add_key(&grant));
    assert_eq!(reader.open(&frame(&a, &new, 2, b"after")).unwrap().batch, b"after");

    // reading the ring again from the start: the old key is still held, so old entries still open
    reader.rewind_to(0);
    assert_eq!(reader.open(&first).unwrap().batch, b"before");
}

#[test]
fn a_gap_in_the_counters_is_reported() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let mut reader = stream(&a, &key);
    reader.open(&frame(&a, &key, 1, b"x")).unwrap();
    assert_eq!(reader.open(&frame(&a, &key, 5, b"x")).unwrap().skipped, 3);
}

// ------------------------------ what the hub could try ------------------------------

#[test]
fn a_frame_replayed_or_reordered_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let mut reader = stream(&a, &key);
    let second = frame(&a, &key, 2, b"x");
    reader.open(&frame(&a, &key, 1, b"x")).unwrap();
    reader.open(&second).unwrap();
    assert_eq!(reader.open(&second).unwrap_err(), StreamError::OutOfOrder { last: 2, counter: 2 });
    let first_again = frame(&a, &key, 1, b"x");
    assert_eq!(reader.open(&first_again).unwrap_err(), StreamError::OutOfOrder { last: 2, counter: 1 });
}

#[test]
fn a_frame_moved_to_another_channel_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    // the same length as CHANNEL, so it is the channel itself that has to be bound, not how long its name is
    let elsewhere = seal_frame(&a.runtime.sender(), b"ch-43", &key, 1, b"x").unwrap();
    assert_eq!(CHANNEL.len(), 5);
    assert_eq!(stream(&a, &key).open(&elsewhere).unwrap_err(), StreamError::Signature);
}

#[test]
fn a_frame_relabelled_with_another_key_id_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let other = StreamKey::generate().unwrap();
    let mut reader = stream(&a, &key);
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, &other, 1, NOW).unwrap();
    reader.add_key(&open_grant(&mut a.phone_receiver(), &a.runtime.id(), &wrapped, NOW).unwrap());
    let mut decoded = StreamFrame::decode(frame(&a, &key, 1, b"x").as_slice()).unwrap();
    decoded.key_id = other.id().to_vec();
    assert_eq!(reader.open(&decoded.encode_to_vec()).unwrap_err(), StreamError::Signature);
}

#[test]
fn a_frame_from_another_publisher_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    // the phone holds the key and publishes its own frame on the runtime's channel
    let forged = seal_frame(&a.phone.sender(), CHANNEL, &key, 1, b"forged").unwrap();
    assert_eq!(stream(&a, &key).open(&forged).unwrap_err(), StreamError::Signature);
}

#[test]
fn a_renumbered_frame_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let mut decoded = StreamFrame::decode(frame(&a, &key, 2, b"x").as_slice()).unwrap();
    decoded.counter = 3;
    assert_eq!(stream(&a, &key).open(&decoded.encode_to_vec()).unwrap_err(), StreamError::Signature);
}

#[test]
fn a_frame_wearing_another_frames_ciphertext_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let mut one = StreamFrame::decode(frame(&a, &key, 1, b"one").as_slice()).unwrap();
    let two = StreamFrame::decode(frame(&a, &key, 2, b"two").as_slice()).unwrap();
    one.ciphertext = two.ciphertext;
    assert_eq!(stream(&a, &key).open(&one.encode_to_vec()).unwrap_err(), StreamError::Signature);
}

#[test]
fn any_flipped_bit_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let good = frame(&a, &key, 1, b"a batch of events");
    for byte in 0..good.len() {
        let mut bad = good.clone();
        bad[byte] ^= 1 << (byte % 8);
        assert!(stream(&a, &key).open(&bad).is_err(), "byte {byte}");
    }
}

#[test]
fn a_frame_under_a_key_the_subscriber_does_not_hold_says_so() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let other = StreamKey::generate().unwrap();
    assert_eq!(stream(&a, &key).open(&frame(&a, &other, 1, b"x")).unwrap_err(), StreamError::UnknownKey);
}

#[test]
fn an_oversized_frame_is_refused_before_anything_else() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    assert_eq!(stream(&a, &key).open(&vec![0u8; MAX_STREAM_FRAME_BYTES + 1]).unwrap_err(), StreamError::TooLarge);
}

// ------------------------------ grants stay grants ------------------------------

#[test]
fn a_command_cannot_be_opened_as_a_grant_and_a_grant_cannot_be_opened_as_a_command() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let (command, nonce) = seal_command(&a.runtime.sender(), &a.phone.recipient(), scope::VIEW, b"x", NOW).unwrap();
    let result = seal_result(&a.runtime.sender(), &a.phone.recipient(), &nonce, b"x", NOW).unwrap();
    let grant = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, &key, 1, NOW).unwrap();
    let mut phone = a.phone_receiver();
    assert_eq!(open_grant(&mut phone, &a.runtime.id(), &command, NOW).unwrap_err(), OpenError::Decrypt);
    assert_eq!(open_grant(&mut phone, &a.runtime.id(), &result, NOW).unwrap_err(), OpenError::Decrypt);
    assert_eq!(phone.open(&a.runtime.id(), &grant, NOW).unwrap_err(), OpenError::Decrypt);
}

#[test]
fn a_grant_for_someone_else_does_not_open() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, &key, 1, NOW).unwrap();
    // the runtime is handed the grant it wrapped for the phone
    assert_eq!(open_grant(&mut a.runtime_receiver(), &a.runtime.id(), &wrapped, NOW).unwrap_err(), OpenError::Decrypt);
}

#[test]
fn a_grant_whose_key_id_does_not_match_its_key_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, &key, 1, NOW).unwrap();
    // rebuild the grant with a key id from a different key, signed properly: only the derivation catches it
    let mut phone = a.phone_receiver();
    let plaintext = phone.unseal(GRANT_INFO_LABEL, &a.runtime.id(), &wrapped).unwrap();
    let signed = SignedGrant::decode(plaintext.as_slice()).unwrap();
    let mut body = GrantBody::decode(signed.body.as_slice()).unwrap();
    body.key_id = StreamKey::generate().unwrap().id().to_vec();
    let body = body.encode_to_vec();
    let forged = SignedGrant {
        signature: wmlhub_keys::sign_grant(&a.runtime.identity, &body),
        body,
        chain: a.runtime.chain.clone(),
    };
    let sealed = hpke_seal(GRANT_INFO_LABEL, &a.runtime.id(), &a.phone.recipient(), &forged.encode_to_vec()).unwrap();
    assert_eq!(open_grant(&mut phone, &a.runtime.id(), &sealed, NOW).unwrap_err(), OpenError::Malformed);
}

#[test]
fn a_replayed_grant_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, &key, 1, NOW).unwrap();
    let mut phone = a.phone_receiver();
    open_grant(&mut phone, &a.runtime.id(), &wrapped, NOW).unwrap();
    assert_eq!(open_grant(&mut phone, &a.runtime.id(), &wrapped, NOW).unwrap_err(), OpenError::Replay);
}

#[test]
fn a_grant_for_another_stream_is_not_taken_by_a_reader() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let mut reader = stream(&a, &key);
    let other = StreamKey::generate().unwrap();
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), b"other-channel", &other, 1, NOW).unwrap();
    let grant = open_grant(&mut a.phone_receiver(), &a.runtime.id(), &wrapped, NOW).unwrap();
    assert!(!reader.add_key(&grant));
    assert_eq!(reader.open(&frame(&a, &other, 1, b"x")).unwrap_err(), StreamError::UnknownKey);
}

/// What a published frame costs, for docs/design/end-to-end-crypto.md. Numbers, not assertions:
/// `cargo test --release -p wmlhub-seal frame_costs -- --ignored --nocapture`.
#[test]
#[ignore]
fn frame_costs() {
    use std::time::Instant;
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    const N: u32 = 2_000;
    for size in [512usize, 8_192, 65_536] {
        let batch = vec![3u8; size];
        let start = Instant::now();
        let frames: Vec<Vec<u8>> =
            (1..=u64::from(N)).map(|n| seal_frame(&a.runtime.sender(), CHANNEL, &key, n, &batch).unwrap()).collect();
        let seal = start.elapsed() / N;
        let mut reader = stream(&a, &key);
        let start = Instant::now();
        for f in &frames {
            reader.open(f).unwrap();
        }
        let open = start.elapsed() / N;
        eprintln!("batch {size} B: frame {} B, seal {seal:?}, open {open:?}", frames[0].len());
    }
}

#[test]
fn channel_names_are_keyed_so_the_hub_cannot_tell_what_they_are_for() {
    let (one, two) = (ChannelKey::from_bytes([1; 32]), ChannelKey::from_bytes([2; 32]));
    let session = b"5f3a9c21";
    assert_eq!(one.channel("events", session), one.channel("events", session), "the same name every time");
    assert_ne!(one.channel("events", session), one.channel("keys", session), "one session, two streams");
    assert_ne!(one.channel("events", session), one.channel("events", b"5f3a9c22"), "two sessions");
    assert_ne!(
        one.channel("events", session),
        two.channel("events", session),
        "two accounts watching the same box do not share a channel name"
    );
    assert_eq!(one.channel("events", session).len(), CHANNEL_BYTES);
}

#[test]
fn a_frame_before_the_counter_its_grant_covers_is_refused() {
    // A device paired this morning is granted the stream from where it joined. The ring still holds last night, and
    // the key opens those frames, so the reader is what stops it reading them.
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, &key, 5, NOW).unwrap();
    let grant = open_grant(&mut a.phone_receiver(), &a.runtime.id(), &wrapped, NOW).unwrap();
    let mut reader = StreamReader::new(&grant);

    assert_eq!(
        reader.open(&frame(&a, &key, 4, b"last night")).unwrap_err(),
        StreamError::BeforeGrant { from_counter: 5, counter: 4 }
    );
    assert_eq!(reader.open(&frame(&a, &key, 5, b"since joining")).unwrap().counter, 5, "the edge is inside");
}

#[test]
fn each_key_carries_its_own_first_counter() {
    // A rotation grants a new key from where it begins; the old key keeps covering what it always did.
    let (a, old) = (Account::new(1), StreamKey::generate().unwrap());
    let new = StreamKey::generate().unwrap();
    let mut reader = stream(&a, &old);
    let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), CHANNEL, &new, 10, NOW).unwrap();
    reader.add_key(&open_grant(&mut a.phone_receiver(), &a.runtime.id(), &wrapped, NOW).unwrap());

    assert_eq!(reader.open(&frame(&a, &old, 2, b"before")).unwrap().counter, 2, "the old key covers from 1");
    assert!(matches!(
        reader.open(&frame(&a, &new, 9, b"too early")).unwrap_err(),
        StreamError::BeforeGrant { from_counter: 10, .. }
    ));
    assert_eq!(reader.open(&frame(&a, &new, 10, b"after")).unwrap().counter, 10);
}

#[test]
fn a_grant_naming_a_channel_the_hub_would_not_route_is_refused() {
    let (a, key) = (Account::new(1), StreamKey::generate().unwrap());
    for channel in [vec![], vec![7u8; MAX_CHANNEL_BYTES + 1]] {
        let wrapped = wrap_key(&a.runtime.sender(), &a.phone.recipient(), &channel, &key, 1, NOW).unwrap();
        assert_eq!(
            open_grant(&mut a.phone_receiver(), &a.runtime.id(), &wrapped, NOW).unwrap_err(),
            OpenError::Malformed,
            "{} bytes",
            channel.len()
        );
    }
}

// ------------------------------ what a paired device is given ------------------------------

#[test]
fn what_a_device_is_paired_with_opens_only_for_the_key_its_offer_carried() {
    use wmlhub_proto::v1::PairedWith;
    let a = Account::new(1);
    let offered = AgreementKey::from_seed(&[77; 32]);
    let paired = PairedWith {
        chain: vec![a.phone.chain[0].clone()],
        account_root: a.root.public().to_vec(),
        channel_key: vec![9; 32],
    };
    let sealed = seal_pairing_answer(&offered.public(), &paired).unwrap();

    let opened = open_pairing_answer(&offered, &sealed).unwrap();
    assert_eq!(opened.account_root, a.root.public().to_vec());
    assert_eq!(opened.channel_key, vec![9; 32]);
    assert_eq!(opened.chain, vec![a.phone.chain[0].clone()]);

    // the hub holds this blob, and a hub is exactly who must not read it: the channel key is in there
    let someone_else = AgreementKey::from_seed(&[78; 32]);
    assert_eq!(open_pairing_answer(&someone_else, &sealed).unwrap_err(), OpenError::Decrypt);
}

#[test]
fn a_pairing_answer_is_not_a_command_and_a_command_is_not_a_pairing_answer() {
    use wmlhub_proto::v1::PairedWith;
    let a = Account::new(1);
    let offered = AgreementKey::from_seed(&[77; 32]);
    let paired = PairedWith {
        chain: vec![a.phone.chain[0].clone()],
        account_root: a.root.public().to_vec(),
        channel_key: vec![9; 32],
    };
    let sealed = seal_pairing_answer(&offered.public(), &paired).unwrap();
    // the phone's own agreement key, and a command sealed to it, are a different label and a different shape
    let (command, _) = seal_command(&a.phone.sender(), &a.runtime.recipient(), scope::DRIVE, b"x", NOW).unwrap();
    assert_eq!(open_pairing_answer(&AgreementKey::from_seed(&[101; 32]), &command).unwrap_err(), OpenError::Decrypt);
    assert_eq!(a.runtime_receiver().open(&a.phone.id(), &sealed, NOW).unwrap_err(), OpenError::Decrypt);
}

#[test]
fn a_malformed_pairing_answer_is_refused_rather_than_half_read() {
    use wmlhub_proto::v1::PairedWith;
    let a = Account::new(1);
    let cert = a.phone.chain[0].clone();
    let offered = AgreementKey::from_seed(&[77; 32]);
    for wrong in [
        PairedWith { chain: vec![cert.clone()], account_root: vec![1; 31], channel_key: vec![9; 32] },
        PairedWith { chain: vec![cert.clone()], account_root: vec![1; 32], channel_key: vec![9; 16] },
        // a chain is at least a leaf, and never longer than a verifier would accept: a device that stored one it
        // cannot log in with would find out at the hub, with nothing to say about why
        PairedWith { chain: Vec::new(), account_root: vec![1; 32], channel_key: vec![9; 32] },
        PairedWith { chain: vec![cert.clone(); MAX_CHAIN + 1], account_root: vec![1; 32], channel_key: vec![9; 32] },
    ] {
        let sealed = seal_pairing_answer(&offered.public(), &wrong).unwrap();
        assert_eq!(open_pairing_answer(&offered, &sealed).unwrap_err(), OpenError::Malformed);
    }
}
