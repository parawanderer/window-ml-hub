//! The relay's routing rules, driven through its public calls. Isolation between accounts is tested first and from
//! several directions, because it is the property the rest of the design leans on.

use super::*;
use wmlhub_proto::v1::{Position, StreamRef, Subscribe};

const NOW: u64 = 1_700_000_000_000;

fn hub() -> Hub {
    Hub::new(Limits::default(), 7).unwrap()
}

fn hello(principal: &str, role: Role) -> v1::Hello {
    v1::Hello { protocol: 1, principal: principal.as_bytes().to_vec(), role: role as i32, ..Default::default() }
}

fn acct(name: &str) -> AccountId {
    AccountId(name.as_bytes().to_vec())
}

/// Connect and discard the welcome burst.
fn join(h: &mut Hub, account: &str, principal: &str, role: Role) -> ConnId {
    let (id, _) = h.connect(acct(account), &hello(principal, role), NOW).unwrap();
    h.take_outbound(id, usize::MAX);
    id
}

fn frame(body: Body) -> Frame {
    Frame { body: Some(body) }
}

fn publish(channel: &str, kind: Kind, payload: &[u8]) -> Frame {
    frame(Body::Envelope(Envelope {
        to: Some(To::Channel(channel.as_bytes().to_vec())),
        kind: kind as i32,
        payload: payload.to_vec().into(),
        ..Default::default()
    }))
}

fn command(to: &str, payload: &[u8], reference: u64) -> Frame {
    frame(Body::Envelope(Envelope {
        to: Some(To::Principal(to.as_bytes().to_vec())),
        kind: Kind::Command as i32,
        payload: payload.to_vec().into(),
        r#ref: reference,
        ..Default::default()
    }))
}

fn subscribe(publisher: &str, channel: &str, since: Option<Position>) -> Frame {
    frame(Body::Subscribe(Subscribe {
        stream: Some(StreamRef { publisher: publisher.as_bytes().to_vec(), channel: channel.as_bytes().to_vec() }),
        since,
    }))
}

/// A readable line per frame, for asserting on sequences.
fn show(frames: &[Frame]) -> Vec<String> {
    frames
        .iter()
        .map(|f| match &f.body {
            Some(Body::Welcome(_)) => "welcome".into(),
            Some(Body::Presence(p)) => {
                format!("presence {} {}", String::from_utf8_lossy(&p.principal), if p.online { "on" } else { "off" })
            }
            Some(Body::Envelope(e)) => {
                format!(
                    "env from={} seq={} {}",
                    String::from_utf8_lossy(&e.sender),
                    e.seq,
                    String::from_utf8_lossy(&e.payload)
                )
            }
            Some(Body::Backfilled(b)) => format!("backfilled seq={} truncated={}", b.seq, b.truncated),
            Some(Body::Error(e)) => format!("error {:?} ref={}", e.code(), e.r#ref),
            Some(Body::Pong(p)) => format!("pong {}", p.nonce),
            Some(Body::Gap(g)) => format!("gap {}", g.dropped),
            other => format!("{other:?}"),
        })
        .collect()
}

/// Everything queued for `conn`, decoded.
fn drain(h: &mut Hub, conn: ConnId) -> Vec<Frame> {
    h.take_outbound(conn, usize::MAX)
        .frames
        .iter()
        .map(|w| wmlhub_proto::decode_frames(w, usize::MAX).unwrap().remove(0))
        .collect()
}

fn out(h: &mut Hub, conn: ConnId) -> Vec<String> {
    show(&drain(h, conn))
}

fn closed(actions: &[Action]) -> Vec<(ConnId, String)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Close { conn, frame } => Some((*conn, show(std::slice::from_ref(frame)).remove(0))),
            Action::Wake(_) => None,
        })
        .collect()
}

// ------------------------------ accounts ------------------------------

#[test]
fn a_subscriber_in_another_account_receives_nothing_from_a_same_named_stream() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let spy = join(&mut h, "mallory", "phone", Role::Client);
    h.receive(rt, publish("s1", Kind::SessionEvents, b"secret"));

    h.receive(spy, subscribe("rt", "s1", None));
    assert_eq!(out(&mut h, spy), ["backfilled seq=0 truncated=false"]);
    h.receive(rt, publish("s1", Kind::SessionEvents, b"later"));
    assert!(out(&mut h, spy).is_empty());
}

#[test]
fn a_command_cannot_reach_a_principal_in_another_account_even_when_it_is_online() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let spy = join(&mut h, "mallory", "phone", Role::Client);
    h.receive(spy, command("rt", b"click", 5));
    assert_eq!(out(&mut h, spy), ["error Unavailable ref=5"]);
    assert!(out(&mut h, rt).is_empty());
}

#[test]
fn presence_never_crosses_accounts() {
    let mut h = hub();
    let a = join(&mut h, "alice", "rt", Role::Runtime);
    let (m, _) = h.connect(acct("mallory"), &hello("phone", Role::Client), NOW).unwrap();
    assert_eq!(out(&mut h, m), ["welcome"]);
    assert!(out(&mut h, a).is_empty());
}

#[test]
fn the_same_principal_id_may_exist_in_two_accounts() {
    let mut h = hub();
    join(&mut h, "alice", "rt", Role::Runtime);
    assert!(h.connect(acct("bob"), &hello("rt", Role::Runtime), NOW).is_ok());
}

// ------------------------------ principals ------------------------------

#[test]
fn a_second_connection_for_an_online_principal_is_refused() {
    let mut h = hub();
    join(&mut h, "alice", "rt", Role::Runtime);
    let err = h.connect(acct("alice"), &hello("rt", Role::Runtime), NOW).unwrap_err();
    assert_eq!(show(&[*err]), ["error Unauthenticated ref=0"]);
}

#[test]
fn a_refused_hello_leaves_no_account_behind() {
    let mut h = Hub::new(Limits { max_accounts: 1, ..Limits::default() }, 1).unwrap();
    assert!(h.connect(acct("x"), &hello("", Role::Client), NOW).is_err());
    assert!(h.connect(acct("y"), &hello("p", Role::Client), NOW).is_ok());
}

#[test]
fn the_hub_stamps_the_sender_whatever_the_peer_claims() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.take_outbound(rt, usize::MAX);
    let mut forged = command("rt", b"go", 1);
    if let Some(Body::Envelope(e)) = &mut forged.body {
        e.sender = b"someone-else".to_vec();
    }
    h.receive(phone, forged);
    assert_eq!(out(&mut h, rt), ["env from=phone seq=0 go"]);
}

#[test]
fn a_new_connection_sees_who_is_online_and_others_see_it_arrive_and_leave() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let (phone, _) = h.connect(acct("alice"), &hello("phone", Role::Client), NOW).unwrap();
    assert_eq!(out(&mut h, phone), ["welcome", "presence rt on"]);
    assert_eq!(out(&mut h, rt), ["presence phone on"]);
    h.close(phone, None);
    assert_eq!(out(&mut h, rt), ["presence phone off"]);
}

#[test]
fn an_empty_account_is_forgotten() {
    let mut h = Hub::new(Limits { max_accounts: 1, ..Limits::default() }, 1).unwrap();
    let c = join(&mut h, "a", "p", Role::Client);
    h.close(c, None);
    assert!(h.connect(acct("b"), &hello("p", Role::Client), NOW).is_ok());
}

// ------------------------------ publish and subscribe ------------------------------

#[test]
fn a_late_subscriber_gets_the_ring_then_live_envelopes() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(rt, publish("s1", Kind::SessionEvents, b"a"));
    h.receive(rt, publish("s1", Kind::SessionEvents, b"b"));
    h.receive(phone, subscribe("rt", "s1", None));
    assert_eq!(out(&mut h, phone), ["env from=rt seq=1 a", "env from=rt seq=2 b", "backfilled seq=2 truncated=false"]);
    h.receive(rt, publish("s1", Kind::SessionEvents, b"c"));
    assert_eq!(out(&mut h, phone), ["env from=rt seq=3 c"]);
}

#[test]
fn resubscribing_with_a_position_sends_only_what_was_missed() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(phone, subscribe("rt", "s1", None));
    let first = drain(&mut h, phone);
    let Some(Body::Backfilled(b)) = &first[0].body else { panic!("expected backfilled") };
    assert_eq!(b.epoch, 0, "no ring before the first publish");

    for p in [b"a", b"b", b"c"] {
        h.receive(rt, publish("s1", Kind::SessionEvents, p));
    }
    let seen = drain(&mut h, phone);
    let Some(Body::Envelope(e)) = &seen[0].body else { panic!("expected envelope") };
    let epoch = e.epoch;
    assert_ne!(epoch, 0);

    h.close(phone, None);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(phone, subscribe("rt", "s1", Some(Position { epoch, seq: 1 })));
    assert_eq!(out(&mut h, phone), ["env from=rt seq=2 b", "env from=rt seq=3 c", "backfilled seq=3 truncated=false"]);
}

#[test]
fn a_subscription_waiting_for_a_publisher_receives_its_first_envelope() {
    let mut h = hub();
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(phone, subscribe("rt", "s1", None));
    h.take_outbound(phone, usize::MAX);
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    h.take_outbound(phone, usize::MAX);
    h.receive(rt, publish("s1", Kind::SessionEvents, b"hello"));
    assert_eq!(out(&mut h, phone), ["env from=rt seq=1 hello"]);
}

#[test]
fn a_ring_outlives_its_publishers_connection() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    h.receive(rt, publish("s1", Kind::SessionEvents, b"kept"));
    h.close(rt, None);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(phone, subscribe("rt", "s1", None));
    assert_eq!(out(&mut h, phone), ["env from=rt seq=1 kept", "backfilled seq=1 truncated=false"]);
}

#[test]
fn a_publisher_cannot_publish_on_another_principals_stream() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let other = join(&mut h, "alice", "other", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.take_outbound(rt, usize::MAX);
    h.receive(phone, subscribe("rt", "s1", None));
    h.take_outbound(phone, usize::MAX);
    // the channel is always the SENDER's: this lands on other:s1, not rt:s1
    h.receive(other, publish("s1", Kind::SessionEvents, b"forged"));
    assert!(out(&mut h, phone).is_empty());
}

#[test]
fn a_kind_that_does_not_match_its_address_is_invalid() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    h.receive(rt, publish("s1", Kind::Command, b"x"));
    let mut cmd_on_channel = command("rt", b"x", 3);
    if let Some(Body::Envelope(e)) = &mut cmd_on_channel.body {
        e.kind = Kind::SessionEvents as i32;
    }
    h.receive(rt, cmd_on_channel);
    assert_eq!(out(&mut h, rt), ["error Invalid ref=0", "error Invalid ref=3"]);
}

#[test]
fn a_channel_keeps_the_kind_of_its_first_publish() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    h.receive(rt, publish("s1", Kind::SessionEvents, b"x"));
    h.receive(rt, publish("s1", Kind::Telemetry, b"y"));
    assert_eq!(out(&mut h, rt), ["error Invalid ref=0"]);
}

// ------------------------------ direct ------------------------------

#[test]
fn a_command_to_an_offline_principal_is_answered_unavailable_not_stored() {
    let mut h = hub();
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(phone, command("rt", b"go", 9));
    assert_eq!(out(&mut h, phone), ["error Unavailable ref=9"]);
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    assert!(out(&mut h, rt).is_empty());
}

// ------------------------------ backpressure and limits ------------------------------

#[test]
fn a_slow_session_event_subscriber_is_closed_and_the_publisher_is_not() {
    let limits = Limits { ring_session_events: 2, queue_session_events: 2, ..Limits::default() };
    let mut h = Hub::new(limits, 1).unwrap();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.take_outbound(rt, usize::MAX);
    h.receive(phone, subscribe("rt", "s1", None));
    h.take_outbound(phone, usize::MAX);
    h.receive(rt, publish("s1", Kind::SessionEvents, b"1"));
    h.receive(rt, publish("s1", Kind::SessionEvents, b"2"));
    let actions = h.receive(rt, publish("s1", Kind::SessionEvents, b"3"));
    assert_eq!(closed(&actions), [(phone, "error SlowConsumer ref=0".to_string())]);
    assert_eq!(out(&mut h, rt), ["presence phone off"]);
}

#[test]
fn an_oversized_payload_closes_the_sender() {
    let mut h = Hub::new(Limits { max_payload_bytes: 4, ..Limits::default() }, 1).unwrap();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let actions = h.receive(rt, publish("s1", Kind::SessionEvents, b"12345"));
    assert_eq!(closed(&actions), [(rt, "error Limit ref=0".to_string())]);
}

#[test]
fn at_the_stream_limit_the_least_recent_idle_stream_is_evicted() {
    let mut h = Hub::new(Limits { max_streams_per_account: 2, ..Limits::default() }, 1).unwrap();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(rt, publish("old", Kind::SessionEvents, b"o"));
    h.receive(rt, publish("new", Kind::SessionEvents, b"n"));
    h.receive(rt, publish("third", Kind::SessionEvents, b"t"));
    h.take_outbound(rt, usize::MAX);
    h.receive(phone, subscribe("rt", "old", None));
    assert_eq!(out(&mut h, phone), ["backfilled seq=0 truncated=false"]);
}

#[test]
fn a_stream_with_subscribers_is_never_evicted_and_the_publish_is_refused_instead() {
    let mut h = Hub::new(Limits { max_streams_per_account: 1, ..Limits::default() }, 1).unwrap();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(phone, subscribe("rt", "watched", None));
    let actions = h.receive(rt, publish("other", Kind::SessionEvents, b"x"));
    assert_eq!(closed(&actions), [(rt, "error Limit ref=0".to_string())]);
}

#[test]
fn the_account_ring_budget_takes_from_the_largest_ring() {
    // The budget counts ENCODED bytes (what the ring actually holds). Payloads are large enough that the envelope's own
    // few dozen bytes cannot change which ring is largest: two 200 B entries (~230 B encoded) and one 100 B (~130 B)
    // exceed 500, and dropping the oldest of the largest ring is enough.
    let mut h = Hub::new(Limits { account_ring_bytes: 500, ..Limits::default() }, 1).unwrap();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(rt, publish("big", Kind::SessionEvents, &[b'x'; 200]));
    h.receive(rt, publish("big", Kind::SessionEvents, &[b'y'; 200]));
    h.receive(rt, publish("small", Kind::SessionEvents, &[b'z'; 100]));
    h.receive(phone, subscribe("rt", "big", None));
    let big = drain(&mut h, phone);
    let seqs: Vec<String> = show(&big).iter().map(|l| l.split(' ').take(3).collect::<Vec<_>>().join(" ")).collect();
    assert_eq!(seqs, ["env from=rt seq=2", "backfilled seq=2 truncated=true"]);
    h.receive(phone, subscribe("rt", "small", None));
    let small: Vec<String> =
        out(&mut h, phone).iter().map(|l| l.split(' ').take(3).collect::<Vec<_>>().join(" ")).collect();
    assert_eq!(small, ["env from=rt seq=1", "backfilled seq=1 truncated=false"]);
}

#[test]
fn ping_is_answered_and_an_unknown_frame_is_unsupported() {
    let mut h = hub();
    let c = join(&mut h, "alice", "p", Role::Client);
    h.receive(c, frame(Body::Ping(v1::Ping { nonce: 42 })));
    h.receive(c, Frame { body: None });
    assert_eq!(out(&mut h, c), ["pong 42", "error Unsupported ref=0"]);
}

#[test]
fn a_hub_to_peer_frame_from_a_peer_closes_it() {
    let mut h = hub();
    let c = join(&mut h, "alice", "p", Role::Client);
    let forged = frame(Body::Presence(v1::Presence { principal: b"x".to_vec(), role: 1, online: true }));
    let actions = h.receive(c, forged);
    assert_eq!(closed(&actions), [(c, "error Invalid ref=0".to_string())]);
}

#[test]
fn limits_that_cannot_work_are_refused() {
    let bad = Limits { ring_session_events: 10, queue_session_events: 5, ..Limits::default() };
    assert!(Hub::new(bad, 0).is_err());
}

#[test]
fn resubscribing_with_envelopes_still_queued_delivers_each_seq_once_in_order() {
    let mut h = hub();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(phone, subscribe("rt", "s1", None));
    h.receive(rt, publish("s1", Kind::SessionEvents, b"a"));
    h.receive(rt, publish("s1", Kind::SessionEvents, b"b"));
    // the phone has not drained; it resubscribes from the start
    h.receive(phone, subscribe("rt", "s1", None));
    let got: Vec<String> = out(&mut h, phone).into_iter().filter(|l| l.starts_with("env")).collect();
    assert_eq!(got, ["env from=rt seq=1 a", "env from=rt seq=2 b"]);
}

#[test]
fn shards_hand_out_connection_ids_that_never_collide() {
    let mut a = Hub::with_id_space(Limits::default(), 1, 0).unwrap();
    let mut b = Hub::with_id_space(Limits::default(), 1, 1).unwrap();
    let ida = a.connect(acct("x"), &hello("p", Role::Client), NOW).unwrap().0;
    let idb = b.connect(acct("x"), &hello("p", Role::Client), NOW).unwrap().0;
    assert_ne!(ida, idb);
    assert_eq!(idb >> 48, 1);
}

#[test]
fn account_count_follows_connections_and_streams() {
    let mut h = hub();
    assert!(!h.has_account(&acct("alice")));
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    assert!(h.has_account(&acct("alice")));
    h.receive(rt, publish("s1", Kind::SessionEvents, b"kept"));
    h.close(rt, None);
    assert_eq!(h.account_count(), 1, "a retained ring keeps the account");
    let c = join(&mut h, "bob", "p", Role::Client);
    h.close(c, None);
    assert_eq!(h.account_count(), 1, "an account with nothing left is forgotten");
}

/// What eviction costs an account at its limits, per publish, worst and mean (docs/perf/README.md §Eviction at the
/// limits). Numbers, not assertions: `cargo test --release -p wmlhub-relay eviction_costs -- --ignored --nocapture`.
#[test]
#[ignore]
fn eviction_costs() {
    use std::time::{Duration, Instant};
    fn timed(n: usize, mut f: impl FnMut(usize)) -> (Duration, Duration) {
        let (mut worst, start) = (Duration::ZERO, Instant::now());
        for i in 0..n {
            let t = Instant::now();
            f(i);
            worst = worst.max(t.elapsed());
        }
        (worst, start.elapsed() / n as u32)
    }
    let l = Limits::default();
    // Fill an account's every stream ring with `size`-byte payloads.
    let filled = |size: usize| {
        let mut h = hub();
        let rt = join(&mut h, "a", "rt", Role::Runtime);
        let p = vec![7u8; size];
        for ch in 0..l.max_streams_per_account {
            for _ in 0..l.ring_session_events {
                h.receive(rt, publish(&format!("c{ch}"), Kind::SessionEvents, &p));
            }
        }
        (h, rt)
    };

    let (mut h, rt) = filled(60);
    let (worst, mean) = timed(l.max_streams_per_account, |i| {
        h.receive(rt, publish(&format!("new{i}"), Kind::SessionEvents, b"x"));
    });
    eprintln!("new stream at the stream limit, victims hold full rings: worst {worst:?} mean {mean:?}");
    let (worst, mean) = timed(20_000, |i| {
        h.receive(rt, publish(&format!("again{i}"), Kind::SessionEvents, b"x"));
    });
    eprintln!("new stream at the stream limit, steady state: worst {worst:?} mean {mean:?}");

    let (mut h, rt) = filled(120);
    let (small, big) = (vec![7u8; 120], vec![1u8; l.max_payload_bytes]);
    let (worst, mean) = timed(20_000, |i| {
        h.receive(rt, publish(&format!("c{}", i % l.max_streams_per_account), Kind::SessionEvents, &small));
    });
    eprintln!("small publish at the byte budget: worst {worst:?} mean {mean:?}");
    // the adversarial loop: refill one ring with small entries, then a maximal payload into it
    let (worst, mean) = timed(50 * (l.ring_session_events + 1), |i| {
        let body = if i % (l.ring_session_events + 1) == l.ring_session_events { &big } else { &small };
        h.receive(rt, publish("c0", Kind::SessionEvents, body));
    });
    eprintln!("refill one ring then a maximal payload, repeated: worst {worst:?} mean {mean:?}");
}

fn budgeted(rate: usize) -> Hub {
    let limits = Limits { account_bytes_per_second: rate, account_burst_bytes: rate, ..Limits::default() };
    Hub::new(limits, 7).unwrap()
}

#[test]
fn an_accounts_work_budget_is_shared_by_its_connections_and_no_one_elses() {
    let mut h = budgeted(10_000);
    let (a1, a2, b) = (
        join(&mut h, "a", "rt", Role::Runtime),
        join(&mut h, "a", "phone", Role::Client),
        join(&mut h, "b", "rt", Role::Runtime),
    );
    assert_eq!(h.charge(a1, 0, 5).0, 0, "the first charge starts the account's clock");
    assert_eq!(h.charge(b, 0, 5).0, 0);
    assert_eq!(h.charge(a1, 10_000, 1_005).0, 0, "a full second's rate, earned since");
    assert_eq!(h.charge(a2, 5_000, 1_005).0, 500, "the other connection pays the same account's debt");
    assert_eq!(h.charge(b, 10_000, 1_005).0, 0, "another account is untouched");
}

#[test]
fn a_new_account_starts_with_no_budget_even_after_being_forgotten() {
    let mut h = budgeted(10_000);
    let rt = join(&mut h, "a", "rt", Role::Runtime);
    h.charge(rt, 0, 0);
    assert_eq!(h.charge(rt, 10_000, 60_000).0, 0, "a minute in, capped at one second's burst");
    h.close(rt, None);
    assert!(!h.has_account(&acct("a")), "nothing retained, so the relay forgot the account");
    let rt = join(&mut h, "a", "rt", Role::Runtime);
    assert_eq!(h.charge(rt, 10_000, 60_000).0, 1_000, "coming back is not a fresh burst");
}

#[test]
fn frames_the_relay_queues_are_charged_to_the_account_that_caused_them() {
    let mut h = budgeted(1_000_000);
    let rt = join(&mut h, "a", "rt", Role::Runtime);
    let subs: Vec<ConnId> = (0..10).map(|i| join(&mut h, "a", &format!("c{i}"), Role::Client)).collect();
    for &s in &subs {
        h.receive(s, subscribe("rt", "ch", None));
        h.take_outbound(s, usize::MAX);
    }
    let tokens = |h: &Hub| h.accounts[&acct("a")].rate.tokens();
    let before = tokens(&h);
    h.receive(rt, publish("ch", Kind::SessionEvents, b"x"));
    assert_eq!(before - tokens(&h), 10 * FRAME_COST_BYTES as i64, "one queued frame per subscriber");
    // a resubscribe backfills: one entry and the Backfilled marker
    let before = tokens(&h);
    h.receive(subs[0], subscribe("rt", "ch", None));
    assert_eq!(before - tokens(&h), 2 * FRAME_COST_BYTES as i64);
}

#[test]
fn a_zero_work_rate_is_a_configuration_error() {
    let zero = Limits { account_bytes_per_second: 0, ..Limits::default() };
    assert!(Hub::new(zero, 7).is_err());
}

#[test]
fn a_throttled_connection_is_told_once_every_ten_seconds_and_stays_open() {
    let mut h = budgeted(1_000);
    let rt = join(&mut h, "a", "rt", Role::Runtime);
    assert_eq!(h.charge(rt, 0, 0), (0, Vec::new()));
    assert!(out(&mut h, rt).is_empty(), "not in debt: nothing to say");
    assert_eq!(h.charge(rt, 99, 0).0, 99);
    assert!(out(&mut h, rt).is_empty(), "a wait under 100 ms is not worth a notice");
    h.charge(rt, 0, 99);
    let throttled = |h: &mut Hub| out(h, rt).iter().filter(|l| l.contains("Throttled")).count();
    let mut notices = 0;
    for ms in (0..=25_000).step_by(100) {
        let (wait, actions) = h.charge(rt, 10_000, ms);
        assert!(wait > 0);
        assert!(closed(&actions).is_empty(), "throttling never closes");
        notices += throttled(&mut h);
    }
    assert_eq!(notices, 3, "at 0, 10 and 20 seconds");
}

#[test]
fn every_epoch_a_hub_chooses_fits_in_a_double() {
    // A browser client holds an epoch in a double; anything above 2^53 - 1 would be rounded, and two rings could
    // then look like one. The seeds here are arbitrary; the property is over all of them.
    for seed in [0u64, 1, 7, u64::MAX, 0x9e37_79b9_7f4a_7c15, 12_345_678_901_234_567_890] {
        let mut h = Hub::new(Limits::default(), seed).unwrap();
        for _ in 0..1_000 {
            let epoch = h.next_epoch();
            assert!(epoch != 0, "an epoch of 0 means 'no ring' on the wire");
            assert!(epoch <= MAX_EXACT_IN_A_DOUBLE, "epoch {epoch} is larger than a double holds exactly");
            assert_eq!(epoch as f64 as u64, epoch, "epoch {epoch} does not survive a double");
        }
    }
}
