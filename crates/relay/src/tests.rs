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
        payload: payload.to_vec(),
        ..Default::default()
    }))
}

fn command(to: &str, payload: &[u8], reference: u64) -> Frame {
    frame(Body::Envelope(Envelope {
        to: Some(To::Principal(to.as_bytes().to_vec())),
        kind: Kind::Command as i32,
        payload: payload.to_vec(),
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

fn out(h: &mut Hub, conn: ConnId) -> Vec<String> {
    show(&h.take_outbound(conn, usize::MAX))
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
    let first = h.take_outbound(phone, usize::MAX);
    let Some(Body::Backfilled(b)) = &first[0].body else { panic!("expected backfilled") };
    assert_eq!(b.epoch, 0, "no ring before the first publish");

    for p in [b"a", b"b", b"c"] {
        h.receive(rt, publish("s1", Kind::SessionEvents, p));
    }
    let seen = h.take_outbound(phone, usize::MAX);
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
    let mut h = Hub::new(Limits { account_ring_bytes: 10, ..Limits::default() }, 1).unwrap();
    let rt = join(&mut h, "alice", "rt", Role::Runtime);
    let phone = join(&mut h, "alice", "phone", Role::Client);
    h.receive(rt, publish("big", Kind::SessionEvents, b"xxxx"));
    h.receive(rt, publish("big", Kind::SessionEvents, b"yyyy"));
    h.receive(rt, publish("small", Kind::SessionEvents, b"zzz"));
    h.receive(phone, subscribe("rt", "big", None));
    assert_eq!(out(&mut h, phone), ["env from=rt seq=2 yyyy", "backfilled seq=2 truncated=true"]);
    h.receive(phone, subscribe("rt", "small", None));
    assert_eq!(out(&mut h, phone), ["env from=rt seq=1 zzz", "backfilled seq=1 truncated=false"]);
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
