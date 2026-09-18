//! The server end to end: real websocket clients against `serve` on an ephemeral loopback port.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use wmlhub_proto::v1::{self, Envelope, Frame, Kind, Role, envelope::To, error::Code, frame::Body};
use wmlhub_proto::{decode_frames, encode_frames};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const MAX: usize = 1 << 20;

async fn start(config: wmlhub::Config) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(wmlhub::serve(listener, config, 1));
    format!("ws://{addr}")
}

async fn open(url: &str) -> Ws {
    try_open(url).await.expect("the hub accepted the connection")
}

/// Connect, or the error the hub answered with. A hub that refuses before the websocket upgrade — which is where it
/// refuses anything it can decide without reading — fails the connect itself rather than closing a live socket.
async fn try_open(url: &str) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    tokio_tungstenite::connect_async(url).await.map(|(ws, _)| ws)
}

async fn send(ws: &mut Ws, frames: &[Frame]) {
    ws.send(Message::binary(encode_frames(frames, MAX).unwrap())).await.unwrap();
}

/// The next frames the server sends, or None if the socket closed. Times out rather than hanging a test.
async fn recv(ws: &mut Ws) -> Option<Vec<Frame>> {
    loop {
        let next = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("server went quiet");
        match next {
            Some(Ok(Message::Binary(b))) => return Some(decode_frames(&b, MAX).unwrap()),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => return None,
        }
    }
}

/// Read until a frame matching `pred`, skipping others (presence, pings).
async fn expect(ws: &mut Ws, pred: impl Fn(&Body) -> bool) -> Body {
    loop {
        let frames = recv(ws).await.expect("socket closed while waiting");
        for f in frames {
            if let Some(body) = f.body {
                if pred(&body) {
                    return body;
                }
            }
        }
    }
}

fn hello(account: &str, principal: &str, role: Role) -> Frame {
    Frame {
        body: Some(Body::Hello(v1::Hello {
            protocol: 1,
            principal: principal.as_bytes().to_vec(),
            role: role as i32,
            account_credential: account.as_bytes().to_vec(),
            ..Default::default()
        })),
    }
}

async fn join(url: &str, account: &str, principal: &str, role: Role) -> Ws {
    let mut ws = open(url).await;
    send(&mut ws, &[hello(account, principal, role)]).await;
    expect(&mut ws, |b| matches!(b, Body::Welcome(_))).await;
    ws
}

fn subscribe(publisher: &str, channel: &str) -> Frame {
    Frame {
        body: Some(Body::Subscribe(v1::Subscribe {
            stream: Some(v1::StreamRef {
                publisher: publisher.as_bytes().to_vec(),
                channel: channel.as_bytes().to_vec(),
            }),
            since: None,
        })),
    }
}

fn envelope(to: To, kind: Kind, payload: &[u8], reference: u64) -> Frame {
    Frame {
        body: Some(Body::Envelope(Envelope {
            to: Some(to),
            kind: kind as i32,
            payload: payload.to_vec().into(),
            r#ref: reference,
            ..Default::default()
        })),
    }
}

#[tokio::test]
async fn every_connection_opens_with_a_fresh_challenge() {
    let url = start(wmlhub::Config::default()).await;
    let mut nonces = Vec::new();
    for _ in 0..2 {
        let mut ws = open(&url).await;
        let Body::Challenge(c) = expect(&mut ws, |b| matches!(b, Body::Challenge(_))).await else { unreachable!() };
        assert_eq!(c.nonce.len(), 32);
        nonces.push(c.nonce);
    }
    assert_ne!(nonces[0], nonces[1]);
}

#[tokio::test]
async fn a_published_envelope_reaches_a_subscriber_with_the_sender_stamped() {
    let url = start(wmlhub::Config::default()).await;
    let mut rt = join(&url, "alice", "rt", Role::Runtime).await;
    let mut phone = join(&url, "alice", "phone", Role::Client).await;

    send(&mut phone, &[subscribe("rt", "s1")]).await;
    expect(&mut phone, |b| matches!(b, Body::Backfilled(_))).await;
    send(&mut rt, &[envelope(To::Channel(b"s1".to_vec()), Kind::SessionEvents, b"ciphertext", 0)]).await;

    let Body::Envelope(e) = expect(&mut phone, |b| matches!(b, Body::Envelope(_))).await else { unreachable!() };
    assert_eq!(e.sender, b"rt");
    assert_eq!(e.seq, 1);
    assert_eq!(e.payload.as_ref(), b"ciphertext");
}

#[tokio::test]
async fn a_command_across_accounts_is_unavailable() {
    let url = start(wmlhub::Config::default()).await;
    let _rt = join(&url, "alice", "rt", Role::Runtime).await;
    let mut spy = join(&url, "mallory", "phone", Role::Client).await;
    send(&mut spy, &[envelope(To::Principal(b"rt".to_vec()), Kind::Command, b"click", 7)]).await;
    let Body::Error(e) = expect(&mut spy, |b| matches!(b, Body::Error(_))).await else { unreachable!() };
    assert_eq!((e.code(), e.r#ref), (Code::Unavailable, 7));
}

#[tokio::test]
async fn a_command_and_its_result_travel_both_ways() {
    let url = start(wmlhub::Config::default()).await;
    let mut rt = join(&url, "alice", "rt", Role::Runtime).await;
    let mut phone = join(&url, "alice", "phone", Role::Client).await;
    send(&mut phone, &[envelope(To::Principal(b"rt".to_vec()), Kind::Command, b"cancel", 1)]).await;
    let Body::Envelope(cmd) = expect(&mut rt, |b| matches!(b, Body::Envelope(_))).await else { unreachable!() };
    assert_eq!((cmd.sender.as_slice(), cmd.payload.as_ref()), (&b"phone"[..], &b"cancel"[..]));
    send(&mut rt, &[envelope(To::Principal(b"phone".to_vec()), Kind::CommandResult, b"ok", 1)]).await;
    let Body::Envelope(res) = expect(&mut phone, |b| matches!(b, Body::Envelope(_))).await else { unreachable!() };
    assert_eq!(res.payload.as_ref(), b"ok");
}

#[tokio::test]
async fn frames_batched_with_hello_are_routed() {
    let url = start(wmlhub::Config::default()).await;
    let mut phone = open(&url).await;
    send(&mut phone, &[hello("alice", "phone", Role::Client), subscribe("rt", "s1")]).await;
    expect(&mut phone, |b| matches!(b, Body::Backfilled(_))).await;
}

#[tokio::test]
async fn a_first_frame_that_is_not_hello_is_refused_and_closed() {
    let url = start(wmlhub::Config::default()).await;
    let mut ws = open(&url).await;
    expect(&mut ws, |b| matches!(b, Body::Challenge(_))).await;
    send(&mut ws, &[subscribe("rt", "s1")]).await;
    expect(&mut ws, |b| matches!(b, Body::Error(e) if e.code() == Code::Invalid)).await;
    assert!(recv(&mut ws).await.is_none());
}

#[tokio::test]
async fn a_hello_without_an_account_credential_is_unauthenticated() {
    let url = start(wmlhub::Config::default()).await;
    let mut ws = open(&url).await;
    send(&mut ws, &[hello("", "phone", Role::Client)]).await;
    expect(&mut ws, |b| matches!(b, Body::Error(e) if e.code() == Code::Unauthenticated)).await;
}

#[tokio::test]
async fn a_malformed_message_closes_the_connection_and_others_see_it_leave() {
    let url = start(wmlhub::Config::default()).await;
    let mut rt = join(&url, "alice", "rt", Role::Runtime).await;
    let mut phone = join(&url, "alice", "phone", Role::Client).await;
    expect(&mut rt, |b| matches!(b, Body::Presence(p) if p.online)).await;

    phone.send(Message::binary(vec![0x05, 0x01])).await.unwrap();
    expect(&mut phone, |b| matches!(b, Body::Error(e) if e.code() == Code::Invalid)).await;
    let Body::Presence(p) = expect(&mut rt, |b| matches!(b, Body::Presence(_))).await else { unreachable!() };
    assert_eq!((p.principal.as_slice(), p.online), (&b"phone"[..], false));
}

#[tokio::test]
async fn the_server_pings_a_quiet_connection() {
    let config = wmlhub::Config { ping_interval: Duration::from_millis(100), ..wmlhub::Config::default() };
    let url = start(config).await;
    let mut phone = join(&url, "alice", "phone", Role::Client).await;
    expect(&mut phone, |b| matches!(b, Body::Ping(_))).await;
}

#[tokio::test]
async fn an_idle_connection_is_closed() {
    let config = wmlhub::Config { idle_timeout: Duration::from_millis(200), ..wmlhub::Config::default() };
    let url = start(config).await;
    let mut phone = join(&url, "alice", "phone", Role::Client).await;
    expect(&mut phone, |b| matches!(b, Body::Error(e) if e.code() == Code::Limit)).await;
}

#[tokio::test]
async fn a_slow_consumer_is_told_and_disconnected() {
    let limits = wmlhub_relay::Limits { queue_bytes: 256, ..wmlhub_relay::Limits::default() };
    let url = start(wmlhub::Config { limits, ..wmlhub::Config::default() }).await;
    let mut rt = join(&url, "alice", "rt", Role::Runtime).await;
    let mut phone = join(&url, "alice", "phone", Role::Client).await;
    send(&mut phone, &[subscribe("rt", "s1")]).await;
    expect(&mut phone, |b| matches!(b, Body::Backfilled(_))).await;

    send(&mut rt, &[envelope(To::Channel(b"s1".to_vec()), Kind::SessionEvents, &[0; 1024], 0)]).await;
    expect(&mut phone, |b| matches!(b, Body::Error(e) if e.code() == Code::SlowConsumer)).await;
    assert!(recv(&mut phone).await.is_none(), "socket stayed open");
}

#[tokio::test]
async fn the_account_limit_holds_across_shards() {
    let limits = wmlhub_relay::Limits { max_accounts: 2, ..wmlhub_relay::Limits::default() };
    let url = start(wmlhub::Config { limits, shards: 8, ..wmlhub::Config::default() }).await;
    let a = join(&url, "a", "p", Role::Client).await;
    let _b = join(&url, "b", "p", Role::Client).await;
    // a third account is refused wherever it hashes to
    let mut c = open(&url).await;
    send(&mut c, &[hello("c", "p", Role::Client)]).await;
    expect(&mut c, |b| matches!(b, Body::Error(e) if e.code() == Code::Limit)).await;
    // another connection of a known account is not a new account
    let _a2 = join(&url, "a", "q", Role::Client).await;
    // when an account is gone, its slot is free again
    drop(a);
    drop(_a2);
    let mut admitted = false;
    for _ in 0..50 {
        let mut d = open(&url).await;
        send(&mut d, &[hello("d", "p", Role::Client)]).await;
        if matches!(expect(&mut d, |b| matches!(b, Body::Welcome(_) | Body::Error(_))).await, Body::Welcome(_)) {
            admitted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(admitted, "a freed account slot was never reused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_new_accounts_never_exceed_the_limit() {
    let limits = wmlhub_relay::Limits { max_accounts: 5, ..wmlhub_relay::Limits::default() };
    let url = start(wmlhub::Config { limits, shards: 8, ..wmlhub::Config::default() }).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(60));
    let tasks: Vec<_> = (0..60)
        .map(|i| {
            let (url, barrier) = (url.clone(), barrier.clone());
            tokio::spawn(async move {
                let mut ws = open(&url).await;
                expect(&mut ws, |b| matches!(b, Body::Challenge(_))).await;
                barrier.wait().await;
                send(&mut ws, &[hello(&format!("acct{i}"), "p", Role::Client)]).await;
                let welcomed = matches!(
                    expect(&mut ws, |b| matches!(b, Body::Welcome(_) | Body::Error(_))).await,
                    Body::Welcome(_)
                );
                (welcomed, ws)
            })
        })
        .collect();
    let mut sockets = Vec::new();
    let mut admitted = 0;
    for t in tasks {
        let (welcomed, ws) = t.await.unwrap();
        admitted += usize::from(welcomed);
        sockets.push(ws);
    }
    assert_eq!(admitted, 5);
}

#[tokio::test]
async fn an_account_over_its_work_rate_is_slowed_loses_nothing_and_slows_no_other_account() {
    const RATE: usize = 20_000;
    let mut config = wmlhub::Config::default();
    config.limits.account_bytes_per_second = RATE;
    config.limits.account_burst_bytes = RATE;
    let url = start(config).await;

    let mut slow_rt = join(&url, "slow", "rt", Role::Runtime).await;
    let mut slow_phone = join(&url, "slow", "phone", Role::Client).await;
    send(&mut slow_phone, &[subscribe("rt", "s")]).await;
    expect(&mut slow_phone, |b| matches!(b, Body::Backfilled(_))).await;
    let mut fast_rt = join(&url, "fast", "rt", Role::Runtime).await;
    let mut fast_phone = join(&url, "fast", "phone", Role::Client).await;
    send(&mut fast_phone, &[subscribe("rt", "s")]).await;
    expect(&mut fast_phone, |b| matches!(b, Body::Backfilled(_))).await;

    // 5 x 8 KB at 20 KB/s: at least two seconds of work, all of it sent at once
    let started = tokio::time::Instant::now();
    for i in 0..5u8 {
        send(&mut slow_rt, &[envelope(To::Channel(b"s".to_vec()), Kind::SessionEvents, &[i; 8_000], 0)]).await;
    }
    // meanwhile another account's small publish goes straight through
    send(&mut fast_rt, &[envelope(To::Channel(b"s".to_vec()), Kind::SessionEvents, b"hi", 0)]).await;
    expect(&mut fast_phone, |b| matches!(b, Body::Envelope(_))).await;
    let fast = started.elapsed();

    let mut seen = Vec::new();
    while seen.len() < 5 {
        let Body::Envelope(e) = expect(&mut slow_phone, |b| matches!(b, Body::Envelope(_))).await else {
            unreachable!()
        };
        seen.push(e.payload[0]);
    }
    let slow = started.elapsed();
    assert_eq!(seen, [0, 1, 2, 3, 4], "every envelope, in order");
    let mut told = false;
    while let Ok(Some(frames)) = tokio::time::timeout(Duration::from_millis(200), recv(&mut slow_rt)).await {
        told |= frames.iter().any(|f| matches!(&f.body, Some(Body::Error(e)) if e.code() == Code::Throttled));
    }
    assert!(told, "the throttled connection was told");
    assert!(slow >= Duration::from_millis(1_800), "40 KB at 20 KB/s took only {slow:?}");
    // and no longer: a budget that never refills (two clocks mixed up, say) makes every message wait longer than the last
    assert!(slow < Duration::from_millis(3_500), "40 KB at 20 KB/s took {slow:?}");
    assert!(fast < Duration::from_millis(500), "the other account waited {fast:?}");
}

#[tokio::test]
async fn a_hello_larger_than_the_limit_is_refused_before_it_is_decoded() {
    let mut config = wmlhub::Config { max_hello_bytes: 4_096, ..Default::default() };
    config.limits.max_frame_bytes = 1 << 20;
    let url = start(config).await;
    let mut ws = open(&url).await;
    // a frame of the right shape, padded past the limit: nothing about it is read
    let huge = Frame {
        body: Some(Body::Hello(v1::Hello {
            protocol: 1,
            principal: b"phone".to_vec(),
            role: Role::Client as i32,
            account_credential: vec![7; 8_192],
            ..Default::default()
        })),
    };
    send(&mut ws, &[huge]).await;
    let answer = expect(&mut ws, |b| matches!(b, Body::Error(_))).await;
    assert!(matches!(&answer, Body::Error(e) if e.code() == Code::Limit && e.message == "hello too large"));
}

#[tokio::test]
async fn a_hello_inside_the_limit_still_works() {
    let url = start(wmlhub::Config { max_hello_bytes: 4_096, ..Default::default() }).await;
    let mut ws = join(&url, "alice", "phone", Role::Client).await;
    send(&mut ws, &[subscribe("rt", "s1")]).await;
    expect(&mut ws, |b| matches!(b, Body::Backfilled(_))).await;
}

#[tokio::test]
async fn connecting_too_often_from_one_address_is_refused_and_the_rest_still_connect() {
    // Off by default (a proxy would share one bucket with everyone behind it), so this turns it on.
    let arrivals = wmlhub::arrivals::Arrivals { per_minute: 60, burst: 3 };
    let url = start(wmlhub::Config { arrivals, ..Default::default() }).await;

    // the burst, then one too many: the refusal is a closed socket, since nothing has been said yet
    let mut held = Vec::new();
    for i in 0..3 {
        held.push(join(&url, "alice", &format!("p{i}"), Role::Client).await);
    }
    assert!(try_open(&url).await.is_err(), "the fourth connection in a burst of three is refused");

    // and the ones that got in are untouched
    for ws in &mut held {
        send(ws, &[Frame { body: Some(Body::Ping(v1::Ping { nonce: 9 })) }]).await;
        let pong = expect(ws, |b| matches!(b, Body::Pong(_))).await;
        assert!(matches!(pong, Body::Pong(p) if p.nonce == 9));
    }
}

/// Connect claiming to be forwarded for `client`, the way a proxy in front of the hub would.
async fn try_open_forwarded(url: &str, client: &str) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = url.into_client_request().unwrap();
    request.headers_mut().insert("x-forwarded-for", client.parse().unwrap());
    tokio_tungstenite::connect_async(request).await.map(|(ws, _)| ws)
}

#[tokio::test]
async fn behind_a_named_proxy_each_client_has_its_own_allowance() {
    // The test's own connections arrive from loopback, so loopback is the proxy here. Without this the whole test
    // would be one address and the limit would be the one that cannot be a default.
    let config = wmlhub::Config {
        arrivals: wmlhub::arrivals::Arrivals { per_minute: 60, burst: 2 },
        trusted_proxies: wmlhub::forwarded::Proxies::parse("127.0.0.1,::1").unwrap(),
        ..Default::default()
    };
    let url = start(config).await;

    // one client spends its own allowance and is refused, twice over what it is allowed
    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(try_open_forwarded(&url, "203.0.113.9").await.expect("inside its burst"));
    }
    assert!(try_open_forwarded(&url, "203.0.113.9").await.is_err(), "a third from that client is refused");

    // another client behind the same proxy is untouched, which is the whole point
    held.push(try_open_forwarded(&url, "198.51.100.7").await.expect("a different client, a different allowance"));
    assert_eq!(held.len(), 3);
}

#[tokio::test]
async fn a_forwarded_header_from_anybody_but_a_named_proxy_is_ignored() {
    // Nothing is named as a proxy, so the header is a client's claim about itself and changes nothing: two
    // connections claiming different clients still share the one allowance their socket really has.
    let config =
        wmlhub::Config { arrivals: wmlhub::arrivals::Arrivals { per_minute: 60, burst: 1 }, ..Default::default() };
    let url = start(config).await;
    let _held = try_open_forwarded(&url, "203.0.113.9").await.expect("the first connection");
    assert!(
        try_open_forwarded(&url, "198.51.100.7").await.is_err(),
        "claiming to be somebody else is not a way to get another allowance"
    );
}

#[tokio::test]
async fn a_socket_that_never_says_hello_holds_a_place_only_until_it_times_out() {
    let config =
        wmlhub::Config { max_pending_sockets: 1, hello_timeout: Duration::from_millis(200), ..Default::default() };
    let url = start(config).await;

    // one socket sits there saying nothing, which is the whole pre-authentication surface
    let mut squatter = open(&url).await;
    expect(&mut squatter, |b| matches!(b, Body::Challenge(_))).await;
    assert!(try_open(&url).await.is_err(), "while the one place is taken, another is refused");

    // its hello timeout ends it, and the place comes back
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut ws = join(&url, "alice", "phone", Role::Client).await;
    send(&mut ws, &[Frame { body: Some(Body::Ping(v1::Ping { nonce: 1 })) }]).await;
    expect(&mut ws, |b| matches!(b, Body::Pong(_))).await;
}

#[tokio::test]
async fn an_authenticated_connection_gives_its_place_back_at_once() {
    let url = start(wmlhub::Config { max_pending_sockets: 1, ..Default::default() }).await;
    // each of these authenticates, so the single pending place is free again every time
    for i in 0..5 {
        let mut ws = join(&url, "alice", &format!("p{i}"), Role::Client).await;
        send(&mut ws, &[Frame { body: Some(Body::Ping(v1::Ping { nonce: i as u64 })) }]).await;
        expect(&mut ws, |b| matches!(b, Body::Pong(_))).await;
    }
}

#[tokio::test]
async fn the_connection_rate_is_off_by_default_so_a_proxys_address_is_not_one_bucket() {
    // Every client behind Tailscale or Caddy arrives from the same address. A default rate would throttle a
    // household to one allowance, so the default admits everything and an operator exposing the hub sets a rate.
    let url = start(wmlhub::Config::default()).await;
    let mut held = Vec::new();
    for i in 0..40 {
        held.push(join(&url, "alice", &format!("p{i}"), Role::Client).await);
    }
    assert_eq!(held.len(), 40);
}
