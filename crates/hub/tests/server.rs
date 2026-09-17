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
    tokio_tungstenite::connect_async(url).await.unwrap().0
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
            payload: payload.to_vec(),
            r#ref: reference,
            ..Default::default()
        })),
    }
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
    assert_eq!(e.payload, b"ciphertext");
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
    assert_eq!((cmd.sender.as_slice(), cmd.payload.as_slice()), (&b"phone"[..], &b"cancel"[..]));
    send(&mut rt, &[envelope(To::Principal(b"phone".to_vec()), Kind::CommandResult, b"ok", 1)]).await;
    let Body::Envelope(res) = expect(&mut phone, |b| matches!(b, Body::Envelope(_))).await else { unreachable!() };
    assert_eq!(res.payload, b"ok");
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
    send(&mut ws, &[subscribe("rt", "s1")]).await;
    let frames = recv(&mut ws).await.unwrap();
    assert!(matches!(&frames[0].body, Some(Body::Error(e)) if e.code() == Code::Invalid));
    assert!(recv(&mut ws).await.is_none());
}

#[tokio::test]
async fn a_hello_without_an_account_credential_is_unauthenticated() {
    let url = start(wmlhub::Config::default()).await;
    let mut ws = open(&url).await;
    send(&mut ws, &[hello("", "phone", Role::Client)]).await;
    let frames = recv(&mut ws).await.unwrap();
    assert!(matches!(&frames[0].body, Some(Body::Error(e)) if e.code() == Code::Unauthenticated));
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
