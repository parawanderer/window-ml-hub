//! `wmlhub-loadgen`: measure the hub, so performance claims are numbers.
//!
//! It starts the hub binary as a child process (so the hub's memory and CPU are its own, not mixed with the load
//! generator's), in development mode on loopback, and drives it:
//!
//! - `fanout`: per account, one runtime publishes on several channels at a fixed rate and several clients subscribe
//!   to all of them. Reports delivered messages per second, end-to-end latency percentiles, and the hub's CPU time and
//!   resident memory.
//! - `idle`: open many connections that do nothing, and report the hub's resident memory per connection.
//!
//! Latency is measured from each message's SCHEDULED send time, not the time the publisher got around to sending it:
//! a publisher that falls behind would otherwise hide exactly the delay being measured (coordinated omission).
//!
//! Development mode skips signature verification. `--keys` runs the hub the way it is deployed instead, with every
//! connection presenting a real certificate chain, which is what makes `--hello-flood` mean anything: a stream of
//! hellos that FAIL verification, whose cost is charged to no account because none exists until one verifies. The
//! question it answers is whether that cost reaches the accounts that are connected.

use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use hdrhistogram::Histogram;
use tokio::net::TcpStream;
use tokio::sync::{Barrier, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use wmlhub_keys::{CertSpec, Identity, account_id, hello_transcript, issue, principal_id, scope, sign_hello};
use wmlhub_proto::v1::{self, Envelope, Frame, Kind, Role, envelope::To, frame::Body};
use wmlhub_proto::{decode_frames, encode_frames};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;
const MAX: usize = 4 << 20;

#[derive(Parser)]
#[command(name = "wmlhub-loadgen")]
struct Cli {
    /// The hub binary to start (build it with `cargo build --release -p wmlhub`).
    #[arg(long, default_value = "target/release/wmlhub")]
    hub_bin: PathBuf,
    #[arg(long, default_value = "127.0.0.1:18787")]
    listen: String,
    /// Environment for the hub, `KEY=VALUE`, repeatable (`--hub-env WMLHUB_SHARDS=1`). Environment rather than flags,
    /// so an older hub binary given a setting it does not know still starts.
    #[arg(long = "hub-env", value_parser = parse_env)]
    hub_env: Vec<(String, String)>,
    /// Run the hub as it is deployed: every connection presents a certificate chain and it is verified. Without this
    /// the hub runs in development mode, which verifies nothing.
    #[arg(long)]
    keys: bool,
    #[command(subcommand)]
    scenario: Scenario,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum FloodKind {
    Verify,
    Cheap,
}

#[derive(Subcommand)]
enum Scenario {
    /// Publishers to subscribers, across accounts.
    Fanout {
        #[arg(long, default_value_t = 10)]
        accounts: usize,
        /// subscribing clients per account
        #[arg(long, default_value_t = 5)]
        subscribers: usize,
        /// channels each runtime publishes on
        #[arg(long, default_value_t = 4)]
        channels: usize,
        /// messages per second per runtime, spread over its channels
        #[arg(long, default_value_t = 200)]
        rate: u64,
        /// payload bytes per message
        #[arg(long, default_value_t = 512)]
        payload: usize,
        #[arg(long, default_value_t = 10)]
        seconds: u64,
        /// messages batched into one websocket message by each publisher
        #[arg(long, default_value_t = 1)]
        batch: usize,
        /// Extra accounts that publish as fast as the hub reads, in batches of 256, with one subscriber each. They are
        /// left out of every latency figure: what they do to the other accounts is the measurement.
        #[arg(long, default_value_t = 0)]
        flooders: usize,
        /// Connections that each open, send a hello that fails, and reconnect, for the whole run. Needs `--keys`.
        #[arg(long, default_value_t = 0)]
        hello_flood: usize,
        /// `verify`: a chain that verifies all the way to the hello signature and fails there, three Ed25519
        /// verifications, the most a failure can cost and needing nothing but a root the attacker made up. `cheap`:
        /// a hello that fails before any signature is checked, which isolates the cost of the connection itself.
        #[arg(long, default_value = "verify")]
        flood_kind: FloodKind,
    },
    /// Idle connections, for memory per connection.
    Idle {
        #[arg(long, default_value_t = 10_000)]
        connections: usize,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    KEYS.set(cli.keys).expect("set once");
    let state = std::env::temp_dir().join(format!("wmlhub-loadgen-{}", std::process::id()));
    let mut args: Vec<String> = vec!["serve".into(), "--listen".into(), cli.listen.clone()];
    if cli.keys {
        // Open registration, so each benchmark account registers itself on its first connection, with limits well
        // above anything a run does: what is measured is the hub, not its registration policy.
        let state = state.to_string_lossy().into_owned();
        args.extend([
            "--hub-name".into(),
            HUB_NAME.into(),
            "--state-dir".into(),
            state,
            "--registration".into(),
            "open".into(),
        ]);
    } else {
        args.push("--dev".into());
    }
    let mut hub = tokio::process::Command::new(&cli.hub_bin)
        .args(&args)
        .env("WMLHUB_OPEN_PER_ADDRESS", "1000000")
        .env("WMLHUB_OPEN_TOTAL", "1000000")
        .envs(cli.hub_env.iter().map(|(k, v)| (k, v)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {}: {e}", cli.hub_bin.display()));
    let pid = hub.id().expect("hub has a pid");
    let url = format!("ws://{}", cli.listen);
    wait_for_hub(&cli.listen).await;
    let baseline = sample(pid);
    println!("hub pid {pid}, baseline rss {} KiB", baseline.rss_kib);

    match cli.scenario {
        Scenario::Fanout {
            accounts,
            subscribers,
            channels,
            rate,
            payload,
            seconds,
            batch,
            flooders,
            hello_flood,
            flood_kind,
        } => {
            assert!(hello_flood == 0 || cli.keys, "--hello-flood needs --keys: development mode verifies nothing");
            let shape = Shape {
                accounts,
                subscribers,
                channels,
                rate,
                payload,
                seconds,
                batch,
                flooders,
                hello_flood,
                flood_kind,
            };
            fanout(&url, pid, baseline, shape).await;
        }
        Scenario::Idle { connections } => idle(&url, pid, baseline, connections).await,
    }
    let _ = hub.kill().await;
    let _ = std::fs::remove_dir_all(&state);
}

fn parse_env(s: &str) -> Result<(String, String), String> {
    s.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())).ok_or_else(|| format!("expected KEY=VALUE: {s}"))
}

async fn wait_for_hub(addr: &str) {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("hub did not start listening on {addr}");
}

#[derive(Clone, Copy)]
struct Sample {
    rss_kib: u64,
    cpu: Duration,
}

/// The hub's resident memory and total CPU time, from `ps` (macOS and Linux).
fn sample(pid: u32) -> Sample {
    let out = std::process::Command::new("ps").args(["-o", "rss=,time=", "-p", &pid.to_string()]).output().expect("ps");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.split_whitespace();
    let rss_kib = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let cpu = parts.next().map(parse_cpu_time).unwrap_or_default();
    Sample { rss_kib, cpu }
}

/// `ps` time: `[[dd-]hh:]mm:ss[.ss]`.
fn parse_cpu_time(s: &str) -> Duration {
    let (days, rest) = s.split_once('-').map_or((0.0, s), |(d, r)| (d.parse().unwrap_or(0.0), r));
    let secs = rest.split(':').fold(0.0, |acc, part| acc * 60.0 + part.parse::<f64>().unwrap_or(0.0));
    Duration::from_secs_f64(days * 86_400.0 + secs)
}

/// Threads the hello flood runs on, kept off the runtime the measuring tasks use.
const FLOOD_THREADS: usize = 2;

/// Whether the hub was started with `--keys`, read wherever a connection is made.
static KEYS: OnceLock<bool> = OnceLock::new();
/// The name the hub is started under in keys mode, which every hello signs.
const HUB_NAME: &str = "loadgen.test";

fn keys_mode() -> bool {
    KEYS.get().copied().unwrap_or(false)
}

/// Thirty-two bytes derived from `parts`, the same every run, so an account's root and a principal's key are stable
/// without storing anything.
fn seed(parts: &[&str]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = std::hash::DefaultHasher::new();
        (parts, i).hash(&mut h);
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    out
}

fn root_of(account: &str) -> Identity {
    Identity::from_seed(seed(&["root", account]))
}

fn identity_of(account: &str, principal: &str) -> Identity {
    Identity::from_seed(seed(&["principal", account, principal]))
}

/// What a principal is called on the wire: the name it claims in development mode, and the hash of its key with keys.
/// Anything that names a publisher has to use this, or a subscription in keys mode names nobody.
fn principal_of(account: &str, principal: &str) -> Vec<u8> {
    if keys_mode() {
        principal_id(&identity_of(account, principal).public()).to_vec()
    } else {
        principal.as_bytes().to_vec()
    }
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// A certificate for `subject`, an hour either side of now.
fn certificate(issuer: &Identity, subject: &Identity, role: Role, may_pair: bool) -> v1::Certificate {
    let now = wall_ms();
    let spec = CertSpec {
        subject: subject.public(),
        agreement_key: [7; 32],
        role,
        scopes: vec![scope::VIEW.into(), scope::DRIVE.into()],
        may_pair,
        may_revoke: false,
        not_before_ms: now - 3_600_000,
        not_after_ms: now + 3_600_000,
        label: String::new(),
    };
    issue(issuer, &spec).expect("a certificate the issuer may make")
}

async fn open(url: &str) -> Ws {
    let config = WebSocketConfig::default().max_message_size(Some(MAX)).max_frame_size(Some(MAX));
    let (ws, _) = tokio_tungstenite::connect_async_with_config(url, Some(config), true).await.expect("connect");
    ws
}

/// The nonce in the hub's first frame.
async fn challenge(ws: &mut Ws) -> Option<Vec<u8>> {
    while let Some(Ok(msg)) = ws.next().await {
        if let Message::Binary(b) = msg {
            for f in decode_frames(&b, MAX).ok()? {
                if let Some(Body::Challenge(c)) = f.body {
                    return Some(c.nonce);
                }
            }
        }
    }
    None
}

async fn connect(url: &str, account: &str, principal: &str, role: Role) -> Ws {
    let mut ws = open(url).await;
    let hello = if keys_mode() {
        let nonce = challenge(&mut ws).await.expect("the hub opens with a challenge");
        let (root, me) = (root_of(account), identity_of(account, principal));
        let id = principal_id(&me.public());
        let transcript = hello_transcript(HUB_NAME, &nonce, &id, role, &account_id(&root.public()));
        v1::Hello {
            protocol: 1,
            principal: id.to_vec(),
            role: role as i32,
            account_root: root.public().to_vec(),
            chain: vec![certificate(&root, &me, role, false)],
            signature: sign_hello(&me, &transcript),
            ..Default::default()
        }
    } else {
        v1::Hello {
            protocol: 1,
            principal: principal.as_bytes().to_vec(),
            role: role as i32,
            account_credential: account.as_bytes().to_vec(),
            ..Default::default()
        }
    };
    ws.send(Message::binary(encode_frames(&[Frame { body: Some(Body::Hello(hello)) }], MAX).unwrap())).await.unwrap();
    wait_for(&mut ws, |b| matches!(b, Body::Welcome(_))).await;
    ws
}

async fn wait_for(ws: &mut Ws, pred: impl Fn(&Body) -> bool) {
    while let Some(Ok(msg)) = ws.next().await {
        if let Message::Binary(b) = msg {
            for f in decode_frames(&b, MAX).unwrap() {
                match f.body {
                    Some(ref body) if pred(body) => return,
                    Some(Body::Error(e)) => panic!("hub refused: {:?} {}", e.code(), e.message),
                    _ => {}
                }
            }
        }
    }
    panic!("connection closed while waiting");
}

struct Shape {
    accounts: usize,
    subscribers: usize,
    channels: usize,
    rate: u64,
    payload: usize,
    seconds: u64,
    batch: usize,
    flooders: usize,
    hello_flood: usize,
    flood_kind: FloodKind,
}

/// One connection's worth of hellos that fail, until `stop`. Counts the refusals it got back.
///
/// `Verify` builds a chain that verifies all the way: an attacker's own root, a delegate it allowed to pair, and a
/// leaf under that. Then it signs the hello over the wrong nonce, so the hub checks two certificates and the hello
/// signature before refusing, which is the most a refusal can cost and takes nothing but keys the attacker made.
/// `Cheap` sends a chain that does not decode, which the hub refuses before any signature, so the difference between
/// the two is what verification costs and not what a connection costs.
async fn failing_hellos(url: String, kind: FloodKind, stop: Arc<AtomicBool>, refused: Arc<AtomicU64>) {
    let (root, mid, leaf) = (
        Identity::from_seed(seed(&["flood-root"])),
        Identity::from_seed(seed(&["flood-mid"])),
        Identity::from_seed(seed(&["flood-leaf"])),
    );
    let chain = match kind {
        FloodKind::Verify => {
            vec![certificate(&mid, &leaf, Role::Client, false), certificate(&root, &mid, Role::Client, true)]
        }
        FloodKind::Cheap => vec![v1::Certificate { body: vec![0xff; 16], signature: vec![0; 64] }],
    };
    let id = principal_id(&leaf.public());
    let account = account_id(&root.public());
    // The right key over the wrong nonce: a signature that is well formed and does not verify. The nonce is wrong
    // whatever the hub sends, so the whole hello is built once. Signing per connection would spend the load
    // generator's own CPU and colour the very latency figures this exists to read.
    let wrong = hello_transcript(HUB_NAME, &[0u8; 32], &id, Role::Client, &account);
    let hello = v1::Hello {
        protocol: 1,
        principal: id.to_vec(),
        role: Role::Client as i32,
        account_root: root.public().to_vec(),
        chain,
        signature: sign_hello(&leaf, &wrong),
        ..Default::default()
    };
    let hello = encode_frames(&[Frame { body: Some(Body::Hello(hello)) }], MAX).unwrap();
    while !stop.load(Ordering::Relaxed) {
        let Ok(Ok((mut ws, _))) = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_tungstenite::connect_async_with_config(&url, Some(WebSocketConfig::default()), true),
        )
        .await
        else {
            continue;
        };
        if challenge(&mut ws).await.is_none() {
            continue;
        }
        if ws.send(Message::binary(hello.clone())).await.is_err() {
            continue;
        }
        // Whatever comes back is a refusal; a close is one too.
        let _ = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
        refused.fetch_add(1, Ordering::Relaxed);
        // Close with a reset, as a flood would. A graceful close leaves the connection in TIME_WAIT for half a minute,
        // and at tens of thousands a second one machine runs out of ephemeral ports within a second: the flood then
        // measures the kernel's port table, and the leftovers corrupt the NEXT run's connected accounts too.
        if let MaybeTlsStream::Plain(tcp) = ws.get_ref() {
            #[allow(deprecated)]
            let _ = tcp.set_linger(Some(Duration::ZERO));
        }
        drop(ws);
    }
}

/// One flooding account: a runtime publishing batches as fast as its socket takes them until `stop`, and one subscriber
/// reading everything. Returns envelopes sent.
async fn flood(url: String, n: usize, payload: usize, ready: Arc<Barrier>, stop: Duration) -> u64 {
    const BATCH: usize = 256;
    let account = format!("flood{n}");
    let mut sub = connect(&url, &account, "client", Role::Client).await;
    let frame = Frame {
        body: Some(Body::Subscribe(v1::Subscribe {
            stream: Some(v1::StreamRef { publisher: principal_of(&account, "runtime"), channel: b"f".to_vec() }),
            since: None,
        })),
    };
    sub.send(Message::binary(encode_frames(&[frame], MAX).unwrap())).await.unwrap();
    wait_for(&mut sub, |b| matches!(b, Body::Backfilled(_))).await;
    let mut ws = connect(&url, &account, "runtime", Role::Runtime).await;
    let deadline = tokio::time::Instant::now() + stop;
    let reader = tokio::spawn(async move {
        while let Ok(Some(Ok(_))) = tokio::time::timeout_at(deadline + Duration::from_secs(2), sub.next()).await {}
    });
    let env = Frame {
        body: Some(Body::Envelope(Envelope {
            to: Some(To::Channel(b"f".to_vec())),
            kind: Kind::SessionEvents as i32,
            payload: vec![3u8; payload].into(),
            ..Default::default()
        })),
    };
    let message = encode_frames(&vec![env; BATCH], MAX).unwrap();
    ready.wait().await;
    let mut sent = 0u64;
    while tokio::time::Instant::now() < deadline {
        if ws.send(Message::binary(message.clone())).await.is_err() {
            break;
        }
        sent += BATCH as u64;
    }
    reader.abort();
    sent
}

async fn fanout(url: &str, pid: u32, baseline: Sample, shape: Shape) {
    let Shape { accounts, subscribers, channels, rate, payload, seconds, batch, flooders, hello_flood, flood_kind } =
        shape;
    let epoch = Instant::now();
    let delivered = Arc::new(AtomicU64::new(0));
    // websocket messages the subscribers received: the hub feeds one per batch it takes and flushes once per wake-up,
    // so envelopes per message is roughly how many deliveries share a write
    let messages = Arc::new(AtomicU64::new(0));
    let (hist_tx, mut hist_rx) = mpsc::unbounded_channel::<(Histogram<u64>, Histogram<u64>)>();
    let ready = Arc::new(Barrier::new(accounts * subscribers + flooders + 1));
    let flooding: Vec<_> = (0..flooders)
        .map(|n| tokio::spawn(flood(url.to_owned(), n, payload, ready.clone(), Duration::from_secs(seconds))))
        .collect();
    let stop_at = Duration::from_secs(seconds + 2);

    for a in 0..accounts {
        for s in 0..subscribers {
            let (url, delivered, messages, hist_tx, ready) =
                (url.to_owned(), delivered.clone(), messages.clone(), hist_tx.clone(), ready.clone());
            tokio::spawn(async move {
                let mut ws = connect(&url, &format!("acct{a}"), &format!("client{s}"), Role::Client).await;
                for c in 0..channels {
                    let sub = v1::Subscribe {
                        stream: Some(v1::StreamRef {
                            publisher: principal_of(&format!("acct{a}"), "runtime"),
                            channel: format!("ch{c}").into_bytes(),
                        }),
                        since: None,
                    };
                    let frame = Frame { body: Some(Body::Subscribe(sub)) };
                    ws.send(Message::binary(encode_frames(&[frame], MAX).unwrap())).await.unwrap();
                    wait_for(&mut ws, |b| matches!(b, Body::Backfilled(_))).await;
                }
                ready.wait().await;
                let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
                let mut transit = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
                let deadline = tokio::time::Instant::now() + stop_at;
                loop {
                    let next = tokio::time::timeout_at(deadline, ws.next()).await;
                    let Ok(Some(Ok(Message::Binary(bytes)))) = next else { break };
                    let now = epoch.elapsed().as_micros() as u64;
                    messages.fetch_add(1, Ordering::Relaxed);
                    for f in decode_frames(&bytes, MAX).unwrap() {
                        if let Some(Body::Envelope(e)) = f.body {
                            let scheduled = u64::from_le_bytes(e.payload[..8].try_into().unwrap());
                            let actual = u64::from_le_bytes(e.payload[8..16].try_into().unwrap());
                            hist.saturating_record(now.saturating_sub(scheduled).max(1));
                            transit.saturating_record(now.saturating_sub(actual).max(1));
                            delivered.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                let _ = hist_tx.send((hist, transit));
            });
        }
    }
    drop(hist_tx);

    let mut publishers = Vec::new();
    let mut runtime_sockets = Vec::new();
    for a in 0..accounts {
        runtime_sockets.push(connect(url, &format!("acct{a}"), "runtime", Role::Runtime).await);
    }
    ready.wait().await;
    // Started inside the measured window, so the latency figures are the connected accounts' latency WHILE failed
    // hellos arrive, which is the whole question.
    //
    // On a runtime of its own: the measuring tasks read their sockets on this one, and a flood sharing its scheduler
    // would delay them and show up as HUB latency, which is exactly the confusion the numbers must not have.
    let stop_flood = Arc::new(AtomicBool::new(false));
    let refused = Arc::new(AtomicU64::new(0));
    let flood_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(FLOOD_THREADS)
        .thread_name("hello-flood")
        .enable_all()
        .build()
        .expect("a runtime for the flood");
    let hellos: Vec<_> = (0..hello_flood)
        .map(|_| flood_rt.spawn(failing_hellos(url.to_owned(), flood_kind, stop_flood.clone(), refused.clone())))
        .collect();
    let before = sample(pid);
    let started = Instant::now();
    let sent = Arc::new(AtomicU64::new(0));
    let late = Arc::new(AtomicU64::new(0));
    let (lag_tx, mut lag_rx) = mpsc::unbounded_channel::<Histogram<u64>>();
    for mut ws in runtime_sockets {
        let (sent, late, lag_tx) = (sent.clone(), late.clone(), lag_tx.clone());
        publishers.push(tokio::spawn(async move {
            let period = Duration::from_nanos(1_000_000_000 / rate.max(1));
            let total = rate * seconds;
            let start = tokio::time::Instant::now();
            let mut i = 0u64;
            // how late each send went out against its schedule: the load generator's own error, reported separately
            let mut lag = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
            while i < total {
                let scheduled = start + period * i as u32;
                if tokio::time::Instant::now() < scheduled {
                    tokio::time::sleep_until(scheduled).await;
                } else if tokio::time::Instant::now() > scheduled + Duration::from_millis(10) {
                    late.fetch_add(1, Ordering::Relaxed);
                }
                let mut bodies = Vec::with_capacity(batch);
                for _ in 0..batch.min((total - i) as usize) {
                    let at = (scheduled + period * (bodies.len() as u32)).into_std();
                    let micros = at.saturating_duration_since(epoch).as_micros() as u64;
                    let mut body = vec![0u8; payload.max(16)];
                    body[..8].copy_from_slice(&micros.to_le_bytes());
                    bodies.push((i as usize % channels, body));
                    i += 1;
                }
                sent.fetch_add(bodies.len() as u64, Ordering::Relaxed);
                let now = tokio::time::Instant::now();
                lag.saturating_record((now - scheduled).as_micros() as u64 + 1);
                // bytes 8..16: when the message was actually handed to the socket, for the hub-only latency
                let actual = now.into_std().saturating_duration_since(epoch).as_micros() as u64;
                let frames: Vec<Frame> = bodies
                    .into_iter()
                    .map(|(channel, mut body)| {
                        body[8..16].copy_from_slice(&actual.to_le_bytes());
                        Frame {
                            body: Some(Body::Envelope(Envelope {
                                to: Some(To::Channel(format!("ch{channel}").into_bytes())),
                                kind: Kind::SessionEvents as i32,
                                payload: body.into(),
                                ..Default::default()
                            })),
                        }
                    })
                    .collect();
                if ws.send(Message::binary(encode_frames(&frames, MAX).unwrap())).await.is_err() {
                    break;
                }
            }
            let _ = lag_tx.send(lag);
            ws
        }));
    }
    let mut sockets = Vec::new();
    for p in publishers {
        sockets.push(p.await.unwrap());
    }
    let publish_elapsed = started.elapsed();
    stop_flood.store(true, Ordering::Relaxed);
    let refusals = refused.load(Ordering::Relaxed);
    for h in hellos {
        h.abort();
    }
    flood_rt.shutdown_background();
    let mut flooded = Vec::new();
    for f in flooding {
        flooded.push(f.await.unwrap());
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = sample(pid);

    drop(lag_tx);
    let mut lag = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
    while let Some(h) = lag_rx.recv().await {
        lag.add(h).unwrap();
    }
    let mut merged = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
    let mut transit = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
    while let Some((h, t)) = hist_rx.recv().await {
        merged.add(h).unwrap();
        transit.add(t).unwrap();
    }
    let expected = sent.load(Ordering::Relaxed) * subscribers as u64;
    let got = delivered.load(Ordering::Relaxed);
    let cpu = after.cpu.saturating_sub(before.cpu);
    println!(
        "fanout: {accounts} accounts x {subscribers} subscribers x {channels} channels, {rate} msg/s per runtime, {payload} B, batch {batch}, {seconds} s"
    );
    println!(
        "  offered   {:>10.0} deliveries/s ({} sent x {} subscribers)",
        expected as f64 / publish_elapsed.as_secs_f64(),
        sent.load(Ordering::Relaxed),
        subscribers
    );
    if hello_flood > 0 {
        let kind = match flood_kind {
            FloodKind::Verify => "failing at the hello signature, three verifications each",
            FloodKind::Cheap => "failing before any signature is checked",
        };
        println!(
            "  hellos    {hello_flood} connections refused {:.0}/s, {kind} (not in any figure below)",
            refusals as f64 / publish_elapsed.as_secs_f64()
        );
    }
    if flooders > 0 {
        let per: Vec<String> =
            flooded.iter().map(|n| format!("{:.0}", *n as f64 / publish_elapsed.as_secs_f64())).collect();
        println!("  flooders  {flooders} accounts, envelopes/s each: {} (not in any figure below)", per.join(", "));
    }
    println!("  delivered {got} of {expected} ({:.2}%)", 100.0 * got as f64 / expected.max(1) as f64);
    println!(
        "  batching  {:.2} envelopes per websocket message received",
        got as f64 / messages.load(Ordering::Relaxed).max(1) as f64
    );
    println!(
        "  latency   p50 {} us  p90 {} us  p99 {} us  p99.9 {} us  max {} us",
        merged.value_at_quantile(0.5),
        merged.value_at_quantile(0.9),
        merged.value_at_quantile(0.99),
        merged.value_at_quantile(0.999),
        merged.max()
    );
    println!(
        "  transit   p50 {} us  p90 {} us  p99 {} us  p99.9 {} us  max {} us  (handed to socket -> decoded by subscriber)",
        transit.value_at_quantile(0.5),
        transit.value_at_quantile(0.9),
        transit.value_at_quantile(0.99),
        transit.value_at_quantile(0.999),
        transit.max()
    );
    println!(
        "  send lag  p50 {} us  p99 {} us  (scheduled -> handed to the socket; subtract from latency)",
        lag.value_at_quantile(0.5),
        lag.value_at_quantile(0.99)
    );
    println!(
        "  publishers late by >10 ms on {} sends (load generator saturated if non-zero)",
        late.load(Ordering::Relaxed)
    );
    println!(
        "  hub cpu   {:.2} s over {:.1} s ({:.0}% of one core)",
        cpu.as_secs_f64(),
        publish_elapsed.as_secs_f64() + 2.0,
        100.0 * cpu.as_secs_f64() / (publish_elapsed.as_secs_f64() + 2.0)
    );
    println!("  hub cpu per 1k deliveries {:.1} us", 1e9 * cpu.as_secs_f64() / got.max(1) as f64 / 1e3);
    println!("  hub rss   {} KiB (baseline {} KiB)", after.rss_kib, baseline.rss_kib);
    drop(sockets);
}

async fn idle(url: &str, pid: u32, baseline: Sample, connections: usize) {
    let mut sockets = Vec::with_capacity(connections);
    let mut checkpoints = [100, 1_000, 10_000, 50_000].into_iter().filter(|n| *n <= connections).peekable();
    for i in 0..connections {
        // 10 per account, well under the relay's per-account connection limit
        sockets.push(connect(url, &format!("acct{}", i / 10), &format!("p{i}"), Role::Client).await);
        if checkpoints.peek() == Some(&(i + 1)) {
            checkpoints.next();
            tokio::time::sleep(Duration::from_millis(200)).await;
            let s = sample(pid);
            let per = (s.rss_kib.saturating_sub(baseline.rss_kib)) as f64 * 1024.0 / (i + 1) as f64;
            println!("idle: {:>6} connections  hub rss {:>8} KiB  ~{:.0} B per connection", i + 1, s.rss_kib, per);
        }
    }
    drop(sockets);
}
