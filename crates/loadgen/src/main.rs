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
//! Development mode skips signature verification; the handshake's own cost is not what this measures.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use hdrhistogram::Histogram;
use tokio::net::TcpStream;
use tokio::sync::{Barrier, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
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
    #[command(subcommand)]
    scenario: Scenario,
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
    let mut hub = tokio::process::Command::new(&cli.hub_bin)
        .args(["serve", "--dev", "--listen", &cli.listen])
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
        Scenario::Fanout { accounts, subscribers, channels, rate, payload, seconds, batch } => {
            fanout(&url, pid, baseline, accounts, subscribers, channels, rate, payload, seconds, batch).await;
        }
        Scenario::Idle { connections } => idle(&url, pid, baseline, connections).await,
    }
    let _ = hub.kill().await;
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

async fn connect(url: &str, account: &str, principal: &str, role: Role) -> Ws {
    let config = WebSocketConfig::default().max_message_size(Some(MAX)).max_frame_size(Some(MAX));
    let (mut ws, _) = tokio_tungstenite::connect_async_with_config(url, Some(config), true).await.expect("connect");
    let hello = v1::Hello {
        protocol: 1,
        principal: principal.as_bytes().to_vec(),
        role: role as i32,
        account_credential: account.as_bytes().to_vec(),
        ..Default::default()
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

#[allow(clippy::too_many_arguments)]
async fn fanout(
    url: &str,
    pid: u32,
    baseline: Sample,
    accounts: usize,
    subscribers: usize,
    channels: usize,
    rate: u64,
    payload: usize,
    seconds: u64,
    batch: usize,
) {
    let epoch = Instant::now();
    let delivered = Arc::new(AtomicU64::new(0));
    let (hist_tx, mut hist_rx) = mpsc::unbounded_channel::<(Histogram<u64>, Histogram<u64>)>();
    let ready = Arc::new(Barrier::new(accounts * subscribers + 1));
    let stop_at = Duration::from_secs(seconds + 2);

    for a in 0..accounts {
        for s in 0..subscribers {
            let (url, delivered, hist_tx, ready) = (url.to_owned(), delivered.clone(), hist_tx.clone(), ready.clone());
            tokio::spawn(async move {
                let mut ws = connect(&url, &format!("acct{a}"), &format!("client{s}"), Role::Client).await;
                for c in 0..channels {
                    let sub = v1::Subscribe {
                        stream: Some(v1::StreamRef {
                            publisher: b"runtime".to_vec(),
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
                let mut frames = Vec::with_capacity(batch);
                for _ in 0..batch.min((total - i) as usize) {
                    let at = (scheduled + period * (frames.len() as u32)).into_std();
                    let micros = at.saturating_duration_since(epoch).as_micros() as u64;
                    let mut body = vec![0u8; payload.max(16)];
                    body[..8].copy_from_slice(&micros.to_le_bytes());
                    frames.push(Frame {
                        body: Some(Body::Envelope(Envelope {
                            to: Some(To::Channel(format!("ch{}", i as usize % channels).into_bytes())),
                            kind: Kind::SessionEvents as i32,
                            payload: body,
                            ..Default::default()
                        })),
                    });
                    i += 1;
                }
                sent.fetch_add(frames.len() as u64, Ordering::Relaxed);
                let now = tokio::time::Instant::now();
                lag.saturating_record((now - scheduled).as_micros() as u64 + 1);
                // bytes 8..16: when the message was actually handed to the socket, for the hub-only latency
                let actual = now.into_std().saturating_duration_since(epoch).as_micros() as u64;
                for f in &mut frames {
                    if let Some(Body::Envelope(e)) = &mut f.body {
                        e.payload[8..16].copy_from_slice(&actual.to_le_bytes());
                    }
                }
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
    println!("  delivered {got} of {expected} ({:.2}%)", 100.0 * got as f64 / expected.max(1) as f64);
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
