//! The hub's websocket server: sockets in, [`wmlhub_relay::Hub`] in the middle, sockets out.
//!
//! Everything about routing is decided by the relay core; this crate owns only what needs IO: accepting
//! connections, the `Hello` handshake, decoding and encoding frames, one writer task per connection draining its
//! queue, pings, and timeouts. It never looks inside `Envelope.payload`, and logs no frame contents.

pub mod arrivals;
pub mod pairing;
pub mod registry;

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use wmlhub_proto::v1::{self, Frame, error::Code, frame::Body};
use wmlhub_proto::{decode_frames_shared, encode_frames, join_frames};
use wmlhub_relay::{AccountId, Action, ConnId, FRAME_COST_BYTES, Hub, Limits};

use registry::{Refusal, Registry};

/// How a `Hello` is authenticated.
#[derive(Debug, Clone)]
pub enum Auth {
    /// Development only: trusts the principal a hello claims and takes `account_credential` as the account. The
    /// binary allows this only on a loopback address.
    Development,
    /// Certificate chains and a signed challenge (docs/design/end-to-end-crypto.md), with accounts admitted by the
    /// registry.
    Keys {
        /// The name clients expect this hub to have; it goes in every challenge and every signed transcript.
        hub_name: String,
        registry: Arc<Registry>,
    },
}

/// Initial read buffer per connection. See `connection`.
const READ_BUFFER_BYTES: usize = 8 << 10;

/// Frames handed to the relay per lock. A websocket message may carry thousands of small frames; taking the shard for
/// all of them at once would make the accounts sharing it wait for the whole message.
const RECEIVE_CHUNK: usize = 16;

/// How the server behaves around the relay.
#[derive(Debug, Clone)]
pub struct Config {
    pub auth: Auth,
    pub limits: Limits,
    /// How long a new socket may take to send its `Hello`.
    pub hello_timeout: Duration,
    /// How often a connection is pinged. The MV3 finding puts the ceiling at about 25 s for an extension runtime.
    pub ping_interval: Duration,
    /// A connection that sends nothing (not even a pong) for this long is closed.
    pub idle_timeout: Duration,
    /// Roughly how many bytes of queued frames go into one websocket message.
    pub write_budget: usize,
    /// Sockets open at once, before or after `Hello`.
    pub max_sockets: usize,
    /// Sockets open at once that have NOT yet said who they are. Every other bound needs a `Hello` first, so this is
    /// what makes the pre-authentication surface finite: at most this many sockets can be reading a hello, holding a
    /// read buffer, or verifying a chain at any moment.
    pub max_pending_sockets: usize,
    /// The largest first message accepted, before anything in it is decoded. A hello is a signature and a chain, a
    /// kilobyte or two; nothing legitimate is near this.
    pub max_hello_bytes: usize,
    /// How often one source address may open a connection (`arrivals`).
    pub arrivals: arrivals::Arrivals,
    /// Sockets waiting for a pairing answer at once. One holds its place for as long as a slot lives (minutes,
    /// because a person is carrying a code to another device), so pairing gets its own cap rather than sharing the
    /// one ordinary logins pass through: a stranger opening pairing sockets cannot keep anybody from logging in.
    pub max_pairing_sockets: usize,
    /// Independent relay shards, each with its own lock; an account lives in exactly one. 0 picks four per core.
    pub shards: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auth: Auth::Development,
            limits: Limits::default(),
            hello_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(60),
            write_budget: 256 << 10,
            max_sockets: 10_000,
            max_pending_sockets: 256,
            max_hello_bytes: 64 << 10,
            arrivals: arrivals::Arrivals::default(),
            max_pairing_sockets: 64,
            shards: 0,
        }
    }
}

/// A connection's wake-up and, once the relay has closed it, the frame to send before closing the socket.
#[derive(Default)]
struct Handle {
    notify: Notify,
    closing: Mutex<Option<Frame>>,
}

/// One shard: a relay and the wake-up handles of the connections it holds, under one lock. Accounts are spread across
/// shards by a keyed hash, so tenants on different shards never wait for each other. Measured before this existed:
/// at 100k deliveries/s most of the hub's non-idle samples were threads waiting on the single global lock
/// (docs/perf/README.md).
struct ShardState {
    hub: Hub,
    handles: HashMap<ConnId, Arc<Handle>>,
    /// this shard's contribution to `Shared::accounts`, as last reconciled
    accounts: usize,
}

struct Shared {
    shards: Box<[Mutex<ShardState>]>,
    /// Accounts across every shard, kept exact: a new account reserves a slot before it is admitted, and every call
    /// reconciles its shard's count. `Limits::max_accounts` is enforced here, not per shard.
    accounts: AtomicUsize,
    /// Keyed per process, so nobody can choose an account id (they are key hashes, easy to grind) that lands on the
    /// same shard as someone else's.
    shard_hasher: RandomState,
    config: Config,
    /// the monotonic clock accounts' work budgets run on
    started: Instant,
    /// how much of its connection allowance each source address has left
    arrivals: Mutex<arrivals::Gate>,
    /// the two blobs of each pairing in flight, which the hub holds and does not read
    slots: Mutex<pairing::Slots>,
}

/// A poisoned lock means a panic mid-update; the relay's state is then not trustworthy, so fail loudly.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().expect("hub state lock poisoned")
}

impl Shared {
    /// Milliseconds on the monotonic clock the relay's work budgets use.
    fn clock_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn shard_of(&self, account: &AccountId) -> usize {
        (self.shard_hasher.hash_one(&account.0) % self.shards.len() as u64) as usize
    }

    /// Run `f` on a shard's relay, then act on what it asked for. Wake-ups happen after the lock is released.
    fn on_shard<R>(&self, shard: usize, f: impl FnOnce(&mut Hub) -> (R, Vec<Action>)) -> R {
        let mut wake = Vec::new();
        let result = {
            let mut st = lock(&self.shards[shard]);
            let (result, actions) = f(&mut st.hub);
            for action in actions {
                match action {
                    Action::Wake(conn) => wake.extend(st.handles.get(&conn).cloned()),
                    Action::Close { conn, frame } => {
                        if let Some(h) = st.handles.get(&conn) {
                            *lock(&h.closing) = Some(frame);
                            wake.push(h.clone());
                        }
                    }
                }
            }
            self.reconcile_accounts(&mut st, 0);
            result
        };
        for h in wake {
            h.notify.notify_one();
        }
        result
    }

    /// Bring the global account count in line with this shard's, in one step. `reserved` is a slot this call already
    /// added to the global count for an account it was about to create: if the account now exists the slot simply
    /// becomes it, and if not the slot is released, with no moment in between where the count is low.
    fn reconcile_accounts(&self, st: &mut ShardState, reserved: usize) {
        let now = st.hub.account_count();
        let change = now as isize - st.accounts as isize - reserved as isize;
        if change > 0 {
            self.accounts.fetch_add(change as usize, Ordering::Relaxed);
        } else if change < 0 {
            self.accounts.fetch_sub(change.unsigned_abs(), Ordering::Relaxed);
        }
        st.accounts = now;
    }

    /// Admit a connection to its account's shard, enforcing the account limit across all shards.
    fn connect(
        &self,
        shard: usize,
        account: AccountId,
        hello: &v1::Hello,
        handle: Arc<Handle>,
    ) -> Result<ConnId, Box<Frame>> {
        let max = self.config.limits.max_accounts;
        let mut wake = Vec::new();
        let result = {
            let mut st = lock(&self.shards[shard]);
            let reserved = if st.hub.has_account(&account) {
                0
            } else {
                // Reserve with a compare-and-swap before admitting, so two shards admitting at once cannot both take
                // the last slot. (A load-then-add passed the concurrency test too: the window is nanoseconds wide and
                // the test does not reach it. The correctness of this line rests on the CAS, not on that test.)
                let taken = self
                    .accounts
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| (n < max).then_some(n + 1))
                    .is_ok();
                if !taken {
                    return Err(Box::new(error_frame(Code::Limit, "relay is full")));
                }
                1
            };
            let result = st.hub.connect(account, hello, now_ms(), self.clock_ms());
            self.reconcile_accounts(&mut st, reserved);
            match result {
                Ok((id, actions)) => {
                    st.handles.insert(id, handle);
                    for action in actions {
                        if let Action::Wake(conn) = action {
                            wake.extend(st.handles.get(&conn).cloned());
                        }
                    }
                    Ok(id)
                }
                Err(frame) => Err(frame),
            }
        };
        for h in wake {
            h.notify.notify_one();
        }
        result
    }
}

fn error_frame(code: Code, message: &str) -> Frame {
    Frame { body: Some(Body::Error(v1::Error { code: code as i32, r#ref: 0, message: message.to_owned() })) }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Accept connections on `listener` until it fails. `epoch_seed` should differ across restarts.
pub async fn serve(listener: TcpListener, config: Config, epoch_seed: u64) -> io::Result<()> {
    let count = match config.shards {
        0 => std::thread::available_parallelism().map_or(4, |n| n.get() * 4),
        n => n,
    }
    .clamp(1, 1024);
    // Each shard's relay may hold any number of accounts; the server enforces the limit across all of them.
    let shard_limits = Limits { max_accounts: usize::MAX, ..config.limits.clone() };
    let shards = (0..count)
        .map(|i| {
            let hub = Hub::with_id_space(shard_limits.clone(), epoch_seed.wrapping_add(i as u64), i as u16)
                .map_err(|e| io::Error::other(e.0))?;
            Ok(Mutex::new(ShardState { hub, handles: HashMap::new(), accounts: 0 }))
        })
        .collect::<io::Result<Vec<_>>>()?
        .into_boxed_slice();
    let sockets = Arc::new(Semaphore::new(config.max_sockets));
    // Sockets that have not authenticated yet are capped separately: they are the only ones a stranger can open.
    let pending = Arc::new(Semaphore::new(config.max_pending_sockets));
    let pairing_sockets = Arc::new(Semaphore::new(config.max_pairing_sockets));
    let shared = Arc::new(Shared {
        shards,
        accounts: AtomicUsize::new(0),
        shard_hasher: RandomState::new(),
        arrivals: Mutex::new(arrivals::Gate::new(config.arrivals)),
        slots: Mutex::new(pairing::Slots::default()),
        config,
        started: Instant::now(),
    });
    loop {
        let (tcp, peer) = listener.accept().await?;
        let Ok(permit) = sockets.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "socket limit reached; refusing");
            continue;
        };
        if !lock(&shared.arrivals).admit(peer.ip(), Instant::now()) {
            tracing::debug!(%peer, "connecting too often; refusing");
            continue;
        }
        let Ok(pending_permit) = pending.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "too many sockets are still unauthenticated; refusing");
            continue;
        };
        let shared = shared.clone();
        let pairing = pairing_sockets.clone();
        tokio::spawn(async move {
            connection(shared, tcp, peer.ip(), pending_permit, pairing).await;
            drop(permit);
        });
    }
}

async fn connection(
    shared: Arc<Shared>,
    tcp: TcpStream,
    address: IpAddr,
    pending: tokio::sync::OwnedSemaphorePermit,
    pairing_sockets: Arc<Semaphore>,
) {
    // Frames are small and latency-sensitive; Nagle would hold one back waiting for an ACK.
    let _ = tcp.set_nodelay(true);
    let limits = &shared.config.limits;
    let max_message = limits.max_frame_bytes.saturating_mul(4);
    // tungstenite's default read buffer is 128 KiB per connection, which made an idle connection cost ~110 KB of
    // resident memory (1 GiB at 10k). Frames are small; the buffer grows for a large message when one arrives.
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(max_message))
        .max_frame_size(Some(max_message))
        .read_buffer_size(READ_BUFFER_BYTES);
    let Ok(ws) = tokio_tungstenite::accept_async_with_config(tcp, Some(ws_config)).await else { return };
    let (mut sink, mut stream) = ws.split();
    let max_frame = limits.max_frame_bytes;

    // --- Challenge, then Hello ---
    let mut nonce = [0u8; 32];
    if getrandom::fill(&mut nonce).is_err() {
        return;
    }
    let hub_name = match &shared.config.auth {
        Auth::Keys { hub_name, .. } => hub_name.clone(),
        Auth::Development => String::new(),
    };
    let challenge = v1::Challenge { nonce: nonce.to_vec(), hub: hub_name, server_time_ms: now_ms() };
    if send(&mut sink, &[Frame { body: Some(Body::Challenge(challenge)) }], max_frame).await.is_err() {
        return;
    }
    let first = tokio::time::timeout(shared.config.hello_timeout, stream.next()).await;
    let Ok(Some(Ok(Message::Binary(bytes)))) = first else { return };
    if bytes.len() > shared.config.max_hello_bytes {
        let _ = send(&mut sink, &[error_frame(Code::Limit, "hello too large")], max_frame).await;
        return;
    }
    let hello_bytes = bytes.len();
    let mut frames = match decode_frames_shared(bytes, max_frame) {
        Ok(f) => f.into_iter(),
        Err(_) => {
            let _ = send(&mut sink, &[error_frame(Code::Invalid, "malformed frame")], max_frame).await;
            return;
        }
    };
    let hello = match frames.next() {
        Some(Frame { body: Some(Body::Hello(hello)) }) => hello,
        // A principal with no certificate yet: it is here to be paired, which is the one other thing a stranger may
        // do. It never joins the relay, so it is handled here and the socket ends with it.
        Some(Frame { body: Some(Body::PairOffer(offer)) }) => {
            let Ok(_permit) = pairing_sockets.try_acquire_owned() else {
                let _ = send(&mut sink, &[error_frame(Code::Limit, "too many pairings at once")], max_frame).await;
                return;
            };
            pairing_socket(&shared, &mut sink, &mut stream, offer, max_frame).await;
            return;
        }
        _ => {
            let _ = send(&mut sink, &[error_frame(Code::Invalid, "the first frame must be hello")], max_frame).await;
            return;
        }
    };
    let account = match authenticate(&shared.config.auth, &hello, &nonce, address) {
        Ok(a) => a,
        Err(frame) => {
            let _ = send(&mut sink, &[*frame], max_frame).await;
            return;
        }
    };
    let handle = Arc::new(Handle::default());
    let shard = shared.shard_of(&account);
    let id = match shared.connect(shard, account, &hello, handle.clone()) {
        Ok(id) => id,
        Err(frame) => {
            let _ = send(&mut sink, &[*frame], max_frame).await;
            return;
        }
    };
    // Authenticated: this socket is no longer part of the surface a stranger can occupy, so its place goes back.
    drop(pending);
    tracing::info!(conn = id, shard, role = ?hello.role(), "connected");

    let mut writer = tokio::spawn(write_loop(shared.clone(), shard, id, handle, sink));
    // true once the relay has queued a closing error the writer should get out before the socket goes
    let mut flush = false;
    let mut writer_done = false;

    // --- frames that rode along with Hello, then the read loop ---
    let mut pending: Vec<Frame> = frames.collect();
    // charged with the whole message they came in, hello included
    let mut pending_bytes = hello_bytes;
    'read: loop {
        if !pending.is_empty() {
            // Charge the account chunk by chunk, each for its share of the message, and hand each chunk over once its
            // cost is covered. In debt, stop reading this connection until the debt is repaid: the peer's sends back up
            // in TCP, and nothing is dropped. Charging the whole message up front made a throttled account's work
            // arrive in bursts of a whole message, and its neighbours' p99 paid for them (docs/perf/README.md).
            let frames = pending.len();
            let mut bytes_left = pending_bytes;
            let mut rest = std::mem::take(&mut pending).into_iter();
            loop {
                let chunk: Vec<Frame> = rest.by_ref().take(RECEIVE_CHUNK).collect();
                if chunk.is_empty() {
                    break;
                }
                let share = if rest.len() == 0 { bytes_left } else { pending_bytes / frames * chunk.len() };
                bytes_left -= share;
                let cost = share.saturating_add(chunk.len().saturating_mul(FRAME_COST_BYTES));
                let now = shared.clock_ms();
                // charged and handed over under one lock, so an unthrottled chunk costs no extra lock
                // Pairing frames are the server's: an authenticated device fetching an offer or answering it. They are
                // taken out here, so the relay only ever sees what it routes.
                let chunk: Vec<Frame> = {
                    let mut keep = Vec::with_capacity(chunk.len());
                    for frame in chunk {
                        match frame.body {
                            Some(Body::PairFetch(fetch)) => {
                                let answer = match lock(&shared.slots).offered(&fetch.code_hash, Instant::now()) {
                                    Ok(offer) => {
                                        Frame { body: Some(Body::Paired(v1::Paired { offer, answer: Vec::new() })) }
                                    }
                                    Err(_) => error_frame(Code::Unavailable, "no pairing is waiting under that code"),
                                };
                                shared.on_shard(shard, |hub| ((), hub.deliver(id, answer)));
                            }
                            Some(Body::PairAnswer(answer)) => {
                                let reply = match lock(&shared.slots).answer(
                                    &answer.code_hash,
                                    answer.answer,
                                    Instant::now(),
                                ) {
                                    Ok(()) => Frame { body: Some(Body::Paired(v1::Paired::default())) },
                                    Err(refusal) => error_frame(Code::Unavailable, slot_refusal(refusal)),
                                };
                                shared.on_shard(shard, |hub| ((), hub.deliver(id, reply)));
                            }
                            other => keep.push(Frame { body: other }),
                        }
                    }
                    keep
                };
                let (wait, unsent) = shared.on_shard(shard, |hub| {
                    let (wait, mut actions) = hub.charge(id, cost, now);
                    if wait > 0 {
                        return ((wait, chunk), actions);
                    }
                    actions.extend(chunk.into_iter().flat_map(|f| hub.receive(id, f)));
                    ((0, Vec::new()), actions)
                });
                if wait > 0 {
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_millis(wait)) => {}
                        _ = &mut writer => {
                            writer_done = true;
                            break 'read;
                        }
                    }
                    shared.on_shard(shard, |hub| ((), unsent.into_iter().flat_map(|f| hub.receive(id, f)).collect()));
                }
            }
        }
        let next = tokio::select! {
            next = tokio::time::timeout(shared.config.idle_timeout, stream.next()) => next,
            // The writer ends when the relay closed this connection (or the socket failed): stop reading too, or a
            // peer that keeps talking would hold the socket forever.
            _ = &mut writer => {
                writer_done = true;
                break 'read;
            }
        };
        let close_with = match next {
            // payloads stay slices of this message all the way into the relay's encoded entry
            Ok(Some(Ok(Message::Binary(bytes)))) => match (bytes.len(), decode_frames_shared(bytes, max_frame)) {
                (len, Ok(f)) => {
                    pending = f;
                    pending_bytes = len;
                    continue;
                }
                (_, Err(_)) => error_frame(Code::Invalid, "malformed frame"),
            },
            // tungstenite answers websocket-level pings itself; either still counts as traffic
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(Some(Ok(Message::Text(_)))) => error_frame(Code::Invalid, "binary frames only"),
            Err(_) => error_frame(Code::Limit, "idle"),
            // closed, errored or ended
            _ => break 'read,
        };
        shared.on_shard(shard, |hub| ((), hub.close(id, Some(close_with))));
        flush = true;
        break 'read;
    }

    shared.on_shard(shard, |hub| ((), hub.close(id, None)));
    if !writer_done {
        // A closing error gets a moment to go out; a peer that simply left gets none, since nothing wakes the writer.
        if !flush || tokio::time::timeout(Duration::from_secs(2), &mut writer).await.is_err() {
            writer.abort();
        }
    }
    lock(&shared.shards[shard]).handles.remove(&id);
    tracing::info!(conn = id, "disconnected");
}

type Sink = futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>;

async fn write_loop(shared: Arc<Shared>, shard: usize, id: ConnId, handle: Arc<Handle>, mut sink: Sink) {
    let max_frame = shared.config.limits.max_frame_bytes;
    let mut ping = tokio::time::interval(shared.config.ping_interval);
    ping.tick().await;
    let mut nonce = 0u64;
    loop {
        tokio::select! {
            () = handle.notify.notified() => {}
            _ = ping.tick() => {
                nonce += 1;
                let frame = Frame { body: Some(Body::Ping(v1::Ping { nonce })) };
                if send(&mut sink, &[frame], max_frame).await.is_err() {
                    return;
                }
            }
        }
        // Feed every batch that is ready, then flush once: one write per wake-up however much was queued. A single
        // queued frame is sent as the relay's own bytes, uncopied. The relay wakes a connection once per drain, not
        // once per frame, so keep taking until it says nothing is left: stopping early would strand what remains.
        let mut fed = false;
        loop {
            let taken = lock(&shared.shards[shard]).hub.take_outbound(id, shared.config.write_budget);
            if !taken.frames.is_empty() {
                if sink.feed(Message::Binary(join_frames(taken.frames))).await.is_err() {
                    return;
                }
                fed = true;
            }
            if !taken.more {
                break;
            }
        }
        if fed && sink.flush().await.is_err() {
            return;
        }
        let closing = lock(&handle.closing).take();
        if let Some(frame) = closing {
            let _ = send(&mut sink, &[frame], max_frame).await;
            let _ = sink.close().await;
            return;
        }
    }
}

/// A socket that offered a pairing: it holds the slot, waits for the answer, and ends. It never authenticates and
/// never touches the relay, so the whole of what a stranger can do here is hold one slot and one socket, both capped.
async fn pairing_socket(
    shared: &Arc<Shared>,
    sink: &mut Sink,
    stream: &mut futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<TcpStream>>,
    offer: v1::PairOffer,
    max_frame: usize,
) {
    let code_hash = offer.code_hash.clone();
    let held = lock(&shared.slots).offer(&code_hash, offer.offer, Instant::now());
    if let Err(refusal) = held {
        let _ = send(sink, &[error_frame(Code::Limit, slot_refusal(refusal))], max_frame).await;
        return;
    }
    // held: the person is now carrying the code to a device that can answer
    if send(sink, &[Frame { body: Some(Body::Paired(v1::Paired::default())) }], max_frame).await.is_err() {
        lock(&shared.slots).forget(&code_hash);
        return;
    }
    let deadline = Instant::now() + pairing::SLOT_LIFETIME;
    while Instant::now() < deadline {
        // Checked rather than pushed: a pairing is human-paced, and a poll on this timescale costs nothing next to
        // the machinery a notification per slot would need.
        // Taken out of the lock before anything is awaited: a guard held across an await is a guard held for as long
        // as the runtime likes.
        let collected = lock(&shared.slots).collect(&code_hash, Instant::now());
        if let Ok(answer) = collected {
            let paired = v1::Paired { offer: Vec::new(), answer };
            let _ = send(sink, &[Frame { body: Some(Body::Paired(paired)) }], max_frame).await;
            return;
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
            // the peer gave up, or said something it should not have
            next = stream.next() => {
                if !matches!(next, Some(Ok(Message::Ping(_) | Message::Pong(_)))) {
                    lock(&shared.slots).forget(&code_hash);
                    return;
                }
            }
        }
    }
    lock(&shared.slots).forget(&code_hash);
    let _ = send(sink, &[error_frame(Code::Limit, "the pairing expired")], max_frame).await;
}

/// What a peer is told about a slot it could not have. Deliberately the same shape for every refusal.
fn slot_refusal(refusal: pairing::SlotError) -> &'static str {
    match refusal {
        pairing::SlotError::Full => "the hub is holding as many pairings as it will",
        _ => "that pairing cannot be held",
    }
}

async fn send(sink: &mut Sink, frames: &[Frame], max_frame: usize) -> Result<(), ()> {
    let bytes = encode_frames(frames, max_frame).map_err(|_| ())?;
    sink.send(Message::binary(bytes)).await.map_err(|_| ())
}

/// Decide which account a hello belongs to, or refuse it. Verification happens here, before the relay is touched.
fn authenticate(auth: &Auth, hello: &v1::Hello, nonce: &[u8; 32], address: IpAddr) -> Result<AccountId, Box<Frame>> {
    let refuse = |code: Code, message: &str| Box::new(error_frame(code, message));
    match auth {
        Auth::Development => {
            if hello.account_credential.is_empty() {
                return Err(refuse(Code::Unauthenticated, "an account credential is required"));
            }
            Ok(AccountId(hello.account_credential.clone()))
        }
        Auth::Keys { hub_name, registry } => {
            // One message for every verification failure: which check failed is for the server's log, not for
            // whoever is probing it.
            const BAD: &str = "hello did not verify";
            let now = now_ms();
            let root: wmlhub_keys::PublicKey =
                hello.account_root.as_slice().try_into().map_err(|_| refuse(Code::Unauthenticated, BAD))?;
            let verified = wmlhub_keys::verify_chain(&root, &hello.chain, now).map_err(|e| {
                tracing::info!(%address, reason = ?e, "certificate chain refused");
                refuse(Code::Unauthenticated, BAD)
            })?;
            if hello.principal != verified.principal || hello.role != verified.leaf.role {
                tracing::info!(%address, "hello names a principal or role its certificate does not");
                return Err(refuse(Code::Unauthenticated, BAD));
            }
            let transcript =
                wmlhub_keys::hello_transcript(hub_name, nonce, &hello.principal, hello.role(), &verified.account);
            if wmlhub_keys::verify_hello(&verified.leaf_key, &transcript, &hello.signature).is_err() {
                tracing::info!(%address, "hello signature refused");
                return Err(refuse(Code::Unauthenticated, BAD));
            }
            match registry.admit(&verified.account, &hello.invite, address, now) {
                Ok(admission) => {
                    if admission == registry::Admission::Registered {
                        tracing::info!(account = %wmlhub_keys::hex(&verified.account[..6]), "account registered");
                    }
                    Ok(AccountId(verified.account.to_vec()))
                }
                Err(Refusal::InviteRequired) => {
                    Err(refuse(Code::Unauthenticated, "this hub needs an invite to register an account"))
                }
                Err(Refusal::InviteInvalid) => Err(refuse(Code::Unauthenticated, "invite not valid")),
                Err(Refusal::RateLimited) => Err(refuse(Code::Limit, "too many new accounts; try later")),
                Err(Refusal::Storage(e)) => {
                    tracing::error!(error = %e, "registry storage failed");
                    Err(refuse(Code::Unavailable, "hub storage error"))
                }
            }
        }
    }
}
