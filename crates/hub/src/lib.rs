//! The hub's websocket server: sockets in, [`wmlhub_relay::Hub`] in the middle, sockets out.
//!
//! Everything about routing is decided by the relay core; this crate owns only what needs IO: accepting
//! connections, the `Hello` handshake, decoding and encoding frames, one writer task per connection draining its
//! queue, pings, and timeouts. It never looks inside `Envelope.payload`, and logs no frame contents.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use wmlhub_proto::v1::{self, Frame, error::Code, frame::Body};
use wmlhub_proto::{decode_frames, encode_frames};
use wmlhub_relay::{AccountId, Action, ConnId, Hub, Limits};

/// How the server behaves around the relay.
#[derive(Debug, Clone)]
pub struct Config {
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            hello_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(60),
            write_budget: 256 << 10,
            max_sockets: 10_000,
        }
    }
}

/// A connection's wake-up and, once the relay has closed it, the frame to send before closing the socket.
#[derive(Default)]
struct Handle {
    notify: Notify,
    closing: Mutex<Option<Frame>>,
}

struct Shared {
    hub: Mutex<Hub>,
    handles: Mutex<HashMap<ConnId, Arc<Handle>>>,
    config: Config,
}

/// A poisoned lock means a panic mid-update; the relay's state is then not trustworthy, so fail loudly.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().expect("hub state lock poisoned")
}

impl Shared {
    fn apply(&self, actions: Vec<Action>) {
        let handles = lock(&self.handles);
        for action in actions {
            match action {
                Action::Wake(conn) => {
                    if let Some(h) = handles.get(&conn) {
                        h.notify.notify_one();
                    }
                }
                Action::Close { conn, frame } => {
                    if let Some(h) = handles.get(&conn) {
                        *lock(&h.closing) = Some(frame);
                        h.notify.notify_one();
                    }
                }
            }
        }
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
    let hub = Hub::new(config.limits.clone(), epoch_seed).map_err(|e| io::Error::other(e.0))?;
    let sockets = Arc::new(Semaphore::new(config.max_sockets));
    let shared = Arc::new(Shared { hub: Mutex::new(hub), handles: Mutex::new(HashMap::new()), config });
    loop {
        let (tcp, peer) = listener.accept().await?;
        let Ok(permit) = sockets.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "socket limit reached; refusing");
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            connection(shared, tcp).await;
            drop(permit);
        });
    }
}

async fn connection(shared: Arc<Shared>, tcp: TcpStream) {
    let limits = &shared.config.limits;
    let max_message = limits.max_frame_bytes.saturating_mul(4);
    let ws_config = WebSocketConfig::default().max_message_size(Some(max_message)).max_frame_size(Some(max_message));
    let Ok(ws) = tokio_tungstenite::accept_async_with_config(tcp, Some(ws_config)).await else { return };
    let (mut sink, mut stream) = ws.split();
    let max_frame = limits.max_frame_bytes;

    // --- Hello ---
    let first = tokio::time::timeout(shared.config.hello_timeout, stream.next()).await;
    let Ok(Some(Ok(Message::Binary(bytes)))) = first else { return };
    let mut frames = match decode_frames(&bytes, max_frame) {
        Ok(f) => f.into_iter(),
        Err(_) => {
            let _ = send(&mut sink, &[error_frame(Code::Invalid, "malformed frame")], max_frame).await;
            return;
        }
    };
    let Some(Frame { body: Some(Body::Hello(hello)) }) = frames.next() else {
        let _ = send(&mut sink, &[error_frame(Code::Invalid, "the first frame must be hello")], max_frame).await;
        return;
    };
    let account = match dev_account(&hello) {
        Ok(a) => a,
        Err(frame) => {
            let _ = send(&mut sink, &[*frame], max_frame).await;
            return;
        }
    };
    let handle = Arc::new(Handle::default());
    let connected = {
        // Registering the handle under the hub lock means every action naming this connection is produced after
        // its handle exists, so no wake is lost.
        let mut hub = lock(&shared.hub);
        let result = hub.connect(account, &hello, now_ms());
        if let Ok((id, _)) = &result {
            lock(&shared.handles).insert(*id, handle.clone());
        }
        result
    };
    let (id, actions) = match connected {
        Ok(ok) => ok,
        Err(frame) => {
            let _ = send(&mut sink, &[*frame], max_frame).await;
            return;
        }
    };
    tracing::info!(conn = id, role = ?hello.role(), "connected");
    shared.apply(actions);

    let mut writer = tokio::spawn(write_loop(shared.clone(), id, handle, sink));
    // true once the relay has queued a closing error the writer should get out before the socket goes
    let mut flush = false;
    let mut writer_done = false;

    // --- frames that rode along with Hello, then the read loop ---
    let mut pending: Vec<Frame> = frames.collect();
    'read: loop {
        for frame in pending.drain(..) {
            let actions = lock(&shared.hub).receive(id, frame);
            shared.apply(actions);
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
            Ok(Some(Ok(Message::Binary(bytes)))) => match decode_frames(&bytes, max_frame) {
                Ok(f) => {
                    pending = f;
                    continue;
                }
                Err(_) => error_frame(Code::Invalid, "malformed frame"),
            },
            // tungstenite answers websocket-level pings itself; either still counts as traffic
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(Some(Ok(Message::Text(_)))) => error_frame(Code::Invalid, "binary frames only"),
            Err(_) => error_frame(Code::Limit, "idle"),
            // closed, errored or ended
            _ => break 'read,
        };
        let actions = lock(&shared.hub).close(id, Some(close_with));
        shared.apply(actions);
        flush = true;
        break 'read;
    }

    let actions = lock(&shared.hub).close(id, None);
    shared.apply(actions);
    if !writer_done {
        // A closing error gets a moment to go out; a peer that simply left gets none, since nothing wakes the writer.
        if !flush || tokio::time::timeout(Duration::from_secs(2), &mut writer).await.is_err() {
            writer.abort();
        }
    }
    lock(&shared.handles).remove(&id);
    tracing::info!(conn = id, "disconnected");
}

type Sink = futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>;

async fn write_loop(shared: Arc<Shared>, id: ConnId, handle: Arc<Handle>, mut sink: Sink) {
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
        loop {
            let frames = lock(&shared.hub).take_outbound(id, shared.config.write_budget);
            if frames.is_empty() {
                break;
            }
            if send(&mut sink, &frames, max_frame).await.is_err() {
                return;
            }
        }
        let closing = lock(&handle.closing).take();
        if let Some(frame) = closing {
            let _ = send(&mut sink, &[frame], max_frame).await;
            let _ = sink.close().await;
            return;
        }
    }
}

async fn send(sink: &mut Sink, frames: &[Frame], max_frame: usize) -> Result<(), ()> {
    let bytes = encode_frames(frames, max_frame).map_err(|_| ())?;
    sink.send(Message::binary(bytes)).await.map_err(|_| ())
}

/// Development mode only: the account is the credential bytes as given, and the principal is whatever `Hello`
/// claims. The binary refuses to run this way on anything but loopback.
fn dev_account(hello: &v1::Hello) -> Result<AccountId, Box<Frame>> {
    if hello.account_credential.is_empty() {
        return Err(Box::new(error_frame(Code::Unauthenticated, "an account credential is required")));
    }
    Ok(AccountId(hello.account_credential.clone()))
}
