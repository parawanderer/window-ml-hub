//! A client for the hub: the authenticated handshake, subscriptions, publishing, and sealed commands
//! (docs/PROTOCOL.md). What the extension's connector and the box connector each do, in Rust, so the protocol has a
//! second implementation from the start and the end-to-end tests exercise the real handshake rather than a fixture.
//!
//! One task owns the socket. [`Client::next`] drives it: it answers the hub's pings, opens sealed commands and
//! results, and hands back everything else. Sending while another task is inside `next` is not possible by
//! construction (`&mut self`), which is the right shape for a runtime or a connector, each of which has one loop.
//!
//! The client checks the hub before it proves anything: a challenge naming another hub is refused, so a hub cannot
//! pass along a challenge from somewhere else and log in there as this principal.

use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use wmlhub_keys::{Identity, PublicKey, account_id, hello_transcript, principal_id, sign_hello};
use wmlhub_proto::v1::{self, Envelope, Frame, Kind, Position, Role, StreamRef, envelope::To, frame::Body};
use wmlhub_proto::{bytes::Bytes, decode_frames_shared, encode_frames};
use wmlhub_seal::{
    AgreementKey, Grant, OpenError, Opened, PrincipalId, Recipient, SealError, Sender, open_grant, seal_command,
    seal_result,
};

pub use wmlhub_seal::{StreamKey, StreamReader, seal_frame, wrap_key};

pub use wmlhub_proto::v1::Certificate;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Everything a principal needs to log in: who it is, what proves it, and which hub it expects.
pub struct Config {
    /// `ws://` or `wss://`
    pub url: String,
    /// The name this hub must give in its challenge. A hub that gives another name is refused.
    pub hub_name: String,
    pub identity: Identity,
    pub agreement: AgreementKey,
    /// leaf first, up to the account root
    pub chain: Vec<Certificate>,
    pub account_root: PublicKey,
    pub role: Role,
    /// an operator invite, on a hub that needs one to register this account
    pub invite: Vec<u8>,
}

/// What a client reads from the hub.
#[derive(Debug)]
pub enum Event {
    /// a published envelope of a stream this client subscribes to; the payload is still sealed (`wmlhub-seal`)
    Published {
        stream: StreamRef,
        kind: Kind,
        sender: Vec<u8>,
        seq: u64,
        epoch: u64,
        payload: Bytes,
    },
    /// a sealed command, opened and verified
    Command(Opened),
    /// a sealed result, opened and verified, naming the command it answers
    Result(Opened),
    /// A direct envelope this client could not open as a command or result: what was wrong, and the bytes, so a
    /// caller can try another opener (a key grant travels the same way).
    Unopened {
        sender: Vec<u8>,
        kind: Kind,
        payload: Bytes,
        error: OpenError,
    },
    Presence(v1::Presence),
    Backfilled(v1::Backfilled),
    Gap(v1::Gap),
    /// the hub reporting something about this connection; `THROTTLED` does not close it, the rest do
    Error(v1::Error),
}

#[derive(Debug)]
pub enum ClientError {
    /// the socket failed, or the hub closed it
    Transport(String),
    /// the hub did not follow the protocol (no challenge, no welcome, a frame out of place)
    Protocol(&'static str),
    /// the hub named itself something else in its challenge
    WrongHub {
        expected: String,
        offered: String,
    },
    /// the hub refused the handshake
    Refused(v1::Error),
    Seal(SealError),
}

/// The protocol major this client speaks.
pub const PROTOCOL: u32 = 1;

/// A connected, authenticated client.
///
/// `Debug` prints who it is, never what it holds: an identity, an agreement key and a replay window have no business
/// in a log line.
pub struct Client {
    ws: Ws,
    identity: Identity,
    chain: Vec<Certificate>,
    principal: PrincipalId,
    account: [u8; 32],
    limits: v1::Limits,
    receiver: wmlhub_seal::Receiver,
    /// frames from the last message not handed out yet
    pending: std::vec::IntoIter<Frame>,
    max_frame: usize,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("principal", &wmlhub_keys::hex(&self.principal[..6]))
            .field("account", &wmlhub_keys::hex(&self.account[..6]))
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Connect, check the hub's name, answer its challenge, and wait for the welcome.
    pub async fn connect(config: Config) -> Result<Self, ClientError> {
        let max = 4 << 20;
        let ws_config = WebSocketConfig::default().max_message_size(Some(max)).max_frame_size(Some(max));
        let Config { url, hub_name, identity, agreement, chain, account_root, role, invite } = config;
        let (mut ws, _) = tokio_tungstenite::connect_async_with_config(&url, Some(ws_config), true)
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        let challenge = match first_frame(&mut ws, max).await? {
            Body::Challenge(c) => c,
            _ => return Err(ClientError::Protocol("the hub's first frame must be a challenge")),
        };
        if challenge.hub != hub_name {
            return Err(ClientError::WrongHub { expected: hub_name, offered: challenge.hub });
        }
        let principal = principal_id(&identity.public());
        let account = account_id(&account_root);
        let transcript = hello_transcript(&hub_name, &challenge.nonce, &principal, role, &account);
        let hello = v1::Hello {
            protocol: PROTOCOL,
            principal: principal.to_vec(),
            role: role as i32,
            chain: chain.clone(),
            account_root: account_root.to_vec(),
            signature: sign_hello(&identity, &transcript),
            invite,
            ..Default::default()
        };
        send(&mut ws, &[Frame { body: Some(Body::Hello(hello)) }], max).await?;
        let welcome = match first_frame(&mut ws, max).await? {
            Body::Welcome(w) => w,
            Body::Error(e) => return Err(ClientError::Refused(e)),
            _ => return Err(ClientError::Protocol("the hub must answer a hello with a welcome or an error")),
        };
        let limits = welcome.limits.unwrap_or_default();
        let max_frame = limits.max_frame_bytes as usize;
        let receiver = wmlhub_seal::Receiver::new(&identity.public(), agreement, account_root);
        Ok(Self {
            ws,
            identity,
            chain,
            principal,
            account,
            limits,
            receiver,
            pending: Vec::new().into_iter(),
            max_frame: max_frame.max(1 << 16),
        })
    }

    /// This client's principal id, as the hub knows it.
    pub fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The account this client belongs to.
    pub fn account(&self) -> [u8; 32] {
        self.account
    }

    /// Open a stream key granted to this principal, wherever it arrived (published on a key channel, or direct). The
    /// client's own replay window and account root are what check it.
    pub fn open_grant(&mut self, sender: &[u8], payload: &[u8]) -> Result<Grant, OpenError> {
        open_grant(&mut self.receiver, sender, payload, now_ms())
    }

    /// What the hub said it will accept.
    pub fn limits(&self) -> &v1::Limits {
        &self.limits
    }

    /// Publish `payload` on a channel of this principal's. The hub stamps the sender, seq and epoch.
    pub async fn publish(&mut self, channel: &[u8], kind: Kind, payload: Bytes) -> Result<(), ClientError> {
        let envelope =
            Envelope { to: Some(To::Channel(channel.to_vec())), kind: kind as i32, payload, ..Default::default() };
        self.send_frames(&[Frame { body: Some(Body::Envelope(envelope)) }]).await
    }

    /// Ask for a stream, from `since` if this client already holds part of it.
    pub async fn subscribe(
        &mut self,
        publisher: &[u8],
        channel: &[u8],
        since: Option<Position>,
    ) -> Result<(), ClientError> {
        let sub = v1::Subscribe {
            stream: Some(StreamRef { publisher: publisher.to_vec(), channel: channel.to_vec() }),
            since,
        };
        self.send_frames(&[Frame { body: Some(Body::Subscribe(sub)) }]).await
    }

    /// Stop receiving a stream.
    pub async fn unsubscribe(&mut self, publisher: &[u8], channel: &[u8]) -> Result<(), ClientError> {
        let unsub =
            v1::Unsubscribe { stream: Some(StreamRef { publisher: publisher.to_vec(), channel: channel.to_vec() }) };
        self.send_frames(&[Frame { body: Some(Body::Unsubscribe(unsub)) }]).await
    }

    /// Seal a command to `to` and send it. Returns the nonce its result will answer.
    pub async fn command(
        &mut self,
        to: &Recipient,
        scope: &str,
        body: &[u8],
    ) -> Result<[u8; wmlhub_seal::NONCE_BYTES], ClientError> {
        let sender = Sender { identity: &self.identity, chain: &self.chain };
        let (sealed, nonce) = seal_command(&sender, to, scope, body, now_ms()).map_err(ClientError::Seal)?;
        self.direct(to.principal, Kind::Command, sealed).await?;
        Ok(nonce)
    }

    /// Seal the result of a command back to whoever sent it.
    pub async fn result(
        &mut self,
        to: &Recipient,
        answers: &[u8; wmlhub_seal::NONCE_BYTES],
        body: &[u8],
    ) -> Result<(), ClientError> {
        let sender = Sender { identity: &self.identity, chain: &self.chain };
        let sealed = seal_result(&sender, to, answers, body, now_ms()).map_err(ClientError::Seal)?;
        self.direct(to.principal, Kind::CommandResult, sealed).await
    }

    /// Send already-sealed bytes to a principal, for kinds this client does not build itself (`BULK`).
    pub async fn direct(&mut self, to: PrincipalId, kind: Kind, payload: Vec<u8>) -> Result<(), ClientError> {
        let envelope = Envelope {
            to: Some(To::Principal(to.to_vec())),
            kind: kind as i32,
            payload: payload.into(),
            ..Default::default()
        };
        self.send_frames(&[Frame { body: Some(Body::Envelope(envelope)) }]).await
    }

    /// The next event. Answers pings, opens sealed commands and results, and never returns one of the hub's own
    /// keepalives to the caller.
    pub async fn next(&mut self) -> Result<Event, ClientError> {
        loop {
            let Some(frame) = self.pending.next() else {
                self.read_message().await?;
                continue;
            };
            match frame.body {
                Some(Body::Envelope(e)) => {
                    if let Some(event) = self.on_envelope(e) {
                        return Ok(event);
                    }
                }
                Some(Body::Presence(p)) => return Ok(Event::Presence(p)),
                Some(Body::Backfilled(b)) => return Ok(Event::Backfilled(b)),
                Some(Body::Gap(g)) => return Ok(Event::Gap(g)),
                Some(Body::Error(e)) => return Ok(Event::Error(e)),
                Some(Body::Ping(p)) => {
                    self.send_frames(&[Frame { body: Some(Body::Pong(v1::Pong { nonce: p.nonce })) }]).await?;
                }
                // pongs answer our own pings; a hub-to-peer frame arriving again is the hub's business
                Some(Body::Pong(_) | Body::Welcome(_) | Body::Challenge(_)) => {}
                Some(Body::Hello(_) | Body::Subscribe(_) | Body::Unsubscribe(_)) | None => {
                    return Err(ClientError::Protocol("the hub sent a client-to-hub frame"));
                }
            }
        }
    }

    fn on_envelope(&mut self, e: Envelope) -> Option<Event> {
        let kind = e.kind();
        let sender = e.sender.clone();
        match kind {
            Kind::Command | Kind::CommandResult => match self.receiver.open(&sender, &e.payload, now_ms()) {
                Ok(opened) if opened.answers.is_some() => Some(Event::Result(opened)),
                Ok(opened) => Some(Event::Command(opened)),
                Err(error) => Some(Event::Unopened { sender, kind, payload: e.payload, error }),
            },
            Kind::SessionEvents | Kind::Telemetry => {
                let stream = match e.to {
                    Some(To::Channel(channel)) => StreamRef { publisher: sender.clone(), channel },
                    _ => return None,
                };
                Some(Event::Published { stream, kind, sender, seq: e.seq, epoch: e.epoch, payload: e.payload })
            }
            // bulk chunks are the caller's to reassemble
            Kind::Bulk => Some(Event::Published {
                stream: StreamRef::default(),
                kind,
                sender,
                seq: e.seq,
                epoch: e.epoch,
                payload: e.payload,
            }),
            Kind::Unspecified => None,
        }
    }

    async fn read_message(&mut self) -> Result<(), ClientError> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(bytes))) => {
                    let frames = decode_frames_shared(bytes, self.max_frame)
                        .map_err(|_| ClientError::Protocol("the hub sent a malformed frame"))?;
                    self.pending = frames.into_iter();
                    return Ok(());
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) | None => {
                    return Err(ClientError::Transport("the hub closed the connection".into()));
                }
                Some(Ok(_)) => return Err(ClientError::Protocol("the hub sent a non-binary message")),
                Some(Err(e)) => return Err(ClientError::Transport(e.to_string())),
            }
        }
    }

    async fn send_frames(&mut self, frames: &[Frame]) -> Result<(), ClientError> {
        send(&mut self.ws, frames, self.max_frame).await
    }
}

async fn send(ws: &mut Ws, frames: &[Frame], max_frame: usize) -> Result<(), ClientError> {
    let bytes = encode_frames(frames, max_frame).map_err(|_| ClientError::Protocol("frame too large to send"))?;
    ws.send(Message::binary(bytes)).await.map_err(|e| ClientError::Transport(e.to_string()))
}

async fn first_frame(ws: &mut Ws, max: usize) -> Result<Body, ClientError> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                let mut frames = decode_frames_shared(bytes, max)
                    .map_err(|_| ClientError::Protocol("the hub sent a malformed frame"))?
                    .into_iter();
                match frames.next().and_then(|f| f.body) {
                    Some(body) => return Ok(body),
                    None => return Err(ClientError::Protocol("the hub sent an empty frame")),
                }
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => {
                return Err(ClientError::Transport("the hub closed the connection".into()));
            }
            Some(Ok(_)) => return Err(ClientError::Protocol("the hub sent a non-binary message")),
            Some(Err(e)) => return Err(ClientError::Transport(e.to_string())),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}
