//! The hub's routing core, with no IO: accounts, presence, streams and their rings, subscriptions, per-connection
//! outbound queues, and every limit. The server feeds it decoded frames and drains what it queues; everything the
//! protocol promises about routing and backpressure is decided here, where it can be tested deterministically.
//!
//! Invariants held here (AGENTS.md): every lookup of a principal or stream goes through the connection's account
//! first; a payload is moved, never read; every collection is bounded by [`Limits`].

mod limits;
#[cfg(any(test, feature = "testing"))]
pub mod model;
mod queue;
mod ring;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use wmlhub_proto::bytes::Bytes;

use wmlhub_proto::v1::{self, Envelope, Frame, Kind, Role, envelope::To, error::Code, frame::Body};

pub use limits::Limits;
use queue::{Outbound, SlowConsumer};
use ring::Ring;

/// The protocol major this relay speaks.
pub const PROTOCOL: u32 = 1;

/// An account, as the server resolved it from a `Hello`'s credential. Opaque to the relay.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId(pub Vec<u8>);

/// A connection's handle, unique for the life of this relay.
pub type ConnId = u64;

/// A stream: one channel of one publisher, always within an account.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub publisher: Vec<u8>,
    pub channel: Vec<u8>,
}

impl StreamKey {
    fn to_ref(&self) -> v1::StreamRef {
        v1::StreamRef { publisher: self.publisher.clone(), channel: self.channel.clone() }
    }
}

/// What the server must do after a call.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// Frames are queued for this connection: drain them with [`Hub::take_outbound`] until it reports nothing more.
    /// Sent once per drain, not once per frame: frames queued while a wake is outstanding do not repeat it, so the
    /// server must keep taking until [`Taken::more`] is false before it waits again.
    Wake(ConnId),
    /// Send this error frame, then close the connection. The relay has already forgotten it.
    Close { conn: ConnId, frame: Frame },
}

/// A [`Limits`] that cannot work.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

/// What [`Hub::take_outbound`] took.
#[derive(Debug, Default)]
pub struct Taken {
    /// encoded frames, oldest first, each with its length prefix, ready to be joined into one websocket message
    pub frames: Vec<Bytes>,
    /// frames are still queued (the budget ran out): take again before waiting for a wake
    pub more: bool,
}

#[derive(Debug)]
struct Conn {
    principal: Vec<u8>,
    out: Outbound,
    subs: HashSet<StreamKey>,
    /// a `Wake` was sent and this connection's queue has not been seen empty since
    armed: bool,
}

impl Conn {
    /// Wake the connection unless a wake is already outstanding. Every successful push goes through here.
    fn arm(&mut self, id: ConnId, fx: &mut Effects) {
        if !self.armed {
            self.armed = true;
            fx.wake(id);
        }
    }
}

#[derive(Debug)]
struct Stream {
    /// shared with every queued item of this stream, so a delivery never clones the key's bytes
    key: Arc<StreamKey>,
    /// absent until the first publish decides the stream's kind
    ring: Option<Ring>,
    subscribers: HashSet<ConnId>,
}

#[derive(Debug, Default)]
struct Account {
    conns: HashMap<ConnId, Conn>,
    online: HashMap<Vec<u8>, (ConnId, Role)>,
    streams: HashMap<StreamKey, Stream>,
    ring_bytes: usize,
}

/// The relay's whole state.
#[derive(Debug)]
pub struct Hub {
    limits: Limits,
    accounts: HashMap<AccountId, Account>,
    conn_account: HashMap<ConnId, AccountId>,
    next_conn: ConnId,
    epoch_state: u64,
    clock: u64,
}

/// Actions collected during one call, with wakes de-duplicated and closes applied after routing finishes.
#[derive(Default)]
struct Effects {
    wake: Vec<ConnId>,
    close: Vec<(ConnId, Frame)>,
}

impl Effects {
    fn wake(&mut self, conn: ConnId) {
        if !self.wake.contains(&conn) {
            self.wake.push(conn);
        }
    }
}

fn error(code: Code, reference: u64, message: &str) -> Frame {
    Frame { body: Some(Body::Error(v1::Error { code: code as i32, r#ref: reference, message: message.to_owned() })) }
}

impl Hub {
    /// A relay with these limits. `epoch_seed` makes ring epochs differ across restarts; pass something random.
    pub fn new(limits: Limits, epoch_seed: u64) -> Result<Self, ConfigError> {
        Self::with_id_space(limits, epoch_seed, 0)
    }

    /// A relay that is shard `shard` of several: its connection ids carry the shard in their top 16 bits, so ids from
    /// different shards never collide. Shards share nothing else; the relay never needs two accounts at once.
    pub fn with_id_space(limits: Limits, epoch_seed: u64, shard: u16) -> Result<Self, ConfigError> {
        if limits.ring_session_events > limits.queue_session_events {
            return Err(ConfigError("a session-events backfill must fit in a connection's queue"));
        }
        if limits.max_payload_bytes >= limits.max_frame_bytes {
            return Err(ConfigError("a payload must fit in a frame with its envelope"));
        }
        Ok(Self {
            limits,
            accounts: HashMap::new(),
            conn_account: HashMap::new(),
            next_conn: (u64::from(shard) << 48) + 1,
            epoch_state: epoch_seed,
            clock: 0,
        })
    }

    /// The limits in force.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Whether this relay holds state for `account`. A server running several shards asks before admitting a new
    /// account, to enforce a limit across all of them.
    pub fn has_account(&self, account: &AccountId) -> bool {
        self.accounts.contains_key(account)
    }

    /// How many accounts this relay holds state for.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Admit a connection whose `Hello` the server has authenticated into `account`. On success the `Welcome` and
    /// the account's presence are queued; on failure the server sends the returned error and closes.
    pub fn connect(
        &mut self,
        account: AccountId,
        hello: &v1::Hello,
        now_ms: u64,
    ) -> Result<(ConnId, Vec<Action>), Box<Frame>> {
        let role = hello.role();
        if hello.protocol < PROTOCOL {
            return Err(Box::new(error(Code::Unsupported, 0, "protocol version not supported")));
        }
        if role == Role::Unspecified
            || hello.principal.is_empty()
            || hello.principal.len() > self.limits.max_id_bytes
            || account.0.is_empty()
            || account.0.len() > self.limits.max_id_bytes
        {
            return Err(Box::new(error(Code::Invalid, 0, "hello needs a principal, a role and an account")));
        }
        if !self.accounts.contains_key(&account) && self.accounts.len() >= self.limits.max_accounts {
            return Err(Box::new(error(Code::Limit, 0, "relay is full")));
        }
        if let Some(acct) = self.accounts.get(&account) {
            if acct.online.contains_key(&hello.principal) {
                return Err(Box::new(error(Code::Unauthenticated, 0, "principal already connected")));
            }
            if acct.conns.len() >= self.limits.max_connections_per_account {
                return Err(Box::new(error(Code::Limit, 0, "too many connections for this account")));
            }
        }
        // created only once every check has passed, so a refused hello leaves nothing behind
        let acct = self.accounts.entry(account.clone()).or_default();

        let id = self.next_conn;
        self.next_conn += 1;
        let mut fx = Effects::default();
        let mut conn =
            Conn { principal: hello.principal.clone(), out: Outbound::default(), subs: HashSet::new(), armed: false };
        let welcome = v1::Welcome { protocol: PROTOCOL, server_time_ms: now_ms, limits: Some(self.limits.announce()) };
        // A fresh queue holds these without trouble; a failure here would be a limits misconfiguration.
        let _ = conn.out.push_frame(&Frame { body: Some(Body::Welcome(welcome)) }, &self.limits);
        for (principal, (_, r)) in &acct.online {
            let p = v1::Presence { principal: principal.clone(), role: *r as i32, online: true };
            let _ = conn.out.push_frame(&Frame { body: Some(Body::Presence(p)) }, &self.limits);
        }
        let others: Vec<ConnId> = acct.conns.keys().copied().collect();
        conn.arm(id, &mut fx);
        acct.conns.insert(id, conn);
        acct.online.insert(hello.principal.clone(), (id, role));
        self.conn_account.insert(id, account.clone());

        let presence = v1::Presence { principal: hello.principal.clone(), role: role as i32, online: true };
        for other in others {
            self.enqueue(&account, other, Frame { body: Some(Body::Presence(presence.clone())) }, &mut fx);
        }
        Ok((id, self.finish(fx)))
    }

    /// Route one frame a connection sent.
    pub fn receive(&mut self, conn: ConnId, frame: Frame) -> Vec<Action> {
        let Some(account) = self.conn_account.get(&conn).cloned() else { return Vec::new() };
        let mut fx = Effects::default();
        match frame.body {
            Some(Body::Envelope(env)) => self.on_envelope(&account, conn, env, &mut fx),
            Some(Body::Subscribe(sub)) => self.on_subscribe(&account, conn, sub, &mut fx),
            Some(Body::Unsubscribe(unsub)) => {
                if let Some(s) = unsub.stream {
                    let key = StreamKey { publisher: s.publisher, channel: s.channel };
                    self.unsubscribe(&account, conn, &key);
                }
            }
            Some(Body::Ping(p)) => {
                self.enqueue(&account, conn, Frame { body: Some(Body::Pong(v1::Pong { nonce: p.nonce })) }, &mut fx);
            }
            // answers to the hub's own pings, and errors a peer reports: nothing to route
            Some(Body::Pong(_)) | Some(Body::Error(_)) => {}
            Some(Body::Hello(_)) => fx.close.push((conn, error(Code::Invalid, 0, "hello sent twice"))),
            Some(Body::Welcome(_) | Body::Backfilled(_) | Body::Gap(_) | Body::Presence(_) | Body::Challenge(_)) => {
                fx.close.push((conn, error(Code::Invalid, 0, "a hub-to-peer frame sent to the hub")));
            }
            None => self.enqueue(&account, conn, error(Code::Unsupported, 0, "unknown frame"), &mut fx),
        }
        self.finish(fx)
    }

    /// Close a connection from outside the routing (a decode failure, a socket that went away). Sends `frame` first
    /// when given.
    pub fn close(&mut self, conn: ConnId, frame: Option<Frame>) -> Vec<Action> {
        let mut fx = Effects::default();
        if let Some(frame) = frame {
            fx.close.push((conn, frame));
        } else {
            self.forget(conn, &mut fx);
        }
        self.finish(fx)
    }

    /// Frames queued for a connection, oldest first, up to about `budget` bytes. When nothing is left the connection
    /// is disarmed, and the next frame queued for it sends a new [`Action::Wake`].
    pub fn take_outbound(&mut self, conn: ConnId, budget: usize) -> Taken {
        let Some(account) = self.conn_account.get(&conn) else { return Taken::default() };
        let Some(c) = self.accounts.get_mut(account).and_then(|a| a.conns.get_mut(&conn)) else {
            return Taken::default();
        };
        let frames = c.out.take(budget);
        let more = !c.out.is_empty();
        c.armed = more;
        Taken { frames, more }
    }

    fn on_envelope(&mut self, account: &AccountId, conn: ConnId, mut env: Envelope, fx: &mut Effects) {
        let reference = env.r#ref;
        if env.payload.len() > self.limits.max_payload_bytes {
            fx.close.push((conn, error(Code::Limit, reference, "payload too large")));
            return;
        }
        if env.coalesce.len() > self.limits.max_coalesce_bytes {
            fx.close.push((conn, error(Code::Limit, reference, "coalesce key too long")));
            return;
        }
        let kind = Kind::try_from(env.kind).unwrap_or(Kind::Unspecified);
        let Some(sender) = self.principal_of(account, conn) else { return };
        env.sender = sender;
        env.seq = 0;
        env.epoch = 0;
        match (env.to.take(), kind) {
            (Some(To::Channel(channel)), Kind::SessionEvents | Kind::Telemetry) => {
                if channel.is_empty() || channel.len() > self.limits.max_id_bytes {
                    self.enqueue(account, conn, error(Code::Invalid, reference, "bad channel"), fx);
                    return;
                }
                if kind != Kind::Telemetry {
                    env.coalesce.clear();
                }
                let key = StreamKey { publisher: env.sender.clone(), channel: channel.clone() };
                env.to = Some(To::Channel(channel));
                self.publish(account, conn, key, kind, env, fx);
            }
            (Some(To::Principal(target)), Kind::Command | Kind::CommandResult | Kind::Bulk) => {
                env.coalesce.clear();
                self.direct(account, conn, target, env, fx);
            }
            (_, Kind::Unspecified) => {
                self.enqueue(account, conn, error(Code::Unsupported, reference, "unknown kind"), fx);
            }
            _ => self.enqueue(account, conn, error(Code::Invalid, reference, "kind does not match its address"), fx),
        }
    }

    fn publish(
        &mut self,
        account: &AccountId,
        conn: ConnId,
        key: StreamKey,
        kind: Kind,
        env: Envelope,
        fx: &mut Effects,
    ) {
        let reference = env.r#ref;
        if !self.ensure_stream(account, &key) {
            fx.close.push((conn, error(Code::Limit, reference, "too many streams for this account")));
            return;
        }
        let existing = self.accounts[account].streams[&key].ring.as_ref().map(|r| r.kind);
        if existing.is_some_and(|k| k != kind) {
            self.enqueue(account, conn, error(Code::Invalid, reference, "channel already carries another kind"), fx);
            return;
        }
        let epoch = if existing.is_none() { self.next_epoch() } else { 0 };
        self.clock += 1;
        let clock = self.clock;
        let capacity = match kind {
            Kind::SessionEvents => self.limits.ring_session_events,
            _ => self.limits.ring_telemetry,
        };
        let limits = &self.limits;
        let acct = self.accounts.get_mut(account).expect("connection's account exists");
        let Account { conns, streams, ring_bytes, .. } = acct;
        let stream = streams.get_mut(&key).expect("ensured above");
        let ring = stream.ring.get_or_insert_with(|| Ring::new(kind, epoch, clock));
        let epoch = ring.epoch;
        // stamped and encoded once; every subscriber below shares these bytes
        let published = ring.publish(env, capacity, clock);
        *ring_bytes = *ring_bytes + published.added - published.freed;
        for &sub in &stream.subscribers {
            let Some(c) = conns.get_mut(&sub) else { continue };
            match c.out.push_published(&stream.key, kind, epoch, &published.entry, limits) {
                Ok(()) => c.arm(sub, fx),
                Err(SlowConsumer) => fx.close.push((sub, error(Code::SlowConsumer, 0, "fell behind"))),
            }
        }
        Self::enforce_ring_budget(acct, limits.account_ring_bytes);
    }

    fn direct(&mut self, account: &AccountId, conn: ConnId, target: Vec<u8>, env: Envelope, fx: &mut Effects) {
        let reference = env.r#ref;
        let target_conn = self.accounts.get(account).and_then(|a| a.online.get(&target)).map(|(c, _)| *c);
        let Some(target_conn) = target_conn else {
            self.enqueue(account, conn, error(Code::Unavailable, reference, "recipient is not online"), fx);
            return;
        };
        let mut env = env;
        env.to = Some(To::Principal(target));
        let acct = self.accounts.get_mut(account).expect("connection's account exists");
        let c = acct.conns.get_mut(&target_conn).expect("online principals have connections");
        match c.out.push_frame(&Frame { body: Some(Body::Envelope(env)) }, &self.limits) {
            Ok(()) => c.arm(target_conn, fx),
            Err(SlowConsumer) => {
                fx.close.push((target_conn, error(Code::SlowConsumer, 0, "fell behind")));
                self.enqueue(account, conn, error(Code::Unavailable, reference, "recipient fell behind"), fx);
            }
        }
    }

    fn on_subscribe(&mut self, account: &AccountId, conn: ConnId, sub: v1::Subscribe, fx: &mut Effects) {
        let Some(s) = sub.stream else {
            self.enqueue(account, conn, error(Code::Invalid, 0, "subscribe needs a stream"), fx);
            return;
        };
        let max_id = self.limits.max_id_bytes;
        if s.publisher.is_empty() || s.publisher.len() > max_id || s.channel.is_empty() || s.channel.len() > max_id {
            self.enqueue(account, conn, error(Code::Invalid, 0, "bad stream"), fx);
            return;
        }
        let key = StreamKey { publisher: s.publisher, channel: s.channel };
        let already = self.accounts[account].conns.get(&conn).is_some_and(|c| c.subs.contains(&key));
        let count = self.accounts[account].conns.get(&conn).map_or(0, |c| c.subs.len());
        if !already && count >= self.limits.max_subscriptions_per_connection {
            fx.close.push((conn, error(Code::Limit, 0, "too many subscriptions")));
            return;
        }
        if !self.ensure_stream(account, &key) {
            fx.close.push((conn, error(Code::Limit, 0, "too many streams for this account")));
            return;
        }
        let acct = self.accounts.get_mut(account).expect("connection's account exists");
        if let Some(c) = acct.conns.get_mut(&conn) {
            // A repeated Subscribe replaces the subscription: anything still queued for this stream would otherwise
            // be delivered and then delivered again by the backfill.
            c.out.purge_stream(&key);
        }
        let stream = acct.streams.get_mut(&key).expect("ensured above");
        stream.subscribers.insert(conn);
        let (entries, kind, epoch, seq, truncated) = match &stream.ring {
            Some(ring) => {
                let b = ring.backfill(sub.since.as_ref());
                (b.entries, ring.kind, ring.epoch, ring.seq, b.truncated)
            }
            None => (Vec::new(), Kind::Unspecified, 0, 0, sub.since.is_some_and(|p| p.seq > 0)),
        };
        let stream_key = stream.key.clone();
        let c = acct.conns.get_mut(&conn).expect("receiving connection exists");
        c.subs.insert(key.clone());
        for entry in &entries {
            if c.out.push_published(&stream_key, kind, epoch, entry, &self.limits).is_err() {
                fx.close.push((conn, error(Code::SlowConsumer, 0, "fell behind")));
                return;
            }
        }
        let done = v1::Backfilled { stream: Some(key.to_ref()), epoch, seq, truncated };
        self.enqueue(account, conn, Frame { body: Some(Body::Backfilled(done)) }, fx);
    }

    /// Make sure `key` has a stream entry, evicting the least recently published stream nobody subscribes to when
    /// the account is at its limit. False when nothing could be evicted.
    fn ensure_stream(&mut self, account: &AccountId, key: &StreamKey) -> bool {
        let limit = self.limits.max_streams_per_account;
        let acct = self.accounts.get_mut(account).expect("connection's account exists");
        if acct.streams.contains_key(key) {
            return true;
        }
        if acct.streams.len() >= limit {
            let victim = acct
                .streams
                .iter()
                .filter(|(_, s)| s.subscribers.is_empty())
                .min_by_key(|(_, s)| s.ring.as_ref().map_or(0, |r| r.touched))
                .map(|(k, _)| k.clone());
            let Some(victim) = victim else { return false };
            if let Some(s) = acct.streams.remove(&victim) {
                acct.ring_bytes -= s.ring.map_or(0, |r| r.bytes);
            }
        }
        acct.streams
            .insert(key.clone(), Stream { key: Arc::new(key.clone()), ring: None, subscribers: HashSet::new() });
        true
    }

    /// Keep an account's retained payload under its budget by taking from its largest ring.
    fn enforce_ring_budget(acct: &mut Account, budget: usize) {
        while acct.ring_bytes > budget {
            let largest = acct.streams.values_mut().filter_map(|s| s.ring.as_mut()).max_by_key(|r| r.bytes);
            match largest {
                Some(r) if !r.is_empty() => acct.ring_bytes -= r.evict_oldest(),
                _ => break,
            }
        }
    }

    fn unsubscribe(&mut self, account: &AccountId, conn: ConnId, key: &StreamKey) {
        let Some(acct) = self.accounts.get_mut(account) else { return };
        if let Some(c) = acct.conns.get_mut(&conn) {
            c.subs.remove(key);
            c.out.purge_stream(key);
        }
        if let Some(s) = acct.streams.get_mut(key) {
            s.subscribers.remove(&conn);
            if s.subscribers.is_empty() && s.ring.is_none() {
                acct.streams.remove(key);
            }
        }
    }

    fn principal_of(&self, account: &AccountId, conn: ConnId) -> Option<Vec<u8>> {
        self.accounts.get(account)?.conns.get(&conn).map(|c| c.principal.clone())
    }

    fn enqueue(&mut self, account: &AccountId, conn: ConnId, frame: Frame, fx: &mut Effects) {
        let Some(c) = self.accounts.get_mut(account).and_then(|a| a.conns.get_mut(&conn)) else { return };
        match c.out.push_frame(&frame, &self.limits) {
            Ok(()) => c.arm(conn, fx),
            Err(SlowConsumer) => fx.close.push((conn, error(Code::SlowConsumer, 0, "fell behind"))),
        }
    }

    /// Remove a connection and tell its account's other connections it went offline.
    fn forget(&mut self, conn: ConnId, fx: &mut Effects) {
        let Some(account) = self.conn_account.remove(&conn) else { return };
        let Some(acct) = self.accounts.get_mut(&account) else { return };
        let Some(c) = acct.conns.remove(&conn) else { return };
        let role = match acct.online.get(&c.principal) {
            Some((id, role)) if *id == conn => {
                let role = *role;
                acct.online.remove(&c.principal);
                role
            }
            _ => Role::Unspecified,
        };
        for key in &c.subs {
            if let Some(s) = acct.streams.get_mut(key) {
                s.subscribers.remove(&conn);
                if s.subscribers.is_empty() && s.ring.is_none() {
                    acct.streams.remove(key);
                }
            }
        }
        let others: Vec<ConnId> = acct.conns.keys().copied().collect();
        if acct.conns.is_empty() && acct.streams.is_empty() {
            self.accounts.remove(&account);
        }
        let presence = v1::Presence { principal: c.principal, role: role as i32, online: false };
        for other in others {
            self.enqueue(&account, other, Frame { body: Some(Body::Presence(presence.clone())) }, fx);
        }
    }

    /// Apply closes (each may cascade into presence for others) and produce the actions.
    fn finish(&mut self, mut fx: Effects) -> Vec<Action> {
        let mut closed = Vec::new();
        while let Some((conn, frame)) = fx.close.pop() {
            if closed.iter().any(|(c, _)| *c == conn) || !self.conn_account.contains_key(&conn) {
                continue;
            }
            self.forget(conn, &mut fx);
            closed.push((conn, frame));
        }
        let mut actions: Vec<Action> =
            fx.wake.into_iter().filter(|c| !closed.iter().any(|(d, _)| d == c)).map(Action::Wake).collect();
        actions.extend(closed.into_iter().map(|(conn, frame)| Action::Close { conn, frame }));
        actions
    }

    /// A fresh ring epoch: splitmix64 over a seeded counter, never 0 (0 means "no ring" on the wire).
    fn next_epoch(&mut self) -> u64 {
        loop {
            self.epoch_state = self.epoch_state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.epoch_state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            if z != 0 {
                return z;
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod model_tests {
    /// Seeded random runs of the model checker on every `cargo test`. The fuzz target `relay` explores further.
    /// The byte strings the seeded runs use, deterministic across machines (xorshift64).
    pub(super) fn seeded_runs() -> impl Iterator<Item = Vec<u8>> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        std::iter::repeat_with(move || {
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let len = 64 + (next() % 4000) as usize;
            (0..len).map(|_| next() as u8).collect()
        })
    }

    #[test]
    fn random_operation_sequences_keep_every_invariant() {
        for (run, data) in seeded_runs().enumerate().take(400) {
            if let Err(e) = super::model::Model::run_bytes(&data) {
                panic!(
                    "run {run} broke an invariant: {e}\n(print its ops: RUN={run} cargo test -p wmlhub-relay print_model_run -- --ignored --nocapture)"
                );
            }
        }
    }
}

/// Debugging aid, not a test: print the operation sequence of one seeded model run.
/// `RUN=8 cargo test -p wmlhub-relay print_model_run -- --ignored --nocapture`
#[cfg(test)]
mod model_debug {
    #[test]
    #[ignore]
    fn print_model_run() {
        use arbitrary::{Arbitrary, Unstructured};
        let target: usize = std::env::var("RUN").expect("set RUN to the failing run number").parse().expect("a number");
        for (run, data) in super::model_tests::seeded_runs().enumerate().take(target + 1) {
            if run == target {
                let mut u = Unstructured::new(&data);
                let _ = u64::arbitrary(&mut u);
                let mut i = 0;
                while let Ok(op) = super::model::Op::arbitrary(&mut u) {
                    println!("{i}: {op:?}");
                    i += 1;
                }
            }
        }
    }
}
