//! A model checker for the relay: random operation sequences, with the relay's invariants asserted after every step.
//!
//! One operation language serves two drivers. `cargo test` runs seeded random sequences (`tests::model_*`), so every
//! build exercises it; the fuzz target `relay` feeds libFuzzer's bytes through [`Op`]'s `Arbitrary` implementation,
//! so coverage guidance finds the sequences a random walk would not. Limits are deliberately tiny, so every boundary
//! (full queues, full rings, stream eviction, byte budgets, connection caps) is reached in a few dozen operations.
//!
//! What is checked, after every operation:
//! - **isolation**: every delivered envelope was sent by a principal of the receiver's own account;
//! - **the sender is the hub's to stamp**: a delivered envelope names the principal that actually sent it, whatever
//!   that principal wrote in the field;
//! - **order**: published envelopes of one stream reach a subscriber in strictly increasing `seq` within an epoch;
//! - **bounds**: queue counters equal their contents and stay under every limit; rings stay under capacity with
//!   ordered, correctly labelled entries; each account's ring bytes equal the sum of its rings and stay under budget;
//!   stream, connection and subscription counts stay under their limits;
//! - **bookkeeping**: the online map, connection map, subscriber sets and per-connection subscription sets agree in
//!   both directions, and an account with no connections and no streams is gone;
//! - **closing**: a connection the relay closed is forgotten;
//! - and, implicitly, no panic.

use std::collections::{HashMap, HashSet};

use arbitrary::{Arbitrary, Unstructured};
use wmlhub_proto::v1::{self, Envelope, Frame, Kind, Role, envelope::To, frame::Body};

use crate::{AccountId, Action, ConnId, Hub, Limits, StreamKey};

// Small on purpose: operations collide on the same accounts, principals and streams often enough to build the
// interleavings that break things. With 3/4/3 the random walk and 52k fuzz runs both missed an in-place coalescing
// bug that 2/3/2 plus `Burst` finds.
const ACCOUNTS: u8 = 2;
const PRINCIPALS: u8 = 3;
const CHANNELS: u8 = 2;
/// Operations per run.
const MAX_STEPS: usize = 500;

/// One step of a run. Small integers are reduced modulo the model's sizes, so any bytes decode to a meaningful op.
#[derive(Debug, Clone, Arbitrary)]
pub enum Op {
    Connect {
        account: u8,
        principal: u8,
    },
    Disconnect {
        slot: u8,
    },
    Publish {
        slot: u8,
        channel: u8,
        telemetry: bool,
        coalesce: u8,
        size: u8,
        forge_sender: bool,
    },
    /// Several telemetry publishes on one stream with no drain between: how a box emits `sample`/`info`/`sample`,
    /// and the shape that exercises coalescing against the queue's order.
    Burst {
        slot: u8,
        channel: u8,
        keys: [u8; 4],
    },
    Subscribe {
        slot: u8,
        publisher: u8,
        channel: u8,
        since: Option<(bool, u8)>,
    },
    Unsubscribe {
        slot: u8,
        publisher: u8,
        channel: u8,
    },
    Command {
        slot: u8,
        to: u8,
        kind: u8,
        size: u8,
    },
    Ping {
        slot: u8,
    },
    Drain {
        slot: u8,
        budget: u16,
    },
    Misbehave {
        slot: u8,
        what: u8,
    },
    /// A websocket message of `bytes` arrives `after_ms` after the last one; the server charges it and, if told to
    /// wait, sleeps that long.
    Charge {
        slot: u8,
        bytes: u16,
        after_ms: u8,
    },
}

/// The tiny limits every run uses.
pub fn limits() -> Limits {
    Limits {
        max_frame_bytes: 4096,
        max_payload_bytes: 300,
        max_id_bytes: 16,
        max_coalesce_bytes: 2,
        ring_session_events: 4,
        ring_telemetry: 3,
        account_ring_bytes: 1200,
        max_streams_per_account: 5,
        max_connections_per_account: 3,
        max_accounts: 2,
        max_subscriptions_per_connection: 4,
        queue_session_events: 6,
        queue_telemetry: 3,
        queue_bytes: 2048,
        account_bytes_per_second: 2_000,
        account_burst_bytes: 3_000,
    }
}

/// A stream as one connection receives it: (receiving conn, publisher, channel).
type Delivery = (ConnId, Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, Copy)]
struct Slot {
    conn: ConnId,
    account: u8,
    principal: u8,
}

/// The model: the relay under test, and what it needs to judge what comes out.
pub struct Model {
    hub: Hub,
    limits: Limits,
    slots: Vec<Slot>,
    /// per (receiving conn, publisher, channel): (epoch, last seq delivered)
    last_seq: HashMap<Delivery, (u64, u64)>,
    /// epochs seen per stream, so `Subscribe { since }` can name a real one
    epochs: Vec<u64>,
    counter: u32,
    /// connections sent an `Action::Wake` and not drained to empty since: what a server waiting on wakes would know
    woken: HashSet<ConnId>,
    /// the server's monotonic clock
    now_ms: u64,
}

fn principal_bytes(p: u8) -> Vec<u8> {
    format!("p{p}").into_bytes()
}

fn account_id(a: u8) -> AccountId {
    AccountId(vec![b'a', a])
}

impl Model {
    pub fn new(seed: u64) -> Self {
        let limits = limits();
        Self {
            hub: Hub::new(limits.clone(), seed).expect("model limits are valid"),
            limits,
            slots: Vec::new(),
            last_seq: HashMap::new(),
            epochs: Vec::new(),
            counter: 0,
            woken: HashSet::new(),
            now_ms: 0,
        }
    }

    /// Run a whole sequence decoded from `data`. Returns the first invariant violated, with the op that broke it.
    pub fn run_bytes(data: &[u8]) -> Result<(), String> {
        let mut u = Unstructured::new(data);
        let seed = u64::arbitrary(&mut u).unwrap_or(0);
        let mut model = Self::new(seed);
        let mut step = 0usize;
        while let Ok(op) = Op::arbitrary(&mut u) {
            model.apply(&op).map_err(|e| format!("step {step} {op:?}: {e}"))?;
            step += 1;
            // Short runs: the whole-relay check after every op is O(state), and a fuzzer gains more from many short
            // inputs than from a few long ones.
            if step >= MAX_STEPS {
                break;
            }
        }
        // drain everything that is left, so the last deliveries are judged too
        for i in 0..model.slots.len() {
            model.apply(&Op::Drain { slot: i as u8, budget: u16::MAX }).map_err(|e| format!("final drain: {e}"))?;
        }
        Ok(())
    }

    fn slot(&self, n: u8) -> Option<Slot> {
        (!self.slots.is_empty()).then(|| self.slots[n as usize % self.slots.len()])
    }

    /// Apply one op and check every invariant.
    pub fn apply(&mut self, op: &Op) -> Result<(), String> {
        let actions = match *op {
            Op::Connect { account, principal } => {
                let (account, principal) = (account % ACCOUNTS, principal % PRINCIPALS);
                let hello = v1::Hello {
                    protocol: 1,
                    principal: principal_bytes(principal),
                    role: Role::Client as i32,
                    ..Default::default()
                };
                match self.hub.connect(account_id(account), &hello, 0) {
                    Ok((conn, actions)) => {
                        self.slots.push(Slot { conn, account, principal });
                        actions
                    }
                    Err(_) => Vec::new(),
                }
            }
            Op::Disconnect { slot } => match self.slot(slot) {
                Some(s) => self.hub.close(s.conn, None),
                None => Vec::new(),
            },
            Op::Publish { slot, channel, telemetry, coalesce, size, forge_sender } => {
                let Some(s) = self.slot(slot) else { return self.check() };
                self.counter += 1;
                let kind = if telemetry { Kind::Telemetry } else { Kind::SessionEvents };
                let env = Envelope {
                    to: Some(To::Channel(vec![b'c', channel % CHANNELS])),
                    kind: kind as i32,
                    sender: if forge_sender { principal_bytes((s.principal + 1) % PRINCIPALS) } else { Vec::new() },
                    coalesce: if coalesce % 3 == 0 { Vec::new().into() } else { vec![coalesce % 3].into() },
                    payload: self.tagged(s, size).into(),
                    ..Default::default()
                };
                self.hub.receive(s.conn, Frame { body: Some(Body::Envelope(env)) })
            }
            Op::Burst { slot, channel, keys } => {
                let Some(s) = self.slot(slot) else { return self.check() };
                let mut actions = Vec::new();
                for k in keys {
                    self.counter += 1;
                    let env = Envelope {
                        to: Some(To::Channel(vec![b'c', channel % CHANNELS])),
                        kind: Kind::Telemetry as i32,
                        coalesce: if k % 3 == 0 { Vec::new().into() } else { vec![k % 3].into() },
                        payload: self.tagged(s, k % 16).into(),
                        ..Default::default()
                    };
                    actions.extend(self.hub.receive(s.conn, Frame { body: Some(Body::Envelope(env)) }));
                }
                actions
            }
            Op::Subscribe { slot, publisher, channel, since } => {
                let Some(s) = self.slot(slot) else { return self.check() };
                let (publisher, channel) = (principal_bytes(publisher % PRINCIPALS), vec![b'c', channel % CHANNELS]);
                self.last_seq.remove(&(s.conn, publisher.clone(), channel.clone()));
                let since = since.map(|(real_epoch, seq)| v1::Position {
                    epoch: if real_epoch && !self.epochs.is_empty() {
                        self.epochs[seq as usize % self.epochs.len()]
                    } else {
                        u64::from(seq)
                    },
                    seq: u64::from(seq % 8),
                });
                let sub = v1::Subscribe { stream: Some(v1::StreamRef { publisher, channel }), since };
                self.hub.receive(s.conn, Frame { body: Some(Body::Subscribe(sub)) })
            }
            Op::Unsubscribe { slot, publisher, channel } => {
                let Some(s) = self.slot(slot) else { return self.check() };
                let stream = v1::StreamRef {
                    publisher: principal_bytes(publisher % PRINCIPALS),
                    channel: vec![b'c', channel % CHANNELS],
                };
                self.hub
                    .receive(s.conn, Frame { body: Some(Body::Unsubscribe(v1::Unsubscribe { stream: Some(stream) })) })
            }
            Op::Command { slot, to, kind, size } => {
                let Some(s) = self.slot(slot) else { return self.check() };
                let kind = [Kind::Command, Kind::CommandResult, Kind::Bulk, Kind::SessionEvents, Kind::Unspecified]
                    [kind as usize % 5];
                let env = Envelope {
                    to: Some(To::Principal(principal_bytes(to % PRINCIPALS))),
                    kind: kind as i32,
                    payload: self.tagged(s, size).into(),
                    r#ref: u64::from(size),
                    ..Default::default()
                };
                self.hub.receive(s.conn, Frame { body: Some(Body::Envelope(env)) })
            }
            Op::Ping { slot } => {
                let Some(s) = self.slot(slot) else { return self.check() };
                self.hub.receive(s.conn, Frame { body: Some(Body::Ping(v1::Ping { nonce: 1 })) })
            }
            Op::Drain { slot, budget } => {
                let Some(s) = self.slot(slot) else { return self.check() };
                let taken = self.hub.take_outbound(s.conn, usize::from(budget));
                if !taken.more {
                    // a server drains until `more` is false, then waits for the next wake
                    self.woken.remove(&s.conn);
                }
                let mut frames = Vec::with_capacity(taken.frames.len());
                for w in &taken.frames {
                    // each item is exactly one encoded frame
                    let mut decoded =
                        wmlhub_proto::decode_frames(w, usize::MAX).map_err(|e| format!("queued bytes: {e}"))?;
                    if decoded.len() != 1 {
                        return Err(format!("a queued item held {} frames", decoded.len()));
                    }
                    frames.push(decoded.remove(0));
                }
                self.judge_deliveries(s, &frames)?;
                Vec::new()
            }
            Op::Charge { slot, bytes, after_ms } => {
                let Some(s) = self.slot(slot) else { return self.check() };
                self.now_ms += u64::from(after_ms);
                let (wait, actions) = self.hub.charge(s.conn, usize::from(bytes), self.now_ms);
                self.judge_actions(&actions)?;
                let account = self.hub.conn_account.get(&s.conn).cloned();
                let acct = account.as_ref().and_then(|a| self.hub.accounts.get(a));
                let Some(acct) = acct else { return self.check() };
                // The server sleeps `wait`: by then the debt, this message included, must be repaid.
                let (rate, burst) = (self.limits.account_bytes_per_second, self.limits.account_burst_bytes);
                let mut after = acct.rate.clone();
                after.refill(self.now_ms + wait, rate, burst);
                if after.tokens() < 0 {
                    return Err(format!("waited {wait} ms and the account is still {} bytes in debt", -after.tokens()));
                }
                if wait > 0 {
                    let mut early = acct.rate.clone();
                    early.refill(self.now_ms + wait - 1, rate, burst);
                    if early.tokens() >= 0 {
                        return Err(format!("told to wait {wait} ms when {} would have done", wait - 1));
                    }
                }
                self.now_ms += wait;
                Vec::new()
            }
            Op::Misbehave { slot, what } => {
                let Some(s) = self.slot(slot) else { return self.check() };
                let body = match what % 6 {
                    0 => None,
                    1 => Some(Body::Hello(v1::Hello::default())),
                    2 => Some(Body::Presence(v1::Presence::default())),
                    3 => Some(Body::Envelope(Envelope { to: None, kind: Kind::Command as i32, ..Default::default() })),
                    4 => Some(Body::Envelope(Envelope {
                        to: Some(To::Channel(vec![0; 40])),
                        kind: Kind::SessionEvents as i32,
                        ..Default::default()
                    })),
                    _ => Some(Body::Envelope(Envelope {
                        to: Some(To::Channel(vec![b'c', 0])),
                        kind: Kind::Telemetry as i32,
                        coalesce: vec![1; 9].into(),
                        ..Default::default()
                    })),
                };
                self.hub.receive(s.conn, Frame { body })
            }
        };
        self.judge_actions(&actions)?;
        self.check()
    }

    /// Payload: [account, principal, 0, 0, counter (4 bytes), padding]. What isolation is judged by.
    fn tagged(&self, s: Slot, size: u8) -> Vec<u8> {
        let mut p = vec![s.account, s.principal, 0, 0];
        p.extend_from_slice(&self.counter.to_le_bytes());
        p.resize(8 + usize::from(size) * 2, 0xab);
        p
    }

    fn judge_actions(&mut self, actions: &[Action]) -> Result<(), String> {
        for action in actions {
            match action {
                Action::Close { conn, .. } => {
                    if self.hub.conn_account.contains_key(conn) {
                        return Err(format!("closed connection {conn} is still known to the relay"));
                    }
                    self.woken.remove(conn);
                }
                Action::Wake(conn) => {
                    self.woken.insert(*conn);
                }
            }
        }
        // forget slots whose connections the relay no longer has
        self.slots.retain(|s| self.hub.conn_account.contains_key(&s.conn));
        Ok(())
    }

    fn judge_deliveries(&mut self, receiver: Slot, frames: &[Frame]) -> Result<(), String> {
        for frame in frames {
            let Some(Body::Envelope(e)) = &frame.body else { continue };
            if e.payload.len() < 8 {
                return Err(format!("delivered envelope without the model's tag: {e:?}"));
            }
            let (account, principal) = (e.payload[0], e.payload[1]);
            if account != receiver.account {
                return Err(format!(
                    "ISOLATION: account {} received an envelope from account {account}",
                    receiver.account
                ));
            }
            if e.sender != principal_bytes(principal) {
                return Err(format!(
                    "sender not stamped: says {:?}, sent by p{principal}",
                    String::from_utf8_lossy(&e.sender)
                ));
            }
            if let Some(To::Channel(channel)) = &e.to {
                if !self.epochs.contains(&e.epoch) {
                    self.epochs.push(e.epoch);
                }
                let key = (receiver.conn, e.sender.clone(), channel.clone());
                if let Some(&(epoch, last)) = self.last_seq.get(&key) {
                    if epoch == e.epoch && e.seq <= last {
                        return Err(format!(
                            "ORDER: stream {:?} delivered seq {} after {last}",
                            String::from_utf8_lossy(channel),
                            e.seq
                        ));
                    }
                }
                self.last_seq.insert(key, (e.epoch, e.seq));
            }
        }
        Ok(())
    }

    /// The structural invariants of the whole relay.
    fn check(&self) -> Result<(), String> {
        let l = &self.limits;
        if self.hub.accounts.len() > l.max_accounts {
            return Err(format!("{} accounts over the limit", self.hub.accounts.len()));
        }
        for acct in self.hub.accounts.values() {
            if acct.rate.tokens() > self.limits.account_burst_bytes as i64 {
                return Err(format!("an account holds {} bytes of work, over its burst", acct.rate.tokens()));
            }
        }
        // No lost wake-ups: anything queued has a wake outstanding, or a server waiting on wakes never sends it.
        for acct in self.hub.accounts.values() {
            for (conn, c) in &acct.conns {
                if !c.out.is_empty() && !self.woken.contains(conn) {
                    return Err(format!("connection {conn} has frames queued and no wake outstanding"));
                }
            }
        }
        for (id, acct) in &self.hub.accounts {
            if acct.conns.is_empty() && acct.streams.is_empty() {
                return Err(format!("empty account {:?} was kept", id.0));
            }
            if acct.conns.len() > l.max_connections_per_account || acct.streams.len() > l.max_streams_per_account {
                return Err(format!(
                    "account over its connection or stream limit: {} conns, {} streams",
                    acct.conns.len(),
                    acct.streams.len()
                ));
            }
            let mut ring_bytes = 0;
            for (key, stream) in &acct.streams {
                if let Some(ring) = &stream.ring {
                    let capacity =
                        if ring.kind == Kind::SessionEvents { l.ring_session_events } else { l.ring_telemetry };
                    ring.check(capacity)?;
                    ring_bytes += ring.bytes;
                }
                for sub in &stream.subscribers {
                    let has = acct.conns.get(sub).is_some_and(|c| c.subs.contains(key));
                    if !has {
                        return Err(format!("stream lists subscriber {sub} that does not list it back"));
                    }
                }
            }
            if ring_bytes != acct.ring_bytes {
                return Err(format!("account ring bytes drifted: {} recorded, {ring_bytes} held", acct.ring_bytes));
            }
            if acct.ring_bytes > l.account_ring_bytes {
                return Err(format!("account ring bytes {} over budget {}", acct.ring_bytes, l.account_ring_bytes));
            }
            for (conn_id, conn) in &acct.conns {
                if self.hub.conn_account.get(conn_id) != Some(id) {
                    return Err(format!("connection {conn_id} is not mapped to its account"));
                }
                conn.out.check(l)?;
                if conn.subs.len() > l.max_subscriptions_per_connection {
                    return Err(format!("connection {conn_id} over its subscription limit"));
                }
                for key in &conn.subs {
                    if !acct.streams.get(key).is_some_and(|s| s.subscribers.contains(conn_id)) {
                        return Err(format!("connection {conn_id} lists a subscription its stream does not"));
                    }
                }
                match acct.online.get(&conn.principal) {
                    Some((online, _)) if online == conn_id => {}
                    _ => return Err(format!("connection {conn_id} is not the online entry for its principal")),
                }
            }
            if acct.online.len() != acct.conns.len() {
                return Err("online map and connections disagree".into());
            }
        }
        for (conn, account) in &self.hub.conn_account {
            if !self.hub.accounts.get(account).is_some_and(|a| a.conns.contains_key(conn)) {
                return Err(format!("connection {conn} maps to an account that does not hold it"));
            }
        }
        Ok(())
    }
}

/// `StreamKey` is part of the relay's API; referenced here so the model's keys and the relay's cannot drift apart.
#[allow(dead_code)]
fn _stream_key_shape(k: StreamKey) -> (Vec<u8>, Vec<u8>) {
    (k.publisher, k.channel)
}
