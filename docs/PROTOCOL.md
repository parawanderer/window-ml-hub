# The hub's wire protocol

**Status: draft, version 1** (2026-09-17). The schema is [`proto/wmlhub/v1/hub.proto`](../proto/wmlhub/v1/hub.proto);
this document is the rules and the reasons. It is the only format the hub reads. What travels inside
`Envelope.payload` (the session contract, box telemetry) is between principals and is specified in window-ml.

## Transport

- **A websocket per principal**, binary messages only. The principal dials the hub; the hub never dials anyone.
- **Each message holds one or more varint-delimited `Frame`s** (`crates/frame`, the framing window-ml's
  `protostream.ts` reads), so a busy source batches without a second framing layer. A message that ends mid-frame is
  corrupt and closes the connection.
- **The hub speaks first, with `Challenge`**: a fresh 32-byte nonce, the hub's configured name and its clock.
- **The principal answers `Hello`**: its role, its account root key, its certificate chain (leaf first, one or two
  certificates, ending at the root), and an Ed25519 signature by the leaf key over the hello transcript (the hub's
  name, the nonce, the principal id, the role and the account id; `crates/keys` `hello_transcript`). A client checks
  the challenge's hub name is the hub it meant to reach before signing, so a malicious hub cannot pass another hub's
  challenge along. The hub verifies the chain and the signature with public keys only (`crates/keys`), derives the
  account from the root and the principal from the leaf, and answers `Welcome` (the protocol version it chose, its
  clock, the limits it enforces) or `Error` and closes. Identities and certificates are specified in
  [`proto/wmlhub/v1/identity.proto`](../proto/wmlhub/v1/identity.proto) and
  [`design/end-to-end-crypto.md`](design/end-to-end-crypto.md).

## Accounts are decided once, per connection

The spec's envelope list included the account. This protocol leaves it out of the envelope on purpose: **the account
is decided at `Hello` from the account credential, and every frame on that connection belongs to it.** A per-message
account would be a field a peer could set to someone else's; with the account bound to the connection, a frame routed
across accounts is not something a peer can even express. Every lookup the hub makes (a principal, a stream, a ring)
is keyed by the connection's account first.

## Principals and the sender

- **`Envelope.sender` is set by the hub** from the connection the envelope arrived on, and ignored when a peer sends
  it. Nothing can claim to be another principal to the hub.
- That is routing hygiene, not trust. A runtime acts on a command because the command's payload is signed by a key on
  its own allowlist; a hub that lied about `sender` would forge nothing.
- **One connection per principal.** A second `Hello` for a principal that is online is refused, so a stolen id cannot
  silently take over a live connection. (Until key authentication lands, see Development mode.)
- **`Presence`** is the account's directory: every online principal right after `Welcome`, then each change. Nothing
  outside the account appears.

## Two ways to send: direct and published

| Kind | Addressed to | Retained | When a recipient falls behind or is away |
| --- | --- | --- | --- |
| `SESSION_EVENTS` | a channel of the sender | ring | never dropped; the subscriber gets `Error{SLOW_CONSUMER}`, is disconnected, and resubscribes from its position |
| `TELEMETRY` | a channel of the sender | ring | coalesced by `coalesce`, then dropped with a `Gap` |
| `COMMAND` | a principal | no | never dropped; recipient offline: `Error{UNAVAILABLE}` to the sender |
| `COMMAND_RESULT` | a principal | no | as `COMMAND` |
| `BULK` | a principal | no | as `COMMAND`; chunks of a large object (a screenshot), never retained |

The direction is part of the kind: a published kind must name a channel and a direct kind a principal, or the hub
answers `Error{INVALID}`.

**A direct envelope that would overflow its recipient's queue** closes the recipient as a slow consumer and answers
the sender `Error{UNAVAILABLE}`: never dropped silently, never held.

**Commands are not stored and forwarded.** A command is signed with a clock window, so one delivered after a delay
would be refused anyway; and holding them would make the hub a database of commands. The sender learns immediately
that the runtime is away and says so to the person.

## Streams, rings and resuming

- **A stream is `(publisher, channel)`** within an account. `channel` is opaque bytes the publisher chooses.
- **The hub keeps a bounded ring per stream** for the retained kinds (sizes in `Welcome.limits`) and stamps each
  published envelope with `seq` (strictly increasing) and `epoch` (the ring's identity). A ring recreated, such as
  after a hub restart, has a new epoch.
- **`Subscribe { stream, since }`** delivers the ring after `since`, then `Backfilled { epoch, seq, truncated }`, then
  live envelopes. `truncated` is true when `since` is older than the ring holds or from another epoch, so the client
  knows its record has a gap and can ask the publisher itself for history (the session contract's backfill).
- **The rings are a cache.** The authority is the runtime (saved sessions) and the box (its own ring), so a lost hub
  node costs a reconnect and a backfill, not data.

## What the hub can see, and what publishers should do about it

The hub sees, for every envelope: the account, the sender, the recipient or channel, the kind, the size, the time and,
for telemetry, the coalesce key. The spec already counts sizes and timing as what a compromised hub learns. Two
choices keep that from growing:

- **Do not use a session hash as a channel.** A box's telemetry carries request hints with session ids, which the hub
  cannot read, but a channel named after the same hash would let it join a runtime's sessions to box traffic by
  metadata alone. Derive a channel from a key the hub does not hold (for example an HMAC of the session id under a key
  shared by the account's devices).
- **Keep `coalesce` coarse.** It exists so a slow subscriber gets the latest `sample`, not every one; a fixed small
  value per telemetry kind is enough, and anything more specific is metadata.

## How the session contract maps onto it

A runtime, as window-ml's `SessionHost` sees it:

| Contract | Protocol |
| --- | --- |
| `runtimes()` | `Presence` for the account, plus each runtime's own description published on a channel |
| `sessions()` | the runtime publishes the index on one channel (`SESSION_EVENTS`: a snapshot, then upserts and removes) |
| `events(session, since)` | one channel per session (`SESSION_EVENTS`); `Subscribe` with the hub position, and the contract's own `epoch`/`cursor` inside the payload for what the ring no longer holds |
| `send(command)` | `COMMAND` to the runtime's principal; the answer is a `COMMAND_RESULT` whose payload names the command |
| screenshots | `BULK` chunks |
| box telemetry | the box connector publishes on a channel per box (`TELEMETRY`) |

There are two positions on purpose. The hub's `epoch`/`seq` resume a subscription within what the hub retained; the
contract's `epoch`/`cursor`, inside the ciphertext, are the runtime's own and survive the hub entirely.

## Limits and failure

- Every limit is per account and announced in `Welcome`. Exceeding one is `Error{LIMIT}` and a close, so a
  misbehaving client finds out.
- **The one exception is work over time.** An account may cause `account_bytes_per_second` of work, with
  `account_burst_bytes` at once, shared by all its connections. Every message costs its size plus 64 bytes a frame, and
  every frame the hub queues on the account's behalf (fan-out, backfill, answers) costs 64 bytes more. Past the rate,
  the hub reads the account's connections more slowly until the debt is repaid: sends back up in TCP, nothing is
  dropped, nothing is closed. A connection made to wait 100 ms or more is told with `Error{THROTTLED}`, at most once
  every 10 seconds, so a client finds out without being disconnected for a burst. A new account starts with nothing banked.
- **A connection costs the same budget.** Admitting one is charged `CONNECT_COST_BYTES` (768, twelve frames' worth):
  a connect and the disconnect that follows it cost about 52 us of hub CPU against 4.7 us for a delivery, so an
  account spends the same budget whether it connects or sends. A handshake is the one piece of work that cannot be
  slowed down instead, because there is no connection to read more slowly yet, so an account whose debt is more than
  a second deep (`CONNECT_REFUSED_ABOVE_MS`) is refused with `Error{LIMIT}` saying how long to wait, rather than
  admitted and charged. Ordinary traffic makes a debt of milliseconds, so a phone can still log in while a runtime
  is publishing hard; a client that only connects and disconnects cannot.
- **A connection that never authenticates is charged to strangers.** It has no account, so strangers are one tenant
  with one budget, a share of one core (`--unauthenticated-cpu-percent`, 25 by default). Each connection that ends
  without authenticating is charged what such a connection was measured to cost: about 50 us if it never sent a hello,
  and about 190 us if it sent one and was refused, whichever check refused it. Past the budget the hub accepts new
  connections more slowly until it is paid off; what waits, waits in the kernel's backlog. Connected accounts are
  never slowed by it, and a connection that authenticates is never charged to it, so a hub restart bringing every
  device back at once is not paced. A flood of failing hellos does pace everyone who is not yet connected, which
  nothing that cannot tell an attacker from a stranger can avoid.
- **Every number the hub chooses fits in a double** (2^53 - 1): `seq`, `epoch`, and the times in `Welcome`. The wire
  types are 64-bit, but a client whose only number is a double — the browser's connector — must be able to hold one
  exactly, and an epoch that rounded would make two rings look like one. A peer's own `ref` is echoed back to that
  peer only, so a peer that chooses a larger one is the only one who suffers for it.
- **A peer answers every `Ping` with a `Pong`**, and a connection that sends nothing at all for 60 seconds is closed
  with `Error{LIMIT}`. The hub pings every 20 seconds.
- `Ping`/`Pong` keep a quiet connection alive. The MV3 finding (`docs/findings/mv3-websocket-lifetime.md`) is that
  traffic either way at least every 20 to 25 seconds keeps the extension's service worker running, so the hub pings a
  runtime at least that often.
- An unknown frame body decodes as no body and is answered `Error{UNSUPPORTED}`; an unknown field is ignored.

## Presence carries a chain

- **A presence that says a principal came online carries the chain it presented**, leaf first; one that says it went
  away carries nothing. Certificates are public — they are what the hub verifies with public keys only — and a
  publisher needs the leaf's agreement key to wrap a stream key to a device. Without it a runtime would know a phone
  is online and have no way to seal anything to it.
- **A subscriber verifies that chain itself**, against the account root it already holds. The hub passing it along is
  a convenience, not a claim: nothing about presence is trusted.
- A chain larger than two certificates at their limits is left out rather than echoed, since presence goes to every
  other connection of the account.

## Pairing

- **A principal with no certificate may send exactly one thing**: a `PairOffer`, in place of its `Hello`. The hub
  holds the offer under SHA-256 of a code it never sees, for ten minutes, and reads neither the offer nor the answer.
  That socket then waits for the answer and ends; it never joins the relay.
- **A principal that HAS a certificate** fetches the offer with `PairFetch` and leaves a certificate with
  `PairAnswer`. Only the first answer is taken, and a code already in use cannot be offered again: two devices on one
  slot is how a hub would pair itself rather than the device in front of the person.
- **What stops a hub pairing itself is the person**, comparing one fingerprint of the offered keys on both screens.
  The hub cannot mint a certificate — it never sees a signing key — but it could substitute the keys in a slot, and
  the fingerprint is what makes that visible.
- Pairing sockets have their own cap (`max_pairing_sockets`), because one holds its place for as long as a person
  takes to carry a code, and that must not keep anybody from logging in.

## Registration and development mode

- **Registration** decides whether an account the hub does not know may connect: `invite` (the default) needs a
  single-use operator invite in `Hello.invite`, `open` admits any valid chain, rate limited per source address and
  overall. A known account never needs an invite and is never rate limited. Refusals are `UNAUTHENTICATED` (no or bad
  invite) and `LIMIT` (rate).
- **Every verification failure answers the same message**, "hello did not verify", so a prober learns nothing about
  which check failed; the reason goes to the hub's log.
- **Development mode** (`wmlhub serve --dev`) skips all of it: it trusts the principal a `Hello` claims and takes
  `account_credential` as the account. It still sends a `Challenge`. The binary refuses to run it on anything but a
  loopback address.

## Open

- Padding payloads to size buckets for `SESSION_EVENTS` (the spec forbids compressing them, and sizes still leak).
- Whether `Presence` should carry anything beyond online state (last seen, a connection count).
