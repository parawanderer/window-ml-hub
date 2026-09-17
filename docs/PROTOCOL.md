# The hub's wire protocol

**Status: draft, version 1** (2026-09-17). The schema is [`proto/wmlhub/v1/hub.proto`](../proto/wmlhub/v1/hub.proto);
this document is the rules and the reasons. It is the only format the hub reads. What travels inside
`Envelope.payload` (the session contract, box telemetry) is between principals and is specified in window-ml.

## Transport

- **A websocket per principal**, binary messages only. The principal dials the hub; the hub never dials anyone.
- **Each message holds one or more varint-delimited `Frame`s** (`crates/frame`, the framing window-ml's
  `protostream.ts` reads), so a busy source batches without a second framing layer. A message that ends mid-frame is
  corrupt and closes the connection.
- **The first frame is `Hello`.** The hub answers `Welcome` (with the protocol version it chose, its clock and the
  limits it enforces) or `Error` and closes.

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

- Every limit is per account and announced in `Welcome`. Exceeding one is `Error{LIMIT}` and a close, never a silent
  throttle, so a misbehaving client finds out.
- `Ping`/`Pong` keep a quiet connection alive. The MV3 finding (`docs/findings/mv3-websocket-lifetime.md`) is that
  traffic either way at least every 20 to 25 seconds keeps the extension's service worker running, so the hub pings a
  runtime at least that often.
- An unknown frame body decodes as no body and is answered `Error{UNSUPPORTED}`; an unknown field is ignored.

## Development mode

Until account credentials and key authentication land (docs/ROADMAP.md steps 5 and 6), the hub runs only in an
explicit development mode: it binds to loopback, accepts the principal id a `Hello` claims, and derives the account
from the credential bytes as given. It refuses to start that way on any other address.

## Open

- Padding payloads to size buckets for `SESSION_EVENTS` (the spec forbids compressing them, and sizes still leak).
- Whether `Presence` should carry anything beyond online state (last seen, a connection count).
- Authentication in `Hello`: a challenge the principal signs, once keys exist.
