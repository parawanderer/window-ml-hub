# Notes: the box connector

**Status: built** (`crates/box` classifies a frame from its tags, `crates/connector` reads the stream, publishes,
and stays connected across a box's restarts). What is not built: running it as a binary, which waits on pairing
(how a connector gets its certificate).

**Reconnecting**: the connector asks for the gap since the newest `at_ms` it published, plus 30 seconds of slack for
clock skew, and the box replays frames it has already relayed. There is no frame id to compare them by, so it
remembers the hashes of the last 4,096 frames it published — the bytes are identical on replay, since nothing
between the box and a subscriber re-encodes them, which is the same property everything else here rests on. A
backfill longer than that window would republish, which is why the window is minutes of frames rather than seconds. What the connector must do with a box's `/api/events` stream, from
the fork maintainer's answer (mlbox `reports/ui-api/events-schema-answer.md`, 2026-09-17) and the relay protocol. The
schema is vendored at `proto/vendor/ollama/api/events.proto`; see [`../SCHEMAS.md`](../SCHEMAS.md).

## Reading the stream

- **Ask for the binary stream** (`Accept: application/protobuf`), and cut it at the varint lengths with
  `crates/frame`: the stream uses the same framing as the hub. **Each frame's bytes go into an envelope unchanged.**
  Nothing between the box and the client decodes and re-encodes a frame, which is the reason the binary encoding was
  built.
- Connect with `?since=<ms>` sized to what the connector may have missed, and check `retainedMs` on the hello: the
  ring may reach less far back than asked.
- **Every frame carries `at_ms`** (field 30, fork `10b026a3`): wall-clock Unix milliseconds of when the event
  happened, including on a backfilled frame. So a frame is self-contained and relays verbatim. Clients place frames on
  a timeline with `at_ms` and measure durations with `t`, which is monotonic within one connection but relative to
  that connection's `hello`. `at_ms` can step when the box's clock is stepped.

## Reading a frame without decoding it

Coalescing needs two facts per frame: its `kind` (field 2) and, for a `sample`, whether it carries `info` (field 28).
The connector reads them by walking the frame's top-level tags (a varint key, then skip the value by its wire type)
and decodes nothing else. Both are in the schema's stability list, and **field numbers are never reused or
renumbered**: the envelope is `v` 1, `kind` 2, `t` 3, `serverTime` 5, `box` 6, `retainedMs` 7, `backfilled` 8,
`dropped` 29, `at_ms` 30, with `ps` 27 and `info` 28 the two large message fields. A frame whose tags do
not parse is relayed on the lossless channel as it is, never dropped: an unreadable frame is a question for the
client, not a reason for the relay to lose it.

## What may be coalesced, and what never

| Kind | Coalescable? |
| --- | --- |
| `sample` without `info` | yes: a later sample supersedes it |
| `sample` carrying `info` | **no**: `info` is sent only when it changed, so dropping that sample loses the change for good (or merge its `info` into the sample kept) |
| `heartbeat` | yes, but never the last in a window: it is what tells a quiet box from a dead link |
| `hello` | never relayed as another connection's |
| every edge (`estimate`, `load.*`, `evict`, `unload`, `expires`, `busy.*`, `gen.*`, `lease.*`) and any unknown kind | **never** dropped, never reordered |

**Never reorder edges**: `estimate` precedes its `load.start`, `load.weights` precedes `load.complete`, `gen.start`
precedes `gen.end`, `busy.end` precedes the `expires` it causes. **Forward unknown kinds**: a connector that relays only
what it knows would stop a newer client seeing a newer box, which is what the schema exists to prevent. Relay the
box's bytes rather than re-encoding them.

## Consequence for the relay protocol

`KIND_TELEMETRY` is coalesced and, past a limit, dropped oldest-first, which is right for samples and wrong for edges.
So the connector publishes on **two channels per box**:

- **an edge channel, as `KIND_SESSION_EVENTS`**: lossless and ordered; a subscriber that falls behind is disconnected
  and resyncs from the ring. Every frame that is not a sample or heartbeat goes here, unknown kinds included.
- **a sample channel, as `KIND_TELEMETRY`**, with `coalesce` set to a fixed value for samples without `info` and to
  empty for samples that carry `info` (empty never coalesces, and the relay's oldest-first drop is then the only
  way one is lost, reported with a `Gap`). Whether a sample carrying `info` should instead go on the edge channel is
  worth deciding when this is built: it would make `info` lossless at the cost of ordering samples among edges.

A client merges the two by absolute time, which is why `t` is converted on ingest.

## Sizes, skips and reasons

- **Frame size**: about 2.1 KB of base plus about 1.6 KB per resident model (NDJSON; binary is smaller), always largest
  on a `sample`. Nothing is capped server-side, but the loaded-model limit bounds it: about 12 KB at six models. The
  relay's 1 MiB payload limit has two orders of magnitude of room.
- **An unencodable frame is skipped and counted in `dropped`**, and the stream continues. It is a build defect the
  fork's lockstep test should make unreachable. `dropped` therefore means "frames this subscriber did not receive",
  from a full buffer or a skip alike.
- **`unload` carries a `reason`**: `expired`, `requested`, `displaced`, `leased`, `load-failed` or `oom-retry`. Absent
  or unrecognised means the server did not say. It is still an edge: never coalesced, never dropped.

## Open

- Captures of `evict`, `load.failed` and `lease.*` for conformance vectors, when the box is idle.
- Whether real captures can be committed to this public repository: they carry model names, hardware details and
  request hints.

## Who gets the key (decided 2026-09-18)

A publisher has to wrap its stream key for every device allowed to read it, and a connector has no directory of an
account's devices: it knows its own keys and whatever reaches it. **So the device asks.** It sends a sealed command
with body `box.grant` under the `view` scope, and the connector wraps the current key for both of its channels and
sends each back as an ordinary key grant.

What makes that safe is that the asking is a sealed command like any other. The seal carries the sender's chain up
to the account root, the scope its leaf grants, and the agreement key to wrap to, so every input to the decision is
already authenticated by the time the connector sees it. A connector that was handed a LIST of devices instead
would be trusting whoever handed it the list, which on this design is the hub.

- ~~**A revoked device is still granted one**, until its certificate expires.~~ A connector follows the account's
  revocation list now (`revoked.rs`, [`revocation.md`](revocation.md)). It learns who may sign one from presence,
  verifying the chain itself, and reads that principal's retained `revocations` channel, so a list published while it
  was away arrives on reconnect. It keeps what it applied on disk, rotates its key when a list names somebody new,
  and refuses the new key to anything the list names, including every device a revoked delegate paired.
- **Silence is an outage, not a bypass.** Once a connector has seen a revoker or applied a list, it refuses NEW grants
  while its list is more than 7 days old (`FRESHNESS_FLOOR_MS`, decided 2026-09-19). The revoker re-signs on every
  reconnect and daily, so an honest hub always delivers a younger one. A hub that withheld lists could otherwise keep
  a revoked device receiving grants for the life of its certificate. A device already reading keeps reading; the
  floor stops only new grants. Before a connector has ever seen a revoker it grants as before, because an account
  with nobody to sign lists has no list to be fresh; what that leaves open is a hub that hides the revoker from a
  connector's first connection onwards.
- **Most refusals are silence, and a revocation refusal is answered.** The common refusal never reaches the connector
  at all: a command from a principal whose certificate does not grant `view` fails in `Receiver::open`. But a
  `box.grant` refused because of the list is answered with a sealed result naming the command's nonce: `revoked`, or
  `stale <ms>` with the epoch milliseconds since which the revoker has not been heard from. The device can then say
  that box access pauses until the revoker is back, where silence would read as a broken box. A device that does not
  expect a result for `box.grant` ignores it.
- **A grant covers the key from where it starts.** The stream key is generated when a connector starts and replaced
  when a revocation names somebody new, so a restart and a rotation look the same to a device: a new key id, and a
  device that held the old one asks again when frames stop opening. A grant covers the new key from the first counter
  it sealed, so nothing sealed under the old key opens with it.
- **The channels are named for the connector's principal**, not for a label: `channel(purpose, principal_id)` under
  the account's channel key. A device knows the principal from the paired-devices list and the channel key from its
  own pairing, so it can name the channels without being told, and two boxes an operator called the same thing do
  not collide.
- **`box.grant` is not the session contract.** window-ml's `SESSION_CONTRACT.md` is a runtime's vocabulary and a
  connector implements none of it. This is the whole of the connector's own: one name, no arguments.

## The two halves, and why the loop is split

One websocket carries both what the connector publishes and what devices ask of it, so one task owns it and waits
on two things at once: a frame from the box, and whatever the hub has to say.

That means the box side cannot be in the same loop, because a loop waiting on a box is not reading its hub. It is
its own task, handing frames over a bounded channel (`PENDING_FRAMES`), and a full channel stops it reading the
box, which is the right way round: a hub that cannot keep up should slow the connector down rather than fill its
memory.

The duplicate check and the resume point live on the PUBLISHING side, because a frame is only a duplicate once it
has actually been published, and a frame handed over that the hub then refused must be asked for again. The box
side learns where to resume from a watch the publisher writes.

The select is only sound because `Client::next` is safe to drop: frames already read stay in the client, and the
one thing a dropped call can lose is a pong, which the hub's idle timeout does not count separately.
