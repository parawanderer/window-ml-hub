# Notes: the box connector

**Status: built** (`crates/box` classifies a frame from its tags, `crates/connector` reads the stream and
publishes). What is not built: running it as a binary, which waits on pairing (how a connector gets its
certificate), and reconnect-with-`since`, for which `at_ms` is already read. What the connector must do with a box's `/api/events` stream, from
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
