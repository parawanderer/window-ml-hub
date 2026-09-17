# Notes: the box connector

**Status: notes for roadmap step 7, not built.** What the connector must do with a box's `/api/events` stream, from
the fork maintainer's answer (mlbox `reports/ui-api/events-schema-answer.md`, 2026-09-17) and the relay protocol. The
schema is vendored at `proto/vendor/ollama/api/events.proto`; see [`../SCHEMAS.md`](../SCHEMAS.md).

## Reading the stream

- Connect with `?since=<ms>` sized to what the connector may have missed, and check `retainedMs` on the hello: the
  ring may reach less far back than asked.
- **Convert `t` on ingest** to absolute time with the hello's `serverTime`. `t` is relative to this connection's
  hello and means nothing to a client that connected later.
- `dropped` counts what the connector itself lost on the box link. It is the box's count, not the connector's: keep a
  separate count of anything the connector coalesces, so no gap is ever drawn as a flat line.

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

## Open

- Captures of `evict`, `load.failed` and `lease.*` for conformance vectors: the fork maintainer offered to record them
  when the box is idle.
- Whether real captures can be committed to this public repository: they carry model names, hardware details and
  request hints.
