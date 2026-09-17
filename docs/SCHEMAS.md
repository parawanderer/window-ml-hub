# Which repository owns which wire schema

**The rule: a schema lives beside its encoder.** The repository that produces a stream owns its definition, because
that copy is the one that cannot drift from what is actually sent. Every other repository that reads the stream
vendors the file unchanged and pins it with a `<name>.proto.pin.json` naming the repo, path, commit and **git blob
id**. A blob id is content-addressed, so `git hash-object <file>` proves offline that the copy is byte for byte the
pinned file, and a check against GitHub says when upstream has moved on. window-ml already does this for the chat
stream (`src/proto/chat.proto.pin.json`); every schema here follows the same pattern.

| Schema | Owner (the encoder) | Read by | Status |
| --- | --- | --- | --- |
| **Envelope** and the hub's own control messages (hello, subscribe, backfill, errors) | this repository, `proto/wmlhub/v1/hub.proto` ([PROTOCOL.md](PROTOCOL.md)) | window-ml's hub connector and hub client | draft, version 1 |
| **Session payloads**: `SessionHost` shapes and `MlDebugEvent` | window-ml, `src/session-host.ts`, `src/contract.ts` | clients only | JSON inside the ciphertext for contract version 1 ([`SESSION_CONTRACT.md` §On the wire](https://github.com/parawanderer/window-ml/blob/main/docs/spec/SESSION_CONTRACT.md)) |
| **BoxFrame**: the box's `/api/events` stream | parawanderer/ollama `slop`, `api/events.proto` (package `slop.events.v1`), kept true by a lockstep test beside `api/types.go` | window-ml's resource panel, this repository's box connector | **vendored** at `proto/vendor/ollama/api/events.proto`, pinned |
| **Chat stream** | parawanderer/ollama `slop`, `middleware/chat.proto` | window-ml | exists and pinned |

**Checking pins**: `tools/check-pins.sh` compares every vendored file's git blob id with its `.pin.json` (CI runs it);
`tools/check-pins.sh --upstream` also asks GitHub whether the pinned branch has moved on.

**The hub never pins a payload schema.** It parses only the envelope, and not having payload schemas as dependencies
is part of how that stays true. The box connector is the exception, and it is a separate mode: it holds the
plaintext before encrypting it, and needs the frame kinds to coalesce samples and find the box id in `hello`.

## BoxFrame: owned by the fork

Requested 2026-09-17 (mlbox `inbox/ui-api/handover-events-schema.md`), built the same day: `api/events.proto` at
fork commit `aa1536a0`, blob `7a842b72`. A protobuf *encoding* for this stream had been declined on 2026-09-13, rightly,
when window.ml was its only consumer; this is a schema for the NDJSON, which did not change.

What a consumer needs to know from it:

- **One flat `EventFrame` with `kind` as a string**, because that is what is sent. The kind list at the top of the file
  is the contract; kinds are added without bumping `v`, so ignore a kind you do not know.
- **`optional` means the key can appear carrying a zero**, so generated code tells "reported as 0" from "not
  reported". Everything else is implicit presence, where absent and zero are the same fact. The fork's test enforces
  this against the Go encoder by reflection, over 301 JSON paths.
- **`ps` and `info` are fully typed**, not opaque JSON. `estimate.breakdown` and `activity` are marked `UNSTABLE`.
- **`backfilled` is `null` on every frame that is not a `hello`** (the only null on the wire). Treat null and absent
  alike.
- **`t` is milliseconds since that connection's `hello`**, negative for backfill; absolute time is `serverTime + t`.
- **Backfill needs `?since=<ms>`** (a duration). Without it a hello reports `backfilled: 0` and replays nothing.

Rules for relaying the stream are in [`design/box-connector.md`](design/box-connector.md).
