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
| **BoxFrame**: the box's `/api/events` stream | parawanderer/ollama `slop`, beside `server/events.go` | window-ml's resource panel, this repository's box connector | proposed, see below |
| **Chat stream** | parawanderer/ollama `slop`, `middleware/chat.proto` | window-ml | exists and pinned |

**The hub never pins a payload schema.** It parses only the envelope, and not having payload schemas as dependencies
is part of how that stays true. The box connector is the exception, and it is a separate mode: it holds the
plaintext before encrypting it, and needs the frame kinds to coalesce samples and find the box id in `hello`.

## BoxFrame: ask the box to own a proto

**Requested 2026-09-17** (mlbox `inbox/ui-api/handover-events-schema.md`). A protobuf *encoding* for this stream was
declined on 2026-09-13, rightly, when window.ml was its only consumer; the request is for a schema, with the NDJSON
unchanged.

The patched Ollama emits `/api/events` as NDJSON today, and window-ml parses it by hand. The box connector will read
the same stream, in Rust. Proposal, for the ollama fork's maintainer to accept or change:

1. **The fork adds `server/events.proto`** beside the encoder: one message per frame kind (`hello`, `sample`,
   `load.*`, `busy.*`, `gen.start`/`gen.end`, `evict`, `expires`, `unload`), each carrying `v`.
2. **The NDJSON output stays, as the canonical JSON mapping of that schema.** Existing clients keep working, and
   the proto is a description of what is already sent rather than a second format. A binary variant is chosen by the
   response content type, the way the chat stream's is, and can come later or never.
3. **window-ml and this repository vendor and pin it.** window-ml can generate its types from it instead of
   maintaining hand-written ones; the connector generates Rust with `prost`.

Open for the fork to decide: whether `sample` embeds the `/api/ps` and `/api/info` bodies as typed messages or as
opaque JSON (they are Ollama's own API shapes, which upstream does not define in proto), and whether field names
follow the JSON's dotted kinds or a `oneof`.
