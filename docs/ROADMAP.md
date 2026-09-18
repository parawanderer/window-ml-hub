# Roadmap

In order. Each step lands as its own PR with CI green. Design questions are answered in window-ml's
`docs/spec/RUNTIME_HUB.md` and recorded there; this file tracks the build.

1. **The session contract.** Done: window-ml `src/session-host.ts` and `docs/spec/SESSION_CONTRACT.md`
   ([#108](https://github.com/parawanderer/window-ml/pull/108)).
2. **MV3 lifetime.** Done: the connector's websocket can live in the service worker
   ([finding](findings/mv3-websocket-lifetime.md)).
3. **Framing.** Done: `crates/frame`.
4. **The envelope and the relay, without crypto.** Protocol drafted: [PROTOCOL.md](PROTOCOL.md). Routing core:
   `crates/relay`. Websocket server: `crates/hub` (development mode only). `proto/` for the envelope and control messages; a websocket
   server (tokio) with per-account routing, bounded rings per source, backpressure by kind (telemetry coalesced and
   dropped with a marker, session events never dropped: a subscriber that falls behind is disconnected and resyncs),
   and per-account limits. Payloads are opaque bytes from the first commit, so nothing has to be taken out later.
5. **Accounts: the hub protects itself.** Decided ([design/end-to-end-crypto.md](design/end-to-end-crypto.md)): an
   account is a root key, devices hold certificates, the hub verifies signatures; registration `invite` (default) or
   `open`. Identities and chains: `crates/keys`. Authenticated handshake, both registration modes and
   `wmlhub invite`: `crates/hub`. Docker image, compose files and [SELF_HOSTING.md](SELF_HOSTING.md).
6. **End-to-end encryption.** Decided: HPKE-style boxes on WebCrypto
   ([finding](findings/webcrypto-in-mv3-worker.md)), stream keys wrapped per device, one signature per published
   envelope, signed commands with nonces and a clock window. Lives in the clients: a Rust client library here, the
   extension's connector in window-ml. Commands and results, published streams (stream keys,
   wrapping, signed batches) and keyed channel names: `crates/seal`. The Rust client, with end-to-end tests that drive
   a real hub: `crates/client`. Vectors both ways: `vectors/seal-v1.json` opened by
   window-ml's TypeScript implementation, and `vectors/seal-ts-v1.json`, sealed there and opened here
   ([VECTORS.md](VECTORS.md)).
7. **The box connector mode.** Schema vendored ([SCHEMAS.md](SCHEMAS.md)); relay rules in
   [design/box-connector.md](design/box-connector.md). Routing a frame by its tags, without decoding it:
   `crates/box`; reading the stream and publishing it sealed on the two channels: `crates/connector`. Next: the
   binary, which waits on pairing ([design/pairing.md](design/pairing.md), proposed).
8. **The extension's connector** in window-ml's background worker. Last, and coordinated with the chat page work,
   because both talk to `background.ts`.
9. **Push for approvals** on a sleeping phone, carrying only "an approval is waiting".

Open, found along the way:

- **Pairing is unbuilt, and everything left waits on it**: the connector's binary, the extension's connector, and the
  chat page's pairing UI. Proposed in [design/pairing.md](design/pairing.md); it adds the hub's only unauthenticated
  write, so the bounds in it want a second reading before code.

- **A first message is still READ at up to 4 MiB before it is refused.** `max_hello_bytes` (64 KiB) now refuses one
  larger than a hello could be, but tokio-tungstenite 0.30 exposes only `get_config`, so the limit a connection reads
  at cannot be lowered for the handshake and raised afterwards. What bounds it instead is `max_pending_sockets`
  (256): at most that many sockets can be holding an unauthenticated message at once. Lowering it properly needs
  either a way to change a live connection's config upstream, or our own handshake before the websocket one.
- **An address-keyed connection rate cannot be the default while every client arrives from a proxy.**
  `WMLHUB_CONNECTIONS_PER_MINUTE` exists and is off by default for that reason. Reading a forwarded address
  (`X-Forwarded-For`, from proxies the operator names as trusted) is what would let it be on.

- ~~**No limit on how fast an account publishes.**~~ Each account has a work budget now (docs/PROTOCOL.md §Limits and
  failure). Still unmetered: connecting and disconnecting, which cost a handshake and presence fan-out each.

Later: agent-to-agent (lineage, spawn grants), headless runtimes, WebTransport.
