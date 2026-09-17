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
   `open`. Identities and chains: `crates/keys`. Next: the authenticated `Hello`, the registration modes and an invite
   command.
6. **End-to-end encryption.** Decided: HPKE-style boxes on WebCrypto
   ([finding](findings/webcrypto-in-mv3-worker.md)), stream keys wrapped per device, one signature per published
   envelope, signed commands with nonces and a clock window. Lives in the clients: a Rust client library here, the
   extension's connector in window-ml.
7. **The box connector mode.** Schema vendored ([SCHEMAS.md](SCHEMAS.md)); relay rules in
   [design/box-connector.md](design/box-connector.md).
8. **The extension's connector** in window-ml's background worker. Last, and coordinated with the chat page work,
   because both talk to `background.ts`.
9. **Push for approvals** on a sleeping phone, carrying only "an approval is waiting".

Later: agent-to-agent (lineage, spawn grants), headless runtimes, WebTransport.
