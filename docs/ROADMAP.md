# Roadmap

In order. Each step lands as its own PR with CI green. Design questions are answered in window-ml's
`docs/spec/RUNTIME_HUB.md` and recorded there; this file tracks the build.

1. **The session contract.** Done: window-ml `src/session-host.ts` and `docs/spec/SESSION_CONTRACT.md`
   ([#108](https://github.com/parawanderer/window-ml/pull/108)).
2. **MV3 lifetime.** Done: the connector's websocket can live in the service worker
   ([finding](findings/mv3-websocket-lifetime.md)).
3. **Framing.** Done: `crates/frame`.
4. **The envelope and the relay, without crypto.** `proto/` for the envelope and control messages; a websocket
   server (tokio) with per-account routing, bounded rings per source, backpressure by kind (telemetry coalesced and
   dropped with a marker, session events never dropped: a subscriber that falls behind is disconnected and resyncs),
   and per-account limits. Payloads are opaque bytes from the first commit, so nothing has to be taken out later.
5. **The hub protects itself.** Account credentials for registration, connection and rate limits per account.
6. **Keys, pairing and end-to-end encryption.** Choose between the Noise framework and per-pair libsodium-style
   boxes. Constraint: the extension side runs in a service worker, so the primitives must exist in WebCrypto or a
   vetted small library there (to verify: Ed25519 and X25519 support in current Chrome's WebCrypto). Signed commands
   with nonces and a clock window.
7. **The box connector mode.** Needs the BoxFrame schema from the ollama fork ([SCHEMAS.md](SCHEMAS.md)).
8. **The extension's connector** in window-ml's background worker. Last, and coordinated with the chat page work,
   because both talk to `background.ts`.
9. **Push for approvals** on a sleeping phone, carrying only "an approval is waiting".

Later: agent-to-agent (lineage, spawn grants), headless runtimes, WebTransport.
