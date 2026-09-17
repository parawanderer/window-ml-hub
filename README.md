# window-ml-hub

The relay server for [window.ml](https://github.com/parawanderer/window-ml)'s runtime hub. It lets you watch and
drive agents running in your browser from somewhere else: a phone, another machine, and later another agent.

**Status: early.** The design is agreed ([`RUNTIME_HUB.md`][hub-spec]); this repository has its framing layer and its
CI, and the relay itself is next. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## What this is, next to window-ml

window.ml is a Chrome extension that exposes `window.ml`, a scripting API that bridges web pages to local LLMs, and
runs agents in the browser with approval-gated tools. Everything that matters happens there: the agent loop, the
tools, the approvals, the keys. This repository is **not** that, and deliberately owns as little as possible.

```text
  phone / chat page / agent client                        Chrome + window.ml extension
  (a client: shows sessions, sends commands)              (a runtime: runs agents, decides approvals)
                  │                                                     │
                  │  wss, dials out                    wss, dials out   │
                  └──────────────────►  window-ml-hub  ◄────────────────┘
                                      (this repository)
                                reads envelopes, relays ciphertext,
                              keeps bounded rings for reconnects

                  patched Ollama box ◄── box connector ──► hub   (telemetry, relayed the same way)
```

| | window-ml (the extension) | window-ml-hub (this) |
| --- | --- | --- |
| Runs agents, tools, the Python sandbox | yes | never |
| Holds end-to-end keys | yes, in the service worker | never |
| Decides an approval | yes, through its one `resolveApproval` | cannot, and cannot forge one |
| Reads session events or commands | yes | no: it sees ciphertext and routing metadata |
| Defines the session contract | yes ([`SESSION_CONTRACT.md`][contract-spec], `src/session-host.ts`) | relays it |
| Defines the envelope and routing | | yes |
| Language, CI | TypeScript, Node, Playwright | Rust, cargo |

The one question the design is judged by: **what can someone who controls the hub, or sees its traffic, make a
runtime do? Nothing.** Runtimes connect out and never listen, every principal is a key, traffic is end-to-end
encrypted, every command is signed and checked against the runtime's own allowlist, and approving is its own scope.
The hub can drop or delay messages and see who is online and how much they send. It cannot read or originate a
command. The full reasoning is in [`RUNTIME_HUB.md` §Security][hub-spec].

One hub serves several unrelated accounts at once and routes only within an account (§Tenancy in the spec).

## Where the specs live

The design documents stay in window-ml, beside the code that implements most of it:

- [`docs/spec/RUNTIME_HUB.md`][hub-spec]: the hub, security first.
- [`docs/spec/SESSION_CONTRACT.md`][contract-spec]: what a runtime offers a client (`SessionHost`).
- [`docs/spec/CHAT_PAGE.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/CHAT_PAGE.md): the client.

Which repository owns which wire schema, and how the others pin it: [`docs/SCHEMAS.md`](docs/SCHEMAS.md).

## Layout

| Path | What |
| --- | --- |
| `crates/frame` | varint-delimited framing, byte-compatible with window-ml's `src/protostream.ts` |
| `crates/proto` | the wire types generated from `proto/wmlhub/v1/hub.proto` (no `protoc` needed) |
| `crates/hub` | the `wmlhub` binary: the websocket server around the relay |
| `crates/relay` | the routing core with no IO: accounts, presence, streams and rings, backpressure, limits |
| `proto/` | the hub's wire schema; rules in [`docs/PROTOCOL.md`](docs/PROTOCOL.md) |
| `tools/mv3-ws-probe` | the probe that showed a websocket keeps an MV3 service worker alive |
| `tools/webcrypto-probe` | the probe listing which WebCrypto primitives an MV3 service worker has |
| `docs/` | roadmap, protocol, schema ownership, design proposals, findings |

## Running it

```bash
cargo run -p wmlhub -- --dev                          # ws://127.0.0.1:8787
cargo run -p wmlhub -- --dev --listen 127.0.0.1:9000
```

There is no authentication yet, so the server starts only with `--dev` and only on a loopback address: it trusts the
principal each `Hello` claims and takes the account credential bytes as the account. Anything else is refused at
startup. See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) §Development mode.

## Building

[`CONTRIBUTING.md`](CONTRIBUTING.md) starts from a machine with no Rust on it.

## License

MIT

[hub-spec]: https://github.com/parawanderer/window-ml/blob/main/docs/spec/RUNTIME_HUB.md
[contract-spec]: https://github.com/parawanderer/window-ml/blob/main/docs/spec/SESSION_CONTRACT.md
