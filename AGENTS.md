# AGENTS.md: window-ml-hub

The Rust relay server for window.ml's runtime hub. What it is and how it relates to the extension: [README.md](README.md).

## Start from window-ml

This repository is one part of [window-ml](https://github.com/parawanderer/window-ml), and **window-ml's
[AGENTS.md](https://github.com/parawanderer/window-ml/blob/main/AGENTS.md) holds the rules that apply to both**:
working on a branch and through a PR with CI, running several sessions each in its own clone, keeping working rules
apart from implementation notes, and the security stance the hub inherits. If you have a window-ml checkout beside this one (`../window-ml`), read it there.

**This file holds only what is specific to this repository**: the hub's invariants, Rust conventions, and the traps
of this codebase. A note that would be true of window-ml as well belongs in window-ml's AGENTS.md, not here. The
design itself stays in window-ml's `docs/spec/`; do not copy it here, link to it.

Read before changing the relay: [`RUNTIME_HUB.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/RUNTIME_HUB.md)
(security first) and [`SESSION_CONTRACT.md`](https://github.com/parawanderer/window-ml/blob/main/docs/spec/SESSION_CONTRACT.md).

## Invariants of the hub (do not regress these)

- **The hub parses only the envelope.** It never decodes, decompresses or inspects a payload, and has no code path
  that could: no payload schema is a dependency of the relay crates. What it does not parse it cannot be tricked by,
  and cannot leak.
- **Never log payload bytes**, and log envelope fields only as routing needs them. Sizes and timings are the most the
  hub may record about traffic, and the spec already counts those as what a compromised hub learns.
- **Every buffer, queue and ring is bounded by a named constant**, and every limit is per account. One account must
  not be able to starve another, of memory or of time: work an account causes is charged to its budget (rate.rs),
  including frames the relay queues on its behalf. A new code path that makes the relay queue frames goes through
  `Conn::arm`, which counts them.
- **A bound that keys on the source address cannot be a default here.** The hub is meant to run behind Tailscale or
  Caddy, where every client arrives from the proxy's address, so one bucket would be shared by a household. The
  connection rate exists and is off; what bounds the pre-authentication surface without an address is
  `max_pending_sockets`.
- **Anything the hub CHOOSES fits in a double** (`MAX_EXACT_IN_A_DOUBLE`). The browser's connector holds a `seq` or
  an `epoch` in a double, and a full 64-bit epoch cannot round-trip: the TypeScript decoder threw on the first
  real connection. The wire types stay 64-bit.
- **The relay takes one clock per purpose.** `connect` gets wall-clock time (it goes into `Welcome`); `charge` gets
  the server's monotonic clock, and the work budget reads nothing else. Mixing them left a bucket that never refilled.
- **Nothing is addressable across accounts.** Every lookup that finds a principal, a runtime or a ring is keyed by
  account first. A global map keyed by runtime id alone is a bug even though ids are unique.
- **No database.** Rings are a cache; the authority is on the runtimes and boxes. A lost node is a reconnect. The one
  thing on disk is operator state (registered account ids, outstanding invites) in a state directory, one file each.
- **A claim on disk is an exclusive create** (`create_new`), never a remove or a rename: claiming an invite by
  removing its file let one invite register up to three accounts in a 16-thread race on macOS.
- **Anything read before authentication is bounded before it is iterated or compared.** A certificate's scopes were
  compared pairwise before the forged delegate's signature was checked, with no bound on either list: a 500 KB hello
  from nobody cost 2.7 s of CPU on a tokio worker. `MAX_CERT_BYTES`, `MAX_SCOPES` and friends are checked first.
- **Every hello verification failure looks the same on the wire.** Log the reason; do not send it.
- **Runtimes and connectors dial out.** The hub never opens a connection to a runtime or a box.
- **No `unsafe`** (forbidden at the workspace level).

## How this repository is built

This is infrastructure plumbing, and it is judged like it: what one message costs, what a hostile peer can do, what
happens when a subscriber stalls, and whether the answers are proven. It is not judged by how extensible its type
hierarchy looks.

- **Extensibility lives in the wire formats** (versioned schemas, additive fields, capability flags), not in
  indirection. Concrete types, plain functions and enums. No trait with one implementation, no factories, managers,
  strategy registries or dependency injection. An abstraction arrives with its second real user.
- **Every resource has a named bound, per tenant.** A shared lock or queue on a path every account uses is a tenancy
  bug as well as a performance one.
- **Know the hot path's cost in numbers**: CPU per message, bytes per idle connection, copies and syscalls per
  delivery.
- **Measure before changing, with spread**: `wmlhub-loadgen`, three or more runs per variant, before/after tables in the
  PR and a row in [`docs/perf/README.md`](docs/perf/README.md). A number that got worse goes in the PR with the trade.
  Profile before deciding where time goes.
- **Dependencies are liabilities**: few, well known, justified in the PR.

**RULE: adversarial tests are part of the change, without being asked.** Anything that parses bytes from a peer gets
a fuzz target in `fuzz/` (never panics; round trips where a round trip exists). Anything with state gets its
operations into a model checker that asserts its invariants after every step (the relay's is `model.rs`: add new
operations to `Op` and new invariants to `check`). Every security or safety check is mutation-checked: break it on
purpose and see a test fail for that reason; a test that still passes is rewritten. A checker that has never been seen
to fail is not evidence. How: [`docs/FUZZING.md`](docs/FUZZING.md).

## Schemas

Each wire schema lives beside its encoder and is pinned by commit and git blob everywhere else:
[`docs/SCHEMAS.md`](docs/SCHEMAS.md). Never edit a vendored `.proto`: replace it wholesale and update its pin.

**A change under `proto/wmlhub/` gets a line in [`proto/wmlhub/CHANGES.md`](proto/wmlhub/CHANGES.md)**, including an
additive field nobody has to act on. CI refuses the pull request otherwise (`tools/check-schema-changes.sh`). The
reason it is a gate and not a habit is that the failure is invisible from the side it happens to: a reader's code is
correct against the schema it holds and simply never asks for what it does not know about, so a missing field is
found by the feature it breaks, weeks later. Say what changed and whether a reader has to do anything.

## Rust conventions

- The toolchain is pinned in `rust-toolchain.toml`; bump it only in its own commit.
- CI treats warnings as errors: run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` and `cargo doc --workspace --no-deps` before pushing. `rust-version` in `Cargo.toml` is
  checked by its own CI job, so do not use a feature newer than it without raising it.
- Crates live in `crates/<name>`, named `wmlhub-<name>`, inheriting lints and package fields from the workspace.
- `///` doc comments on every public item, saying what it is FOR. Unit tests sit beside the code in `mod tests`.
- A format another implementation must agree with (the framing, later the envelope) gets shared byte vectors in its
  tests, checked against the other side once when written.

## Measuring

`wmlhub-loadgen` (`crates/loadgen`) starts a release hub as a child process and drives it: `fanout` for throughput,
latency percentiles and CPU per delivery, `idle` for memory per connection. How to read its three latency figures,
and every result so far: [`docs/perf/README.md`](docs/perf/README.md).

## Traps

- **`cargo: command not found` in an agent shell.** rustup puts `. "$HOME/.cargo/env"` in the login profile, which a
  non-interactive shell may not read. Prefix the command with `. "$HOME/.cargo/env" &&`.
- **CI builds fuzz targets with `-D warnings`; a local `cargo fuzz run` does not.** An unused import passes locally
  and fails the fuzz job. Build them the way CI does before pushing:
  `cd fuzz && RUSTFLAGS="-D warnings" cargo +nightly fuzz build`.
- **Two green PRs can break main between them.** CI runs each branch against ITS base, so a signature change in one
  and a new caller in the other compile everywhere except on main, where both are. It has happened once here (#37
  made `issue` fallible while #40 added a test that called it, and main did not build). Rebase onto main before
  MERGING, not only before opening, and merge one at a time.
- **tungstenite's default read buffer is 128 KiB per connection.** Leaving it cost ~110 KB per idle connection; the
  hub sets 8 KiB (`READ_BUFFER_BYTES`). Any new websocket endpoint must set it too.
- **Never compare memory with a power-of-two payload.** macOS rounds 16,448 bytes to 20,480; a 16,384-byte payload
  that fits a size class in one layout and misses it by 64 bytes in another makes the allocator the variable. Use
  sizes like 16,000 or 18,000.
- **Relay queues and rings hold ENCODED frames (`Bytes`).** A published envelope is encoded once in `Ring::publish`;
  add metadata the queue needs beside the bytes (as `Entry` does), never by decoding them.
- **On macOS, tokio's timer adds about 1 ms** to anything scheduled. A latency measured from a schedule includes it;
  `wmlhub-loadgen` reports it separately as `send lag`.
- **An attached debugger keeps an MV3 service worker alive.** Any experiment about worker lifetime must run Chromium
  with no CDP or Playwright attached, and include an idle control that shows eviction. See
  `docs/findings/mv3-websocket-lifetime.md`.

## Pull requests here

PRs in this repository are **documented checkpoints**, one coherent unit of work each, not review gates: open one
with a description that says what changed, what was decided and what is untested, and merge it yourself once CI is
green. Stacked PRs: merge the bottom one, retarget the next to `main`, merge.

## Findings and tools

A question answered by experiment gets a `docs/findings/<topic>.md` (result, method, what it means, the browser or
server version) and its script under `tools/`, so it can be re-run when the answer might have changed. Negative
results are written up the same way.
