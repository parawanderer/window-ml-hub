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
  not be able to starve another.
- **Nothing is addressable across accounts.** Every lookup that finds a principal, a runtime or a ring is keyed by
  account first. A global map keyed by runtime id alone is a bug even though ids are unique.
- **No database.** Rings are a cache; the authority is on the runtimes and boxes. A lost node is a reconnect. The one
  thing on disk is operator state (registered account ids, outstanding invites) in a state directory, one file each.
- **A claim on disk is an exclusive create** (`create_new`), never a remove or a rename: claiming an invite by
  removing its file let one invite register up to three accounts in a 16-thread race on macOS.
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

## Schemas

Each wire schema lives beside its encoder and is pinned by commit and git blob everywhere else:
[`docs/SCHEMAS.md`](docs/SCHEMAS.md). Never edit a vendored `.proto`: replace it wholesale and update its pin.

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
- **tungstenite's default read buffer is 128 KiB per connection.** Leaving it cost ~110 KB per idle connection; the
  hub sets 8 KiB (`READ_BUFFER_BYTES`). Any new websocket endpoint must set it too.
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
