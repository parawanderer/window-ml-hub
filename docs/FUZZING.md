# Fuzzing and model checking

Every decoder and every state machine in this repository is tested adversarially, not only by examples. The rule is
in [AGENTS.md](../AGENTS.md); this is how it is done.

## Two drivers, one operation language

- **The model checker** (`crates/relay/src/model.rs`) turns bytes into relay operations (connect, publish, burst,
  subscribe with or without a position, unsubscribe, command, drain with a byte budget, disconnect, misbehave) on
  deliberately tiny limits, and checks the whole relay after every operation: isolation, sender stamping, per-stream
  order, every bound, every counter against what it counts, and the bookkeeping in both directions. The list is at
  the top of the file.
- **`cargo test`** runs 400 seeded byte strings through it (`random_operation_sequences_keep_every_invariant`, under
  a second). Deterministic, on every build and in CI.
- **`cargo-fuzz`** runs the same checker from libFuzzer's coverage-guided inputs (`fuzz/fuzz_targets/relay.rs`),
  which reaches interleavings a seeded walk does not.

## The targets

| target | what it asserts |
| --- | --- |
| `relay` | the model checker's invariants, for any operation sequence |
| `frames` | decoding one websocket message never panics; what decodes re-encodes and decodes to the same frames |
| `frame_reader` | however the same bytes are split into reads, the frames, the error and the pending count match a single read |
| `chain` | certificate verification never panics on arbitrary bytes; a valid one- or two-certificate chain with any one bit flipped never verifies |
| `stream` | reading a published frame never panics on arbitrary bytes; an honest frame with any one bit flipped never opens |
| `seal` | opening a sealed command never panics, whatever arrives and whoever the hub claims sent it; an honest one with any one bit flipped, or delivered as from any other sender, never opens |

## Running

Needs nightly (`rustup toolchain install nightly`) and `cargo install cargo-fuzz`.

```bash
cd fuzz
cargo +nightly fuzz run relay -- -max_total_time=60
cargo +nightly fuzz run frames -- -max_total_time=60
cargo +nightly fuzz list
```

A crash writes `fuzz/artifacts/<target>/crash-*`; replay it with `cargo +nightly fuzz run <target> <file>`. For a
failing seeded model run, the test prints the command that lists its operations
(`RUN=<n> cargo test -p wmlhub-relay print_model_run -- --ignored --nocapture`).

CI runs every target for 30 seconds on each push, and uploads any crash as an artifact.

## What it has found

- **Resubscribing duplicated a stream.** A repeated `Subscribe` while envelopes were still queued delivered them,
  then delivered them again from the backfill. A repeated `Subscribe` now purges what is queued for that stream first.
- **Coalescing reordered a stream.** Replacing a superseded telemetry envelope in place put a newer `seq` ahead of an
  older envelope of the same stream (different coalesce key) queued after it. The superseded envelope is now removed
  and the new one appended.
- **The checker itself was too diffuse at first.** With 3 accounts, 4 principals and 3 channels, and no burst
  operation, neither 400 seeded runs nor 52,000 fuzz runs found the reordering bug when it was put back on purpose.
  With 2/3/2 and `Burst`, the seeded runs find it, and the fuzzer finds it from an empty corpus within two minutes.

## Checking the checker

A model checker that passes proves nothing until it has been seen to fail. Every invariant is mutation-checked: break
the code it guards and confirm a run fails for that reason. Current results (each caught by the seeded runs alone):

| mutation | caught as |
| --- | --- |
| no purge on a repeated `Subscribe` | ORDER |
| coalescing in place | ORDER |
| sender kept when the peer sets it | sender not stamped |
| direct-envelope lookup across accounts | panic on the account's connection map |
| stream eviction forgets its ring bytes | ring bytes drifted |
| no account ring byte budget | ring bytes over budget |
| no telemetry drop at the queue bound | queue over its bounds |

Removing the purge on `Unsubscribe` is not caught, correctly: a late delivery after unsubscribing wastes work but
breaks no invariant.
