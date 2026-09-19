# Performance: how it is measured, and what the numbers are

Every performance claim about the hub is a number from `wmlhub-loadgen`, with its spread. Changes that touch the hot
path put before/after tables in their PR, and add a row here.

## The tool

```bash
cargo build --release -p wmlhub -p wmlhub-loadgen
./target/release/wmlhub-loadgen fanout --accounts 10 --subscribers 5 --channels 4 --rate 2000 --seconds 8
./target/release/wmlhub-loadgen idle --connections 10000
./target/release/wmlhub-loadgen --hub-bin target-before/release/wmlhub ...   # A/B against another build
./target/release/wmlhub-loadgen --keys fanout --seconds 10 --hello-flood 64 --flood-kind verify
```

- **It starts the hub as a child process** on loopback, so the hub's CPU time and resident memory (sampled with `ps`)
  are its own. By default in development mode, which skips signature verification: the handshake is not what
  `fanout` measures. **`--keys`** runs it as deployed instead, every connection presenting a real certificate chain,
  with open registration so each benchmark account registers itself.
- **`--hello-flood N`** (needs `--keys`): N connections that each open, send a hello that FAILS, and reconnect, for
  the whole measured window, on a runtime of their own so they cannot delay the measuring tasks. `--flood-kind verify`
  sends a chain that verifies all the way to the hello signature and fails there, three Ed25519 verifications, the
  most a failure can cost; `cheap` fails before any signature, which isolates what the connection itself costs. Both
  close with a reset: a graceful close leaves each connection in TIME_WAIT for half a minute, and at tens of thousands
  a second one machine runs out of ephemeral ports within a second, after which the flood measures the port table and
  the leftovers corrupt the next run. Check `netstat -an -p tcp | grep -c TIME_WAIT` is low before each run.
- **`fanout`**: per account, one runtime publishes session events at a fixed rate across several channels, and
  several clients subscribe to all of them. `--rate` is per runtime.
- **Latency is reported three ways**, because each hides something the others show:
  - `latency`: scheduled send time to decoded by the subscriber. Measuring from the schedule, not from when the
    publisher got to it, is what keeps a stalled publisher from hiding the delay (coordinated omission).
  - `send lag`: scheduled to handed to the socket. The load generator's own error; on macOS tokio's timer alone is
    about 1 ms, which dominates `latency` at low rates.
  - `transit`: handed to the socket to decoded by the subscriber. Hub plus loopback plus the subscriber's wake-up.
- **`idle`**: opens connections (10 per account, under the per-account limit) that do nothing, and reports resident
  memory per connection at 100, 1k and 10k.
- **Run each variant at least three times.** On a laptop the load generator competes with the hub for CPU, and tail
  percentiles move by 2x between identical runs. A difference inside the spread is not a result.
- **Profile with `sample <pid> 5`** (macOS, no root needed for your own process) while a `fanout` runs: the
  "Sort by top of stack" section at the end of its output is the summary.

## Results

Machine for every row: Apple M4 (10 cores), 16 GiB, macOS, loopback; hub and load generator on the same machine.

### Baseline, 2026-09-17 (main at `9b7fa7d`)

`fanout --accounts 10 --subscribers 5 --channels 4 --payload 512`:

| rate per runtime | deliveries/s | transit p50 | transit p99 | transit p99.9 | hub CPU per 1k deliveries |
| --- | --- | --- | --- | --- | --- |
| 10 | 508 | 649 us | 1.0 ms | 1.1 ms | 43 us (idle overhead dominates) |
| 1000 | 50k | 399 us | 1.2 ms | 2.5 ms | 21 us |
| 2000 | 100k | 426 us | 1.4 ms | 3.7 ms | 13.5 us |

All deliveries arrived in every run. `idle`: **~110 KB resident per idle connection** (1.03 GiB at 10k).

Profile at 100k deliveries/s (samples, excluding parked threads): mutex wait and drop 4,576 (the single `Mutex<Hub>`
and the handles map), `kevent` 2,473, `sendto` 826 (a syscall per websocket message); the relay's own code, malloc,
hashing and encoding in the tens each. **Lock contention and per-message syscalls are the cost, not the routing.**

### TCP_NODELAY and an 8 KiB read buffer

- `set_nodelay` on accepted sockets: transit p50 at 10 msg/s 649 -> 610 us, within noise. Kept because a small
  latency-sensitive frame should never wait on Nagle, but it was not the cause of the low-rate latency (thread
  wake-up on idle cores is the likely cause; not proven).
- tungstenite allocates a 128 KiB read buffer per connection by default. Read buffer 8 KiB, `idle`, 10k connections:

| read buffer | resident per idle connection | at 10k |
| --- | --- | --- |
| 128 KiB (default) | ~110 KB | 1.03 GiB |
| 32 KiB | ~41 KB | 390 MiB |
| **8 KiB (chosen)** | **~16 KB** | **155 MiB** |

`fanout --rate 2000`, three rounds each:

| read buffer | transit p50 | p99 | p99.9 | CPU per 1k |
| --- | --- | --- | --- | --- |
| 128 KiB | 445-468 us | 1.28-1.46 ms | 3.7, 4.6, 6.0 ms | 13.4-14.6 us |
| 32 KiB | 470-542 us | 1.43-1.66 ms | 8.2, 5.7, 3.9 ms | 13.8-14.3 us |
| 8 KiB | 460-469 us | 1.36-1.52 ms | 4.9, 8.9, 9.1 ms | 13.0-14.4 us |

p50, p99 and CPU overlap. p99.9 with 8 KiB was higher than 128 KiB in all three rounds, but 32 KiB spans both ranges,
so the p99.9 spread on this machine is wider than any effect of buffer size that three rounds can show. 8 KiB is kept
for 7x less memory per connection. Revisit on a dedicated machine, where tail latency can be measured properly.

### Sharding by account

The server runs N independent relays (default four per core), each under its own lock, and routes each connection to
one by a keyed hash of its account; the account limit is enforced across shards with a compare-and-swap reservation.
Before is `main` at `582e348`; three rounds each, 100k deliveries/s offered, every delivery arrived in every run.

| scenario | build | transit p50 | transit p99 | hub CPU per 1k deliveries |
| --- | --- | --- | --- | --- |
| 10 accounts x 5 subscribers x 4 channels | before | 320-461 us | 1.31-7.69 ms | 12.0-14.8 us |
| | after | 232-338 us | 1.34-4.72 ms | **5.8-9.2 us** |
| 50 accounts x 2 subscribers x 2 channels | before | 521-566 us | 1.41-4.83 ms | 19.4-23.9 us |
| | after | 344-460 us | 0.83-2.29 ms | **9.8-13.8 us** |
| 1 account x 50 subscribers x 4 channels | before | 250-390 us | 1.10-4.20 ms | 6.6-10.5 us |
| | after | 260-424 us | 1.29-1.80 ms | 6.1-9.8 us |

- With several accounts, CPU per delivery roughly halves and median transit drops; the ranges do not overlap.
- With one account the ranges overlap: sharding cannot help a single tenant, and it costs nothing measurable.
- p99 and p99.9 stay inside the machine's noise (p99.9 ranged 2.7-46 ms across these runs).

`sample` over 5 s at 50 accounts, before -> after: `__psynch_mutexwait` 12,482 -> 596, `__psynch_mutexdrop` 1,456 -> 44.
What is left on top is `kevent` (2,506) and `sendto` (1,455): the IO reactor and a syscall per websocket message.

### Encode once, share bytes

A published envelope is stamped and encoded once, in the ring; the ring, every subscriber's queue and every backfill
hold the same `Bytes`. Payloads arrive as slices of the websocket message (zero-copy decode), stream keys are shared
(`Arc`), fan-out no longer collects subscribers into a `Vec`, and the writer feeds every ready batch and flushes once.
Before is `main` at `25317e1` (sharded). Three rounds each unless stated; every delivery arrived.

| scenario | build | transit p50 | transit p99 | hub CPU per 1k deliveries | hub RSS |
| --- | --- | --- | --- | --- | --- |
| 512 B, 10 accounts x 5 subscribers, 100k/s | before | 228-287 us | 0.76-3.45 ms | 6.2-8.2 us | 26-28 MB |
| | after | 202-280 us | 0.41-1.04 ms | 4.4-6.6 us | 22-27 MB |
| 16 KiB, 10 accounts x 5 subscribers, 10k/s | before | 249-401 us | 0.50-1.68 ms | 20.6, 33.9, 34.2 us | 273-276 MB |
| | after | 248-329 us | 0.60-1.21 ms | 18.4, 22.0, 23.2 us | **354-356 MB** (see below) |
| 512 B, 1 account x 50 subscribers, 100k/s | before | 235-379 us | 0.41-1.23 ms | 6.3-10.4 us | ~9 MB |
| | after | 220-268 us | 0.48-2.47 ms | 6.2-6.8 us | ~9 MB |
| 16,000 B, 10 accounts (one round) | before | | | 37.2 us | 269.7 MB |
| | after | | | 26.8 us | 270.6 MB |
| 18,000 B, 10 accounts (one round) | before | | | 43.6 us | 359.5 MB |
| | after | | | 29.6 us | 354.0 MB |

- **CPU falls with payload size**: about 30% at 16-18 KB, inside the noise at 512 B (the ranges overlap).
- **The 16 KiB memory "regression" is the allocator, not the design.** With a payload of exactly 16,384 bytes the
  old ring's payload `Vec` sat on a malloc size class; the encoded frame (payload plus about 64 bytes of envelope)
  is 16,448 bytes, which macOS 26.6 rounds to 20,480 (`malloc_size`), 4,032 bytes wasted per retained entry. That
  matches the ~4.6 KB per entry measured. At 16,000 and 18,000 bytes, which align with nothing, memory is equal or
  lower. Real payloads are ciphertext of arbitrary length.
- **Trap for anyone benchmarking memory here**: never use a power-of-two payload size. It lands on an allocator size
  class for one layout and just past it for another, and the comparison measures the allocator.

### One wake per drain, and where the rest of the time goes

Profiled at 500k deliveries/s (`fanout --accounts 50 --subscribers 5 --channels 4 --rate 2000 --payload 512`, 40
shards) before choosing what to do next. The hub used about two cores, 4.7 us per delivery. Top of stack, one 5 s
`sample`:

| where | samples |
| --- | --- |
| `__sendto` | 5,737 |
| `__psynch_mutexwait` (2,186 of them in `write_loop` locking its shard) | 2,690 |
| `__recvfrom` | 1,148 |
| `kevent` | 1,074 |
| SipHash over ids (`DefaultHasher::write`, `hash_one`) | 290 |
| `memcmp` | 68 |

- **Ids are about 2% of on-CPU samples.** A fixed-size key would still be hashed byte by byte, so replacing `Vec<u8>`
  keys cannot buy more than that at this load. Deferred until a profile says otherwise.
- **The mutex waits are within an account.** With 40 shards and 50 accounts, a shard holds about one account: its
  publisher's reader and its five subscribers' writers share the lock, and every publish woke all five.

The relay now sends `Action::Wake` once per drain rather than once per queued frame (a connection is armed on its first
push and disarmed when a take leaves its queue empty), and `take_outbound` reports `more`, so a writer no longer locks
once extra to find its queue empty. The model checker holds the contract: a connection with anything queued has a wake
outstanding. Before is `main` at `434c3c1`; three rounds each at the load above.

| build | hub CPU per 1k deliveries | latency p50 | latency p99 | `mutexwait` samples | envelopes per write |
| --- | --- | --- | --- | --- | --- |
| before | 4.7, 4.8, 4.9 us | 1,251-1,268 us | 5.1-9.4 ms | 3,190, 2,822, 2,874 | 2.36-2.41 |
| after | 4.6, 4.8, 4.7 us | 1,246-1,258 us | 4.0-8.1 ms | 1,853, 2,393, 1,524 | 2.28-2.40 |

- **Lock waits fall by a third to a half; CPU and latency do not move.** A waiting thread is asleep, so fewer waits
  show up as fewer context switches, not as less CPU at this load.
- **`sendto` is the cost, and it is set by the subscribers' own rate.** Each subscriber receives 2,000 envelopes/s and
  about 2.4 arrive during one write. Yielding once before draining, so more could accumulate, gave 2.42-2.48 per write,
  no CPU change and a worse p99 in two rounds of three; not kept. Fewer syscalls would need a deliberate delay before
  writing (Nagle's trade), which the latency budget does not want.
- `wmlhub-loadgen fanout` now prints `batching`: envelopes per websocket message the subscribers received.

### Eviction at the limits

`ensure_stream` scans an account's streams for the least recently published idle one when a new stream would pass
`max_streams_per_account`; `enforce_ring_budget` scans them for the largest ring once per entry it evicts. Both are
linear in a named constant (1,024 streams), and a publish evicts at most one ring's entries (512) before the ring it
landed in is the largest no more. Measured directly on the relay, no sockets, three rounds (`cargo test --release -p
wmlhub-relay eviction_costs -- --ignored --nocapture`), per publish:

| scenario | worst | mean |
| --- | --- | --- |
| small publish into an account at its 64 MiB ring budget (the baseline) | 14-36 us | 2.4-2.9 us |
| new stream at the stream limit, each victim holding a full ring | 1.6-2.0 ms | 25-30 us |
| new stream at the stream limit, steady state | 0.22-1.3 ms | 8.1-9.7 us |
| adversarial: refill one ring with 512 small entries, then a 1 MiB payload into it, repeated | 0.87-1.1 ms | 2.3-2.8 us |

- **Amortized, eviction costs nothing extra.** The expensive publish (about 1 ms, evicting one ring's worth under the
  shard lock) has to be paid for with 512 cheap ones first, and the loop averages what a plain publish does.
- **The one lasting cost is 3-4x a plain publish**, for an account that creates a new stream on every publish while
  at its stream limit. An ordered index by last publish would remove the scan and add bookkeeping to every publish of
  every account. Not done.
- **What is actually unbounded is rate.** Nothing limits how fast an account publishes, so one account at full speed
  takes its shard's lock from the others on it whether or not it evicts anything. That is fairness, recorded in
  `docs/ROADMAP.md`, not an eviction question.

### A work budget per account

Every other bound is on memory; nothing bounded time, so an account publishing as fast as its sockets allowed held its
shard's lock as often as it liked. Each account now has a byte budget (8 MiB/s, 32 MiB burst by default; rate.rs):
messages at their size plus 64 bytes a frame, and 64 bytes per frame queued on its behalf. Past it the hub stops
reading the account's connection until the debt is repaid; nothing is dropped. Measured with `wmlhub-loadgen fanout
--flooders 8 --hub-env WMLHUB_SHARDS=1`: 9 accounts x 5 subscribers at 200 msg/s each, sharing one shard with 8
accounts that each publish as fast as the hub reads them (batches of 256 x 512 B). Figures are the 9 accounts'.

| build | rounds | transit p50 | transit p90 | transit p99 | hub CPU | flood, per account |
| --- | --- | --- | --- | --- | --- | --- |
| no flooders (floor) | 3 | 264-296 us | 480-520 us | 0.70-0.91 ms | 15-18% | |
| no budget (`main`) | 3 | 775-831 us | 1.39-1.51 ms | 1.9-2.1 ms | 241-261% | 64-68k envelopes/s |
| budget, charged per message | 6 | 274-320 us | 1.25-2.46 ms | **2.8-4.7 ms** | 34-42% | 13.1-13.7k envelopes/s |
| budget, charged per 16 frames (shipped) | 6 | 330-638 us | 0.81-1.33 ms | 1.2-2.0 ms | 41-63% | 13.2-13.7k envelopes/s |
| per 16 frames, sleeping only on 4 ms of debt | 3 | 372-603 us | 0.89-1.40 ms | 2.2-2.3 ms | 36-59% | 13.2-13.6k envelopes/s |

- **The budget holds each flooder to its rate** (13.3k envelopes of about 630 B of work each is 8.4 MiB/s) and takes
  the hub from two and a half cores to under one.
- **How it is charged decides the tail.** Charging a whole 256-frame message up front made a throttled account sleep
  about 20 ms and then do 20 ms of work at once; eight flooders waking on the same timer ticks put their bursts in the
  neighbours' p99, worse than no budget at all. Charging every 16 frames spreads the same work out: p99 is back to
  what it was without a budget. Median and CPU move between rounds more than between the two variants.
- Sleeping only once 4 ms of debt had built up, to wake flooders less often, bought nothing measurable.

No cost when under budget: `fanout --accounts 50 --subscribers 5 --channels 4 --rate 2000` (500k deliveries/s, about
1.9 MiB/s of work per account), before -> after, three rounds each: hub CPU per 1k deliveries 4.6-4.8 -> 4.6-4.9 us,
transit p50 624-634 -> 623-634 us, p99 1.4-2.4 -> 1.5-1.9 ms.

### The pre-authentication caps do not cost the idle case

`max_pending_sockets` (256) bounds sockets that have not authenticated, and every connection passes through it, so
the 10k-idle scenario is the one to check it against. Unchanged after it landed: 100 connections at ~23 KB each,
1,000 at ~15.8 KB, 10,000 at ~15.1 KB and 150 MB resident, the same figures as before.

A handshake holds its place for as long as it takes to verify a chain (about 100 us in keys mode), so 256 at once is
a few thousand logins a second: a hub restart with ten thousand clients reconnecting is bounded by that rather than
blocked by it.

### Strangers: a flood of hellos that fail, 2026-09-19

Every bound here is per account, and a connection that authenticates pays for its own handshake. One that never
authenticates had no account to charge, so its work was charged to nobody, and it runs on the same threads as every
connected account's traffic. `max_pending_sockets` bounds how many strangers there are at once, which is memory; it
said nothing about how fast they come and go, which is time. `strangers.rs` makes them one tenant with a CPU budget:
each connection that gives its place back without authenticating is charged what it measured, and past the budget
the accept loop takes new connections more slowly.

`--keys fanout --seconds 10` (10 accounts x 5 subscribers x 4 channels at 200 msg/s per runtime) with and without
`--hello-flood 64`, three runs each. The latency is the CONNECTED accounts', which is the whole question:

| flood | build | failed hellos/s | connected p99 | transit p99 | hub CPU |
| --- | --- | --- | --- | --- | --- |
| none | before | 0 | 2.8, 7.3, 3.3 ms | 0.9-3.9 ms | 10-11% |
| | after | 0 | 3.9, 7.7, 2.2 ms | 0.4-3.6 ms | 10-11% |
| `cheap`: fails before any signature | before | 27-37k | 62-66 ms | 61-65 ms | 135-181% |
| | after | 1,441 | **3.3-3.4 ms** | 1.5 ms | 17-18% |
| `verify`: fails at the hello signature | before | 20-24k | 34, 80, 40 ms | 33-79 ms | 385-410% |
| | after | 1,440-1,442 | **4.0, 7.7, 3.5 ms** | 1.4-4.1 ms | 32-33% |

What it showed:

- **The damage follows churn, not CPU.** The `cheap` flood does as much harm as `verify` on less than half the CPU,
  because it comes and goes faster. So the thing to bound is how fast strangers arrive, which a budget charged per
  failure does.
- **Only failures are charged**, so a hub nobody is attacking is unchanged, and a restart that brings every device
  back at once is never paced: each of those connections authenticates and is its account's cost. A flood does pace
  everybody not yet connected, which nothing that cannot tell an attacker from a stranger can avoid.
- **Both kinds are held to the same ~1,441 a second, and that is the budget.** Any connection that sends a hello and
  is refused is charged the verified cost (`REFUSED_HELLO_US`, 190 us), whichever check refused it, so both floods
  cost the same: (250 ms/s x 10 s + 250 ms banked) / 190 us = 1,447 a second. Charging a malformed hello exactly would
  need the verifier to report how far it got, and over-charging one only makes strangers slower.
- **A bigger budget lets harm back in.** At `--unauthenticated-cpu-percent 100` the `verify` flood ran at 5,760 a
  second against a predicted 5,789, and connected p99 was 11 and 24 ms. The setting trades how fast newcomers are
  accepted against connected accounts' latency, and a quarter of a core is where the table above puts it.
- **The charge is an estimate, and it varies.** A refused hello's realised cost was about 183 us at the default,
  which is what the 190 us charge is set against, about 242 us at a whole core (the hub used 1.27 cores against a
  budget of one), and about 176 us unpaced at 20k a second. It is not simply rising with the rate, so no cause is
  claimed here. At the default it lands on target: 33% total against 11% without the flood.
- **Two explanations were measured and dropped.** That both kinds ran at 1,441 a second looked like the timer: a
  tokio sleep lasts at least a millisecond, so sleeping off every microsecond of debt would pace by the tick. A carry
  for debt under a millisecond made no difference, and neither did removing it at a full core (5,760 a second with,
  5,763 without): under a concurrent flood the debt arrives several failures deep, so every wait is already longer
  than a tick. The carry was taken out rather than kept on an argument the numbers did not support.
- **The debt is read after `accept`, not before.** The loop spends its idle time parked in `accept`, so a check before
  it is read before the failures that land while it waits, and the connection that wakes it goes through unpaced.
  `a_stranger_who_fails_slows_the_next_and_one_who_authenticates_does_not` fails when the check is moved.

The "after" rows are the build this landed as. A later confirmation run on it was discarded rather than averaged in:
the machine was saturated (load average 10 on 10 cores, macOS storage indexing at 220%), and the runs with NO flood
showed the load generator's own send lag at 7-45 ms p99 against 2-4 ms in every other batch, which is noise larger
than anything being measured.

The load generator needed three fixes before any of this meant anything, each of which produced plausible numbers
first:

- The flood tasks shared the measuring tasks' runtime and signed a hello per connection, so the flood's cost showed
  up as HUB latency. They run on a runtime of their own now, and the hello is built once: it signs the wrong nonce,
  which is wrong whatever the hub sends.
- Each flood connection closed gracefully and left a socket in TIME_WAIT. At 26k a second one machine runs out of
  ephemeral ports within a second, and the leftovers corrupted the NEXT run: one delivered 20% of its messages with
  the flood refused 5 times a second. They close with a reset now, as a flood would.
- The runs without a flood recorded nothing: an empty argument array under `set -u` is an error in macOS's bash 3.2.

## Next (from the profile)

1. ~~Shard the relay by account, so tenants do not share a lock.~~ Done, above.
2. ~~Encode a published envelope once and share its bytes across subscribers and backfill.~~ Done, above.
3. ~~Bounded-cost eviction.~~ Measured above: bounded and amortized; no change.
4. ~~Fewer syscalls per message on the write path.~~ Measured above: set by delivery rate, not by the hub.
5. Fixed-size ids: about 2% of samples at 500k deliveries/s. Deferred.
6. ~~Per-account publish rate.~~ Done, above.

## What a connection costs

Measured on an M4 in release, 2,000 iterations each (`cargo test --release -p wmlhub-relay connect_costs --
--ignored --nocapture`, and `chain_and_hello_costs` in `wmlhub-keys`):

| | per connect and its disconnect |
| --- | --- |
| certificate chain (one certificate) + hello signature | 48.6 us |
| relay: welcome burst, presence in and out, no siblings | 0.7 us |
| the same with 8 devices on the account | 3.2 us |
| the same at the connection cap (63) | 19.3 us |

So a connection is about 52 us of hub CPU for an ordinary account, against 4.7 us for a delivery, which is where
`CONNECT_COST_BYTES` (twelve frames' worth) comes from. Verification dominates by an order of magnitude, which is
why the charge is flat rather than scaled by how many devices hear the presence.
