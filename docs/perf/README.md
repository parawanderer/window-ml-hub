# Performance: how it is measured, and what the numbers are

Every performance claim about the hub is a number from `wmlhub-loadgen`, with its spread. Changes that touch the hot
path put before/after tables in their PR, and add a row here.

## The tool

```bash
cargo build --release -p wmlhub -p wmlhub-loadgen
./target/release/wmlhub-loadgen fanout --accounts 10 --subscribers 5 --channels 4 --rate 2000 --seconds 8
./target/release/wmlhub-loadgen idle --connections 10000
./target/release/wmlhub-loadgen --hub-bin target-before/release/wmlhub ...   # A/B against another build
```

- **It starts the hub as a child process** in development mode on loopback, so the hub's CPU time and resident memory
  (sampled with `ps`) are its own. Development mode skips signature verification: the handshake is not what `fanout`
  measures.
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

## Next (from the profile)

1. ~~Shard the relay by account, so tenants do not share a lock.~~ Done, above.
2. Encode a published envelope once and share its bytes across subscribers and backfill.
3. Fixed-size ids instead of `Vec<u8>` keys; bounded-cost eviction for the ring byte budget.
4. Fewer syscalls per message on the write path.
