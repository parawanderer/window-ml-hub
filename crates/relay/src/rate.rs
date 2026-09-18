//! One account's work budget: a token bucket in bytes, shared by every connection of the account
//! (docs/PROTOCOL.md §Limits).
//!
//! Work is charged, never refused. A websocket message costs its size plus [`FRAME_COST_BYTES`] per frame, and every
//! frame the relay queues on the account's behalf (fan-out, backfill, answers) costs [`FRAME_COST_BYTES`] more. When
//! the balance is negative the server stops reading that connection until the debt is repaid, so an account that
//! sends faster than its rate is slowed by TCP flow control and loses nothing.
//!
//! Time is the server's monotonic clock, passed to every charge and to nothing else: the bucket starts at its first
//! charge. (It first started at `connect`, which the server passes wall-clock time for `Welcome`; a bucket created at
//! 1.8 x 10^12 ms and charged at 5,000 never refilled, and every message waited longer than the last.)
//!
//! A new bucket starts EMPTY. A full one would let an account with nothing retained disconnect, be forgotten, and come
//! back with a fresh burst as often as it likes.
//!
//! Integer arithmetic, exact: the balance is kept in thousandths of a byte, so a millisecond at any rate credits a
//! whole number of units and nothing is lost to rounding. (Crediting whole bytes and carrying the time over, the first
//! version, minted work: at 300 bytes a second it paid a byte every 3 ms.)

/// What one frame costs beyond its bytes: a frame is a lock, a decode and a routing decision whatever its size, and a
/// queued frame is a queue entry and a share of a write. Without it a flood of empty frames would cost nothing.
pub const FRAME_COST_BYTES: usize = 64;

/// What admitting a connection costs the account, in the same work-bytes as everything else. A connect and the
/// disconnect that follows it cost about 52 us of hub CPU: 49 verifying the certificate chain and the hello
/// signature (`wmlhub-keys` `chain_and_hello_costs`), and 3 routing the welcome burst and the presence an account
/// of eight devices sends and is sent (`connect_costs`). A delivery costs 4.7 us at [`FRAME_COST_BYTES`]
/// (docs/perf), so a connection is worth twelve frames of work. An account may therefore spend its budget on
/// connecting or on traffic, and either way it spends the same CPU, which is the point of one budget per account.
///
/// It undercharges an account at the connection cap, where the presence fan-out reaches 19 us. Verification
/// dominates by an order of magnitude, so the flat number is worth more than a term nobody can check.
pub const CONNECT_COST_BYTES: usize = 12 * FRAME_COST_BYTES;

/// Debt above which a connection is refused rather than charged. A connect is the one piece of work that cannot be
/// slowed down instead: there is no connection to read more slowly yet, so charging alone would leave a client that
/// only connects and disconnects paying nothing. Above this the account is told to come back.
///
/// It is far above the debt ordinary traffic makes, because the failure it prevents (a flood of handshakes) and the
/// case it must not break (a phone connecting while the runtime publishes hard) are separated by three orders of
/// magnitude: a burst of publishing repays in milliseconds, a handshake flood holds the debt at its ceiling.
pub const CONNECT_REFUSED_ABOVE_MS: u64 = 1_000;

/// Units per byte in the balance.
const MILLI: i128 = 1000;

#[derive(Debug, Clone)]
pub(crate) struct Bucket {
    /// thousandths of a byte of work available; negative is debt
    balance: i128,
    /// the time refill has been credited up to, in the caller's monotonic milliseconds; none before the first refill
    credited_ms: Option<u64>,
}

impl Bucket {
    pub(crate) fn new() -> Self {
        Self { balance: 0, credited_ms: None }
    }

    /// Credit the time since the last refill at `rate` bytes a second, up to `burst` bytes. A clock that goes
    /// backwards credits nothing.
    pub(crate) fn refill(&mut self, now_ms: u64, rate: usize, burst: usize) {
        let Some(credited) = self.credited_ms else {
            // the first charge: nothing earned before it
            self.credited_ms = Some(now_ms);
            return;
        };
        if now_ms <= credited {
            return;
        }
        // one millisecond at `rate` bytes a second is exactly `rate` thousandths of a byte
        let earned = i128::from(now_ms - credited).saturating_mul(rate as i128);
        self.balance = self.balance.saturating_add(earned).min(burst as i128 * MILLI);
        self.credited_ms = Some(now_ms);
    }

    /// Spend `bytes`, going into debt if need be.
    pub(crate) fn spend(&mut self, bytes: usize) {
        self.balance = self.balance.saturating_sub(bytes as i128 * MILLI);
    }

    /// How long until the debt is repaid at `rate`, in milliseconds (rounded up); 0 when there is none.
    pub(crate) fn wait_ms(&self, rate: usize) -> u64 {
        if self.balance >= 0 || rate == 0 {
            return 0;
        }
        // both positive here, so the unsigned ceiling is the right one
        u64::try_from(self.balance.unsigned_abs().div_ceil(rate as u128)).unwrap_or(u64::MAX)
    }

    /// Whole bytes available (negative: debt), for tests and the model checker.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn tokens(&self) -> i64 {
        i64::try_from(self.balance.div_euclid(MILLI)).unwrap_or(if self.balance < 0 { i64::MIN } else { i64::MAX })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: usize = 8_000;

    /// A bucket whose first refill happened at `at`.
    fn started(at: u64) -> Bucket {
        let mut b = Bucket::new();
        b.refill(at, 1, 1);
        b
    }
    const BURST: usize = 32_000;

    #[test]
    fn a_new_bucket_is_empty_and_fills_at_the_rate_up_to_the_burst() {
        let mut b = started(1_000);
        b.refill(1_000, RATE, BURST);
        assert_eq!(b.tokens(), 0);
        b.refill(1_500, RATE, BURST);
        assert_eq!(b.tokens(), 4_000);
        b.refill(1_000_000, RATE, BURST);
        assert_eq!(b.tokens(), BURST as i64);
    }

    #[test]
    fn debt_is_repaid_in_the_time_it_reports() {
        let mut b = started(0);
        b.spend(12_345);
        let wait = b.wait_ms(RATE);
        assert_eq!(wait, 1_544, "12,345 bytes at 8,000/s is 1,543.1 ms, rounded up");
        b.refill(wait - 1, RATE, BURST);
        assert!(b.tokens() < 0, "one millisecond early is still in debt");
        let mut b2 = started(0);
        b2.spend(12_345);
        b2.refill(wait, RATE, BURST);
        assert!(b2.tokens() >= 0);
    }

    #[test]
    fn a_slow_rate_still_accrues_across_millisecond_steps() {
        // 300 bytes a second earns 0.3 bytes a millisecond; crediting whole milliseconds would earn nothing, ever
        let mut b = started(0);
        for ms in 1..=1_000 {
            b.refill(ms, 300, 10_000);
        }
        assert_eq!(b.tokens(), 300);
    }

    #[test]
    fn nothing_is_earned_before_the_first_refill_whatever_the_clock_reads() {
        let mut b = Bucket::new();
        b.refill(1_800_000_000_000, RATE, BURST);
        assert_eq!(b.tokens(), 0);
        b.spend(4_000);
        assert_eq!(b.wait_ms(RATE), 500);
        b.refill(1_800_000_000_500, RATE, BURST);
        assert_eq!(b.tokens(), 0, "half a second later the debt is repaid, no more");
    }

    #[test]
    fn a_clock_that_goes_backwards_credits_nothing() {
        let mut b = started(10_000);
        b.refill(5_000, RATE, BURST);
        assert_eq!(b.tokens(), 0);
        b.refill(10_500, RATE, BURST);
        assert_eq!(b.tokens(), 4_000);
    }

    #[test]
    fn time_spent_full_is_not_banked() {
        let mut b = started(0);
        b.refill(100_000, RATE, BURST);
        b.spend(BURST);
        b.refill(100_001, RATE, BURST);
        assert_eq!(b.tokens(), 8, "one millisecond of refill, not a hundred seconds");
    }

    #[test]
    fn extreme_values_saturate_instead_of_overflowing() {
        let mut b = started(0);
        b.spend(usize::MAX);
        b.spend(usize::MAX);
        assert_eq!(b.tokens(), i64::MIN);
        assert_eq!(b.wait_ms(1), u64::MAX);
        b.refill(u64::MAX, usize::MAX, usize::MAX);
        assert_eq!(b.tokens(), i64::MAX);
    }

    /// Over any schedule of spends and refills, what was spent never exceeds what the rate earned since creation plus
    /// the final debt: the bucket cannot mint work.
    #[test]
    fn no_schedule_spends_more_than_the_rate_earned() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200 {
            let (rate, burst) = (1 + (next() % 50_000) as usize, 1 + (next() % 200_000) as usize);
            let mut b = started(0);
            let (mut now, mut spent) = (0u64, 0i128);
            for _ in 0..500 {
                now += next() % 50;
                b.refill(now, rate, burst);
                assert!(b.tokens() <= burst as i64, "over the burst");
                let cost = (next() % 20_000) as usize;
                b.spend(cost);
                spent += cost as i128;
                let earned = i128::from(now) * rate as i128 / 1000;
                // tokens = credited - spent, and credited <= earned
                assert!(spent + i128::from(b.tokens()) <= earned, "spent {spent} beyond earned {earned}");
            }
        }
    }
}
