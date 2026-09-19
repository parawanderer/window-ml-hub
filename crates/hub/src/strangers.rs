//! What strangers may cost: the work the hub does for connections that never authenticate.
//!
//! Every other bound is per account, and a connection that authenticates pays for its own handshake out of its
//! account's budget (`CONNECT_COST_BYTES`). A connection that never authenticates has no account to charge, so until
//! this existed its work was charged to nobody — and it runs on the same threads as every connected account's
//! traffic. `max_pending_sockets` bounds how many strangers there are at once, which bounds memory; it says nothing
//! about how fast they come and go, which is what costs time (docs/perf/README.md §Strangers).
//!
//! So strangers are one tenant with one budget, charged in microseconds of measured hub CPU for each connection that
//! gives its place back without authenticating. While the budget is spent the accept loop stops accepting: strangers
//! are accepted more slowly, as an account over its rate is READ more slowly, and what waits costs the hub nothing,
//! because it waits in the kernel's backlog rather than in anything the hub holds.
//!
//! Only failures are charged. A hub restart that brings every device back at once is never paced by this, since each
//! of those connections authenticates and is its own account's cost. A flood of failures paces everybody who is not
//! yet connected, which nothing that cannot tell an attacker from a stranger can avoid, and leaves everybody who IS
//! connected alone, which is the invariant.

use std::time::{Duration, Instant};

/// Hub CPU for a connection that ends without sending a hello: a websocket handshake that never finishes, a first
/// frame that is not a hello, a hello that never arrives. Measured as an upper bound, with hellos that fail before any
/// signature is checked (about 46 us each), since nothing here costs more than that does (docs/perf/README.md
/// §Strangers).
pub const NO_HELLO_US: u64 = 50;
/// Hub CPU for a connection whose hello is refused, WHATEVER refused it: two certificates and the hello signature
/// verified, plus the connection. Measured with hellos that fail at the last signature, the most a refusal can cost:
/// about 183 us each at the default budget, which this is set against, and about 242 us at a whole core, where the
/// estimate runs low (docs/perf/README.md §Strangers).
///
/// A hello that fails an earlier and cheaper check is charged this too. Charging exactly would need the verifier to
/// report how far it got, and over-charging one only makes strangers slower, never anybody who is connected.
pub const REFUSED_HELLO_US: u64 = 190;

/// A quarter of one core, and a second of it available at once. `wmlhub serve --unauthenticated-cpu-percent` defaults
/// to the same 25.
pub const DEFAULT_BUDGET: Budget = Budget { us_per_second: 250_000, burst_us: 250_000 };

/// How much hub CPU connections that never authenticate may cost, in microseconds per second of wall time, and how
/// much of it may be spent at once.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// 0 turns pacing off.
    pub us_per_second: u64,
    pub burst_us: u64,
}

/// The budget strangers have left.
#[derive(Debug)]
pub struct Strangers {
    budget: Budget,
    /// microseconds of credit; negative is debt the accept loop waits out
    balance_us: i64,
    at: Instant,
}

impl Strangers {
    /// A full budget: the first burst of failures after a start is not paced.
    pub fn new(budget: Budget, now: Instant) -> Self {
        Self { budget, balance_us: clamp(budget.burst_us), at: now }
    }

    /// Record a connection that gave its place back without authenticating.
    pub fn charge(&mut self, cost_us: u64, now: Instant) {
        self.refill(now);
        // Debt is allowed to go as deep as the failures take it: the pending-socket cap bounds how many can be in
        // flight, so how deep it goes is bounded too, and all of it is repaid before the next stranger is accepted.
        self.balance_us = self.balance_us.saturating_sub(clamp(cost_us));
    }

    /// How long the accept loop should wait before accepting again, or `None` when it need not.
    pub fn wait(&mut self, now: Instant) -> Option<Duration> {
        if self.budget.us_per_second == 0 {
            return None;
        }
        self.refill(now);
        if self.balance_us >= 0 {
            return None;
        }
        let debt = self.balance_us.unsigned_abs();
        // Rounded UP, so a wait never ends a microsecond short and spins the loop through a zero-length sleep.
        let micros = debt.saturating_mul(1_000_000).div_ceil(self.budget.us_per_second);
        Some(Duration::from_micros(micros))
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at);
        self.at = now;
        let earned = (elapsed.as_micros().saturating_mul(u128::from(self.budget.us_per_second)) / 1_000_000)
            .min(i64::MAX as u128) as i64;
        self.balance_us = self.balance_us.saturating_add(earned).min(clamp(self.budget.burst_us));
    }
}

fn clamp(us: u64) -> i64 {
    i64::try_from(us).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUARTER_CORE: Budget = Budget { us_per_second: 250_000, burst_us: 250_000 };

    #[test]
    fn a_full_budget_absorbs_a_burst_and_then_paces() {
        let t = Instant::now();
        let mut s = Strangers::new(QUARTER_CORE, t);
        s.charge(250_000, t);
        assert_eq!(s.wait(t), None, "spending the burst exactly leaves nothing owed");
        s.charge(50_000, t);
        // 50 ms of CPU owed at a quarter of a core is 200 ms of wall time
        assert_eq!(s.wait(t), Some(Duration::from_millis(200)));
    }

    #[test]
    fn debt_is_repaid_by_time_and_the_wait_shrinks_with_it() {
        let t = Instant::now();
        let mut s = Strangers::new(QUARTER_CORE, t);
        s.charge(250_000 + 50_000, t);
        assert_eq!(s.wait(t + Duration::from_millis(100)), Some(Duration::from_millis(100)));
        assert_eq!(s.wait(t + Duration::from_millis(200)), None, "repaid");
    }

    #[test]
    fn the_budget_refills_to_the_burst_and_no_further() {
        let t = Instant::now();
        let mut s = Strangers::new(QUARTER_CORE, t);
        // an hour idle earns an hour's worth, and none of it past the burst
        let later = t + Duration::from_secs(3_600);
        s.charge(250_000, later);
        assert_eq!(s.wait(later), None);
        // a millisecond of CPU past the burst is four of wall time: exactly that, so nothing was banked beyond it
        s.charge(1_000, later);
        assert_eq!(s.wait(later), Some(Duration::from_millis(4)), "idle time did not bank more than the burst");
    }

    #[test]
    fn a_wait_is_never_a_microsecond_short() {
        let t = Instant::now();
        let mut s = Strangers::new(Budget { us_per_second: 3, burst_us: 0 }, t);
        s.charge(1, t);
        // one microsecond of debt at three a second is 333,333.3 us: rounded up, so the loop wakes to credit
        assert_eq!(s.wait(t), Some(Duration::from_micros(333_334)));
        assert_eq!(s.wait(t + Duration::from_micros(333_334)), None);
    }

    #[test]
    fn a_budget_of_zero_never_paces() {
        let t = Instant::now();
        let mut s = Strangers::new(Budget { us_per_second: 0, burst_us: 0 }, t);
        s.charge(u64::MAX, t);
        assert_eq!(s.wait(t), None, "off means off, however much is charged");
    }
}
