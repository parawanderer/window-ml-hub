//! How often one address may open a connection.
//!
//! Everything else the hub bounds is per account, which needs a `Hello`; this is the one bound that has to work
//! before anyone has said who they are, so it keys on the source address. It is the cheapest thing that makes the
//! pre-authentication surface finite: a socket that is refused here costs a TCP accept and nothing else — no
//! websocket handshake, no read buffer, no challenge.
//!
//! An address behind a shared NAT shares its allowance, which is the usual price of address-keyed limits. The rate is
//! generous enough that a household reconnecting after a network blip does not notice, and a script opening sockets
//! in a loop does.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Addresses tracked at once. Past it the oldest idle entry is dropped, which at worst forgives an address early.
const MAX_TRACKED: usize = 8_192;

/// How often an address may open a connection, and how many it may open at once.
#[derive(Debug, Clone, Copy)]
pub struct Arrivals {
    pub per_minute: u32,
    pub burst: u32,
}

// Written out rather than derived: zero is not an arbitrary default and the reason has to live beside it.
#[allow(clippy::derivable_impls)]
impl Default for Arrivals {
    fn default() -> Self {
        // OFF by default, and the reason is the deployment this hub recommends: behind Tailscale or Caddy, every
        // client arrives from the PROXY's address, so one bucket would be shared by everyone and a rate that stops a
        // script would also stop a household. An operator who exposes the hub directly should set it (60 a minute
        // with a burst of 30 suits a person's devices); until the hub can read a forwarded address it cannot be a
        // default. What bounds the surface with it off is `max_pending_sockets`, which needs no address.
        Self { per_minute: 0, burst: 0 }
    }
}

#[derive(Debug, Clone, Copy)]
struct Allowance {
    /// tokens, in thousandths so a rate below one a second still accrues
    milli: i64,
    at: Instant,
}

/// The allowance each address has left.
#[derive(Debug)]
pub struct Gate {
    limits: Arrivals,
    seen: HashMap<IpAddr, Allowance>,
}

impl Gate {
    pub fn new(limits: Arrivals) -> Self {
        Self { limits, seen: HashMap::new() }
    }

    /// May this address open a connection now? Records it when it may. A `per_minute` of 0 admits everything, which
    /// is the default: see `Arrivals::default`.
    pub fn admit(&mut self, address: IpAddr, now: Instant) -> bool {
        if self.limits.per_minute == 0 {
            return true;
        }
        let burst = i64::from(self.limits.burst.max(1)) * 1_000;
        let per_ms = f64::from(self.limits.per_minute) / 60_000.0;
        let entry = self.seen.entry(address).or_insert(Allowance { milli: burst, at: now });
        let elapsed = now.saturating_duration_since(entry.at).as_millis().min(u128::from(u32::MAX)) as f64;
        entry.milli = (entry.milli + (elapsed * per_ms * 1_000.0) as i64).min(burst);
        entry.at = now;
        if entry.milli < 1_000 {
            return false;
        }
        entry.milli -= 1_000;
        self.forget_idle(now);
        true
    }

    /// Drop entries that are back to full, so the map holds addresses that are actually using their allowance.
    fn forget_idle(&mut self, now: Instant) {
        if self.seen.len() <= MAX_TRACKED {
            return;
        }
        let burst = i64::from(self.limits.burst.max(1)) * 1_000;
        let per_ms = f64::from(self.limits.per_minute) / 60_000.0;
        self.seen.retain(|_, a| {
            let elapsed = now.saturating_duration_since(a.at).as_millis().min(u128::from(u32::MAX)) as f64;
            (a.milli + (elapsed * per_ms * 1_000.0) as i64) < burst
        });
        // Still full of busy addresses: forget the least recently seen half rather than growing without bound.
        if self.seen.len() > MAX_TRACKED {
            let mut times: Vec<Instant> = self.seen.values().map(|a| a.at).collect();
            times.sort_unstable();
            let cutoff = times[times.len() / 2];
            self.seen.retain(|_, a| a.at > cutoff);
        }
    }

    /// How many addresses are being tracked, for the tests and the logs.
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const ONE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    const TWO: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

    #[test]
    fn an_address_may_burst_and_is_then_paced() {
        let mut gate = Gate::new(Arrivals { per_minute: 60, burst: 3 });
        let now = Instant::now();
        for i in 0..3 {
            assert!(gate.admit(ONE, now), "burst {i}");
        }
        assert!(!gate.admit(ONE, now), "the burst is spent");
        assert!(gate.admit(ONE, now + Duration::from_secs(1)), "a second later, one more");
        assert!(!gate.admit(ONE, now + Duration::from_secs(1)));
    }

    #[test]
    fn one_address_spending_its_allowance_does_not_touch_another() {
        let mut gate = Gate::new(Arrivals { per_minute: 60, burst: 2 });
        let now = Instant::now();
        assert!(gate.admit(ONE, now));
        assert!(gate.admit(ONE, now));
        assert!(!gate.admit(ONE, now));
        assert!(gate.admit(TWO, now), "another address has its own");
    }

    #[test]
    fn an_allowance_refills_to_the_burst_and_no_further() {
        let mut gate = Gate::new(Arrivals { per_minute: 60, burst: 2 });
        let now = Instant::now();
        assert!(gate.admit(ONE, now));
        let later = now + Duration::from_secs(3_600);
        assert!(gate.admit(ONE, later));
        assert!(gate.admit(ONE, later));
        assert!(!gate.admit(ONE, later), "an hour of quiet is still only a burst");
    }

    #[test]
    fn a_rate_of_zero_admits_everything() {
        let mut gate = Gate::new(Arrivals { per_minute: 0, burst: 0 });
        let now = Instant::now();
        for _ in 0..1_000 {
            assert!(gate.admit(ONE, now));
        }
    }

    #[test]
    fn the_map_stays_bounded_however_many_addresses_arrive() {
        let mut gate = Gate::new(Arrivals::default());
        let now = Instant::now();
        for i in 0..(MAX_TRACKED as u32 * 2) {
            let address = IpAddr::V4(std::net::Ipv4Addr::from(i.to_be_bytes()));
            gate.admit(address, now);
        }
        assert!(gate.tracked() <= MAX_TRACKED, "tracked {} addresses", gate.tracked());
    }
}
