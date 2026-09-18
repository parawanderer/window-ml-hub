//! Which address a connection really came from, when a proxy is in front of the hub.
//!
//! The hub is meant to be run behind Tailscale or Caddy (docs/SELF_HOSTING.md), which means every client arrives
//! from the proxy's address and every address-keyed limit becomes one bucket shared by everybody. That is why the
//! arrivals gate ships off: a rate that stops a script would also stop a household.
//!
//! `X-Forwarded-For` is what fixes that, and it is a header anybody can write, so the rule is narrow: it is read
//! ONLY when the socket's own peer is an address the operator named as a proxy, and the client is the RIGHTMOST
//! entry that is not itself one of those. A client may prepend whatever it likes to the header; it cannot make its
//! own hop appear to the right of the proxy that appended it.

use std::net::IpAddr;

/// The longest header this reads. A proxy chain is a handful of hops; anything longer is somebody filling a buffer.
const MAX_FORWARDED_BYTES: usize = 512;
/// The most hops read out of one header, for the same reason.
const MAX_HOPS: usize = 16;

/// The addresses the operator says are proxies, as CIDR blocks. Empty means "no proxy", and then a forwarded header
/// is never read at all.
#[derive(Debug, Clone, Default)]
pub struct Proxies(Vec<Block>);

#[derive(Debug, Clone, Copy)]
struct Block {
    network: IpAddr,
    bits: u8,
}

impl Proxies {
    /// Parse a comma-separated list of CIDR blocks or bare addresses (`10.0.0.0/8, 127.0.0.1, ::1`).
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut blocks = Vec::new();
        for entry in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            blocks.push(Block::parse(entry)?);
        }
        Ok(Self(blocks))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Is this address one the operator named?
    pub fn contains(&self, address: IpAddr) -> bool {
        self.0.iter().any(|b| b.contains(address))
    }
}

impl Block {
    fn parse(entry: &str) -> Result<Self, String> {
        let (address, bits) = match entry.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (entry, None),
        };
        let network: IpAddr = address.parse().map_err(|_| format!("{entry}: not an address"))?;
        let full = if network.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => full,
            Some(b) => {
                let bits: u8 = b.parse().map_err(|_| format!("{entry}: not a prefix length"))?;
                if bits > full {
                    return Err(format!("{entry}: /{bits} is longer than the address"));
                }
                bits
            }
        };
        Ok(Self { network, bits })
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(net), IpAddr::V4(a)) => prefix_eq(&net.octets(), &a.octets(), self.bits),
            (IpAddr::V6(net), IpAddr::V6(a)) => prefix_eq(&net.octets(), &a.octets(), self.bits),
            // A v4-mapped v6 peer (::ffff:10.0.0.1) is the same machine as its v4 form, and which one a socket
            // reports depends on how the listener was bound rather than on anything the operator chose.
            (IpAddr::V4(_), IpAddr::V6(a)) => a.to_ipv4_mapped().is_some_and(|a| self.contains(IpAddr::V4(a))),
            (IpAddr::V6(net), IpAddr::V4(a)) => net.to_ipv4_mapped().is_some_and(|net| {
                Self { network: IpAddr::V4(net), bits: self.bits.saturating_sub(96) }.contains(IpAddr::V4(a))
            }),
        }
    }
}

/// Whether the first `bits` bits of two addresses match.
fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let (whole, rest) = (usize::from(bits / 8), bits % 8);
    if a[..whole] != b[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    a[whole] & mask == b[whole] & mask
}

/// The address to hold responsible for this connection: the peer, unless the peer is a proxy the operator named and
/// the header says who it is forwarding for.
///
/// `header` is the raw `X-Forwarded-For` value, if the request carried one.
pub fn client_address(peer: IpAddr, header: Option<&str>, proxies: &Proxies) -> IpAddr {
    if proxies.is_empty() || !proxies.contains(peer) {
        // Anybody can send this header, so from anybody but a named proxy it is ignored. Without this line the
        // header would be a way to be rate limited as somebody else.
        return peer;
    }
    let Some(header) = header.filter(|h| h.len() <= MAX_FORWARDED_BYTES) else { return peer };
    let hops: Vec<IpAddr> = header.split(',').take(MAX_HOPS).filter_map(|hop| parse_hop(hop.trim())).collect();
    // Rightmost first: each proxy APPENDS the address it received from, so the entries on the right are the ones
    // written by machines we trust. The first one that is not itself a proxy is the client; anything further left is
    // whatever the client chose to claim.
    hops.iter()
        .rev()
        .find(|a| !proxies.contains(**a))
        .copied()
        // every hop is a proxy of ours: the leftmost is as close to a client as this header gets
        .or_else(|| hops.first().copied())
        .unwrap_or(peer)
}

/// One entry of the header. Bare addresses, and the `[v6]:port` and `v4:port` forms a proxy may write.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    if let Ok(address) = hop.parse::<IpAddr>() {
        return Some(address);
    }
    if let Some(rest) = hop.strip_prefix('[') {
        let (inside, _) = rest.split_once(']')?;
        return inside.parse().ok();
    }
    // v4 with a port; a bare v6 has colons of its own and was parsed above
    let (address, _) = hop.rsplit_once(':')?;
    address.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn proxies(list: &str) -> Proxies {
        Proxies::parse(list).unwrap()
    }

    #[test]
    fn with_no_proxies_the_header_is_never_read() {
        let none = Proxies::default();
        assert_eq!(client_address(ip("203.0.113.9"), Some("1.2.3.4"), &none), ip("203.0.113.9"));
    }

    #[test]
    fn a_client_cannot_claim_someone_elses_address() {
        // the header is only read from a named proxy; sent by anybody else it is a way to be limited as somebody else
        let trusted = proxies("10.0.0.0/8");
        assert_eq!(client_address(ip("203.0.113.9"), Some("198.51.100.7"), &trusted), ip("203.0.113.9"));
    }

    #[test]
    fn behind_a_proxy_the_client_is_the_rightmost_entry_it_did_not_write() {
        let trusted = proxies("10.0.0.0/8");
        // the client prepended a lie; the proxy appended what it actually saw
        let header = "198.51.100.7, 203.0.113.9";
        assert_eq!(client_address(ip("10.1.2.3"), Some(header), &trusted), ip("203.0.113.9"));
    }

    #[test]
    fn a_chain_of_proxies_is_walked_past() {
        let trusted = proxies("10.0.0.0/8, 172.16.0.0/12");
        let header = "203.0.113.9, 10.0.0.5, 172.16.4.4";
        assert_eq!(client_address(ip("10.1.2.3"), Some(header), &trusted), ip("203.0.113.9"));
    }

    #[test]
    fn a_header_of_nothing_but_proxies_falls_back_rather_than_to_the_socket() {
        let trusted = proxies("10.0.0.0/8");
        assert_eq!(client_address(ip("10.1.2.3"), Some("10.0.0.5, 10.0.0.6"), &trusted), ip("10.0.0.5"));
        assert_eq!(client_address(ip("10.1.2.3"), None, &trusted), ip("10.1.2.3"));
        assert_eq!(client_address(ip("10.1.2.3"), Some(""), &trusted), ip("10.1.2.3"));
    }

    #[test]
    fn a_header_that_is_someone_filling_a_buffer_is_ignored() {
        let trusted = proxies("10.0.0.0/8");
        let long = (0..200).map(|_| "203.0.113.9").collect::<Vec<_>>().join(", ");
        assert_eq!(client_address(ip("10.1.2.3"), Some(&long), &trusted), ip("10.1.2.3"), "too long to read");
        // and a header within the size limit is read only to MAX_HOPS, so the work is bounded either way
        let sixteen = (0..16).map(|_| "10.0.0.5").collect::<Vec<_>>().join(",");
        assert_eq!(client_address(ip("10.1.2.3"), Some(&sixteen), &trusted), ip("10.0.0.5"));
    }

    #[test]
    fn ports_and_brackets_are_read_the_way_proxies_write_them() {
        let trusted = proxies("10.0.0.0/8");
        assert_eq!(client_address(ip("10.1.2.3"), Some("203.0.113.9:4123"), &trusted), ip("203.0.113.9"));
        assert_eq!(client_address(ip("10.1.2.3"), Some("[2001:db8::1]:4123"), &trusted), ip("2001:db8::1"));
        assert_eq!(client_address(ip("10.1.2.3"), Some("2001:db8::1"), &trusted), ip("2001:db8::1"));
    }

    #[test]
    fn a_v4_mapped_peer_is_the_machine_the_operator_named() {
        // which form a socket reports depends on how the listener was bound, not on anything the operator chose
        let trusted = proxies("127.0.0.1");
        assert_eq!(client_address(ip("::ffff:127.0.0.1"), Some("203.0.113.9"), &trusted), ip("203.0.113.9"));
    }

    #[test]
    fn blocks_are_parsed_or_refused_with_a_reason() {
        assert!(proxies("10.0.0.0/8, 127.0.0.1, ::1, 2001:db8::/32").contains(ip("10.255.255.255")));
        assert!(!proxies("10.0.0.0/8").contains(ip("11.0.0.1")));
        assert!(proxies("2001:db8::/32").contains(ip("2001:db8:1234::1")));
        assert!(!proxies("2001:db8::/32").contains(ip("2001:db9::1")));
        assert!(proxies("203.0.113.9").contains(ip("203.0.113.9")), "a bare address is its own block");
        for bad in ["10.0.0.0/33", "not-an-address", "10.0.0.0/x", "::1/129"] {
            assert!(Proxies::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_prefix_that_is_not_a_whole_byte_masks_correctly() {
        let trusted = proxies("192.168.16.0/20");
        assert!(trusted.contains(ip("192.168.31.255")));
        assert!(!trusted.contains(ip("192.168.32.0")));
    }
}
