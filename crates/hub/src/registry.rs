//! Which accounts this hub serves, and how a new one gets in (docs/design/end-to-end-crypto.md, decision 3).
//!
//! The only state the hub keeps on disk, and it is operator state, not traffic: one empty-ish file per registered
//! account and one file per outstanding invite, in a state directory. Every claim is an exclusive create
//! (`create_new`, `O_CREAT|O_EXCL`), which is what makes an invite single-use even when two connections race for it,
//! and lets `wmlhub invite create` run beside a live server without any locking. (Removing the invite file was the
//! first design, and it is not a claim: two concurrent removals of one file both succeeded on macOS, registering up
//! to three accounts with one invite in the race test.)
//!
//! Invites are stored as the SHA-256 of the token, so reading the state directory does not reveal a usable invite.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};
use wmlhub_keys::hex;

/// How a hub admits an account it has not seen before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// A new account root needs an operator-issued, single-use invite. The default.
    Invite,
    /// Any valid account root is admitted, rate limited by source address and overall.
    Open,
}

impl std::str::FromStr for Registration {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "invite" => Ok(Self::Invite),
            "open" => Ok(Self::Open),
            other => Err(format!("registration must be `invite` or `open`, not `{other}`")),
        }
    }
}

/// How fast an open hub admits new accounts.
#[derive(Debug, Clone, Copy)]
pub struct OpenLimits {
    /// new accounts one source address may register per window
    pub per_address: u32,
    /// new accounts in total per window
    pub total: u32,
    pub window: Duration,
}

impl Default for OpenLimits {
    fn default() -> Self {
        Self { per_address: 3, total: 60, window: Duration::from_secs(3600) }
    }
}

/// Why an account was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// invite-only hub, and no invite was presented
    InviteRequired,
    /// the invite does not exist, was already used, or has expired
    InviteInvalid,
    /// open hub, and the new-account rate was exceeded
    RateLimited,
    /// the state directory could not be read or written
    Storage(String),
}

/// How an account got in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// already registered
    Known,
    /// registered just now
    Registered,
}

/// The registry over a state directory.
#[derive(Debug)]
pub struct Registry {
    mode: Registration,
    dir: PathBuf,
    open: OpenLimits,
    /// open mode: registrations per source address, and in total, within the current window
    window: Mutex<Window>,
}

#[derive(Debug, Default)]
struct Window {
    started_ms: u64,
    total: u32,
    by_address: HashMap<IpAddr, u32>,
}

impl Registry {
    /// Open (creating if needed) the registry in `dir`.
    pub fn open(dir: impl Into<PathBuf>, mode: Registration, open: OpenLimits) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(dir.join("accounts"))?;
        fs::create_dir_all(dir.join("invites"))?;
        fs::create_dir_all(dir.join("invites-used"))?;
        Ok(Self { mode, dir, open, window: Mutex::new(Window::default()) })
    }

    /// The registration mode.
    pub fn mode(&self) -> Registration {
        self.mode
    }

    /// Admit `account` (an account id), registering it if new and the mode allows it.
    pub fn admit(&self, account: &[u8; 32], invite: &[u8], address: IpAddr, now_ms: u64) -> Result<Admission, Refusal> {
        let path = self.account_path(account);
        if path.exists() {
            return Ok(Admission::Known);
        }
        match self.mode {
            Registration::Invite => {
                if invite.is_empty() {
                    return Err(Refusal::InviteRequired);
                }
                self.consume_invite(invite, now_ms)?;
            }
            Registration::Open => self.take_open_slot(address, now_ms)?,
        }
        let how = match self.mode {
            Registration::Invite => "invite",
            Registration::Open => "open",
        };
        match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                writeln!(f, "registered_ms={now_ms}\nvia={how}").map_err(storage)?;
                Ok(Admission::Registered)
            }
            // two devices of one new account racing: the other one registered it
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(Admission::Known),
            Err(e) => Err(storage(e)),
        }
    }

    /// Create an invite valid for `ttl`. Returns the token to hand to the person; only its hash is stored.
    pub fn create_invite(dir: &Path, ttl: Duration, now_ms: u64) -> io::Result<String> {
        fs::create_dir_all(dir.join("invites"))?;
        let mut raw = [0u8; 20];
        getrandom::fill(&mut raw).map_err(|e| io::Error::other(e.to_string()))?;
        let token = format!("wmlhub-invite-{}", hex(&raw));
        let expires = now_ms.saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX));
        let path = dir.join("invites").join(hex(&Sha256::digest(token.as_bytes())));
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        writeln!(f, "{expires}")?;
        Ok(token)
    }

    /// Outstanding invites as (hash prefix, expiry ms), for `wmlhub invite list`.
    pub fn list_invites(dir: &Path) -> io::Result<Vec<(String, u64)>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(dir.join("invites")) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let expires = fs::read_to_string(entry.path())?.trim().parse().unwrap_or(0);
            out.push((name.chars().take(12).collect(), expires));
        }
        out.sort_by_key(|(_, e)| *e);
        Ok(out)
    }

    /// Registered account ids (hex), for `wmlhub accounts list`.
    pub fn list_accounts(dir: &Path) -> io::Result<Vec<String>> {
        let entries = match fs::read_dir(dir.join("accounts")) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out: Vec<String> =
            entries.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        out.sort();
        Ok(out)
    }

    fn account_path(&self, account: &[u8; 32]) -> PathBuf {
        self.dir.join("accounts").join(hex(account))
    }

    fn consume_invite(&self, invite: &[u8], now_ms: u64) -> Result<(), Refusal> {
        let hash = hex(&Sha256::digest(invite));
        let path = self.dir.join("invites").join(&hash);
        let expires: u64 = match fs::read_to_string(&path) {
            Ok(s) => s.trim().parse().unwrap_or(0),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Refusal::InviteInvalid),
            Err(e) => return Err(storage(e)),
        };
        // The exclusive create IS the claim: of connections racing for one invite, exactly one creates the marker.
        match fs::OpenOptions::new().write(true).create_new(true).open(self.dir.join("invites-used").join(&hash)) {
            Ok(mut f) => {
                let _ = writeln!(f, "claimed_ms={now_ms}");
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(Refusal::InviteInvalid),
            Err(e) => return Err(storage(e)),
        }
        // Tidy up; the marker is what refuses a second use, so a failure here changes nothing.
        let _ = fs::remove_file(&path);
        if now_ms > expires {
            return Err(Refusal::InviteInvalid);
        }
        Ok(())
    }

    fn take_open_slot(&self, address: IpAddr, now_ms: u64) -> Result<(), Refusal> {
        let mut w = self.window.lock().expect("registry window lock poisoned");
        let window_ms = u64::try_from(self.open.window.as_millis()).unwrap_or(u64::MAX);
        if now_ms.saturating_sub(w.started_ms) >= window_ms {
            *w = Window { started_ms: now_ms, ..Window::default() };
        }
        let mine = w.by_address.get(&address).copied().unwrap_or(0);
        if mine >= self.open.per_address || w.total >= self.open.total {
            return Err(Refusal::RateLimited);
        }
        w.by_address.insert(address, mine + 1);
        w.total += 1;
        Ok(())
    }
}

fn storage(e: io::Error) -> Refusal {
    Refusal::Storage(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const NOW: u64 = 1_800_000_000_000;
    const HOUR: Duration = Duration::from_secs(3600);

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wmlhub-registry-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn invite_mode_refuses_a_new_account_without_an_invite() {
        let r = Registry::open(dir("no-invite"), Registration::Invite, OpenLimits::default()).unwrap();
        assert_eq!(r.admit(&[1; 32], b"", ip(1), NOW), Err(Refusal::InviteRequired));
        assert_eq!(r.admit(&[1; 32], b"wmlhub-invite-made-up", ip(1), NOW), Err(Refusal::InviteInvalid));
    }

    #[test]
    fn an_invite_registers_one_account_once_and_the_account_stays_known() {
        let d = dir("invite");
        let r = Registry::open(&d, Registration::Invite, OpenLimits::default()).unwrap();
        let token = Registry::create_invite(&d, HOUR, NOW).unwrap();
        assert_eq!(r.admit(&[1; 32], token.as_bytes(), ip(1), NOW), Ok(Admission::Registered));
        assert_eq!(r.admit(&[2; 32], token.as_bytes(), ip(1), NOW), Err(Refusal::InviteInvalid));
        assert_eq!(r.admit(&[1; 32], b"", ip(9), NOW), Ok(Admission::Known));
    }

    #[test]
    fn registration_survives_reopening_the_state_directory() {
        let d = dir("persist");
        let token = Registry::create_invite(&d, HOUR, NOW).unwrap();
        Registry::open(&d, Registration::Invite, OpenLimits::default())
            .unwrap()
            .admit(&[1; 32], token.as_bytes(), ip(1), NOW)
            .unwrap();
        let again = Registry::open(&d, Registration::Invite, OpenLimits::default()).unwrap();
        assert_eq!(again.admit(&[1; 32], b"", ip(1), NOW), Ok(Admission::Known));
        assert_eq!(Registry::list_accounts(&d).unwrap(), [hex(&[1; 32])]);
    }

    #[test]
    fn an_expired_invite_is_refused_and_consumed() {
        let d = dir("expired");
        let r = Registry::open(&d, Registration::Invite, OpenLimits::default()).unwrap();
        let token = Registry::create_invite(&d, HOUR, NOW).unwrap();
        assert_eq!(r.admit(&[1; 32], token.as_bytes(), ip(1), NOW + 2 * 3_600_000), Err(Refusal::InviteInvalid));
        assert!(Registry::list_invites(&d).unwrap().is_empty());
    }

    #[test]
    fn the_state_directory_does_not_hold_usable_tokens() {
        let d = dir("hashed");
        let token = Registry::create_invite(&d, HOUR, NOW).unwrap();
        for entry in fs::read_dir(d.join("invites")).unwrap() {
            let entry = entry.unwrap();
            assert!(!entry.file_name().to_string_lossy().contains(&token["wmlhub-invite-".len()..]));
            assert!(!fs::read_to_string(entry.path()).unwrap().contains(&token));
        }
    }

    #[test]
    fn racing_connections_share_one_invite_exactly_once() {
        let d = dir("race");
        let r = std::sync::Arc::new(Registry::open(&d, Registration::Invite, OpenLimits::default()).unwrap());
        let token = Registry::create_invite(&d, HOUR, NOW).unwrap();
        let handles: Vec<_> = (0..16u8)
            .map(|n| {
                let (r, token) = (r.clone(), token.clone());
                std::thread::spawn(move || r.admit(&[n + 1; 32], token.as_bytes(), ip(n), NOW))
            })
            .collect();
        let registered =
            handles.into_iter().map(|h| h.join().unwrap()).filter(|a| *a == Ok(Admission::Registered)).count();
        assert_eq!(registered, 1);
    }

    #[test]
    fn open_mode_admits_without_an_invite_up_to_the_per_address_limit() {
        let limits = OpenLimits { per_address: 2, total: 100, window: HOUR };
        let r = Registry::open(dir("open"), Registration::Open, limits).unwrap();
        assert_eq!(r.admit(&[1; 32], b"", ip(1), NOW), Ok(Admission::Registered));
        assert_eq!(r.admit(&[2; 32], b"", ip(1), NOW), Ok(Admission::Registered));
        assert_eq!(r.admit(&[3; 32], b"", ip(1), NOW), Err(Refusal::RateLimited));
        assert_eq!(r.admit(&[3; 32], b"", ip(2), NOW), Ok(Admission::Registered));
        // a known account is never rate limited
        assert_eq!(r.admit(&[1; 32], b"", ip(1), NOW), Ok(Admission::Known));
    }

    #[test]
    fn open_mode_has_a_total_limit_and_the_window_resets() {
        let limits = OpenLimits { per_address: 100, total: 2, window: HOUR };
        let r = Registry::open(dir("open-total"), Registration::Open, limits).unwrap();
        assert!(r.admit(&[1; 32], b"", ip(1), NOW).is_ok());
        assert!(r.admit(&[2; 32], b"", ip(2), NOW).is_ok());
        assert_eq!(r.admit(&[3; 32], b"", ip(3), NOW), Err(Refusal::RateLimited));
        assert_eq!(r.admit(&[3; 32], b"", ip(3), NOW + 3_600_000), Ok(Admission::Registered));
    }

    #[test]
    fn listing_a_state_directory_that_does_not_exist_yet_is_empty() {
        let d = dir("absent");
        assert!(Registry::list_accounts(&d).unwrap().is_empty());
        assert!(Registry::list_invites(&d).unwrap().is_empty());
    }

    #[test]
    fn registration_mode_parses_and_rejects_anything_else() {
        assert_eq!("invite".parse(), Ok(Registration::Invite));
        assert_eq!("open".parse(), Ok(Registration::Open));
        assert!("Open".parse::<Registration>().is_err());
    }
}
