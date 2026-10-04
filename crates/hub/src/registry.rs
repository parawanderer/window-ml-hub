//! Which accounts this hub serves, and how a new one gets in (docs/design/end-to-end-crypto.md, decision 3).
//!
//! The only state the hub keeps on disk, and it is operator state, not traffic: one empty-ish file per registered
//! account and one file per outstanding invite, in a state directory. Every claim is an exclusive create
//! (`create_new`, `O_CREAT|O_EXCL`), which is what makes an invite single-use even when two connections race for it,
//! and lets `wmlhub invite create` run beside a live server without any locking. (Removing the invite file was the
//! first design, and it is not a claim: under the race test on macOS it let one invite register up to three
//! accounts.)
//!
//! Invites are stored as the SHA-256 of the token, so reading the state directory does not reveal a usable invite.
//!
//! It also holds the one thing about an account that cannot be decided anywhere else: which principal signs its
//! revocation lists ([`Registry::claim_revoker`], docs/design/revocation.md).

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

/// What a hello carrying `may_revoke` is, judged against the account's record of its one signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revoker {
    /// It signs for this account: it claimed the grant just now, or the record already named it.
    Held,
    /// Another principal is the account's signer. This one does not sign for it, whichever grant is newer.
    Second { holder: String, since_ms: u64 },
}

/// The registry over a state directory.
#[derive(Debug)]
pub struct Registry {
    mode: Registration,
    dir: PathBuf,
    open: OpenLimits,
    /// open mode: registrations per source address, and in total, within the current window
    window: Mutex<Window>,
    /// Serializes `claim_revoker`, so two of an account's connections arriving at once cannot both read "no signer"
    /// and both claim it. The record itself is read from disk inside the lock, never cached: a stale cache is how one
    /// shard would displace a signer another had just recorded.
    revoker: Mutex<()>,
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
        fs::create_dir_all(dir.join("revokers"))?;
        Ok(Self { mode, dir, open, window: Mutex::new(Window::default()), revoker: Mutex::new(()) })
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

    /// Who signs `account`'s revocation lists, given a hello whose VERIFIED leaf carries `may_revoke`.
    ///
    /// The invariant is the design's (docs/design/revocation.md, "Where the root key lives"): exactly one principal
    /// holds `may_revoke` at a time. The list's `version` is per account and monotonic, so two signers race and the
    /// loser's revocation is refused as STALE, which is the worst possible way for a revocation to fail. Nothing but
    /// the hub can hold that invariant: to know whether another signer exists, an issuer needs the whole account,
    /// which a client gets only by asking an online runtime for its device list. That is best effort, racy between
    /// two devices pairing at once, and unavailable in exactly the state that needs it.
    ///
    /// THE FIRST CLAIM WINS, and a later grant does not take over by being later. The tempting rule is "the newest
    /// certificate wins", which sounds like the handover the design wants to allow and is the wrong way round in the
    /// common case: pairing a second device carelessly issues the newest grant there is, so the careless act would
    /// silently displace the working signer and the refusal would land on a laptop nobody is touching, later. Both
    /// readings of a second grant look identical from here, so this holds the one record and refuses the arrival,
    /// where somebody is standing. Re-placing the signer deliberately is `wmlhub accounts clear-revoker`, an
    /// operator's act on the hub that serves the account, and [`Revoker::Second`] says so.
    ///
    /// A record that cannot be read or parsed counts as ABSENT rather than refusing every runtime of the account: a
    /// corrupt byte in the state directory must not lock a person out of their own hub, and anyone who can write
    /// there owns the hub already.
    pub fn claim_revoker(&self, account: &[u8; 32], principal: &[u8; 32], issued_ms: u64) -> Result<Revoker, Refusal> {
        // A poisoned lock means another thread panicked holding it, which says nothing about the record on disk.
        let _claim = self.revoker.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.revoker_path(account);
        let me = hex(principal);
        match fs::read_to_string(&path).ok().and_then(|s| parse_revoker(&s)) {
            // The same principal with a later grant: a renewal, or the same key re-paired. Hold the record to the
            // newest one, so what an operator is shown is the grant actually in use.
            Some((holder, since_ms)) if holder == me => {
                if issued_ms > since_ms {
                    write_revoker(&path, &me, issued_ms)?;
                }
                Ok(Revoker::Held)
            }
            Some((holder, since_ms)) => Ok(Revoker::Second { holder, since_ms }),
            None => {
                write_revoker(&path, &me, issued_ms)?;
                Ok(Revoker::Held)
            }
        }
    }

    /// Forget which principal signs `account`'s revocations, so the next `may_revoke` hello claims it: how an
    /// operator re-places the signer after the device holding it was lost, and how an account that acquired two
    /// before this was enforced chooses between them. Returns whether there was a record to forget.
    pub fn clear_revoker(dir: &Path, account: &str) -> io::Result<bool> {
        match fs::remove_file(dir.join("revokers").join(account)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Which principal signs each account's revocations, for `wmlhub accounts list`: account, signer, and when the
    /// grant it presented was issued.
    pub fn list_revokers(dir: &Path) -> io::Result<HashMap<String, (String, u64)>> {
        let mut out = HashMap::new();
        let entries = match fs::read_dir(dir.join("revokers")) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let account = entry.file_name().to_string_lossy().into_owned();
            if let Some(held) = fs::read_to_string(entry.path()).ok().and_then(|s| parse_revoker(&s)) {
                out.insert(account, held);
            }
        }
        Ok(out)
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

    fn revoker_path(&self, account: &[u8; 32]) -> PathBuf {
        self.dir.join("revokers").join(hex(account))
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

/// The signer on record: its principal and when the grant it presented was issued. None when the file is absent,
/// truncated or not in this shape, which `claim_revoker` treats as no record at all.
fn parse_revoker(text: &str) -> Option<(String, u64)> {
    let mut principal = None;
    let mut since_ms = None;
    for line in text.lines() {
        match line.split_once('=') {
            Some(("principal", v)) if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) => {
                principal = Some(v.to_owned());
            }
            Some(("since_ms", v)) => since_ms = v.trim().parse().ok(),
            _ => {}
        }
    }
    Some((principal?, since_ms?))
}

/// Replace the record in one step. A half-written record would be read as no record, which would let the next hello
/// claim a signer the account already has, so it is written beside and renamed over.
fn write_revoker(path: &Path, principal: &str, since_ms: u64) -> Result<(), Refusal> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut f = fs::File::create(&tmp).map_err(storage)?;
    writeln!(f, "principal={principal}\nsince_ms={since_ms}").map_err(storage)?;
    fs::rename(&tmp, path).map_err(storage)
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

    fn dir_of(r: &Registry) -> PathBuf {
        r.dir.clone()
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

    // --- one revocation signer per account ---

    #[test]
    fn the_first_may_revoke_hello_claims_the_account_and_keeps_it() {
        let r = Registry::open(dir("revoker-first"), Registration::Open, OpenLimits::default()).unwrap();
        assert_eq!(r.claim_revoker(&[1; 32], &[7; 32], NOW), Ok(Revoker::Held));
        // Reconnecting is not a second signer, and neither is a renewal of the same grant.
        assert_eq!(r.claim_revoker(&[1; 32], &[7; 32], NOW), Ok(Revoker::Held));
        assert_eq!(r.claim_revoker(&[1; 32], &[7; 32], NOW + 86_400_000), Ok(Revoker::Held));
        assert_eq!(
            Registry::list_revokers(&dir_of(&r)).unwrap().get(&hex(&[1; 32])),
            Some(&(hex(&[7; 32]), NOW + 86_400_000)),
            "the record follows the newest grant the signer presented"
        );
    }

    #[test]
    fn a_second_signer_is_refused_whichever_grant_is_newer() {
        let r = Registry::open(dir("revoker-second"), Registration::Open, OpenLimits::default()).unwrap();
        assert_eq!(r.claim_revoker(&[1; 32], &[7; 32], NOW), Ok(Revoker::Held));
        // NEWER, which is what pairing a second device carelessly produces: refused, so the refusal lands on the
        // device being paired and not on the working signer.
        assert_eq!(
            r.claim_revoker(&[1; 32], &[8; 32], NOW + 60_000),
            Ok(Revoker::Second { holder: hex(&[7; 32]), since_ms: NOW })
        );
        // Older, and the same millisecond: a grant that is not the record is not the signer, whatever its clock says.
        assert!(matches!(r.claim_revoker(&[1; 32], &[8; 32], NOW - 60_000), Ok(Revoker::Second { .. })));
        assert!(matches!(r.claim_revoker(&[1; 32], &[8; 32], NOW), Ok(Revoker::Second { .. })));
        // The incumbent is untouched by any of it.
        assert_eq!(r.claim_revoker(&[1; 32], &[7; 32], NOW), Ok(Revoker::Held));
        // And another account is a separate question.
        assert_eq!(r.claim_revoker(&[2; 32], &[8; 32], NOW), Ok(Revoker::Held));
    }

    #[test]
    fn the_signer_survives_reopening_the_state_directory() {
        let d = dir("revoker-persist");
        Registry::open(&d, Registration::Open, OpenLimits::default())
            .unwrap()
            .claim_revoker(&[1; 32], &[7; 32], NOW)
            .unwrap();
        let again = Registry::open(&d, Registration::Open, OpenLimits::default()).unwrap();
        assert!(
            matches!(again.claim_revoker(&[1; 32], &[8; 32], NOW + 1), Ok(Revoker::Second { .. })),
            "a restart must not hand the account to whoever connects first"
        );
    }

    #[test]
    fn clearing_the_record_hands_the_account_to_the_next_grant() {
        let d = dir("revoker-clear");
        let r = Registry::open(&d, Registration::Open, OpenLimits::default()).unwrap();
        r.claim_revoker(&[1; 32], &[7; 32], NOW).unwrap();
        assert!(Registry::clear_revoker(&d, &hex(&[1; 32])).unwrap());
        assert!(!Registry::clear_revoker(&d, &hex(&[1; 32])).unwrap(), "nothing left to forget");
        assert_eq!(r.claim_revoker(&[1; 32], &[8; 32], NOW + 1), Ok(Revoker::Held));
        // And the device that held it is now the second signer, which is the point of clearing it.
        assert!(matches!(r.claim_revoker(&[1; 32], &[7; 32], NOW), Ok(Revoker::Second { .. })));
    }

    #[test]
    fn a_record_that_cannot_be_read_counts_as_none() {
        let d = dir("revoker-corrupt");
        let r = Registry::open(&d, Registration::Open, OpenLimits::default()).unwrap();
        for junk in ["", "principal=\n", "principal=nothex since_ms=1", &format!("principal={}", hex(&[7; 32]))] {
            fs::write(d.join("revokers").join(hex(&[1; 32])), junk).unwrap();
            assert_eq!(r.claim_revoker(&[1; 32], &[9; 32], NOW), Ok(Revoker::Held), "junk: {junk:?}");
        }
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
