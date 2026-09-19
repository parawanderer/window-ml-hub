//! What a connector keeps between runs: its own two keys, and what a pairing gave it.
//!
//! Three files rather than one blob, because they have different lifetimes: the keys are generated once and are the
//! connector's identity for as long as it is paired, while what a pairing gave it is replaced on every re-pairing.
//! All three hold a secret (the certificate does not, but the channel key beside it names every channel the account
//! uses), so all three are written `0600` in a `0700` directory and are refused if they are readable by anyone else.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use std::collections::BTreeSet;

use wmlhub_keys::revocation::verify_revocations;
use wmlhub_keys::{Identity, PublicKey, hex};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{PairedWith, RevocationBody, RevocationList};
use wmlhub_seal::AgreementKey;

use crate::revoked::Revocations;

/// The Ed25519 seed this connector signs with, hex.
const IDENTITY_FILE: &str = "identity.key";
/// The X25519 seed sealed things are opened with, hex.
const AGREEMENT_FILE: &str = "agreement.key";
/// The `PairedWith` a pairing handed over, as it arrived: the certificate, the account root, the channel key.
const PAIRED_FILE: &str = "paired";
/// The revocation list this connector applies, as it arrived, so a restart does not forget who is revoked.
const REVOCATIONS_FILE: &str = "revocations";
/// When the freshness floor armed and which principals were seen holding `may_revoke`: `armed <ms>`, then one hex
/// principal id a line. Its absence is the one state in which the floor does not apply.
const REVOKERS_FILE: &str = "revokers";

/// A connector's state directory.
pub struct State {
    dir: PathBuf,
}

/// Both of a connector's keys, loaded.
pub struct Keys {
    pub identity: Identity,
    pub agreement: AgreementKey,
}

/// Prints what is public about them and nothing else: two secrets in a log line is what this type exists to hold.
impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keys(identity {}, agreement {})", hex(&self.identity.public()), hex(&self.agreement.public()))
    }
}

impl State {
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The keys, or `None` when this connector has never been paired anywhere.
    pub fn keys(&self) -> io::Result<Option<Keys>> {
        let (Some(identity), Some(agreement)) = (self.seed(IDENTITY_FILE)?, self.seed(AGREEMENT_FILE)?) else {
            return Ok(None);
        };
        Ok(Some(Keys { identity: Identity::from_seed(identity), agreement: AgreementKey::from_seed(&agreement) }))
    }

    /// Generate this connector's keys. Refuses rather than overwrite: a key that is replaced is a connector that
    /// silently became a different principal, and everything granted to the old one stays granted to nobody.
    pub fn generate_keys(&self) -> io::Result<Keys> {
        let (mut identity, mut agreement) = ([0u8; 32], [0u8; 32]);
        getrandom::fill(&mut identity).map_err(io::Error::other)?;
        getrandom::fill(&mut agreement).map_err(io::Error::other)?;
        self.make_dir()?;
        self.write_secret(IDENTITY_FILE, format!("{}\n", hex(&identity)).as_bytes(), false)?;
        self.write_secret(AGREEMENT_FILE, format!("{}\n", hex(&agreement)).as_bytes(), false)?;
        Ok(Keys { identity: Identity::from_seed(identity), agreement: AgreementKey::from_seed(&agreement) })
    }

    /// What a pairing gave this connector, or `None` when it has not been paired.
    pub fn paired(&self) -> io::Result<Option<PairedWith>> {
        let Some(bytes) = self.read(PAIRED_FILE)? else { return Ok(None) };
        PairedWith::decode(bytes.as_slice()).map(Some).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("{PAIRED_FILE} is not what a pairing wrote: {e}"))
        })
    }

    /// Keep what a pairing gave this connector, replacing anything it was paired with before.
    pub fn write_paired(&self, paired: &PairedWith) -> io::Result<()> {
        self.make_dir()?;
        self.write_secret(PAIRED_FILE, &paired.encode_to_vec(), true)
    }

    /// What this connector knew about revocations when it last ran, for the account whose root is `root`.
    ///
    /// The held list is verified again, AS OF WHEN IT WAS SIGNED. Its signer's certificate may have lapsed since, and a
    /// revoker whose certificate expired must not make a connector forget whom it revoked: the chain was valid when
    /// the list was applied, and that is what this checks. A file that does not verify is an error, as a key file
    /// that does not decode is: what it says is who must not be granted anything, and guessing is not an option.
    pub fn revocations(&self, root: &PublicKey) -> io::Result<Revocations> {
        let held = match self.read(REVOCATIONS_FILE)? {
            None => None,
            Some(bytes) => {
                let bad = |why: &str| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} {why}", self.dir.join(REVOCATIONS_FILE).display()),
                    )
                };
                let list = RevocationList::decode(bytes.as_slice()).map_err(|_| bad("is not a revocation list"))?;
                let body = RevocationBody::decode(list.body.as_slice()).map_err(|_| bad("is not a revocation list"))?;
                let held = verify_revocations(root, &list, body.version, None)
                    .map_err(|e| bad(&format!("no longer verifies ({e:?})")))?;
                Some(held)
            }
        };
        let (mut revokers, mut armed_at) = (BTreeSet::new(), None);
        if let Some(bytes) = self.read(REVOKERS_FILE)? {
            let text = String::from_utf8(bytes).map_err(|_| self.garbled(REVOKERS_FILE))?;
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                match line.strip_prefix("armed ") {
                    Some(ms) => armed_at = Some(ms.parse().map_err(|_| self.garbled(REVOKERS_FILE))?),
                    None => {
                        revokers.insert(unhex(line).ok_or_else(|| self.garbled(REVOKERS_FILE))?);
                    }
                }
            }
        }
        Ok(Revocations::new(*root, held, revokers, armed_at))
    }

    /// Keep the list just applied, replacing the one before. Written aside and renamed into place, so a crash leaves
    /// the old list or the new one and never half of either.
    pub fn write_revocation_list(&self, list: &RevocationList) -> io::Result<()> {
        self.make_dir()?;
        self.replace_atomically(REVOCATIONS_FILE, &list.encode_to_vec())
    }

    /// Keep when the floor armed and which revokers this connector has seen.
    pub fn write_revokers(&self, revocations: &Revocations) -> io::Result<()> {
        self.make_dir()?;
        let mut text = String::new();
        if let Some(ms) = revocations.armed_at() {
            text.push_str(&format!("armed {ms}\n"));
        }
        for principal in revocations.revokers() {
            text.push_str(&hex(principal));
            text.push('\n');
        }
        self.replace_atomically(REVOKERS_FILE, text.as_bytes())
    }

    fn replace_atomically(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let aside = format!("{name}.new");
        self.write_secret(&aside, bytes, true)?;
        fs::rename(self.dir.join(&aside), self.dir.join(name))
    }

    fn garbled(&self, name: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not what a connector wrote", self.dir.join(name).display()),
        )
    }

    fn seed(&self, name: &str) -> io::Result<Option<[u8; 32]>> {
        let Some(bytes) = self.read(name)? else { return Ok(None) };
        let text = String::from_utf8(bytes).map_err(|_| self.malformed(name))?;
        unhex(text.trim()).map(Some).ok_or_else(|| self.malformed(name))
    }

    fn malformed(&self, name: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not 32 bytes of hex; delete it to pair again", self.dir.join(name).display()),
        )
    }

    /// The file's bytes, `None` when it does not exist, and an error when anyone but its owner can read it.
    fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.dir.join(name);
        match fs::metadata(&path) {
            Ok(meta) => {
                check_private(&path, &meta)?;
                fs::read(&path).map(Some)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_secret(&self, name: &str, bytes: &[u8], replace: bool) -> io::Result<()> {
        let path = self.dir.join(name);
        let mut options = fs::OpenOptions::new();
        options.write(true).truncate(replace);
        if replace {
            options.create(true);
        } else {
            options.create_new(true);
        }
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&path).map_err(|e| {
            if !replace && e.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(e.kind(), format!("{} already exists: this connector already has keys", path.display()))
            } else {
                e
            }
        })?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn make_dir(&self) -> io::Result<()> {
        let mut options = fs::DirBuilder::new();
        options.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut options, 0o700);
        options.create(&self.dir)
    }
}

/// Refuse a key file anyone but its owner can read. The same rule ssh has, for the same reason: a private key in a
/// world-readable file is a private key that has been handed out, and the only honest time to say so is before it is
/// used.
#[cfg(unix)]
fn check_private(path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is readable by others (mode {mode:o}): chmod 600 it, or pair again", path.display()),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path, _meta: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

/// 32 bytes from 64 hex characters, and nothing else.
fn unhex(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("wmlbox-state-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn who_is_revoked_survives_a_restart_and_its_signer_lapsing() {
        use wmlhub_keys::revocation::sign_revocations;
        use wmlhub_keys::{CertSpec, account_id, issue, principal_id, scope};
        use wmlhub_proto::v1::Role;

        const SIGNED_AT: u64 = 1_800_000_000_000;
        let root = Identity::from_seed([1; 32]);
        let revoker = Identity::from_seed([2; 32]);
        let spec = |subject: &Identity, may_revoke: bool| CertSpec {
            subject: subject.public(),
            agreement_key: [9; 32],
            role: Role::Client,
            scopes: vec![scope::VIEW.into()],
            may_pair: false,
            may_revoke,
            // the revoker's certificate lapses an hour after it signs
            not_before_ms: SIGNED_AT - 3_600_000,
            not_after_ms: SIGNED_AT + 3_600_000,
            label: String::new(),
        };
        let revoker_chain = vec![issue(&root, &spec(&revoker, true)).unwrap()];
        let phone = Identity::from_seed([3; 32]);
        let phone_chain = vec![issue(&root, &spec(&phone, false)).unwrap()];
        let list = sign_revocations(
            &revoker,
            &revoker_chain,
            account_id(&root.public()),
            SIGNED_AT,
            &[principal_id(&phone.public())],
            &[],
        );

        let state = State::at(dir("revocations"));
        assert!(state.revocations(&root.public()).unwrap().armed_at().is_none(), "nothing kept: not armed");
        let mut kept = state.revocations(&root.public()).unwrap();
        kept.apply(&list, SIGNED_AT).unwrap();
        state.write_revocation_list(&list).unwrap();
        state.write_revokers(&kept).unwrap();

        // A restart a day later, the revoker's certificate long lapsed: the list it signed still stands.
        let back = state.revocations(&root.public()).unwrap();
        assert_eq!(back.armed_at(), Some(SIGNED_AT));
        assert_eq!(back.revokers().collect::<Vec<_>>(), vec![&principal_id(&revoker.public())]);
        let a_day_later = SIGNED_AT + 24 * 3_600_000;
        assert_eq!(back.may_grant(&phone_chain, a_day_later), Err(crate::revoked::NotNow::Revoked));

        // and a file that is not a list is refused, loudly, rather than read as "nobody is revoked"
        // (written privately, so what is wrong with it is its contents and not its permissions)
        state.write_secret(REVOCATIONS_FILE, b"not a list", true).unwrap();
        let err = state.revocations(&root.public()).unwrap_err();
        assert!(err.to_string().contains("is not a revocation list"), "{err}");
    }

    #[test]
    fn keys_survive_a_restart_and_are_not_regenerated() {
        let state = State::at(dir("restart"));
        assert!(state.keys().unwrap().is_none(), "nothing is there before pairing");
        let made = state.generate_keys().unwrap();
        let loaded = state.keys().unwrap().expect("the keys are there");
        assert_eq!(made.identity.public(), loaded.identity.public());
        assert_eq!(made.agreement.public(), loaded.agreement.public());
    }

    #[test]
    fn generating_twice_refuses_rather_than_replacing_an_identity() {
        let state = State::at(dir("twice"));
        state.generate_keys().unwrap();
        let again = state.generate_keys().unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        assert!(again.to_string().contains("already has keys"), "{again}");
    }

    #[test]
    fn what_a_pairing_gave_it_round_trips() {
        let state = State::at(dir("paired"));
        assert!(state.paired().unwrap().is_none());
        let paired = PairedWith { chain: Vec::new(), account_root: vec![3; 32], channel_key: vec![4; 32] };
        state.write_paired(&paired).unwrap();
        assert_eq!(state.paired().unwrap(), Some(paired));
        // pairing again replaces it, because a connector belongs to one account at a time
        let again = PairedWith { chain: Vec::new(), account_root: vec![5; 32], channel_key: vec![6; 32] };
        state.write_paired(&again).unwrap();
        assert_eq!(state.paired().unwrap(), Some(again));
    }

    #[test]
    fn a_malformed_key_file_says_which_file_and_what_to_do() {
        let state = State::at(dir("malformed"));
        state.generate_keys().unwrap();
        fs::write(state.dir().join(IDENTITY_FILE), "not hex\n").unwrap();
        let e = state.keys().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains(IDENTITY_FILE), "{e}");
        assert!(e.to_string().contains("pair again"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn a_key_anyone_can_read_is_refused_before_it_is_used() {
        use std::os::unix::fs::PermissionsExt;
        let state = State::at(dir("readable"));
        state.generate_keys().unwrap();
        let path = state.dir().join(IDENTITY_FILE);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "it is written private in the first place"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let e = state.keys().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("chmod 600"), "{e}");
    }

    #[test]
    fn hex_is_read_back_exactly() {
        assert_eq!(unhex(&hex(&[7u8; 32])), Some([7u8; 32]));
        assert_eq!(unhex(&hex(&[0u8; 31])), None, "too short");
        assert_eq!(unhex("g".repeat(64).as_str()), None, "not hex");
    }
}
