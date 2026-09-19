//! What a box connector knows about the account's revocations, and whether that lets it hand its key to someone new
//! (docs/design/revocation.md §A).
//!
//! A connector grants its stream key to anything with a valid certificate that asks, and has no allowlist of its own.
//! So without this, a device the runtime has revoked goes on being granted box telemetry until its certificate
//! expires. With it, the connector applies the list the account's revoker signs, rotates its key when the list names
//! somebody new, and refuses the new key to anything the list names.
//!
//! **The floor.** A connector that only talks through the hub cannot tell a withheld list from no list, so a hub that
//! stayed silent could keep a revoked device receiving new grants for as long as its certificate lasts. Once armed, a
//! connector refuses NEW grants while the list it holds is more than [`FRESHNESS_FLOOR_MS`] old, and the revoker
//! re-signs often enough that an honest hub always delivers a younger one. Silence becomes an outage rather than a
//! bypass. A device already reading keeps reading; only a rotation ends that.
//!
//! **Arming.** The floor applies from the first time this connector sees a revoker in a presence chain, or applies a
//! list, and it stays armed for good. Before either it behaves as it did before revocation existed. That is not a
//! softening but a necessity: an account with no revoker has no lists to be fresh, and a floor that refused then would
//! switch off every box on it. What it leaves open is a hub that hides the revoker from a connector's very first
//! connection onwards; naming it here is the point.

use std::collections::BTreeSet;

use wmlhub_keys::PublicKey;
use wmlhub_keys::revocation::{RevocationError, Revoked, verify_revocations};
use wmlhub_proto::v1::{Certificate, RevocationList};

/// How old a held list may be before a connector stops granting its key to anyone new: 7 days, decided 2026-09-19
/// (window-ml `tmp/chat-page-revocation-floor-decided.md`).
///
/// A constant here rather than a field of the list, because a floor the signer chooses is a floor a compromised signer
/// sets to a year. The revoker re-signs on every reconnect and at least daily, so an honest hub always delivers a list
/// far younger than this, and it bites only after a week with the revoker offline.
pub const FRESHNESS_FLOOR_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Why a device may not be granted the key now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotNow {
    /// the list names something in the asker's chain
    Revoked,
    /// the floor is armed and the list is older than it, or no list has come since it armed: the revoker has not been
    /// heard from, epoch ms, since this time
    Stale { since_ms: u64 },
}

/// A list that verified and was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// it names somebody the previous list did not, so the key must rotate for them to be left out of the new one
    pub rotate: bool,
}

/// This connector's view of the account's revocations.
#[derive(Debug)]
pub struct Revocations {
    root: PublicKey,
    held: Option<Revoked>,
    /// principals seen holding `may_revoke`, whose revocations channels this connector subscribes to
    revokers: BTreeSet<[u8; 32]>,
    /// when the floor armed, epoch ms, or `None` while it has not
    armed_at: Option<u64>,
}

impl Revocations {
    /// Where a connector starts: what it kept from its last run, or nothing.
    pub fn new(root: PublicKey, held: Option<Revoked>, revokers: BTreeSet<[u8; 32]>, armed_at: Option<u64>) -> Self {
        Self { root, held, revokers, armed_at }
    }

    /// The account root lists and revokers are verified against.
    pub fn root(&self) -> &PublicKey {
        &self.root
    }

    /// The principals whose revocations channels to read.
    pub fn revokers(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.revokers.iter()
    }

    pub fn armed_at(&self) -> Option<u64> {
        self.armed_at
    }

    pub fn held(&self) -> Option<&Revoked> {
        self.held.as_ref()
    }

    /// A verified presence chain showed `principal` holding `may_revoke`. True when it is new, which is the caller's
    /// cue to subscribe to its channel and to write the state down.
    pub fn saw_revoker(&mut self, principal: [u8; 32], now_ms: u64) -> bool {
        let armed = self.armed_at.is_none();
        self.armed_at.get_or_insert(now_ms);
        self.revokers.insert(principal) || armed
    }

    /// A list arrived. Applied when it verifies against the root and against the list already held; the caller then
    /// writes it down, and rotates the key if [`Applied::rotate`] says so.
    pub fn apply(&mut self, list: &RevocationList, now_ms: u64) -> Result<Applied, RevocationError> {
        let revoked = verify_revocations(&self.root, list, now_ms, self.held.as_ref())?;
        let rotate = revoked.adds_to(self.held.as_ref());
        self.armed_at.get_or_insert(now_ms);
        self.revokers.insert(revoked.signer);
        self.held = Some(revoked);
        Ok(Applied { rotate })
    }

    /// May the principal whose verified chain is `chain` be granted the key now?
    pub fn may_grant(&self, chain: &[Certificate], now_ms: u64) -> Result<(), NotNow> {
        if self.held.as_ref().is_some_and(|held| held.revokes(chain)) {
            return Err(NotNow::Revoked);
        }
        let Some(armed_at) = self.armed_at else { return Ok(()) };
        // With no list yet, the clock runs from arming: a revoker gets a floor's length to publish its first one.
        let fresh_since = self.held.as_ref().map_or(armed_at, |held| held.version);
        if now_ms.saturating_sub(fresh_since) > FRESHNESS_FLOOR_MS {
            return Err(NotNow::Stale { since_ms: fresh_since });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wmlhub_keys::revocation::sign_revocations;
    use wmlhub_keys::{CertSpec, Identity, account_id, issue, principal_id, scope};
    use wmlhub_proto::v1::Role;

    const NOW: u64 = 1_800_000_000_000;
    const DAY: u64 = 24 * 60 * 60 * 1_000;

    struct Account {
        root: Identity,
        revoker: Identity,
        revoker_chain: Vec<Certificate>,
        phone: Vec<Certificate>,
        tablet: Vec<Certificate>,
    }

    fn cert(issuer: &Identity, subject: &Identity, may_revoke: bool) -> Certificate {
        let spec = CertSpec {
            subject: subject.public(),
            agreement_key: [9; 32],
            role: Role::Client,
            scopes: vec![scope::VIEW.into()],
            may_pair: false,
            may_revoke,
            not_before_ms: NOW - 30 * DAY,
            not_after_ms: NOW + 30 * DAY,
            label: String::new(),
        };
        issue(issuer, &spec).unwrap()
    }

    fn account() -> Account {
        let root = Identity::from_seed([1; 32]);
        let revoker = Identity::from_seed([2; 32]);
        let revoker_chain = vec![cert(&root, &revoker, true)];
        let phone = vec![cert(&root, &Identity::from_seed([3; 32]), false)];
        let tablet = vec![cert(&root, &Identity::from_seed([4; 32]), false)];
        Account { root, revoker, revoker_chain, phone, tablet }
    }

    impl Account {
        fn list(&self, version: u64, revoked: &[&[Certificate]]) -> RevocationList {
            let principals: Vec<[u8; 32]> = revoked.iter().map(|chain| principal_of(chain)).collect();
            sign_revocations(
                &self.revoker,
                &self.revoker_chain,
                account_id(&self.root.public()),
                version,
                &principals,
                &[],
            )
        }

        fn fresh(&self) -> Revocations {
            Revocations::new(self.root.public(), None, BTreeSet::new(), None)
        }
    }

    fn principal_of(chain: &[Certificate]) -> [u8; 32] {
        use wmlhub_proto::prost::Message;
        let body = wmlhub_proto::v1::CertificateBody::decode(chain[0].body.as_slice()).unwrap();
        principal_id(&body.subject.as_slice().try_into().unwrap())
    }

    #[test]
    fn before_anything_arms_it_every_valid_chain_is_granted_forever() {
        // No revoker has ever been seen, so no list will ever come, and a floor now would switch the box off.
        let a = account();
        let r = a.fresh();
        assert_eq!(r.may_grant(&a.phone, NOW), Ok(()));
        assert_eq!(r.may_grant(&a.phone, NOW + 365 * DAY), Ok(()));
    }

    #[test]
    fn a_revoker_gets_a_floor_s_length_to_publish_its_first_list() {
        let a = account();
        let mut r = a.fresh();
        assert!(r.saw_revoker(principal_of(&a.revoker_chain), NOW), "new, so subscribe");
        assert!(!r.saw_revoker(principal_of(&a.revoker_chain), NOW + 1), "and only once");
        assert_eq!(r.may_grant(&a.phone, NOW + FRESHNESS_FLOOR_MS), Ok(()));
        assert_eq!(r.may_grant(&a.phone, NOW + FRESHNESS_FLOOR_MS + 1), Err(NotNow::Stale { since_ms: NOW }));
    }

    #[test]
    fn a_named_device_is_refused_and_the_rest_are_not() {
        let a = account();
        let mut r = a.fresh();
        assert_eq!(r.apply(&a.list(NOW, &[&a.phone]), NOW), Ok(Applied { rotate: true }));
        assert_eq!(r.may_grant(&a.phone, NOW), Err(NotNow::Revoked));
        assert_eq!(r.may_grant(&a.tablet, NOW), Ok(()));
        assert_eq!(r.revokers().collect::<Vec<_>>(), vec![&principal_of(&a.revoker_chain)], "applying a list arms it");
    }

    #[test]
    fn a_list_older_than_the_floor_stops_new_grants_and_a_fresh_one_restarts_them() {
        let a = account();
        let mut r = a.fresh();
        r.apply(&a.list(NOW, &[&a.phone]), NOW).unwrap();
        let later = NOW + FRESHNESS_FLOOR_MS + 1;
        assert_eq!(r.may_grant(&a.tablet, later), Err(NotNow::Stale { since_ms: NOW }), "silence, for a week");
        // the revoker re-signs the same entries on its next connect
        assert_eq!(r.apply(&a.list(later, &[&a.phone]), later), Ok(Applied { rotate: false }), "nobody new");
        assert_eq!(r.may_grant(&a.tablet, later), Ok(()));
        assert_eq!(r.may_grant(&a.phone, later), Err(NotNow::Revoked), "and the revoked stay revoked");
    }

    #[test]
    fn the_key_rotates_only_when_somebody_new_is_named() {
        let a = account();
        let mut r = a.fresh();
        assert_eq!(r.apply(&a.list(NOW - 3, &[]), NOW), Ok(Applied { rotate: false }), "an empty list");
        assert_eq!(r.apply(&a.list(NOW - 2, &[&a.phone]), NOW), Ok(Applied { rotate: true }));
        assert_eq!(r.apply(&a.list(NOW - 1, &[&a.phone]), NOW), Ok(Applied { rotate: false }), "re-signed");
        assert_eq!(r.apply(&a.list(NOW, &[&a.phone, &a.tablet]), NOW), Ok(Applied { rotate: true }));
    }

    #[test]
    fn a_list_that_does_not_verify_changes_nothing() {
        let a = account();
        let mut r = a.fresh();
        r.apply(&a.list(NOW, &[&a.phone]), NOW).unwrap();
        let stale = a.list(NOW - 1, &[]);
        assert_eq!(r.apply(&stale, NOW), Err(RevocationError::Stale));
        assert_eq!(r.may_grant(&a.phone, NOW), Err(NotNow::Revoked), "the older list did not undo the newer one");
    }
}
