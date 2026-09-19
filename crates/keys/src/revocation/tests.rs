//! Revocation lists. Every refusal in [`RevocationError`] has a test that builds exactly that defect, and the three
//! things that are decisions rather than mechanics — a revoked delegate takes its devices with it, revoking a
//! certificate revokes its renewals, a replaced revoker is shut out — each have one of their own.

use super::*;
use crate::{CertSpec, issue, renew, scope};
use wmlhub_proto::v1::Role;

const NOW: u64 = 1_800_000_000_000;

fn id(n: u8) -> Identity {
    Identity::from_seed([n; 32])
}

fn spec(subject: &Identity, role: Role) -> CertSpec {
    CertSpec {
        subject: subject.public(),
        agreement_key: [9; 32],
        role,
        scopes: vec![scope::VIEW.into(), scope::DRIVE.into()],
        may_pair: false,
        may_revoke: false,
        not_before_ms: NOW - 10_000,
        not_after_ms: NOW + 10_000,
        label: String::new(),
    }
}

fn cert(issuer: &Identity, spec: &CertSpec) -> Certificate {
    issue(issuer, spec).expect("a certificate this issuer may make")
}

/// An account: its root, a runtime that holds `may_revoke`, a phone, a laptop that may pair, and a tablet it paired.
struct Account {
    root: Identity,
    runtime: Identity,
    runtime_chain: Vec<Certificate>,
    phone: Vec<Certificate>,
    laptop: Identity,
    laptop_cert: Certificate,
    tablet: Vec<Certificate>,
}

fn account() -> Account {
    let (root, runtime, phone, laptop, tablet) = (id(1), id(2), id(3), id(4), id(5));
    let runtime_chain = vec![cert(&root, &CertSpec { may_revoke: true, ..spec(&runtime, Role::Runtime) })];
    let laptop_cert = cert(&root, &CertSpec { may_pair: true, ..spec(&laptop, Role::Client) });
    let tablet = vec![cert(&laptop, &spec(&tablet, Role::Client)), laptop_cert.clone()];
    Account {
        phone: vec![cert(&root, &spec(&phone, Role::Client))],
        root,
        runtime,
        runtime_chain,
        laptop,
        laptop_cert,
        tablet,
    }
}

fn principal(chain: &[Certificate]) -> [u8; 32] {
    let body = CertificateBody::decode(chain[0].body.as_slice()).unwrap();
    principal_id(&body.subject.as_slice().try_into().unwrap())
}

impl Account {
    fn account(&self) -> [u8; 32] {
        account_id(&self.root.public())
    }

    fn list(&self, version: u64, principals: &[[u8; 32]], certificates: &[[u8; 32]]) -> RevocationList {
        sign_revocations(&self.runtime, &self.runtime_chain, self.account(), version, principals, certificates)
    }

    fn verify(&self, list: &RevocationList, held: Option<&Revoked>) -> Result<Revoked, RevocationError> {
        verify_revocations(&self.root.public(), list, NOW, held)
    }
}

#[test]
fn a_list_the_revoker_signed_verifies_and_names_what_it_revokes() {
    let a = account();
    let revoked = a.verify(&a.list(NOW, &[principal(&a.phone)], &[]), None).unwrap();
    assert_eq!(revoked.version, NOW);
    assert_eq!(revoked.signer, principal(&a.runtime_chain));
    assert!(revoked.revokes(&a.phone));
    assert!(!revoked.revokes(&a.tablet), "names one device, not the account");
    assert!(!revoked.revokes(&a.runtime_chain));
}

#[test]
fn a_revoked_delegate_takes_the_devices_it_paired_with_it() {
    // Revoking a laptop that may pair is what a person does when the laptop is lost, and the devices it paired are
    // exactly the ones in doubt then. A chain is revoked if anything in it is.
    let a = account();
    let revoked = a.verify(&a.list(NOW, &[principal(std::slice::from_ref(&a.laptop_cert))], &[]), None).unwrap();
    assert!(revoked.revokes(&a.tablet), "the tablet's chain passes through the laptop");
    assert!(!revoked.revokes(&a.phone), "the root paired the phone, and the root was not lost");
}

#[test]
fn revoking_one_certificate_revokes_its_renewals_and_not_the_device() {
    let a = account();
    let old = &a.phone[0];
    // A renewal re-grants exactly the revoked terms, so leaving it standing would let a renewer undo the revocation.
    let renewed = renew(&a.laptop, old, NOW - 1_000, NOW + 5_000).unwrap();
    let revoked = a.verify(&a.list(NOW, &[], &[certificate_hash(old)]), None).unwrap();
    assert!(revoked.revokes(std::slice::from_ref(old)));
    assert!(revoked.revokes(&[renewed, a.laptop_cert.clone()]), "a renewal of it");
    // A different certificate for the same device is untouched: by certificate is not by device.
    let reissued = cert(&a.root, &CertSpec { not_before_ms: NOW - 20_000, ..spec(&id(3), Role::Client) });
    assert!(!revoked.revokes(&[reissued]));
}

#[test]
fn a_revoker_that_has_been_replaced_signs_nothing() {
    // The runtime holding `may_revoke` is lost. The root grants it to a second runtime, whose first list names the
    // first. Its certificate still verifies, so the only thing that can stop it is the list the holder already has.
    let a = account();
    let second = id(6);
    let second_chain = vec![cert(&a.root, &CertSpec { may_revoke: true, ..spec(&second, Role::Runtime) })];
    let replace = sign_revocations(&second, &second_chain, a.account(), NOW - 2, &[principal(&a.runtime_chain)], &[]);
    let held = a.verify(&replace, None).unwrap();

    let from_the_lost_one = a.list(NOW - 1, &[principal(&a.phone)], &[]);
    assert_eq!(a.verify(&from_the_lost_one, Some(&held)).unwrap_err(), RevocationError::SignerRevoked);
    // and the new holder goes on signing
    let next = sign_revocations(&second, &second_chain, a.account(), NOW - 1, &[principal(&a.phone)], &[]);
    assert!(a.verify(&next, Some(&held)).is_ok());
}

#[test]
fn only_the_holder_of_may_revoke_can_sign() {
    let a = account();
    let phone = id(3);
    let list = sign_revocations(&phone, &a.phone, a.account(), NOW, &[principal(&a.tablet)], &[]);
    assert_eq!(a.verify(&list, None).unwrap_err(), RevocationError::NotRevoker);
}

#[test]
fn a_version_is_newer_than_the_one_held_and_no_more_than_a_minute_ahead() {
    let a = account();
    let held = a.verify(&a.list(NOW, &[], &[]), None).unwrap();
    assert_eq!(a.verify(&a.list(NOW, &[], &[]), Some(&held)).unwrap_err(), RevocationError::Stale, "the same version");
    assert_eq!(a.verify(&a.list(NOW - 1, &[], &[]), Some(&held)).unwrap_err(), RevocationError::Stale, "an older one");
    assert!(a.verify(&a.list(NOW + 1, &[], &[]), Some(&held)).is_ok());

    // A fast clock costs at most a minute: past that, the account would be locked out of revoking until it was reached.
    assert!(a.verify(&a.list(NOW + MAX_FUTURE_MS, &[], &[]), None).is_ok());
    assert_eq!(a.verify(&a.list(NOW + MAX_FUTURE_MS + 1, &[], &[]), None).unwrap_err(), RevocationError::FromTheFuture);
}

#[test]
fn a_list_for_another_account_is_never_applied() {
    let a = account();
    let list = sign_revocations(&a.runtime, &a.runtime_chain, [7; 32], NOW, &[principal(&a.phone)], &[]);
    assert_eq!(a.verify(&list, None).unwrap_err(), RevocationError::WrongAccount);
}

#[test]
fn the_signers_chain_must_verify_now() {
    let a = account();
    let lapsed = vec![cert(
        &a.root,
        &CertSpec {
            may_revoke: true,
            not_before_ms: NOW - 20_000,
            not_after_ms: NOW - 1,
            ..spec(&a.runtime, Role::Runtime)
        },
    )];
    let list = sign_revocations(&a.runtime, &lapsed, a.account(), NOW, &[], &[]);
    assert_eq!(a.verify(&list, None).unwrap_err(), RevocationError::Chain(ChainError::Expired), "a lapsed revoker");

    let other_root = id(8);
    let elsewhere = vec![cert(&other_root, &CertSpec { may_revoke: true, ..spec(&a.runtime, Role::Runtime) })];
    let list = sign_revocations(&a.runtime, &elsewhere, a.account(), NOW, &[], &[]);
    assert!(matches!(a.verify(&list, None).unwrap_err(), RevocationError::Chain(_)), "a chain to another root");
}

#[test]
fn a_signature_covers_every_byte() {
    let a = account();
    let mut list = a.list(NOW, &[principal(&a.phone)], &[]);
    list.signature[0] ^= 1;
    assert_eq!(a.verify(&list, None).unwrap_err(), RevocationError::Signature);

    // an entry changed after signing: the phone's revocation moved onto the tablet
    let mut list = a.list(NOW, &[principal(&a.phone)], &[]);
    let mut body = RevocationBody::decode(list.body.as_slice()).unwrap();
    body.principals = vec![principal(&a.tablet).to_vec()];
    list.body = body.encode_to_vec();
    assert_eq!(a.verify(&list, None).unwrap_err(), RevocationError::Signature);
}

#[test]
fn a_list_is_bounded_before_it_is_read() {
    let a = account();
    // distinct entries, n in the first four bytes
    let entries = |n: usize| -> Vec<[u8; 32]> {
        (0..n as u32)
            .map(|i| {
                let mut e = [0u8; 32];
                e[..4].copy_from_slice(&i.to_le_bytes());
                e
            })
            .collect()
    };
    let full = a.list(NOW, &entries(MAX_REVOKED), &[]);
    assert!(full.body.len() <= MAX_REVOCATION_BYTES, "a full list fits the byte bound, or the two limits disagree");
    assert!(a.verify(&full, None).is_ok(), "a full list verifies");
    let over = a.list(NOW, &entries(MAX_REVOKED + 1), &[]);
    assert_eq!(a.verify(&over, None).unwrap_err(), RevocationError::Malformed, "one past the limit");

    let mut short = a.list(NOW, &[principal(&a.phone)], &[]);
    let mut body = RevocationBody::decode(short.body.as_slice()).unwrap();
    body.principals = vec![vec![1; 31]];
    short.body = body.encode_to_vec();
    assert_eq!(a.verify(&short, None).unwrap_err(), RevocationError::Malformed, "an entry that is not 32 bytes");

    let huge = RevocationList { body: vec![0; MAX_REVOCATION_BYTES + 1], ..a.list(NOW, &[], &[]) };
    assert_eq!(a.verify(&huge, None).unwrap_err(), RevocationError::Malformed, "refused before it is decoded");

    let garbage = RevocationList { body: vec![0xff; 64], ..a.list(NOW, &[], &[]) };
    assert_eq!(a.verify(&garbage, None).unwrap_err(), RevocationError::Malformed);
}

#[test]
fn a_certificate_that_does_not_decode_counts_as_revoked() {
    // A publisher asking this is deciding whether to hand over a key, and "I could not tell" is not a yes.
    let a = account();
    let revoked = a.verify(&a.list(NOW, &[], &[]), None).unwrap();
    assert!(revoked.is_empty());
    assert!(revoked.revokes(&[Certificate { body: vec![0xff; 16], signature: vec![] }]));
}
