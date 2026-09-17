//! Certificate chains and hellos. Each refusal in [`ChainError`] has a test that builds exactly that defect, since a
//! verifier that accepts a forged chain looks identical to a working one until someone forges one.

use super::*;
use wmlhub_proto::prost::Message;

const NOW: u64 = 1_800_000_000_000;

fn id(n: u8) -> Identity {
    Identity::from_seed([n; 32])
}

fn spec(subject: &Identity) -> CertSpec {
    CertSpec {
        subject: subject.public(),
        agreement_key: [9; 32],
        role: Role::Client,
        scopes: vec![Scope::View, Scope::Drive],
        may_pair: false,
        not_before_ms: NOW - 1000,
        not_after_ms: NOW + 1000,
        label: "phone".into(),
    }
}

#[test]
fn a_leaf_issued_by_the_root_verifies() {
    let (root, phone) = (id(1), id(2));
    let v = verify_chain(&root.public(), &[issue(&root, &spec(&phone))], NOW).unwrap();
    assert_eq!(v.account, account_id(&root.public()));
    assert_eq!(v.principal, principal_id(&phone.public()));
    assert_eq!(v.leaf.label, "phone");
}

#[test]
fn a_leaf_issued_by_a_delegate_verifies() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue(&root, &CertSpec { may_pair: true, ..spec(&laptop) });
    let leaf = issue(&laptop, &spec(&phone));
    assert!(verify_chain(&root.public(), &[leaf, delegate], NOW).is_ok());
}

#[test]
fn a_chain_to_another_root_is_refused() {
    let (root, other, phone) = (id(1), id(9), id(2));
    let cert = issue(&other, &spec(&phone));
    assert_eq!(verify_chain(&root.public(), &[cert], NOW).unwrap_err(), ChainError::Issuer);
}

#[test]
fn a_tampered_body_is_refused() {
    let (root, phone) = (id(1), id(2));
    let mut cert = issue(&root, &spec(&phone));
    // grant APPROVE by editing the encoded body; the signature no longer covers it
    let mut body = CertificateBody::decode(cert.body.as_slice()).unwrap();
    body.scopes.push(Scope::Approve as i32);
    cert.body = body.encode_to_vec();
    assert_eq!(verify_chain(&root.public(), &[cert], NOW).unwrap_err(), ChainError::Signature);
}

#[test]
fn a_certificate_signature_cannot_be_used_as_a_hello_signature() {
    let (root, phone) = (id(1), id(2));
    let cert = issue(&root, &spec(&phone));
    // the root's signature over the body, presented as the root "saying hello" with the body as transcript
    assert!(verify_hello(&root.public(), &cert.body, &cert.signature).is_err());
}

#[test]
fn an_intermediate_without_may_pair_is_refused() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let not_delegate = issue(&root, &spec(&laptop));
    let leaf = issue(&laptop, &spec(&phone));
    assert_eq!(verify_chain(&root.public(), &[leaf, not_delegate], NOW).unwrap_err(), ChainError::NotDelegated);
}

#[test]
fn a_delegate_cannot_grant_a_scope_it_does_not_hold() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue(&root, &CertSpec { may_pair: true, ..spec(&laptop) });
    let leaf = issue(&laptop, &CertSpec { scopes: vec![Scope::View, Scope::Approve], ..spec(&phone) });
    assert_eq!(verify_chain(&root.public(), &[leaf, delegate], NOW).unwrap_err(), ChainError::ScopeWidened);
}

#[test]
fn a_leaf_cannot_outlive_its_delegate() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue(&root, &CertSpec { may_pair: true, ..spec(&laptop) });
    let forever = issue(&laptop, &CertSpec { not_after_ms: 0, ..spec(&phone) });
    let longer = issue(&laptop, &CertSpec { not_after_ms: NOW + 5000, ..spec(&phone) });
    let chain = |leaf: Certificate| verify_chain(&root.public(), &[leaf, delegate.clone()], NOW);
    assert_eq!(chain(forever).unwrap_err(), ChainError::OutlivesIssuer);
    assert_eq!(chain(longer).unwrap_err(), ChainError::OutlivesIssuer);
}

#[test]
fn expiry_and_not_yet_valid_are_refused_and_zero_means_no_expiry() {
    let (root, phone) = (id(1), id(2));
    let cert = issue(&root, &spec(&phone));
    assert_eq!(verify_chain(&root.public(), std::slice::from_ref(&cert), NOW + 1001).unwrap_err(), ChainError::Expired);
    assert_eq!(verify_chain(&root.public(), &[cert], NOW - 1001).unwrap_err(), ChainError::Expired);
    let forever = issue(&root, &CertSpec { not_after_ms: 0, ..spec(&phone) });
    assert!(verify_chain(&root.public(), &[forever], u64::MAX).is_ok());
}

#[test]
fn an_empty_or_too_long_chain_is_refused() {
    let (root, a, b, c) = (id(1), id(2), id(3), id(4));
    assert_eq!(verify_chain(&root.public(), &[], NOW).unwrap_err(), ChainError::Length);
    let d1 = issue(&root, &CertSpec { may_pair: true, ..spec(&a) });
    let d2 = issue(&a, &CertSpec { may_pair: true, ..spec(&b) });
    let leaf = issue(&b, &spec(&c));
    assert_eq!(verify_chain(&root.public(), &[leaf, d2, d1], NOW).unwrap_err(), ChainError::Length);
}

#[test]
fn the_root_cannot_log_in_as_a_principal() {
    let root = id(1);
    let cert = issue(&root, &spec(&root));
    assert_eq!(verify_chain(&root.public(), &[cert], NOW).unwrap_err(), ChainError::RootAsSubject);
}

#[test]
fn a_malformed_key_is_refused_not_a_panic() {
    let root = id(1);
    let mut cert = issue(&root, &spec(&id(2)));
    let mut body = CertificateBody::decode(cert.body.as_slice()).unwrap();
    body.subject.truncate(31);
    cert.body = body.encode_to_vec();
    assert_eq!(verify_chain(&root.public(), &[cert], NOW).unwrap_err(), ChainError::Malformed);
    let garbage = Certificate { body: vec![0xff; 7], signature: vec![] };
    assert_eq!(verify_chain(&root.public(), &[garbage], NOW).unwrap_err(), ChainError::Malformed);
}

#[test]
fn a_hello_verifies_only_for_its_own_hub_nonce_principal_role_and_account() {
    let phone = id(2);
    let principal = principal_id(&phone.public());
    let account = [7u8; 32];
    let base = hello_transcript("hub.example", &[1; 32], &principal, Role::Client, &account);
    let sig = sign_hello(&phone, &base);
    assert!(verify_hello(&phone.public(), &base, &sig).is_ok());

    let variants = [
        hello_transcript("other.example", &[1; 32], &principal, Role::Client, &account),
        hello_transcript("hub.example", &[2; 32], &principal, Role::Client, &account),
        hello_transcript("hub.example", &[1; 32], &[0; 32], Role::Client, &account),
        hello_transcript("hub.example", &[1; 32], &principal, Role::Runtime, &account),
        hello_transcript("hub.example", &[1; 32], &principal, Role::Client, &[8; 32]),
    ];
    for v in variants {
        assert!(verify_hello(&phone.public(), &v, &sig).is_err());
    }
    assert!(verify_hello(&id(3).public(), &base, &sig).is_err());
}

#[test]
fn transcript_fields_cannot_be_shifted_between_each_other() {
    // length prefixes: moving a byte from the hub name into the nonce changes the transcript
    let a = hello_transcript("ab", b"c", b"p", Role::Client, &[0; 32]);
    let b = hello_transcript("a", b"bc", b"p", Role::Client, &[0; 32]);
    assert_ne!(a, b);
}
