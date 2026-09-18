//! Certificate chains and hellos. Each refusal in [`ChainError`] has a test that builds exactly that defect, since a
//! verifier that accepts a forged chain looks identical to a working one until someone forges one.

use super::*;

/// `issue`, for the specs a test means to be valid. The ones that are not are signed with `sign_certificate`, since
/// the issuer now refuses what a verifier would reject.
fn issue_ok(issuer: &Identity, spec: &CertSpec) -> Certificate {
    issue(issuer, spec).expect("a certificate this issuer may make")
}
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
        scopes: vec![scope::VIEW.into(), scope::DRIVE.into()],
        may_pair: false,
        may_revoke: false,
        not_before_ms: NOW - 1000,
        not_after_ms: NOW + 1000,
        label: "phone".into(),
    }
}

#[test]
fn a_leaf_issued_by_the_root_verifies() {
    let (root, phone) = (id(1), id(2));
    let v = verify_chain(&root.public(), &[issue_ok(&root, &spec(&phone))], NOW).unwrap();
    assert_eq!(v.account, account_id(&root.public()));
    assert_eq!(v.principal, principal_id(&phone.public()));
    assert_eq!(v.leaf.label, "phone");
}

#[test]
fn a_leaf_issued_by_a_delegate_verifies() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, ..spec(&laptop) });
    let leaf = issue_ok(&laptop, &spec(&phone));
    assert!(verify_chain(&root.public(), &[leaf, delegate], NOW).is_ok());
}

#[test]
fn a_chain_to_another_root_is_refused() {
    let (root, other, phone) = (id(1), id(9), id(2));
    let cert = issue_ok(&other, &spec(&phone));
    assert_eq!(verify_chain(&root.public(), &[cert], NOW).unwrap_err(), ChainError::Issuer);
}

#[test]
fn a_tampered_body_is_refused() {
    let (root, phone) = (id(1), id(2));
    let mut cert = issue_ok(&root, &spec(&phone));
    // grant APPROVE by editing the encoded body; the signature no longer covers it
    let mut body = CertificateBody::decode(cert.body.as_slice()).unwrap();
    body.scopes.push(scope::APPROVE.into());
    cert.body = body.encode_to_vec();
    assert_eq!(verify_chain(&root.public(), &[cert], NOW).unwrap_err(), ChainError::Signature);
}

#[test]
fn command_and_hello_signatures_cannot_stand_in_for_each_other() {
    let phone = id(2);
    let message = b"the same bytes, signed for two purposes";
    let as_hello = sign_hello(&phone, message);
    let as_command = sign_command(&phone, message);
    assert!(verify_command(&phone.public(), message, &as_command).is_ok());
    assert!(verify_command(&phone.public(), message, &as_hello).is_err());
    assert!(verify_hello(&phone.public(), message, &as_command).is_err());
}

#[test]
fn a_certificate_signature_cannot_be_used_as_a_hello_signature() {
    let (root, phone) = (id(1), id(2));
    let cert = issue_ok(&root, &spec(&phone));
    // the root's signature over the body, presented as the root "saying hello" with the body as transcript
    assert!(verify_hello(&root.public(), &cert.body, &cert.signature).is_err());
}

#[test]
fn an_intermediate_without_may_pair_is_refused() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let not_delegate = issue_ok(&root, &spec(&laptop));
    let leaf = issue_ok(&laptop, &spec(&phone));
    assert_eq!(verify_chain(&root.public(), &[leaf, not_delegate], NOW).unwrap_err(), ChainError::NotDelegated);
}

#[test]
fn a_delegate_cannot_grant_a_scope_it_does_not_hold() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, ..spec(&laptop) });
    let leaf = issue_ok(&laptop, &CertSpec { scopes: vec![scope::VIEW.into(), scope::APPROVE.into()], ..spec(&phone) });
    assert_eq!(verify_chain(&root.public(), &[leaf, delegate], NOW).unwrap_err(), ChainError::ScopeWidened);
}

#[test]
fn a_leaf_cannot_outlive_its_delegate() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, ..spec(&laptop) });
    let longer = issue_ok(&laptop, &CertSpec { not_after_ms: NOW + 5000, ..spec(&phone) });
    let chain = |leaf: Certificate| verify_chain(&root.public(), &[leaf, delegate.clone()], NOW);
    assert_eq!(chain(longer).unwrap_err(), ChainError::OutlivesIssuer);
}

#[test]
fn expired_and_not_yet_valid_are_both_refused() {
    let (root, phone) = (id(1), id(2));
    let cert = issue_ok(&root, &spec(&phone));
    assert_eq!(verify_chain(&root.public(), std::slice::from_ref(&cert), NOW + 1001).unwrap_err(), ChainError::Expired);
    assert_eq!(verify_chain(&root.public(), &[cert], NOW - 1001).unwrap_err(), ChainError::Expired);
}

#[test]
fn a_certificate_must_carry_a_window_and_may_not_outlast_the_maximum() {
    // Expiry is the revocation that works with nobody online, so "valid forever" is not something a certificate can
    // say: a device that stops being renewed stops having access, however many lists were lost.
    let (root, phone) = (id(1), id(2));
    // signed around the issuer, because `issue` refuses these too: what is under test here is the VERIFIER
    let chain = |spec: CertSpec| verify_chain(&root.public(), &[sign_certificate(&root, &spec)], NOW);
    for refused in [
        CertSpec { not_after_ms: 0, ..spec(&phone) },
        CertSpec { not_before_ms: 0, ..spec(&phone) },
        CertSpec { not_after_ms: NOW + MAX_CERTIFICATE_MS + 1, ..spec(&phone) },
    ] {
        assert!(issue(&root, &refused).is_err(), "the issuer refuses it as well");
    }
    assert_eq!(chain(CertSpec { not_after_ms: 0, ..spec(&phone) }).unwrap_err(), ChainError::Unbounded);
    assert_eq!(chain(CertSpec { not_before_ms: 0, ..spec(&phone) }).unwrap_err(), ChainError::Unbounded);
    assert_eq!(
        chain(CertSpec { not_after_ms: NOW + MAX_CERTIFICATE_MS + 1, ..spec(&phone) }).unwrap_err(),
        ChainError::TooLong,
        "a window one millisecond past the maximum"
    );
    assert_eq!(
        chain(CertSpec { not_after_ms: NOW - 1000, ..spec(&phone) }).unwrap_err(),
        ChainError::TooLong,
        "a window that ends before it begins"
    );
    // and the longest window there is, at its edge
    let longest = CertSpec { not_before_ms: NOW, not_after_ms: NOW + MAX_CERTIFICATE_MS, ..spec(&phone) };
    assert!(chain(longest).is_ok());
}

#[test]
fn a_box_connector_may_neither_pair_nor_approve() {
    // It relays one machine's telemetry. Encoding that beats documenting it: an issuer that gets it wrong is refused
    // rather than trusted.
    let (root, connector) = (id(1), id(2));
    let as_connector = |spec: CertSpec| CertSpec { role: Role::BoxConnector, ..spec };
    // the issuer refuses these too, so the verifier is checked on certificates signed around it
    let chain = |spec: CertSpec| verify_chain(&root.public(), &[sign_certificate(&root, &spec)], NOW);
    let may_pair = as_connector(CertSpec { may_pair: true, ..spec(&connector) });
    assert!(issue(&root, &may_pair).is_err(), "the issuer refuses it as well");
    assert_eq!(chain(may_pair).unwrap_err(), ChainError::RoleNotPermitted);
    for forbidden in BOX_CONNECTOR_FORBIDS {
        let scopes = vec![scope::VIEW.into(), forbidden.into()];
        let refused = as_connector(CertSpec { scopes, ..spec(&connector) });
        assert!(issue(&root, &refused).is_err(), "{forbidden}: the issuer refuses it as well");
        assert_eq!(chain(refused).unwrap_err(), ChainError::RoleNotPermitted, "{forbidden}");
    }
    // what it may hold
    let ordinary = as_connector(CertSpec { scopes: vec![scope::VIEW.into()], ..spec(&connector) });
    assert!(chain(ordinary).is_ok());
    // and the same scopes on a client are fine: the rule is about the role, not the names
    let client = CertSpec { scopes: vec![scope::APPROVE.into()], ..spec(&connector) };
    assert!(chain(client).is_ok());
}

#[test]
fn an_empty_or_too_long_chain_is_refused() {
    let (root, a, b, c) = (id(1), id(2), id(3), id(4));
    assert_eq!(verify_chain(&root.public(), &[], NOW).unwrap_err(), ChainError::Length);
    let d1 = issue_ok(&root, &CertSpec { may_pair: true, ..spec(&a) });
    let d2 = issue_ok(&a, &CertSpec { may_pair: true, ..spec(&b) });
    let leaf = issue_ok(&b, &spec(&c));
    assert_eq!(verify_chain(&root.public(), &[leaf, d2, d1], NOW).unwrap_err(), ChainError::Length);
}

#[test]
fn the_root_cannot_log_in_as_a_principal() {
    let root = id(1);
    let cert = issue_ok(&root, &spec(&root));
    assert_eq!(verify_chain(&root.public(), &[cert], NOW).unwrap_err(), ChainError::RootAsSubject);
}

#[test]
fn a_malformed_key_is_refused_not_a_panic() {
    let root = id(1);
    let mut cert = issue_ok(&root, &spec(&id(2)));
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

/// A leaf signed by a key the attacker holds, under a forged "delegate" whose own signature is garbage. The scope
/// comparison used to run before the delegate's signature was checked, over unbounded lists: 250,000 scopes each
/// (a 500 KB hello, from nobody) took 2.7 s of hub CPU on a tokio worker. Bodies are now bounded before anything else.
fn forged_pair(delegate_scopes: Vec<String>, leaf_scopes: Vec<String>, label: &str) -> [Certificate; 2] {
    let (root, attacker, phone) = (id(1), id(2), id(3));
    let mut parent =
        CertificateBody::decode(issue_ok(&root, &CertSpec { may_pair: true, ..spec(&attacker) }).body.as_slice())
            .unwrap();
    parent.scopes = delegate_scopes;
    let delegate = Certificate { body: parent.encode_to_vec(), signature: vec![0; 64] };
    let leaf = issue_ok(&attacker, &CertSpec { scopes: leaf_scopes, label: label.into(), ..spec(&phone) });
    [leaf, delegate]
}

#[test]
fn an_oversized_certificate_is_refused_before_its_scopes_are_compared() {
    let many: Vec<String> = vec!["view".into(); 100_000];
    let chain = forged_pair(many.clone(), many, "");
    assert_eq!(verify_chain(&id(1).public(), &chain, NOW).unwrap_err(), ChainError::Malformed);
}

#[test]
fn every_certificate_bound_is_enforced_at_its_edge() {
    let root = id(1).public();
    let names = |n: usize| (0..n).map(|i| format!("s{i}")).collect::<Vec<_>>();
    // at the limits: refused only for the forged delegate's signature, so every bound passed
    let at = forged_pair(names(MAX_SCOPES), names(MAX_SCOPES), &"l".repeat(MAX_LABEL_BYTES));
    assert_eq!(verify_chain(&root, &at, NOW).unwrap_err(), ChainError::Signature);
    let long_name = vec!["a".repeat(MAX_SCOPE_BYTES)];
    assert_eq!(
        verify_chain(&root, &forged_pair(long_name.clone(), long_name, ""), NOW).unwrap_err(),
        ChainError::Signature
    );
    // one past each
    for chain in [
        forged_pair(names(MAX_SCOPES), names(MAX_SCOPES + 1), ""),
        forged_pair(vec![], vec!["a".repeat(MAX_SCOPE_BYTES + 1)], ""),
        forged_pair(vec![], vec![String::new()], ""),
        forged_pair(vec![], vec![], &"l".repeat(MAX_LABEL_BYTES + 1)),
    ] {
        assert_eq!(verify_chain(&root, &chain, NOW).unwrap_err(), ChainError::Malformed);
    }
}

#[test]
fn a_scope_name_outside_the_alphabet_is_refused() {
    let root = id(1).public();
    for bad in ["View", "drive ", "ap\u{0}prove", "scr\neen", "é"] {
        let chain = forged_pair(vec![], vec![bad.into()], "");
        assert_eq!(verify_chain(&root, &chain, NOW).unwrap_err(), ChainError::Malformed, "{bad:?}");
    }
}

#[test]
fn a_certificate_body_over_the_byte_limit_is_refused() {
    let (root, phone) = (id(1), id(2));
    let mut cert = issue_ok(&root, &spec(&phone));
    // An unknown field (tag 15, length-delimited) decodes and is ignored, so only the byte limit can refuse this.
    cert.body.push(15 << 3 | 2);
    cert.body.extend_from_slice(&[0x80, 0x08]); // varint 1024
    cert.body.extend_from_slice(&[0; 1024]);
    cert.signature = root.sign(CERT_LABEL, &cert.body);
    assert_eq!(verify_chain(&root.public(), &[cert], NOW).unwrap_err(), ChainError::Malformed);
}

#[test]
fn a_scope_name_no_runtime_knows_yet_verifies_and_attenuates() {
    // The set is open: a name this hub has never heard of must still verify and attenuate. `control` is not the
    // example any more, because it is one of the few the root alone may grant (NEVER_DELEGABLE).
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let control = || vec![scope::VIEW.to_string(), "dictate".to_string()];
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, scopes: control(), ..spec(&laptop) });
    let leaf = issue_ok(&laptop, &CertSpec { scopes: control(), ..spec(&phone) });
    let v = verify_chain(&root.public(), &[leaf, delegate], NOW).unwrap();
    assert_eq!(v.leaf.scopes, control());
    // and a delegate that does not hold it cannot pass it on
    let narrow = issue_ok(&root, &CertSpec { may_pair: true, scopes: vec![scope::VIEW.into()], ..spec(&laptop) });
    let leaf = issue_ok(&laptop, &CertSpec { scopes: control(), ..spec(&phone) });
    assert_eq!(verify_chain(&root.public(), &[leaf, narrow], NOW).unwrap_err(), ChainError::ScopeWidened);
}

#[test]
fn what_only_the_root_may_grant_does_not_travel_through_a_delegate() {
    // A phone that may approve a click should not thereby be able to pair another phone, so the powers a person
    // decides at the root are not powers a paired device passes on.
    let (root, laptop, phone) = (id(1), id(2), id(3));
    for never in NEVER_DELEGABLE {
        let held = vec![scope::VIEW.into(), never.to_string()];
        let delegate = issue_ok(&root, &CertSpec { may_pair: true, scopes: held.clone(), ..spec(&laptop) });
        let leaf = issue_ok(&laptop, &CertSpec { scopes: held.clone(), ..spec(&phone) });
        assert_eq!(
            verify_chain(&root.public(), &[leaf, delegate], NOW).unwrap_err(),
            ChainError::NotDelegable,
            "{never}, even from a delegate that holds it"
        );
        // and straight from the root it is fine, which is the point
        let direct = issue_ok(&root, &CertSpec { scopes: held, ..spec(&phone) });
        assert!(verify_chain(&root.public(), &[direct], NOW).is_ok(), "{never} from the root");
    }
}

/// What admitting a connection costs in signature verification, for docs/PROTOCOL.md §Limits. Numbers, not
/// assertions: `cargo test --release -p wmlhub-keys chain_and_hello_costs -- --ignored --nocapture`.
#[test]
#[ignore]
fn chain_and_hello_costs() {
    use std::time::Instant;
    const N: u32 = 2_000;
    let root = Identity::from_seed([1; 32]);
    let phone = Identity::from_seed([2; 32]);
    let leaf = issue_ok(
        &root,
        &CertSpec {
            subject: phone.public(),
            agreement_key: [3; 32],
            role: Role::Client,
            scopes: vec![scope::VIEW.into()],
            may_pair: false,
            may_revoke: false,
            not_before_ms: NOW - 1_000,
            not_after_ms: NOW + 1_000_000,
            label: String::new(),
        },
    );
    let chain = vec![leaf];
    let verified = verify_chain(&root.public(), &chain, NOW).unwrap();
    let transcript = hello_transcript("hub.test", &[9; 32], &verified.principal, Role::Client, &verified.account);
    let signature = sign_hello(&phone, &transcript);

    let start = Instant::now();
    for _ in 0..N {
        let v = verify_chain(&root.public(), &chain, NOW).unwrap();
        let t = hello_transcript("hub.test", &[9; 32], &v.principal, Role::Client, &v.account);
        verify_hello(&v.leaf_key, &t, &signature).unwrap();
    }
    eprintln!("one-certificate chain + hello: {:?} each", start.elapsed() / N);
}

// ------------------------------ may_revoke (docs/design/revocation.md) ------------------------------

#[test]
fn the_root_may_grant_may_revoke_and_a_delegate_may_not() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let from_root = issue_ok(&root, &CertSpec { may_revoke: true, ..spec(&laptop) });
    let v = verify_chain(&root.public(), &[from_root], NOW).unwrap();
    assert!(v.leaf.may_revoke, "the root grants it explicitly, the way it grants `admin`");

    // A delegate issuing it is the account takeover the field exists to prevent: whoever may revoke may unpair every
    // other device, and `may_pair` creates things NARROWER than itself while revoking acts on a peer.
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, may_revoke: true, ..spec(&laptop) });
    let leaf = issue_ok(&laptop, &CertSpec { may_revoke: true, ..spec(&phone) });
    assert_eq!(verify_chain(&root.public(), &[leaf, delegate], NOW).unwrap_err(), ChainError::NotDelegable);
}

#[test]
fn a_box_connector_may_never_revoke() {
    // It relays one machine's telemetry. Nothing about that involves deciding who is still on the account.
    let connector = id(2);
    let spec = CertSpec { role: Role::BoxConnector, scopes: vec![], may_revoke: true, ..spec(&connector) };
    assert_eq!(issue(&id(1), &spec).unwrap_err(), ChainError::RoleNotPermitted);
}

// ------------------------------ renewal ------------------------------

#[test]
fn a_delegate_renews_a_scope_it_could_never_have_granted() {
    // The whole reason renewal is its own case. Without it nothing but the root can re-issue a certificate carrying
    // `approve`, so a 90-day window reads as "produce the root device four times a year, once per powerful device".
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, not_after_ms: NOW + 9_000, ..spec(&laptop) });
    let approver = issue_ok(&root, &CertSpec { scopes: vec![scope::APPROVE.into()], ..spec(&phone) });

    // Issuing those scopes fresh is refused; renewing them is not. This delegate does not hold `approve` itself, so
    // the refusal is `ScopeWidened`; one that did would get `NotDelegable`, which is its own test above.
    let fresh = sign_certificate(&laptop, &CertSpec { scopes: vec![scope::APPROVE.into()], ..spec(&phone) });
    assert_eq!(verify_chain(&root.public(), &[fresh, delegate.clone()], NOW).unwrap_err(), ChainError::ScopeWidened);

    let renewed = renew(&laptop, &approver, NOW + 500, NOW + 5_000).unwrap();
    let v = verify_chain(&root.public(), &[renewed, delegate], NOW + 1_000).unwrap();
    assert_eq!(v.leaf.scopes, vec![scope::APPROVE.to_owned()]);
    assert_eq!(v.principal, principal_id(&phone.public()));
}

#[test]
fn the_predecessor_may_be_expired_because_that_is_the_point() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, not_after_ms: NOW + 9_000, ..spec(&laptop) });
    let lapsed = issue_ok(&root, &CertSpec { not_before_ms: NOW - 9_000, not_after_ms: NOW - 5_000, ..spec(&phone) });
    // Long expired, and at no point in this is it checked: a renewal exists precisely for a certificate that ran out.
    let renewed = renew(&laptop, &lapsed, NOW - 100, NOW + 5_000).unwrap();
    assert!(verify_chain(&root.public(), &[renewed, delegate], NOW).is_ok());
}

#[test]
fn a_renewal_may_not_move_the_agreement_key() {
    // The field a loose rule loses. It is where sealed commands go, so a delegate free to change it could redirect
    // everything sealed to an approver into a key it holds, without ever holding the approver's identity key.
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, not_after_ms: NOW + 9_000, ..spec(&laptop) });
    let approver = issue_ok(&root, &CertSpec { scopes: vec![scope::APPROVE.into()], ..spec(&phone) });

    let honest = renew(&laptop, &approver, NOW, NOW + 5_000).unwrap();
    let mut body = CertificateBody::decode(honest.body.as_slice()).unwrap();
    body.agreement_key = [7; 32].to_vec();
    let forged = resign(&laptop, body);
    assert_eq!(verify_chain(&root.public(), &[forged, delegate], NOW).unwrap_err(), ChainError::BadRenewal);
}

#[test]
fn every_other_term_has_to_be_repeated_exactly() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, not_after_ms: NOW + 9_000, ..spec(&laptop) });
    let before = issue_ok(&root, &CertSpec { scopes: vec![scope::APPROVE.into()], ..spec(&phone) });
    let honest = renew(&laptop, &before, NOW, NOW + 5_000).unwrap();

    let tampered = |f: fn(&mut CertificateBody)| {
        let mut body = CertificateBody::decode(honest.body.as_slice()).unwrap();
        f(&mut body);
        verify_chain(&root.public(), &[resign(&laptop, body), delegate.clone()], NOW).unwrap_err()
    };
    // Renaming a device is not a renewal: `label` travels unchanged like everything else.
    assert_eq!(tampered(|b| b.label = "somebody else's phone".into()), ChainError::BadRenewal, "label");
    assert_eq!(tampered(|b| b.scopes.push(scope::DRIVE.into())), ChainError::BadRenewal, "a scope added");
    assert_eq!(tampered(|b| b.scopes.clear()), ChainError::BadRenewal, "a scope removed");
    assert_eq!(tampered(|b| b.may_pair = true), ChainError::BadRenewal, "may_pair");
    assert_eq!(tampered(|b| b.subject = id(9).public().to_vec()), ChainError::BadRenewal, "subject");
    assert_eq!(tampered(|b| b.role = Role::Runtime as i32), ChainError::BadRenewal, "role");
}

#[test]
fn the_predecessor_must_be_the_roots_own_signature() {
    // Under a delegate this would be a delegate certifying its own authority, and renewals would chain into wider
    // ones: renew something narrow, then renew THAT with more.
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, not_after_ms: NOW + 9_000, ..spec(&laptop) });
    let by_delegate = issue_ok(&laptop, &spec(&phone));
    let renewed = renew(&laptop, &by_delegate, NOW, NOW + 5_000).unwrap();
    assert_eq!(verify_chain(&root.public(), &[renewed, delegate.clone()], NOW).unwrap_err(), ChainError::BadRenewal);

    // And it has to SAY the root signed it. A predecessor is not in the chain, so nothing else ever compares its
    // `issuer` against who signed it, and a body that disagrees with its own signature is not a term of anything.
    let mut body = CertificateBody::decode(issue_ok(&root, &spec(&phone)).body.as_slice()).unwrap();
    body.issuer = laptop.public().to_vec();
    let renewed = renew(&laptop, &resign(&root, body), NOW, NOW + 5_000).unwrap();
    assert_eq!(verify_chain(&root.public(), &[renewed, delegate], NOW).unwrap_err(), ChainError::BadRenewal);
}

#[test]
fn renewals_do_not_chain() {
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, not_after_ms: NOW + 9_000, ..spec(&laptop) });
    // The predecessor has to be root-signed, so the only renewal that could chain is one the ROOT made: anything a
    // delegate signed is already refused for its issuer. This is that case, and it is the one this rule is for.
    let root_renewal = renew(&root, &issue_ok(&root, &spec(&phone)), NOW, NOW + 4_000).unwrap();
    assert_eq!(renew(&laptop, &root_renewal, NOW, NOW + 3_000).unwrap_err(), ChainError::BadRenewal);

    // Built around `renew`, every other rule satisfied: root-signed predecessor, every term repeated, inside the
    // delegate's window. Only "renewals do not chain" stands between this and a delegate renewing its own renewal.
    let mut body = CertificateBody::decode(root_renewal.body.as_slice()).unwrap();
    body.issuer = laptop.public().to_vec();
    body.not_after_ms = NOW + 3_000;
    body.renews = Some(root_renewal);
    assert_eq!(
        verify_chain(&root.public(), &[resign(&laptop, body), delegate], NOW).unwrap_err(),
        ChainError::BadRenewal
    );
}

#[test]
fn a_renewal_cannot_outlive_the_delegate_that_signed_it() {
    // This is what keeps the root's part in renewal to one visit per account per window rather than none: a runtime
    // can keep every device on its allowlist alive, and not past its own certificate.
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, not_after_ms: NOW + 2_000, ..spec(&laptop) });
    let before = issue_ok(&root, &CertSpec { scopes: vec![scope::APPROVE.into()], ..spec(&phone) });
    let too_long = renew(&laptop, &before, NOW, NOW + 9_000).unwrap();
    assert_eq!(verify_chain(&root.public(), &[too_long, delegate], NOW).unwrap_err(), ChainError::OutlivesIssuer);
}

#[test]
fn a_delegate_may_not_renew_may_revoke_either() {
    // The one field where "a renewal grants nothing new" is false. Its value IS that exactly one principal holds it,
    // so keeping a second holder alive after the root re-placed the power is how two signers happen -- and two
    // signers race on a monotonic per-account `version`, with the loser's revocation refused as stale.
    let (root, laptop, phone) = (id(1), id(2), id(3));
    let delegate = issue_ok(&root, &CertSpec { may_pair: true, not_after_ms: NOW + 9_000, ..spec(&laptop) });
    let revoker = issue_ok(&root, &CertSpec { may_revoke: true, ..spec(&phone) });
    let renewed = renew(&laptop, &revoker, NOW, NOW + 5_000).unwrap();
    assert_eq!(verify_chain(&root.public(), &[renewed, delegate], NOW).unwrap_err(), ChainError::NotDelegable);
    // The root renewing its own grant is fine: there is still only one signer.
    let by_root = renew(&root, &revoker, NOW, NOW + 5_000).unwrap();
    assert!(verify_chain(&root.public(), &[by_root], NOW).unwrap().leaf.may_revoke);
}

#[test]
fn only_a_renewal_may_be_larger_than_a_certificate() {
    // The size bound is checked before decoding, because a hello is read before its sender is authenticated. A
    // renewal carries another whole certificate, and nothing else has any business being that big.
    let (root, phone) = (id(1), id(2));
    let padded = CertSpec { label: "p".repeat(MAX_LABEL_BYTES), ..spec(&phone) };
    let before = issue_ok(&root, &padded);
    let renewed = renew(&root, &before, NOW, NOW + 5_000).unwrap();
    assert!(renewed.body.len() > MAX_CERT_BYTES / 4, "a renewal really is much larger than what it renews");
    assert!(verify_chain(&root.public(), &[renewed], NOW).is_ok());

    // A plain body of the same size is refused rather than measured against the renewal ceiling.
    let mut body = CertificateBody::decode(issue_ok(&root, &padded).body.as_slice()).unwrap();
    body.label = "p".repeat(MAX_LABEL_BYTES);
    let mut oversized = body.encode_to_vec();
    oversized.resize(MAX_CERT_BYTES + 1, 0);
    assert_eq!(
        verify_chain(&root.public(), &[Certificate { body: oversized, signature: vec![0; 64] }], NOW).unwrap_err(),
        ChainError::Malformed
    );
}

/// Re-sign a body a test has altered, so what is under test is the VERIFIER and not `issue`'s own refusals.
fn resign(issuer: &Identity, body: CertificateBody) -> Certificate {
    let body = body.encode_to_vec();
    let signature = issuer.sign(CERT_LABEL, &body);
    Certificate { body, signature }
}

#[test]
fn install_is_the_roots_to_grant_by_name() {
    // The loop above proves whatever is in NEVER_DELEGABLE is enforced; it would still pass if `install` were taken
    // out. The NAME is what has to match window-ml's keys.ts, so it is pinned here on its own.
    assert!(NEVER_DELEGABLE.contains(&scope::INSTALL), "install is never delegable");
    assert_eq!(scope::INSTALL, "install", "the name window-ml checks for");

    let (root, laptop, phone) = (id(1), id(2), id(3));
    let held = vec![scope::VIEW.to_owned(), scope::INSTALL.to_owned()];
    let delegate =
        issue_ok(&root, &CertSpec { may_pair: true, scopes: held.clone(), not_after_ms: NOW + 9_000, ..spec(&laptop) });
    let leaf = issue_ok(&laptop, &CertSpec { scopes: held.clone(), ..spec(&phone) });
    assert_eq!(
        verify_chain(&root.public(), &[leaf, delegate.clone()], NOW).unwrap_err(),
        ChainError::NotDelegable,
        "a delegate that may pair and holds install still cannot hand it out"
    );

    // Renewal is different, and deliberately so: the root already granted this subject `install`, and a renewal
    // re-issues that grant unchanged. It creates nothing new, unlike minting, so the reason install is never
    // delegable does not apply to keeping it alive. `may_revoke` is the one power a delegate may not renew, because
    // its value is exclusivity. `install` has no such property.
    let granted = issue_ok(&root, &CertSpec { scopes: held, ..spec(&phone) });
    let renewed = renew(&laptop, &granted, NOW, NOW + 5_000).unwrap();
    let out = verify_chain(&root.public(), &[renewed, delegate], NOW).unwrap();
    assert!(out.leaf.scopes.iter().any(|s| s == scope::INSTALL));
}
