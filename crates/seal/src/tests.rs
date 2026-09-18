//! Each refusal in [`OpenError`] has a test that builds exactly that defect, and the suite is checked against the RFC
//! 9180 vector: a sealing that opens only for itself proves nothing about interoperating with the extension.

use super::*;
use wmlhub_keys::{CertSpec, issue, scope};
use wmlhub_proto::v1::Role;

#[path = "rfc9180_vector.rs"]
mod rfc9180_vector;

pub(crate) const NOW: u64 = 1_800_000_000_000;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A principal of an account: its identity, the seed of its agreement key, and its chain.
pub(crate) struct Principal {
    pub(crate) identity: Identity,
    agreement_seed: [u8; 32],
    pub(crate) chain: Vec<Certificate>,
}

impl Principal {
    pub(crate) fn new(root: &Identity, seed: u8, role: Role, scopes: &[&str]) -> Self {
        let identity = Identity::from_seed([seed; 32]);
        let agreement_seed = [seed.wrapping_add(100); 32];
        let spec = CertSpec {
            subject: identity.public(),
            agreement_key: AgreementKey::from_seed(&agreement_seed).public(),
            role,
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            may_pair: false,
            not_before_ms: NOW - 3_600_000,
            not_after_ms: NOW + 3_600_000,
            label: String::new(),
        };
        let chain = vec![issue(root, &spec)];
        Self { identity, agreement_seed, chain }
    }

    pub(crate) fn id(&self) -> PrincipalId {
        principal_id(&self.identity.public())
    }

    pub(crate) fn sender(&self) -> Sender<'_> {
        Sender { identity: &self.identity, chain: &self.chain }
    }

    pub(crate) fn recipient(&self) -> Recipient {
        Recipient { principal: self.id(), agreement_key: AgreementKey::from_seed(&self.agreement_seed).public() }
    }

    pub(crate) fn receiver(&self, root: &Identity) -> Receiver {
        Receiver::new(&self.identity.public(), AgreementKey::from_seed(&self.agreement_seed), root.public())
    }
}

/// A root, a phone that may view and drive, and a runtime.
pub(crate) struct Account {
    pub(crate) root: Identity,
    pub(crate) phone: Principal,
    pub(crate) runtime: Principal,
}

impl Account {
    pub(crate) fn new(root_seed: u8) -> Self {
        let root = Identity::from_seed([root_seed; 32]);
        let phone = Principal::new(&root, root_seed.wrapping_add(1), Role::Client, &[scope::VIEW, scope::DRIVE]);
        let runtime = Principal::new(&root, root_seed.wrapping_add(2), Role::Runtime, &[]);
        Self { root, phone, runtime }
    }

    pub(crate) fn runtime_receiver(&self) -> Receiver {
        self.runtime.receiver(&self.root)
    }

    pub(crate) fn phone_receiver(&self) -> Receiver {
        self.phone.receiver(&self.root)
    }
}

fn command(a: &Account, scope: &str) -> (Vec<u8>, [u8; NONCE_BYTES]) {
    seal_command(&a.phone.sender(), &a.runtime.recipient(), scope, b"session.send hello", NOW).unwrap()
}

/// Seal an arbitrary `SignedCommand` between `from` and `to`, for defects `seal` cannot make.
fn seal_raw(from: &PrincipalId, to: &Recipient, signed: &SignedCommand) -> Vec<u8> {
    hpke_seal(SEAL_INFO_LABEL, from, to, &signed.encode_to_vec()).unwrap()
}

fn body(a: &Account, edit: impl FnOnce(&mut CommandBody)) -> SignedCommand {
    let mut b = CommandBody {
        from: a.phone.id().to_vec(),
        to: a.runtime.id().to_vec(),
        scope: scope::DRIVE.into(),
        nonce: vec![7; NONCE_BYTES],
        time_ms: NOW,
        body: b"x".to_vec(),
        answers: Vec::new(),
    };
    edit(&mut b);
    let encoded = b.encode_to_vec();
    SignedCommand { signature: sign_command(&a.phone.identity, &encoded), body: encoded, chain: a.phone.chain.clone() }
}

// ------------------------------ the standard ------------------------------

#[test]
fn the_suite_matches_the_rfc_9180_vector() {
    use rfc9180_vector::*;
    let (sk, pk) = X25519HkdfSha256::derive_keypair(&hex(IKM_R));
    assert_eq!(sk.to_bytes().to_vec(), hex(SK_RM));
    assert_eq!(pk.to_bytes().to_vec(), hex(PK_RM));
    let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&hex(ENC)).unwrap();
    let pt = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        &hex(INFO),
        &hex(CT),
        &hex(AAD),
    )
    .unwrap();
    assert_eq!(pt, hex(PT));
}

// ------------------------------ what works ------------------------------

#[test]
fn a_command_opens_for_its_recipient_with_everything_it_said() {
    let a = Account::new(1);
    let (sealed, nonce) = command(&a, scope::DRIVE);
    let opened = a.runtime_receiver().open(&a.phone.id(), &sealed, NOW + 500).unwrap();
    assert_eq!(opened.from, a.phone.id());
    assert_eq!(opened.scope, scope::DRIVE);
    assert_eq!(opened.nonce, nonce);
    assert_eq!(opened.body, b"session.send hello");
    assert_eq!(opened.answers, None);
    assert_eq!(opened.leaf.role, Role::Client as i32);
}

#[test]
fn a_result_opens_for_the_commands_sender_and_names_the_command() {
    let a = Account::new(1);
    let (sealed, nonce) = command(&a, scope::DRIVE);
    a.runtime_receiver().open(&a.phone.id(), &sealed, NOW).unwrap();
    let result = seal_result(&a.runtime.sender(), &a.phone.recipient(), &nonce, b"ok", NOW).unwrap();
    let opened = a.phone_receiver().open(&a.runtime.id(), &result, NOW).unwrap();
    assert_eq!(opened.answers, Some(nonce));
    assert_eq!(opened.body, b"ok");
    assert!(opened.scope.is_empty());
}

#[test]
fn every_seal_is_different_even_for_the_same_command() {
    let a = Account::new(1);
    let (one, n1) = command(&a, scope::DRIVE);
    let (two, n2) = command(&a, scope::DRIVE);
    assert_ne!(one, two);
    assert_ne!(n1, n2);
}

// ------------------------------ what the hub could try ------------------------------

#[test]
fn delivered_to_another_principal_it_does_not_decrypt() {
    let a = Account::new(1);
    let (sealed, _) = command(&a, scope::DRIVE);
    // the phone receives what was sealed to the runtime
    assert_eq!(a.phone_receiver().open(&a.phone.id(), &sealed, NOW).unwrap_err(), OpenError::Decrypt);
}

#[test]
fn stamped_with_another_sender_it_does_not_decrypt() {
    let a = Account::new(1);
    let (sealed, _) = command(&a, scope::DRIVE);
    // the hub claims the command came from someone else
    let other = [9u8; 32];
    assert_eq!(a.runtime_receiver().open(&other, &sealed, NOW).unwrap_err(), OpenError::Decrypt);
}

#[test]
fn replayed_it_is_refused() {
    let a = Account::new(1);
    let (sealed, _) = command(&a, scope::DRIVE);
    let mut runtime = a.runtime_receiver();
    runtime.open(&a.phone.id(), &sealed, NOW).unwrap();
    assert_eq!(runtime.open(&a.phone.id(), &sealed, NOW + 10).unwrap_err(), OpenError::Replay);
}

#[test]
fn delayed_past_the_window_it_is_refused_and_so_is_one_from_the_future() {
    let a = Account::new(1);
    let (sealed, _) = command(&a, scope::DRIVE);
    let mut runtime = a.runtime_receiver();
    assert_eq!(runtime.open(&a.phone.id(), &sealed, NOW + CLOCK_WINDOW_MS + 1).unwrap_err(), OpenError::Clock);
    assert_eq!(runtime.open(&a.phone.id(), &sealed, NOW - CLOCK_WINDOW_MS - 1).unwrap_err(), OpenError::Clock);
    assert!(runtime.open(&a.phone.id(), &sealed, NOW + CLOCK_WINDOW_MS).is_ok(), "the edge is inside");
}

#[test]
fn any_flipped_bit_is_refused() {
    let a = Account::new(1);
    let (sealed, _) = command(&a, scope::DRIVE);
    for byte in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[byte] ^= 1 << (byte % 8);
        assert!(a.runtime_receiver().open(&a.phone.id(), &bad, NOW).is_err(), "byte {byte}");
    }
}

#[test]
fn oversized_input_is_refused_before_anything_else() {
    let a = Account::new(1);
    let huge = vec![0u8; MAX_SEALED_BYTES + 1];
    assert_eq!(a.runtime_receiver().open(&a.phone.id(), &huge, NOW).unwrap_err(), OpenError::TooLarge);
}

// ------------------------------ what a sender without the right could try ------------------------------

#[test]
fn a_sender_whose_certificate_lacks_the_scope_is_refused() {
    let a = Account::new(1);
    let (sealed, _) = command(&a, scope::APPROVE);
    assert_eq!(a.runtime_receiver().open(&a.phone.id(), &sealed, NOW).unwrap_err(), OpenError::Scope);
}

#[test]
fn a_sender_from_another_account_is_refused() {
    let (a, b) = (Account::new(1), Account::new(50));
    // b's phone knows a's runtime's keys and seals a well-formed command to it
    let (sealed, _) = seal_command(&b.phone.sender(), &a.runtime.recipient(), scope::DRIVE, b"x", NOW).unwrap();
    assert!(matches!(a.runtime_receiver().open(&b.phone.id(), &sealed, NOW).unwrap_err(), OpenError::Chain(_)));
}

#[test]
fn a_chain_belonging_to_someone_else_is_refused() {
    let a = Account::new(1);
    let mut signed = body(&a, |_| {});
    // the runtime's (valid) chain presented by the phone
    signed.chain = a.runtime.chain.clone();
    let sealed = seal_raw(&a.phone.id(), &a.runtime.recipient(), &signed);
    assert_eq!(a.runtime_receiver().open(&a.phone.id(), &sealed, NOW).unwrap_err(), OpenError::NotSender);
}

#[test]
fn a_signature_by_another_key_is_refused() {
    let a = Account::new(1);
    let mut signed = body(&a, |_| {});
    signed.signature = sign_command(&a.runtime.identity, &signed.body);
    let sealed = seal_raw(&a.phone.id(), &a.runtime.recipient(), &signed);
    assert_eq!(a.runtime_receiver().open(&a.phone.id(), &sealed, NOW).unwrap_err(), OpenError::Signature);
}

#[test]
fn a_hello_signature_is_not_a_command_signature() {
    let a = Account::new(1);
    let mut signed = body(&a, |_| {});
    signed.signature = wmlhub_keys::sign_hello(&a.phone.identity, &signed.body);
    let sealed = seal_raw(&a.phone.id(), &a.runtime.recipient(), &signed);
    assert_eq!(a.runtime_receiver().open(&a.phone.id(), &sealed, NOW).unwrap_err(), OpenError::Signature);
}

#[test]
fn a_body_claiming_another_sender_is_refused() {
    let a = Account::new(1);
    let signed = body(&a, |b| b.from = a.runtime.id().to_vec());
    let sealed = seal_raw(&a.phone.id(), &a.runtime.recipient(), &signed);
    assert_eq!(a.runtime_receiver().open(&a.phone.id(), &sealed, NOW).unwrap_err(), OpenError::NotSender);
}

#[test]
fn a_body_addressed_to_someone_else_is_refused() {
    let a = Account::new(1);
    // sealed to the runtime's key, but the signed body is for the phone: forwarding a command it received
    let signed = body(&a, |b| b.to = a.phone.id().to_vec());
    let sealed = seal_raw(&a.phone.id(), &a.runtime.recipient(), &signed);
    assert_eq!(a.runtime_receiver().open(&a.phone.id(), &sealed, NOW).unwrap_err(), OpenError::NotForMe);
}

#[test]
fn a_body_that_is_both_or_neither_command_and_result_is_malformed() {
    let a = Account::new(1);
    for edit in [
        (|b: &mut CommandBody| b.answers = vec![1; NONCE_BYTES]) as fn(&mut CommandBody),
        |b: &mut CommandBody| b.scope = String::new(),
        |b: &mut CommandBody| b.nonce = vec![1; 8],
        |b: &mut CommandBody| {
            b.scope = String::new();
            b.answers = vec![1; 3];
        },
    ] {
        let sealed = seal_raw(&a.phone.id(), &a.runtime.recipient(), &body(&a, edit));
        assert_eq!(a.runtime_receiver().open(&a.phone.id(), &sealed, NOW).unwrap_err(), OpenError::Malformed);
    }
}

#[test]
fn a_hub_stamped_sender_of_the_wrong_length_is_refused() {
    let a = Account::new(1);
    let (sealed, _) = command(&a, scope::DRIVE);
    assert_eq!(a.runtime_receiver().open(&[1, 2, 3], &sealed, NOW).unwrap_err(), OpenError::NotSender);
}

// ------------------------------ the replay window ------------------------------

#[test]
fn a_refused_command_does_not_occupy_the_replay_window() {
    let a = Account::new(1);
    let mut runtime = a.runtime_receiver();
    let (sealed, _) = command(&a, scope::DRIVE);
    // refused for its clock first, then accepted in its window: the refusal recorded nothing
    assert_eq!(runtime.open(&a.phone.id(), &sealed, NOW + 2 * CLOCK_WINDOW_MS).unwrap_err(), OpenError::Clock);
    assert!(runtime.open(&a.phone.id(), &sealed, NOW).is_ok());
}

#[test]
fn the_same_nonce_from_two_senders_is_two_commands() {
    let mut w = ReplayWindow::with_capacity(4, MAX_REPLAY_PER_SENDER);
    w.admit([1; 32], [5; NONCE_BYTES], NOW).unwrap();
    w.admit([2; 32], [5; NONCE_BYTES], NOW).unwrap();
    assert_eq!(w.admit([1; 32], [5; NONCE_BYTES], NOW).unwrap_err(), OpenError::Replay);
}

#[test]
fn a_full_window_refuses_until_nonces_age_out_and_never_forgets_a_live_one() {
    let forget = |arrived: u64| arrived + 2 * CLOCK_WINDOW_MS + 1;
    let mut w = ReplayWindow::with_capacity(3, MAX_REPLAY_PER_SENDER);
    for n in 0..3u8 {
        w.admit([1; 32], [n; NONCE_BYTES], NOW + u64::from(n)).unwrap();
    }
    assert_eq!(w.admit([1; 32], [9; NONCE_BYTES], NOW + 10).unwrap_err(), OpenError::Busy);
    // up to the last moment the first could pass the clock, all three are still refused as replays
    for n in 0..3u8 {
        assert_eq!(w.admit([1; 32], [n; NONCE_BYTES], forget(NOW) - 1).unwrap_err(), OpenError::Replay);
    }
    // then the first ages out, freeing exactly one place
    w.admit([1; 32], [9; NONCE_BYTES], forget(NOW)).unwrap();
    assert_eq!(w.admit([1; 32], [10; NONCE_BYTES], forget(NOW)).unwrap_err(), OpenError::Busy);
}

#[test]
fn a_nonce_is_kept_as_long_as_its_command_could_pass_the_clock() {
    // Dated as far ahead as the window allows and accepted on arrival, a command passes the clock check until two
    // windows after arrival, inclusive. A replay at that last millisecond must still be caught.
    let a = Account::new(1);
    let (sealed, _) =
        seal_command(&a.phone.sender(), &a.runtime.recipient(), scope::DRIVE, b"x", NOW + CLOCK_WINDOW_MS).unwrap();
    let mut runtime = a.runtime_receiver();
    runtime.open(&a.phone.id(), &sealed, NOW).unwrap();
    assert_eq!(runtime.open(&a.phone.id(), &sealed, NOW + 2 * CLOCK_WINDOW_MS).unwrap_err(), OpenError::Replay);
    assert_eq!(runtime.open(&a.phone.id(), &sealed, NOW + 2 * CLOCK_WINDOW_MS + 1).unwrap_err(), OpenError::Clock);
}

/// What sealing and opening cost, for docs/design/end-to-end-crypto.md. Numbers, not assertions:
/// `cargo test --release -p wmlhub-seal seal_and_open_costs -- --ignored --nocapture`.
#[test]
#[ignore]
fn seal_and_open_costs() {
    use std::time::Instant;
    let a = Account::new(1);
    const N: u32 = 2_000;
    for size in [64usize, 4_096, 65_536] {
        let body = vec![7u8; size];
        let start = Instant::now();
        let sealed: Vec<Vec<u8>> = (0..N)
            .map(|_| seal_command(&a.phone.sender(), &a.runtime.recipient(), scope::DRIVE, &body, NOW).unwrap().0)
            .collect();
        let seal = start.elapsed() / N;
        let mut runtime = a.runtime_receiver();
        let start = Instant::now();
        for s in &sealed {
            runtime.open(&a.phone.id(), s, NOW).unwrap();
        }
        let open = start.elapsed() / N;
        eprintln!("body {size} B: sealed {} B, seal {seal:?}, open {open:?}", sealed[0].len());
    }
}

#[test]
fn one_senders_flood_cannot_refuse_another_senders_commands() {
    // The window is shared by every device of an account. Without a per-sender share, a phone that sent its fill
    // would refuse the runtime's commands for two windows.
    let mut w = ReplayWindow::with_capacity(8, 2);
    let (noisy, quiet) = ([1u8; 32], [2u8; 32]);
    w.admit(noisy, [1; NONCE_BYTES], NOW).unwrap();
    w.admit(noisy, [2; NONCE_BYTES], NOW).unwrap();
    assert_eq!(w.admit(noisy, [3; NONCE_BYTES], NOW).unwrap_err(), OpenError::Busy, "it filled its own share");
    w.admit(quiet, [1; NONCE_BYTES], NOW).unwrap();
    w.admit(quiet, [2; NONCE_BYTES], NOW).unwrap();
    assert_eq!(w.admit(quiet, [9; NONCE_BYTES], NOW).unwrap_err(), OpenError::Busy, "and only its own");
}

#[test]
fn a_senders_share_is_returned_when_its_nonces_age_out() {
    let mut w = ReplayWindow::with_capacity(8, 1);
    let sender = [1u8; 32];
    w.admit(sender, [1; NONCE_BYTES], NOW).unwrap();
    assert_eq!(w.admit(sender, [2; NONCE_BYTES], NOW).unwrap_err(), OpenError::Busy);
    let later = NOW + 2 * CLOCK_WINDOW_MS + 1;
    w.admit(sender, [2; NONCE_BYTES], later).unwrap();
    assert_eq!(w.admit(sender, [3; NONCE_BYTES], later).unwrap_err(), OpenError::Busy, "one at a time, still");
}

#[test]
fn the_window_still_has_a_ceiling_across_senders() {
    let mut w = ReplayWindow::with_capacity(2, 8);
    w.admit([1; 32], [1; NONCE_BYTES], NOW).unwrap();
    w.admit([2; 32], [1; NONCE_BYTES], NOW).unwrap();
    assert_eq!(w.admit([3; 32], [1; NONCE_BYTES], NOW).unwrap_err(), OpenError::Busy);
}
