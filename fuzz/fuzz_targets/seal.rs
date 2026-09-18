//! Sealed commands from arbitrary bytes: opening never panics whatever arrives or whoever the hub claims sent it, and
//! an honest sealed command with any single bit flipped, or delivered as from anyone else, never opens.
#![no_main]
use std::sync::OnceLock;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use wmlhub_keys::{CertSpec, Identity, issue, principal_id, scope};
use wmlhub_proto::v1::{Certificate, Role};
use wmlhub_seal::{AgreementKey, Receiver, Recipient, Sender, seal_command};

/// `issue`, which now refuses a spec every verifier would reject.
fn issue_ok(issuer: &Identity, spec: &CertSpec) -> Certificate {
    issue(issuer, spec).expect("a certificate this issuer may make")
}


const NOW: u64 = 1_800_000_000_000;

struct Fixture {
    root: Identity,
    phone: Identity,
    runtime: Identity,
    /// one honest sealed command, made once: sealing draws fresh randomness, which a fuzzer cannot replay
    sealed: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let root = Identity::from_seed([1; 32]);
        let (phone, runtime) = (Identity::from_seed([2; 32]), Identity::from_seed([3; 32]));
        let spec = |who: &Identity, seed: u8, role, scopes: Vec<String>| CertSpec {
            subject: who.public(),
            agreement_key: AgreementKey::from_seed(&[seed; 32]).public(),
            role,
            scopes,
            may_pair: false, may_revoke: false,
            not_before_ms: NOW - 86_400_000,
            not_after_ms: NOW + 86_400_000,
            label: String::new(),
        };
        let phone_chain = vec![issue_ok(&root, &spec(&phone, 12, Role::Client, vec![scope::DRIVE.into()]))];
        let to = Recipient {
            principal: principal_id(&runtime.public()),
            agreement_key: AgreementKey::from_seed(&[13; 32]).public(),
        };
        let from = Sender { identity: &phone, chain: &phone_chain };
        let (sealed, _) = seal_command(&from, &to, scope::DRIVE, b"fuzz", NOW).unwrap();
        Fixture { root, phone, runtime, sealed }
    })
}

fn receiver(f: &Fixture) -> Receiver {
    Receiver::new(&f.runtime.public(), AgreementKey::from_seed(&[13; 32]), f.root.public())
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let mut u = Unstructured::new(data);
    let Ok(mode) = u8::arbitrary(&mut u) else { return };
    let Ok(now) = u64::arbitrary(&mut u) else { return };
    match mode % 3 {
        // anything at all, from anyone
        0 => {
            let Ok(sender) = Vec::<u8>::arbitrary(&mut u) else { return };
            let _ = receiver(f).open(&sender, u.take_rest(), now);
        }
        // the honest command with one bit flipped
        1 => {
            let Ok(at) = u32::arbitrary(&mut u) else { return };
            let mut bad = f.sealed.clone();
            let bit = at as usize % (bad.len() * 8);
            bad[bit / 8] ^= 1 << (bit % 8);
            let from = principal_id(&f.phone.public());
            assert!(receiver(f).open(&from, &bad, NOW).is_err(), "a flipped bit {bit} opened");
        }
        // the honest command, delivered as from someone else
        _ => {
            let Ok(sender) = <[u8; 32]>::arbitrary(&mut u) else { return };
            if sender == principal_id(&f.phone.public()) {
                assert!(receiver(f).open(&sender, &f.sealed, NOW).is_ok());
                return;
            }
            assert!(receiver(f).open(&sender, &f.sealed, NOW).is_err(), "opened as from {sender:?}");
        }
    }
});
