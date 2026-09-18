//! Published frames from arbitrary bytes: reading never panics, and an honest frame with any single bit flipped never
//! opens.
#![no_main]
use std::sync::OnceLock;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use wmlhub_keys::{CertSpec, Identity, issue, principal_id, scope};
use wmlhub_proto::v1::{Certificate, Role};
use wmlhub_seal::{
    AgreementKey, Grant, Receiver, Recipient, Sender, StreamKey, StreamReader, open_grant, seal_frame, wrap_key,
};

/// `issue`, which now refuses a spec every verifier would reject.
fn issue_ok(issuer: &Identity, spec: &CertSpec) -> Certificate {
    issue(issuer, spec).expect("a certificate this issuer may make")
}

const NOW: u64 = 1_800_000_000_000;
const CHANNEL: &[u8] = b"channel";

struct Fixture {
    grant: Grant,
    /// one honest frame, made once: sealing draws randomness a fuzzer cannot replay
    frame: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let root = Identity::from_seed([1; 32]);
        let (runtime, phone) = (Identity::from_seed([2; 32]), Identity::from_seed([3; 32]));
        let cert = |who: &Identity, seed: u8, role| CertSpec {
            subject: who.public(),
            agreement_key: AgreementKey::from_seed(&[seed; 32]).public(),
            role,
            scopes: vec![scope::VIEW.into()],
            may_pair: false, may_revoke: false,
            not_before_ms: NOW - 86_400_000,
            not_after_ms: NOW + 86_400_000,
            label: String::new(),
        };
        let runtime_chain = vec![issue_ok(&root, &cert(&runtime, 12, Role::Runtime))];
        let _ = issue_ok(&root, &cert(&phone, 13, Role::Client));
        let publisher = Sender { identity: &runtime, chain: &runtime_chain };
        let to = Recipient {
            principal: principal_id(&phone.public()),
            agreement_key: AgreementKey::from_seed(&[13; 32]).public(),
        };
        let key = StreamKey::from_bytes([9; 32]);
        let wrapped = wrap_key(&publisher, &to, CHANNEL, &key, 1, NOW).unwrap();
        let mut receiver = Receiver::new(&phone.public(), AgreementKey::from_seed(&[13; 32]), root.public());
        let grant = open_grant(&mut receiver, &principal_id(&runtime.public()), &wrapped, NOW).unwrap();
        let frame = seal_frame(&publisher, CHANNEL, &key, 1, b"a batch").unwrap();
        Fixture { grant, frame }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let mut u = Unstructured::new(data);
    let Ok(flip) = bool::arbitrary(&mut u) else { return };
    let mut reader = StreamReader::new(&f.grant);
    if !flip {
        let _ = reader.open(u.take_rest());
        return;
    }
    let Ok(at) = u32::arbitrary(&mut u) else { return };
    let mut bad = f.frame.clone();
    let bit = at as usize % (bad.len() * 8);
    bad[bit / 8] ^= 1 << (bit % 8);
    assert!(reader.open(&bad).is_err(), "a flipped bit {bit} opened");
});
