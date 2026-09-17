//! Certificate chains and hellos from arbitrary bytes: verification never panics, and a valid chain with any single
//! byte of any certificate flipped never verifies.
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use wmlhub_keys::{CertSpec, Identity, issue, scope, verify_chain};
use wmlhub_proto::v1::{Certificate, Role};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(mode) = u8::arbitrary(&mut u) else { return };
    let Ok(now) = u64::arbitrary(&mut u) else { return };
    if mode % 2 == 0 {
        // raw: arbitrary root and certificates
        let Ok(root) = <[u8; 32]>::arbitrary(&mut u) else { return };
        let Ok(raw) = Vec::<(Vec<u8>, Vec<u8>)>::arbitrary(&mut u) else { return };
        let chain: Vec<Certificate> =
            raw.into_iter().map(|(body, signature)| Certificate { body, signature }).collect();
        let _ = verify_chain(&root, &chain, now);
        return;
    }
    // structured: build a valid chain, flip one byte, expect refusal
    let Ok(seeds) = <[u8; 3]>::arbitrary(&mut u) else { return };
    let Ok(delegate) = bool::arbitrary(&mut u) else { return };
    let Ok(flip_cert) = u8::arbitrary(&mut u) else { return };
    let Ok(flip_at) = u16::arbitrary(&mut u) else { return };
    let Ok(flip_bit) = u8::arbitrary(&mut u) else { return };
    let root = Identity::from_seed([seeds[0]; 32]);
    let mid = Identity::from_seed([seeds[1].wrapping_add(1); 32]);
    let leaf = Identity::from_seed([seeds[2].wrapping_add(2); 32]);
    if root.public() == mid.public() || root.public() == leaf.public() || mid.public() == leaf.public() {
        return;
    }
    let spec = |subject: &Identity, may_pair: bool| CertSpec {
        subject: subject.public(),
        agreement_key: [7; 32],
        role: Role::Client,
        scopes: vec![scope::VIEW.into()],
        may_pair,
        not_before_ms: 0,
        not_after_ms: 0,
        label: String::new(),
    };
    let mut chain = if delegate {
        vec![issue(&mid, &spec(&leaf, false)), issue(&root, &spec(&mid, true))]
    } else {
        vec![issue(&root, &spec(&leaf, false))]
    };
    assert!(verify_chain(&root.public(), &chain, now).is_ok(), "the unmodified chain verifies");
    let i = usize::from(flip_cert) % chain.len();
    let cert = &mut chain[i];
    let total = cert.body.len() + cert.signature.len();
    let at = usize::from(flip_at) % total;
    let bit = 1u8 << (flip_bit % 8);
    if at < cert.body.len() {
        cert.body[at] ^= bit;
    } else {
        cert.signature[at - cert.body.len()] ^= bit;
    }
    assert!(verify_chain(&root.public(), &chain, now).is_err(), "a flipped bit in certificate {i} at {at} verified");
});
