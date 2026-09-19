//! Revocation lists from arbitrary bytes: verification never panics, asking whether a list revokes an arbitrary chain
//! never panics, and a valid list with any single bit of it flipped never verifies.
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use wmlhub_keys::revocation::{sign_revocations, verify_revocations};
use wmlhub_keys::{CertSpec, Identity, account_id, issue, principal_id, scope};
use wmlhub_proto::v1::{Certificate, RevocationList, Role};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(mode) = u8::arbitrary(&mut u) else { return };
    let Ok(now) = u64::arbitrary(&mut u) else { return };
    let now = now.clamp(3_600_001, u64::MAX - 3_600_001);
    let root = Identity::from_seed([1; 32]);
    let revoker = Identity::from_seed([2; 32]);
    let spec = CertSpec {
        subject: revoker.public(),
        agreement_key: [7; 32],
        role: Role::Runtime,
        scopes: vec![scope::VIEW.into()],
        may_pair: false,
        may_revoke: true,
        not_before_ms: now - 3_600_000,
        not_after_ms: now + 3_600_000,
        label: String::new(),
    };
    let chain = vec![issue(&root, &spec).expect("a revoker the root may make")];

    if mode % 2 == 0 {
        // raw: an arbitrary list, then whether whatever verified revokes an arbitrary chain
        let Ok((body, signature)) = <(Vec<u8>, Vec<u8>)>::arbitrary(&mut u) else { return };
        let Ok(raw_chain) = Vec::<(Vec<u8>, Vec<u8>)>::arbitrary(&mut u) else { return };
        let raw_chain: Vec<Certificate> =
            raw_chain.into_iter().map(|(body, signature)| Certificate { body, signature }).collect();
        let list = RevocationList { body, signature, chain: chain.clone() };
        if let Ok(revoked) = verify_revocations(&root.public(), &list, now, None) {
            let _ = revoked.revokes(&raw_chain);
        }
        let list = RevocationList { body: list.body, signature: list.signature, chain: raw_chain };
        let _ = verify_revocations(&root.public(), &list, now, None);
        return;
    }

    // structured: a valid list, one bit flipped anywhere in it, must not verify
    let Ok(names) = u8::arbitrary(&mut u) else { return };
    let Ok(flip_at) = u32::arbitrary(&mut u) else { return };
    let Ok(flip_bit) = u8::arbitrary(&mut u) else { return };
    let principals: Vec<[u8; 32]> = (0..names % 8).map(|n| principal_id(&[n; 32])).collect();
    let mut list = sign_revocations(&revoker, &chain, account_id(&root.public()), now, &principals, &[]);
    assert!(verify_revocations(&root.public(), &list, now, None).is_ok(), "the unmodified list verifies");

    let (body, signature, cert) = (list.body.len(), list.signature.len(), list.chain[0].body.len());
    let total = body + signature + cert + list.chain[0].signature.len();
    let at = flip_at as usize % total;
    let bit = 1u8 << (flip_bit % 8);
    match at {
        a if a < body => list.body[a] ^= bit,
        a if a < body + signature => list.signature[a - body] ^= bit,
        a if a < body + signature + cert => list.chain[0].body[a - body - signature] ^= bit,
        a => list.chain[0].signature[a - body - signature - cert] ^= bit,
    }
    assert!(verify_revocations(&root.public(), &list, now, None).is_err(), "a flipped bit at {at} verified");
});
