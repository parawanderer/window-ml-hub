//! The connector's HTTP reading, from arbitrary bytes: parsing a response head and decoding a chunked body never
//! panic, and however the reads are split the body decodes the same.
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use wmlhub_connector::http::{Chunked, ResponseHead, Target};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(mode) = u8::arbitrary(&mut u) else { return };
    match mode % 3 {
        // a head, from anything at all
        0 => {
            let bytes = u.take_rest();
            let _ = ResponseHead::parse(bytes);
            if let Ok(text) = std::str::from_utf8(bytes) {
                let _ = Target::parse(text);
            }
        }
        // a chunked body, in one piece
        1 => {
            let _ = Chunked::default().push(u.take_rest());
        }
        // the same bytes, split two ways: a decoder that reads differently by chunk boundary is broken
        _ => {
            let Ok(cut) = u16::arbitrary(&mut u) else { return };
            let bytes = u.take_rest();
            if bytes.is_empty() {
                return;
            }
            let at = (cut as usize) % bytes.len();
            let whole = Chunked::default().push(bytes);
            let mut split = Chunked::default();
            let first = split.push(&bytes[..at]);
            let second = split.push(&bytes[at..]);
            match (whole, first, second) {
                (Ok(whole), Ok(mut a), Ok(b)) => {
                    a.extend_from_slice(&b);
                    assert_eq!(whole, a, "the body decoded differently when the reads fell elsewhere");
                }
                // an error either way is fine: what matters is that a split does not turn a refusal into an accept
                (Err(_), Ok(a), Ok(b)) => {
                    assert!(a.is_empty() && b.is_empty(), "a split accepted what one read refused")
                }
                _ => {}
            }
        }
    }
});
