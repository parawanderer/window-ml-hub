//! The streaming reader against arbitrary chunking: however the same bytes are split into reads, the frames that come
//! out, the error (if any) and the bytes left pending are the same as reading them in one piece.
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use wmlhub_frame::FrameReader;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(cuts) = Vec::<u8>::arbitrary(&mut u) else { return };
    let bytes = u.take_rest();
    let max = 256;

    let mut whole = FrameReader::new(max);
    let whole_result = whole.push(bytes);

    let mut chunked = FrameReader::new(max);
    let mut frames = Vec::new();
    let mut error = None;
    let mut at = 0;
    for cut in cuts.iter().chain(std::iter::once(&u8::MAX)) {
        if at >= bytes.len() {
            break;
        }
        let end = (at + usize::from(*cut).max(1)).min(bytes.len());
        match chunked.push(&bytes[at..end]) {
            Ok(f) => frames.extend(f),
            Err(e) => {
                error = Some(e);
                break;
            }
        }
        at = end;
    }
    if error.is_none() && at < bytes.len() {
        match chunked.push(&bytes[at..]) {
            Ok(f) => frames.extend(f),
            Err(e) => error = Some(e),
        }
    }

    match whole_result {
        Ok(expected) => {
            assert!(error.is_none(), "chunked read failed where the whole read did not: {error:?}");
            assert_eq!(frames, expected);
            assert_eq!(chunked.pending(), whole.pending());
        }
        Err(e) => {
            // The whole read stops at the first bad prefix; the chunked read must stop there too, having yielded
            // exactly the frames before it.
            assert_eq!(error, Some(e));
        }
    }
});
