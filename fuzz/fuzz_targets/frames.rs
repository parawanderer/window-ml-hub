//! One websocket message's worth of bytes: decoding never panics, and whatever decodes re-encodes to frames that
//! decode to the same thing.
#![no_main]
use libfuzzer_sys::fuzz_target;
use wmlhub_proto::{decode_frames, encode_frames};

const MAX: usize = 1 << 16;

fuzz_target!(|data: &[u8]| {
    if let Ok(frames) = decode_frames(data, MAX) {
        let again = encode_frames(&frames, MAX).expect("a frame that decoded under the limit re-encodes under it");
        assert_eq!(decode_frames(&again, MAX).expect("re-encoded frames decode"), frames);
    }
});
