//! One websocket message's worth of bytes: decoding never panics; the zero-copy decoder (payloads as slices of the
//! message) agrees exactly with the copying one, frames or error; and whatever decodes re-encodes, frame by frame
//! (`encode_frame` + `join_frames`, the relay's path) and in one go, to frames that decode to the same thing.
#![no_main]
use libfuzzer_sys::fuzz_target;
use wmlhub_proto::bytes::Bytes;
use wmlhub_proto::{decode_frames, decode_frames_shared, encode_frame, encode_frames, join_frames};

const MAX: usize = 1 << 16;

fuzz_target!(|data: &[u8]| {
    let copied = decode_frames(data, MAX);
    let shared = decode_frames_shared(Bytes::copy_from_slice(data), MAX);
    match (&copied, &shared) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "the two decoders disagree"),
        (Err(_), Err(_)) => {}
        _ => panic!("one decoder accepted what the other refused: copied {copied:?}, shared {shared:?}"),
    }
    if let Ok(frames) = copied {
        let again = encode_frames(&frames, MAX).expect("a frame that decoded under the limit re-encodes under it");
        assert_eq!(decode_frames(&again, MAX).expect("re-encoded frames decode"), frames);
        let joined = join_frames(frames.iter().map(encode_frame).collect());
        assert_eq!(joined.as_ref(), again.as_slice(), "encode_frame + join_frames differs from encode_frames");
    }
});
