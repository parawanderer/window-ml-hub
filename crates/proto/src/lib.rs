//! The hub's wire protocol, generated from `proto/wmlhub/v1/hub.proto`. Read that file and `docs/PROTOCOL.md` for
//! what each message means; this crate adds only framing helpers.

#[allow(missing_docs, clippy::all, clippy::pedantic)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/wmlhub.v1.rs"));
}

use prost::Message;
use wmlhub_frame::{FrameError, write_frame};

/// Why bytes off the wire are not a sequence of frames.
#[derive(Debug)]
pub enum DecodeError {
    /// The length prefixes were corrupt or a frame exceeded the limit.
    Frame(FrameError),
    /// A delimited message was not a valid `Frame`.
    Proto(prost::DecodeError),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Frame(e) => e.fmt(f),
            DecodeError::Proto(e) => write!(f, "frame: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode frames as one websocket message: each varint-delimited. Refuses a frame over `max` bytes.
pub fn encode_frames(frames: &[v1::Frame], max: usize) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::new();
    for frame in frames {
        write_frame(&frame.encode_to_vec(), max, &mut out)?;
    }
    Ok(out)
}

/// Decode one whole websocket message into its frames. A websocket message is already complete, so a message that
/// ends mid-frame is corruption here, not a short read.
pub fn decode_frames(message: &[u8], max: usize) -> Result<Vec<v1::Frame>, DecodeError> {
    let mut reader = wmlhub_frame::FrameReader::new(max);
    let raw = reader.push(message).map_err(DecodeError::Frame)?;
    if reader.pending() != 0 {
        return Err(DecodeError::Frame(FrameError::Truncated { pending: reader.pending() }));
    }
    raw.iter().map(|b| v1::Frame::decode(b.as_slice()).map_err(DecodeError::Proto)).collect()
}

#[cfg(test)]
mod tests {
    use super::v1::{Envelope, Frame, Kind, frame::Body};
    use super::*;

    fn published(seq: u64) -> Frame {
        Frame {
            body: Some(Body::Envelope(Envelope {
                to: Some(v1::envelope::To::Channel(b"ch".to_vec())),
                kind: Kind::SessionEvents as i32,
                seq,
                payload: vec![0xde, 0xad],
                ..Default::default()
            })),
        }
    }

    #[test]
    fn a_batch_round_trips() {
        let frames = vec![published(1), published(2), Frame { body: Some(Body::Ping(v1::Ping { nonce: 7 })) }];
        let bytes = encode_frames(&frames, 1 << 16).unwrap();
        assert_eq!(decode_frames(&bytes, 1 << 16).unwrap(), frames);
    }

    #[test]
    fn a_message_cut_mid_frame_is_an_error() {
        let bytes = encode_frames(&[published(1)], 1 << 16).unwrap();
        assert!(matches!(
            decode_frames(&bytes[..bytes.len() - 1], 1 << 16),
            Err(DecodeError::Frame(FrameError::Truncated { .. }))
        ));
    }

    #[test]
    fn an_unknown_field_is_skipped_not_fatal() {
        // field 99, varint 1: what a newer peer's frame looks like to this build
        let mut msg = published(3).encode_to_vec();
        msg.extend_from_slice(&[0x98, 0x06, 0x01]);
        let mut bytes = Vec::new();
        write_frame(&msg, 1 << 16, &mut bytes).unwrap();
        assert_eq!(decode_frames(&bytes, 1 << 16).unwrap(), vec![published(3)]);
    }

    #[test]
    fn an_unknown_body_decodes_as_no_body() {
        // oneof member 50 (length-delimited, empty) that this build does not know
        let mut bytes = Vec::new();
        write_frame(&[0x92, 0x03, 0x00], 1 << 16, &mut bytes).unwrap();
        assert_eq!(decode_frames(&bytes, 1 << 16).unwrap(), vec![Frame { body: None }]);
    }
}
