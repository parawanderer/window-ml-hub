//! The hub's wire protocol, generated from `proto/wmlhub/v1/hub.proto`. Read that file and `docs/PROTOCOL.md` for
//! what each message means; this crate adds only framing helpers.

#[allow(missing_docs, clippy::all, clippy::pedantic)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/wmlhub.v1.rs"));
}

pub use bytes;
pub use prost;

use bytes::{BufMut, Bytes, BytesMut};
use prost::Message;
use wmlhub_frame::{FrameError, read_varint, write_frame};

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

/// Encode one frame for the wire, length prefix included, in a single allocation. The result is what a relay queues,
/// retains and fans out: every subscriber shares these bytes.
pub fn encode_frame(frame: &v1::Frame) -> Bytes {
    let len = frame.encoded_len();
    let mut buf = BytesMut::with_capacity(len + prost::length_delimiter_len(len));
    frame.encode_length_delimited(&mut buf).expect("capacity reserved for the whole frame");
    buf.freeze()
}

/// Decode one whole websocket message into its frames without copying payloads: each `Envelope.payload` (and
/// `coalesce`) is a slice of `message`, kept alive by reference count.
pub fn decode_frames_shared(message: Bytes, max: usize) -> Result<Vec<v1::Frame>, DecodeError> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < message.len() {
        let Some((len, head)) = read_varint(&message[at..]).map_err(DecodeError::Frame)? else {
            return Err(DecodeError::Frame(FrameError::Truncated { pending: message.len() - at }));
        };
        if len > max as u64 {
            return Err(DecodeError::Frame(FrameError::TooLarge { len, max }));
        }
        let start = at + head;
        let end = start.checked_add(len as usize).filter(|e| *e <= message.len());
        let Some(end) = end else {
            return Err(DecodeError::Frame(FrameError::Truncated { pending: message.len() - at }));
        };
        frames.push(v1::Frame::decode(message.slice(start..end)).map_err(DecodeError::Proto)?);
        at = end;
    }
    Ok(frames)
}

/// Join already-encoded frames into one websocket message. One frame is passed through without copying.
pub fn join_frames(mut frames: Vec<Bytes>) -> Bytes {
    if frames.len() == 1 {
        return frames.pop().expect("one frame");
    }
    let mut buf = BytesMut::with_capacity(frames.iter().map(Bytes::len).sum());
    for f in &frames {
        buf.put_slice(f);
    }
    buf.freeze()
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
                payload: Bytes::from_static(&[0xde, 0xad]),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn shared_decoding_agrees_with_copying_decoding_and_shares_the_payload() {
        let frames = vec![published(1), published(2)];
        let bytes = encode_frames(&frames, 1 << 16).unwrap();
        let message = Bytes::from(bytes.clone());
        let shared = decode_frames_shared(message.clone(), 1 << 16).unwrap();
        assert_eq!(shared, decode_frames(&bytes, 1 << 16).unwrap());
        let Some(Body::Envelope(e)) = &shared[0].body else { panic!("envelope") };
        // a slice of the message, not a copy
        let range = message.as_ptr() as usize..message.as_ptr() as usize + message.len();
        assert!(range.contains(&(e.payload.as_ptr() as usize)));
    }

    #[test]
    fn encode_frame_then_join_is_the_same_bytes_as_encode_frames() {
        let frames = vec![published(1), published(2), Frame { body: Some(Body::Ping(v1::Ping { nonce: 9 })) }];
        let joined = join_frames(frames.iter().map(encode_frame).collect());
        assert_eq!(joined.as_ref(), encode_frames(&frames, 1 << 16).unwrap().as_slice());
    }

    #[test]
    fn shared_decoding_refuses_what_copying_decoding_refuses() {
        let bytes = encode_frames(&[published(1)], 1 << 16).unwrap();
        assert!(decode_frames_shared(Bytes::from(bytes[..bytes.len() - 1].to_vec()), 1 << 16).is_err());
        assert!(decode_frames_shared(Bytes::from_static(&[0xff; 11]), 1 << 16).is_err());
        assert!(decode_frames_shared(Bytes::from(bytes.clone()), 3).is_err());
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
