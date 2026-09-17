//! Varint-delimited framing: how one protobuf message is told from the next on a byte stream.
//!
//! A varint byte count precedes each message, protobuf's own delimited convention (`writeDelimitedTo` /
//! `parseDelimitedFrom`). It is the framing the extension already reads for the patched Ollama's chat stream
//! (`src/protostream.ts` in window-ml), and the hub uses the same one so a batch of envelopes can share one
//! websocket message. The two implementations must agree byte for byte; the vectors in the tests are shared.
//!
//! Transport chunks have nothing to do with message boundaries: one read can carry three messages and half of a
//! fourth. So [`FrameReader`] buffers and yields only what is wholly present, and the difference between "wait
//! for more" and "this is corrupt" is the whole job of this crate.

use std::fmt;

/// The largest single frame assembled by default, as a guard against a corrupt length prefix claiming gigabytes.
/// Matches `MAX_FRAME_BYTES` in `protostream.ts`.
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// A varint longer than this many bytes encodes more than 64 bits, which no length we send ever needs.
const MAX_VARINT_BYTES: usize = 10;

/// Why a stream cannot be framed. Both are corruption, not a short read: the stream is unusable afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// A length prefix ran past ten bytes.
    VarintTooLong,
    /// A frame declared (or a writer was handed) more bytes than the limit allows.
    TooLarge { len: u64, max: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::VarintTooLong => write!(f, "frame: varint too long"),
            FrameError::TooLarge { len, max } => write!(f, "frame: frame of {len} bytes refused (limit {max})"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Read one varint from the start of `buf`.
///
/// `Ok(None)` means the bytes present do not yet hold a whole one: the ordinary case at the end of a chunk.
/// On success returns the value and how many bytes it took.
pub fn read_varint(buf: &[u8]) -> Result<Option<(u64, usize)>, FrameError> {
    let mut value: u64 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= MAX_VARINT_BYTES {
            return Err(FrameError::VarintTooLong);
        }
        // The tenth byte carries only the top bit of a u64; anything above it would be silently lost.
        if i == MAX_VARINT_BYTES - 1 && (b & 0x7f) > 1 {
            return Err(FrameError::VarintTooLong);
        }
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Ok(Some((value, i + 1)));
        }
    }
    if buf.len() >= MAX_VARINT_BYTES {
        return Err(FrameError::VarintTooLong);
    }
    Ok(None)
}

/// Append `value` as a varint.
pub fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Append one delimited frame (length prefix, then `message`). Refuses a message over `max`, so a writer cannot
/// produce what its own reader would reject.
pub fn write_frame(message: &[u8], max: usize, out: &mut Vec<u8>) -> Result<(), FrameError> {
    if message.len() > max {
        return Err(FrameError::TooLarge { len: message.len() as u64, max });
    }
    write_varint(message.len() as u64, out);
    out.extend_from_slice(message);
    Ok(())
}

/// A stateful reader: push bytes as they arrive, take the whole frames that have become available.
///
/// Not an async stream over a transport on purpose: the caller owns its read loop (cancellation, timing,
/// backpressure), and handing the loop over to get framing back would be the wrong trade.
#[derive(Debug)]
pub struct FrameReader {
    buf: Vec<u8>,
    /// Bytes at the front of `buf` already handed out, compacted lazily so a stream of small frames is not a
    /// quadratic copy.
    start: usize,
    max: usize,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new(MAX_FRAME_BYTES)
    }
}

impl FrameReader {
    /// A reader that refuses frames over `max` bytes.
    pub fn new(max: usize) -> Self {
        Self { buf: Vec::new(), start: 0, max }
    }

    /// Add a chunk; get back every frame that is now complete, in order. After an error the stream is corrupt and
    /// the reader should be dropped with the connection.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        if self.start > 0 && self.start * 2 >= self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            let rest = &self.buf[self.start..];
            let Some((len, head)) = read_varint(rest)? else { break };
            if len > self.max as u64 {
                return Err(FrameError::TooLarge { len, max: self.max });
            }
            let len = len as usize;
            if rest.len() < head + len {
                break;
            }
            out.push(rest[head..head + len].to_vec());
            self.start += head + len;
        }
        Ok(out)
    }

    /// Bytes held back waiting for the rest of their frame. Non-zero when a stream ends means it was cut
    /// mid-frame, which is a transport failure rather than an end.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors shared with window-ml's `protostream.ts`: the same bytes must frame the same way in both.
    const VARINTS: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (1, &[0x01]),
        (127, &[0x7f]),
        (128, &[0x80, 0x01]),
        (300, &[0xac, 0x02]),
        (16_384, &[0x80, 0x80, 0x01]),
        (1 << 20, &[0x80, 0x80, 0x40]),
        (u64::MAX, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
    ];

    #[test]
    fn varints_encode_and_decode_to_the_shared_vectors() {
        for &(value, bytes) in VARINTS {
            let mut out = Vec::new();
            write_varint(value, &mut out);
            assert_eq!(out, bytes, "encode {value}");
            assert_eq!(read_varint(bytes), Ok(Some((value, bytes.len()))), "decode {value}");
        }
    }

    #[test]
    fn a_partial_varint_waits() {
        assert_eq!(read_varint(&[]), Ok(None));
        assert_eq!(read_varint(&[0x80]), Ok(None));
        assert_eq!(read_varint(&[0xff; 9]), Ok(None));
    }

    #[test]
    fn an_overlong_varint_is_corruption() {
        assert_eq!(read_varint(&[0xff; 11]), Err(FrameError::VarintTooLong));
        assert_eq!(read_varint(&[0xff; 10]), Err(FrameError::VarintTooLong));
        // ten bytes whose last carries more than bit 63
        let mut over = vec![0xff; 9];
        over.push(0x02);
        assert_eq!(read_varint(&over), Err(FrameError::VarintTooLong));
    }

    fn frames(messages: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in messages {
            write_frame(m, MAX_FRAME_BYTES, &mut out).unwrap();
        }
        out
    }

    #[test]
    fn frames_survive_every_chunk_boundary() {
        let messages: [&[u8]; 4] = [b"", b"a", &[7u8; 200], b"last"];
        let stream = frames(&messages);
        for cut in 0..=stream.len() {
            let mut r = FrameReader::default();
            let mut got = r.push(&stream[..cut]).unwrap();
            got.extend(r.push(&stream[cut..]).unwrap());
            assert_eq!(got, messages.map(<[u8]>::to_vec), "cut at {cut}");
            assert_eq!(r.pending(), 0);
        }
    }

    #[test]
    fn byte_at_a_time_yields_each_frame_once() {
        let messages: [&[u8]; 3] = [b"one", b"two", &[1u8; 300]];
        let mut r = FrameReader::default();
        let mut got = Vec::new();
        for b in frames(&messages) {
            got.extend(r.push(&[b]).unwrap());
        }
        assert_eq!(got, messages.map(<[u8]>::to_vec));
    }

    #[test]
    fn a_cut_stream_reports_pending_bytes() {
        let stream = frames(&[b"hello"]);
        let mut r = FrameReader::default();
        assert!(r.push(&stream[..3]).unwrap().is_empty());
        assert_eq!(r.pending(), 3);
    }

    #[test]
    fn an_oversized_length_is_refused_before_buffering_its_body() {
        let mut r = FrameReader::new(16);
        let mut head = Vec::new();
        write_varint(17, &mut head);
        assert_eq!(r.push(&head), Err(FrameError::TooLarge { len: 17, max: 16 }));
    }

    #[test]
    fn a_writer_cannot_emit_what_the_reader_refuses() {
        let mut out = Vec::new();
        assert_eq!(write_frame(&[0; 17], 16, &mut out), Err(FrameError::TooLarge { len: 17, max: 16 }));
        assert!(out.is_empty());
    }
}
