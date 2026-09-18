//! The box's `/api/events`, read as frames: one TCP connection, one GET, and the varint-delimited protobuf the box
//! streams back (docs/design/box-connector.md §Reading the stream).
//!
//! A frame's bytes are handed on UNCHANGED. That is the whole point of the binary stream: what the box wrote is what
//! a client decodes, with nothing in between decoding and re-encoding it.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wmlhub_box::MAX_BOX_FRAME_BYTES;
use wmlhub_frame::FrameReader;

use crate::http::{Chunked, HttpError, ResponseHead, Target};

/// How long a connect or a read may take before the connector gives up and reconnects. A box that has nothing to say
/// still sends a heartbeat every 5 s, so silence past this is a dead link rather than a quiet one.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

const READ_BUFFER_BYTES: usize = 16 << 10;

#[derive(Debug)]
pub enum IngestError {
    Io(std::io::Error),
    Http(HttpError),
    /// the box answered with something other than the binary stream (NDJSON, when it did not understand the request)
    NotProtobuf(String),
    /// a frame's length prefix did not make sense, or a frame was over the limit
    Frames(wmlhub_frame::FrameError),
    /// the box closed the stream
    Ended,
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Http(e) => write!(f, "{e}"),
            Self::NotProtobuf(got) => write!(f, "the box answered {got}, not the binary stream"),
            Self::Frames(e) => write!(f, "framing: {e:?}"),
            Self::Ended => write!(f, "the box closed the stream"),
        }
    }
}

/// An open stream of a box's frames.
pub struct Events {
    socket: TcpStream,
    chunked: Option<Chunked>,
    frames: FrameReader,
    ready: std::collections::VecDeque<Vec<u8>>,
}

impl Events {
    /// Connect, ask for the binary stream, and read the head. `since_ms` asks the box to replay that far back.
    pub async fn open(target: &Target, since_ms: Option<u64>) -> Result<Self, IngestError> {
        let socket = tokio::time::timeout(READ_TIMEOUT, TcpStream::connect((target.host.as_str(), target.port)))
            .await
            .map_err(|_| IngestError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "connecting")))?
            .map_err(IngestError::Io)?;
        let mut events =
            Self { socket, chunked: None, frames: FrameReader::new(MAX_BOX_FRAME_BYTES), ready: Default::default() };
        events.socket.write_all(target.request(since_ms).as_bytes()).await.map_err(IngestError::Io)?;

        // the head, then whatever of the body came with it
        let mut head = Vec::new();
        let mut buf = vec![0u8; READ_BUFFER_BYTES];
        loop {
            let (parsed, consumed) = match ResponseHead::parse(&head).map_err(IngestError::Http)? {
                Some(found) => found,
                None => {
                    let read = events.read_into(&mut buf).await?;
                    head.extend_from_slice(&buf[..read]);
                    continue;
                }
            };
            if parsed.status != 200 {
                return Err(IngestError::Http(HttpError::Status(parsed.status)));
            }
            if !parsed.is_protobuf() {
                return Err(IngestError::NotProtobuf(parsed.content_type));
            }
            events.chunked = parsed.chunked.then(Chunked::default);
            let body = head.split_off(consumed);
            events.feed(&body)?;
            return Ok(events);
        }
    }

    /// The next frame the box sent, exactly as it sent it.
    pub async fn next_frame(&mut self) -> Result<Vec<u8>, IngestError> {
        let mut buf = vec![0u8; READ_BUFFER_BYTES];
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(frame);
            }
            if self.chunked.as_ref().is_some_and(Chunked::done) {
                return Err(IngestError::Ended);
            }
            let read = self.read_into(&mut buf).await?;
            let chunk = buf[..read].to_vec();
            self.feed(&chunk)?;
        }
    }

    async fn read_into(&mut self, buf: &mut [u8]) -> Result<usize, IngestError> {
        let read = tokio::time::timeout(READ_TIMEOUT, self.socket.read(buf))
            .await
            .map_err(|_| IngestError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "reading")))?
            .map_err(IngestError::Io)?;
        if read == 0 {
            return Err(IngestError::Ended);
        }
        Ok(read)
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<(), IngestError> {
        let body = match self.chunked.as_mut() {
            Some(chunked) => chunked.push(bytes).map_err(IngestError::Http)?,
            None => bytes.to_vec(),
        };
        if body.is_empty() {
            return Ok(());
        }
        for frame in self.frames.push(&body).map_err(IngestError::Frames)? {
            self.ready.push_back(frame);
        }
        Ok(())
    }
}
