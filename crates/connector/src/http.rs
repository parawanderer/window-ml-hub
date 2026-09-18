//! Just enough HTTP/1.1 to read one streaming response: a GET, its headers, and a chunked body
//! (docs/design/box-connector.md §Reading the stream).
//!
//! An HTTP client crate would bring a dependency tree for one request shape that never changes, and this repository
//! already writes its own framing for the same reason. What it deliberately does NOT do: TLS (a box is reached over
//! loopback or a tailnet), redirects, compression, or any method but GET. Anything else it meets is an error rather
//! than a guess.
//!
//! The parsing is two state machines with no IO, so they can be tested and fuzzed directly: [`ResponseHead::parse`]
//! and [`Chunked`]. Every buffer they keep is bounded, because the far end is a program, not a friend.

use std::fmt;

/// The most a status line and headers may take together.
pub const MAX_HEAD_BYTES: usize = 16 << 10;
/// The most headers one response may carry.
pub const MAX_HEADERS: usize = 64;
/// The largest single chunk accepted, which also bounds what one read can add to the frame reader.
pub const MAX_CHUNK_BYTES: usize = 4 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum HttpError {
    /// the head did not parse, or a chunk's framing did not
    Malformed(&'static str),
    /// a head, header count, or chunk past its bound
    TooLarge(&'static str),
    /// the response was not 200
    Status(u16),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed {what}"),
            Self::TooLarge(what) => write!(f, "{what} over its limit"),
            Self::Status(code) => write!(f, "the box answered {code}"),
        }
    }
}

impl std::error::Error for HttpError {}

/// A response's status and the headers this connector cares about.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub content_type: String,
    pub chunked: bool,
    /// absent on a stream, which is the ordinary case here
    pub content_length: Option<u64>,
}

impl ResponseHead {
    /// Parse a head from the front of `buf`. `Ok(None)` means the blank line has not arrived yet, which is the
    /// ordinary case on a socket and not an error.
    pub fn parse(buf: &[u8]) -> Result<Option<(Self, usize)>, HttpError> {
        let Some(end) = find(buf, b"\r\n\r\n") else {
            return if buf.len() > MAX_HEAD_BYTES { Err(HttpError::TooLarge("the response head")) } else { Ok(None) };
        };
        let consumed = end + 4;
        if consumed > MAX_HEAD_BYTES {
            return Err(HttpError::TooLarge("the response head"));
        }
        let head = std::str::from_utf8(&buf[..end]).map_err(|_| HttpError::Malformed("head: not text"))?;
        let mut lines = head.split("\r\n");
        let status_line = lines.next().ok_or(HttpError::Malformed("status line"))?;
        // HTTP/1.1 200 OK
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/1.") {
            return Err(HttpError::Malformed("status line: not HTTP/1.x"));
        }
        let status: u16 =
            parts.next().unwrap_or_default().parse().map_err(|_| HttpError::Malformed("status line: code"))?;

        let mut out = Self { status, ..Self::default() };
        for (n, line) in lines.enumerate() {
            if n >= MAX_HEADERS {
                return Err(HttpError::TooLarge("the header count"));
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(HttpError::Malformed("a header without a colon"));
            };
            let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
            match name.as_str() {
                "content-type" => out.content_type = value.to_owned(),
                // Only the chunked case matters: a body with a length is a response that ends, which this reader
                // handles by reading that many bytes, and anything else it meets it refuses.
                "transfer-encoding" => {
                    out.chunked = value.to_ascii_lowercase().split(',').any(|e| e.trim() == "chunked")
                }
                "content-length" => {
                    out.content_length = Some(value.parse().map_err(|_| HttpError::Malformed("content-length"))?);
                }
                _ => {}
            }
        }
        Ok(Some((out, consumed)))
    }

    /// Is this the protobuf stream we asked for? The box answers `application/protobuf; delimited=varint`, and NDJSON
    /// when it did not understand the request, which is worth saying plainly rather than failing at the first frame.
    pub fn is_protobuf(&self) -> bool {
        self.content_type.split(';').next().is_some_and(|t| t.trim().eq_ignore_ascii_case("application/protobuf"))
    }
}

/// A chunked body, decoded as it arrives. Holds at most one chunk's worth of unparsed bytes.
#[derive(Debug, Default)]
pub struct Chunked {
    buf: Vec<u8>,
    /// bytes still to come of the chunk being read
    left: usize,
    done: bool,
}

impl Chunked {
    /// Add what was read; get back the body bytes now available, in order. An empty result means "more is coming".
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, HttpError> {
        if self.done {
            return Ok(Vec::new());
        }
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.left > 0 {
                let take = self.left.min(self.buf.len());
                out.extend_from_slice(&self.buf[..take]);
                self.buf.drain(..take);
                self.left -= take;
                if self.left > 0 {
                    break;
                }
                continue;
            }
            // between chunks: a size line, or the CRLF that ended the last chunk
            if self.buf.starts_with(b"\r\n") {
                self.buf.drain(..2);
                continue;
            }
            let Some(end) = find(&self.buf, b"\r\n") else {
                if self.buf.len() > 64 {
                    return Err(HttpError::Malformed("a chunk size line"));
                }
                break;
            };
            let line = std::str::from_utf8(&self.buf[..end]).map_err(|_| HttpError::Malformed("a chunk size line"))?;
            // a chunk extension (`1f;name=value`) is legal and ignored
            let size_text = line.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size_text, 16).map_err(|_| HttpError::Malformed("a chunk size"))?;
            if size > MAX_CHUNK_BYTES {
                return Err(HttpError::TooLarge("a chunk"));
            }
            self.buf.drain(..end + 2);
            if size == 0 {
                // the last chunk; trailers and the final CRLF are of no interest to a stream reader
                self.done = true;
                break;
            }
            self.left = size;
        }
        Ok(out)
    }

    /// Has the far end said the body is complete?
    pub fn done(&self) -> bool {
        self.done
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Where to read a box's events from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Target {
    /// Split an `http://host[:port]/path` URL. No other scheme: TLS is out of scope here, and a silent downgrade
    /// would be worse than saying so.
    pub fn parse(url: &str) -> Result<Self, HttpError> {
        let rest = url.strip_prefix("http://").ok_or(HttpError::Malformed("a url that is not http://"))?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(HttpError::Malformed("a url without a host"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().map_err(|_| HttpError::Malformed("a url with a bad port"))?),
            None => (authority, 80),
        };
        Ok(Self { host: host.to_owned(), port, path: path.to_owned() })
    }

    /// The request this connector sends: the binary stream, and a backfill window when one is wanted.
    pub fn request(&self, since_ms: Option<u64>) -> String {
        let query = match since_ms {
            Some(ms) if self.path.contains('?') => format!("&since={ms}"),
            Some(ms) => format!("?since={ms}"),
            None => String::new(),
        };
        format!(
            "GET {path}{query} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/protobuf\r\n\
             Accept-Encoding: identity\r\nUser-Agent: wmlhub-connector\r\n\r\n",
            path = self.path,
            host = self.host,
            port = self.port,
        )
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
