//! Which channel a box's `/api/events` frame belongs on, decided without decoding it
//! (docs/design/box-connector.md).
//!
//! The point of the binary stream is that a frame the box wrote reaches a client byte for byte: nothing between them
//! decodes and re-encodes it. But the relay needs two facts to route one: its `kind` (field 2) and, for a sample,
//! whether it carries `info` (field 28). So this walks the frame's top-level tags, reads those two, skips everything
//! else by wire type, and hands the bytes on untouched.
//!
//! What cannot be read is relayed, not dropped: a frame whose tags do not parse, or whose kind this connector has
//! never heard of, goes on the lossless channel. An unreadable frame is a question for the client, never a reason for
//! the relay to lose one.

/// The largest frame accepted, matching the relay's payload limit. A frame is about 2.1 KB plus 1.6 KB per resident
/// model, so this is two orders of magnitude of room (docs/design/box-connector.md §Sizes).
pub const MAX_BOX_FRAME_BYTES: usize = 1 << 20;

/// `EventFrame.kind`, a string.
const FIELD_KIND: u64 = 2;
/// `EventFrame.info`, sent only when it changed.
const FIELD_INFO: u64 = 28;

/// The coalesce key for a sample that carries no `info`: any queued one may be superseded by a newer one.
pub const SAMPLE_COALESCE: &[u8] = b"s";
/// Heartbeats coalesce among themselves, never with samples. The relay keeps the newest, which is what tells a quiet
/// box from a dead link.
pub const HEARTBEAT_COALESCE: &[u8] = b"h";

/// Where a frame goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// The connector's own business: a `hello` belongs to one connection and is never relayed as another's.
    Consume,
    /// Lossless and ordered (`KIND_SESSION_EVENTS`): every edge, every unknown kind, every unreadable frame.
    Edge,
    /// Coalesced and, past a limit, dropped oldest-first (`KIND_TELEMETRY`). An empty key never coalesces.
    Sample { coalesce: &'static [u8] },
}

/// What the tags say. `kind` borrows from the frame; it is not decoded further.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read<'a> {
    /// absent when the frame carries no kind, or its tags do not parse
    pub kind: Option<&'a str>,
    pub has_info: bool,
    /// false when the tags do not parse: the frame is still relayed, losslessly
    pub readable: bool,
}

/// Read a frame's kind and whether it carries `info`, walking top-level tags only.
pub fn read(frame: &[u8]) -> Read<'_> {
    let mut at = 0usize;
    let mut kind = None;
    let mut has_info = false;
    while at < frame.len() {
        let Some((key, next)) = varint(frame, at) else { return unreadable(kind, has_info) };
        at = next;
        let (field, wire) = (key >> 3, key & 7);
        match wire {
            // varint
            0 => {
                let Some((_, next)) = varint(frame, at) else { return unreadable(kind, has_info) };
                at = next;
            }
            // 64-bit
            1 => at = at.saturating_add(8),
            // length-delimited
            2 => {
                let Some((len, next)) = varint(frame, at) else { return unreadable(kind, has_info) };
                let Ok(len) = usize::try_from(len) else { return unreadable(kind, has_info) };
                let Some(end) = next.checked_add(len).filter(|end| *end <= frame.len()) else {
                    return unreadable(kind, has_info);
                };
                match field {
                    FIELD_KIND => kind = std::str::from_utf8(&frame[next..end]).ok(),
                    FIELD_INFO => has_info = true,
                    _ => {}
                }
                at = end;
            }
            // 32-bit
            5 => at = at.saturating_add(4),
            // groups (3, 4) were removed from proto3, and 6 and 7 do not exist
            _ => return unreadable(kind, has_info),
        }
        if at > frame.len() {
            return unreadable(kind, has_info);
        }
    }
    Read { kind, has_info, readable: true }
}

fn unreadable(kind: Option<&str>, has_info: bool) -> Read<'_> {
    Read { kind, has_info, readable: false }
}

/// Where this frame goes, and what the connector read to decide.
pub fn route(frame: &[u8]) -> (Route, Read<'_>) {
    let read = read(frame);
    let route = match (read.readable, read.kind) {
        (true, Some("hello")) => Route::Consume,
        (true, Some("heartbeat")) => Route::Sample { coalesce: HEARTBEAT_COALESCE },
        // A sample carrying `info` is sent only when `info` changed, so superseding it would lose that change for
        // good: it rides the sample channel with an empty key, which never coalesces.
        (true, Some("sample")) => Route::Sample { coalesce: if read.has_info { b"" } else { SAMPLE_COALESCE } },
        // every edge, every kind this connector has not heard of, and every frame whose tags did not parse
        _ => Route::Edge,
    };
    (route, read)
}

/// The varint at `at`, and where it ends. None when it runs off the end or is longer than ten bytes.
fn varint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (shift, i) in (at..bytes.len().min(at + 10)).enumerate() {
        let byte = bytes[i];
        value |= u64::from(byte & 0x7f) << (shift * 7);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// The box's own event types, generated from the vendored schema. For tests and fuzzing only: the connector reads two
/// tags and relays the bytes, and nothing in this crate's own path decodes a frame.
#[cfg(feature = "testing")]
#[allow(clippy::doc_markdown, clippy::struct_field_names, clippy::large_enum_variant, missing_docs)]
pub mod schema {
    include!(concat!(env!("OUT_DIR"), "/slop.events.v1.rs"));
}

#[cfg(test)]
mod tests;
