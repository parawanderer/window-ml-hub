//! Reading a frame's two tags must agree with decoding it, for every kind and whatever else the frame carries.

use super::*;

use prost::Message;
use wmlhub_box::schema::{self, EventFrame};

fn frame(kind: &str, info: bool) -> Vec<u8> {
    EventFrame {
        v: Some(1),
        kind: Some(kind.to_owned()),
        t: Some(1_500),
        at_ms: Some(1_800_000_000_000),
        r#box: "mlbox".into(),
        dropped: 0,
        info: info.then(schema::InfoResponse::default),
        ps: Some(schema::ProcessResponse::default()),
        ..Default::default()
    }
    .encode_to_vec()
}

#[test]
fn what_the_tags_say_is_what_the_frame_says() {
    for kind in ["hello", "heartbeat", "sample", "gen.end", "load.complete", "something.new"] {
        for info in [false, true] {
            let bytes = frame(kind, info);
            let read = read(&bytes);
            let decoded = EventFrame::decode(bytes.as_slice()).expect("the fixture decodes");
            assert_eq!(read.kind, decoded.kind.as_deref(), "{kind} info={info}");
            assert_eq!(read.has_info, decoded.info.is_some(), "{kind} info={info}");
            assert_eq!(read.at_ms, decoded.at_ms.map(|ms| ms as u64), "{kind} at_ms");
            assert!(read.readable);
        }
    }
}

#[test]
fn each_kind_goes_where_the_design_says() {
    assert_eq!(route(&frame("hello", false)).0, Route::Consume);
    assert_eq!(route(&frame("heartbeat", false)).0, Route::Sample { coalesce: HEARTBEAT_COALESCE });
    assert_eq!(route(&frame("sample", false)).0, Route::Sample { coalesce: SAMPLE_COALESCE });
    assert_eq!(
        route(&frame("sample", true)).0,
        Route::Sample { coalesce: b"" },
        "a sample carrying info is never superseded: info is sent only when it changed"
    );
    for edge in [
        "estimate",
        "load.start",
        "load.weights",
        "load.complete",
        "load.failed",
        "evict",
        "unload",
        "expires",
        "busy.start",
        "busy.end",
        "gen.start",
        "gen.end",
        "lease.start",
        "lease.granted",
        "lease.end",
    ] {
        assert_eq!(route(&frame(edge, false)).0, Route::Edge, "{edge}");
    }
}

#[test]
fn a_kind_this_connector_has_never_heard_of_is_relayed_losslessly() {
    let bytes = frame("something.the.fork.added", false);
    let (route, read) = route(&bytes);
    assert_eq!(route, Route::Edge);
    assert_eq!(read.kind, Some("something.the.fork.added"));
}

#[test]
fn a_frame_whose_tags_do_not_parse_is_relayed_not_dropped() {
    let good = frame("sample", false);
    for cut in 1..good.len() {
        let (route, read) = route(&good[..cut]);
        if !read.readable {
            assert_eq!(route, Route::Edge, "truncated at {cut}");
        }
    }
    for garbage in [&[0xff, 0xff, 0xff][..], &[0x23][..], &[0x0a, 0x7f][..], &[0x3c][..]] {
        assert_eq!(route(garbage).0, Route::Edge, "{garbage:?}");
    }
    assert_eq!(route(&[]).0, Route::Edge, "a frame with no kind at all");
}

#[test]
fn a_field_this_connector_does_not_know_is_skipped_whatever_its_wire_type() {
    let mut bytes = frame("sample", false);
    // field 1000, each wire type, appended after everything the reader cares about
    bytes.extend_from_slice(&[0xc0, 0x3e, 0x2a]); // varint
    bytes.extend_from_slice(&[0xc1, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0]); // 64-bit
    bytes.extend_from_slice(&[0xc2, 0x3e, 2, 7, 7]); // length-delimited
    bytes.extend_from_slice(&[0xc5, 0x3e, 0, 0, 0, 0]); // 32-bit
    let read = read(&bytes);
    assert!(read.readable, "unknown fields are skipped, not refused");
    assert_eq!(read.kind, Some("sample"));
    assert_eq!(read.at_ms, Some(1_800_000_000_000), "a field after the ones we read is still skipped correctly");
}

#[test]
fn a_length_that_runs_off_the_end_is_not_read_as_a_kind() {
    // field 2, length-delimited, length 100, but only three bytes follow
    let bytes = [0x12, 100, b'a', b'b', b'c'];
    let read = read(&bytes);
    assert!(!read.readable);
    assert_eq!(read.kind, None);
    assert_eq!(route(&bytes).0, Route::Edge);
}

#[test]
fn a_group_is_unreadable_even_though_prost_skips_it() {
    // proto2 groups: field 87475, start (wire 3) then end (wire 4), carrying nothing. prost skips an unknown group,
    // so this decodes; the reader refuses wire types 3 and 4 outright, so the frame is relayed losslessly instead.
    // The two disagreeing is deliberate: a box writes proto3, and skipping a group means recursing, which this
    // reader never does. A frame it cannot read is a question for the client, not a reason to teach it grammar.
    let bytes = [0x9b, 0xdb, 0x2a, 0x9c, 0xdb, 0x2a];
    EventFrame::decode(&bytes[..]).expect("prost skips an unknown group");
    let (route, read) = route(&bytes);
    assert!(!read.readable);
    assert_eq!(route, Route::Edge);
}
