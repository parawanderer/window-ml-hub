//! The two state machines, driven the way a socket drives them: a byte at a time, in odd splits, and with the shapes
//! a server is allowed to send but rarely does.

use super::*;

fn head(text: &str) -> Result<Option<(ResponseHead, usize)>, HttpError> {
    ResponseHead::parse(text.as_bytes())
}

#[test]
fn a_head_is_read_once_its_blank_line_arrives() {
    let text = "HTTP/1.1 200 OK\r\nContent-Type: application/protobuf; delimited=varint\r\nTransfer-Encoding: chunked\r\n\r\nbody";
    let (parsed, consumed) = head(text).unwrap().expect("a whole head");
    assert_eq!(parsed.status, 200);
    assert!(parsed.is_protobuf());
    assert!(parsed.chunked);
    assert_eq!(&text[consumed..], "body");

    // every prefix of it is "not yet", never a wrong answer
    for cut in 0..text.len() - 4 {
        assert_eq!(head(&text[..cut]).unwrap(), None, "cut at {cut}");
    }
}

#[test]
fn header_names_are_case_insensitive_and_whitespace_is_trimmed() {
    let (parsed, _) = head("HTTP/1.1 200 OK\r\ncONTENT-tYPE:   application/protobuf   \r\n\r\n").unwrap().unwrap();
    assert!(parsed.is_protobuf());
}

#[test]
fn ndjson_is_told_apart_from_the_binary_stream() {
    let (parsed, _) = head("HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\r\n").unwrap().unwrap();
    assert!(!parsed.is_protobuf(), "a box that did not understand the request answers NDJSON");
}

#[test]
fn a_head_that_is_not_http_or_has_no_code_is_refused() {
    assert!(matches!(head("nonsense\r\n\r\n"), Err(HttpError::Malformed(_))));
    assert!(matches!(head("HTTP/1.1 nope OK\r\n\r\n"), Err(HttpError::Malformed(_))));
    assert!(matches!(head("HTTP/1.1 200 OK\r\nno-colon\r\n\r\n"), Err(HttpError::Malformed(_))));
}

#[test]
fn a_head_past_its_bound_is_refused_rather_than_buffered() {
    let long = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD_BYTES));
    assert_eq!(ResponseHead::parse(long.as_bytes()), Err(HttpError::TooLarge("the response head")));
    // and one still arriving, with no end in sight
    let unfinished = vec![b'x'; MAX_HEAD_BYTES + 1];
    assert_eq!(ResponseHead::parse(&unfinished), Err(HttpError::TooLarge("the response head")));
}

#[test]
fn too_many_headers_is_refused() {
    let mut text = String::from("HTTP/1.1 200 OK\r\n");
    for i in 0..MAX_HEADERS + 2 {
        text.push_str(&format!("X-{i}: v\r\n"));
    }
    text.push_str("\r\n");
    assert_eq!(head(&text), Err(HttpError::TooLarge("the header count")));
}

// ------------------------------ the body ------------------------------

/// Feed `bytes` to a decoder in pieces of `step`, collecting everything it yields.
fn chunked_in_steps(bytes: &[u8], step: usize) -> Result<Vec<u8>, HttpError> {
    let mut decoder = Chunked::default();
    let mut out = Vec::new();
    for piece in bytes.chunks(step.max(1)) {
        out.extend_from_slice(&decoder.push(piece)?);
    }
    Ok(out)
}

#[test]
fn a_chunked_body_decodes_however_the_reads_fall() {
    let body = "5\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\n\r\n";
    for step in 1..=body.len() {
        assert_eq!(chunked_in_steps(body.as_bytes(), step).unwrap(), b"hello world", "step {step}");
    }
}

#[test]
fn a_chunk_extension_is_ignored() {
    let body = "5;name=value\r\nhello\r\n0\r\n\r\n";
    assert_eq!(chunked_in_steps(body.as_bytes(), 1).unwrap(), b"hello");
}

#[test]
fn the_last_chunk_ends_the_body_and_nothing_after_it_is_read() {
    let mut decoder = Chunked::default();
    assert_eq!(decoder.push(b"3\r\nabc\r\n0\r\n\r\n").unwrap(), b"abc");
    assert!(decoder.done());
    assert!(decoder.push(b"5\r\nlater\r\n").unwrap().is_empty(), "nothing is read past the end");
}

#[test]
fn a_chunk_over_the_limit_is_refused_before_it_is_buffered() {
    let mut decoder = Chunked::default();
    let size = format!("{:x}\r\n", MAX_CHUNK_BYTES + 1);
    assert_eq!(decoder.push(size.as_bytes()), Err(HttpError::TooLarge("a chunk")));
}

#[test]
fn a_size_line_that_is_not_hex_or_never_ends_is_refused() {
    assert!(matches!(Chunked::default().push(b"zz\r\n"), Err(HttpError::Malformed(_))));
    assert!(matches!(Chunked::default().push(&[b'a'; 65]), Err(HttpError::Malformed(_))));
}

// ------------------------------ the target ------------------------------

#[test]
fn a_url_splits_into_host_port_and_path() {
    assert_eq!(
        Target::parse("http://mlbox:11434/api/events").unwrap(),
        Target { host: "mlbox".into(), port: 11434, path: "/api/events".into() }
    );
    assert_eq!(Target::parse("http://localhost").unwrap().path, "/");
    assert_eq!(Target::parse("http://localhost/x").unwrap().port, 80);
}

#[test]
fn a_url_this_connector_cannot_read_is_refused_rather_than_downgraded() {
    for url in ["https://mlbox/api/events", "mlbox/api/events", "http://", "http://host:port/x"] {
        assert!(Target::parse(url).is_err(), "{url}");
    }
}

#[test]
fn the_request_asks_for_the_binary_stream_and_places_since_correctly() {
    let target = Target::parse("http://mlbox:11434/api/events").unwrap();
    let plain = target.request(None);
    assert!(plain.starts_with("GET /api/events HTTP/1.1\r\n"));
    assert!(plain.contains("Accept: application/protobuf\r\n"));
    assert!(plain.contains("Host: mlbox:11434\r\n"));
    assert!(plain.ends_with("\r\n\r\n"));
    assert!(target.request(Some(60_000)).starts_with("GET /api/events?since=60000 "));

    let with_query = Target::parse("http://mlbox/api/events?box=one").unwrap();
    assert!(with_query.request(Some(5)).starts_with("GET /api/events?box=one&since=5 "));
}
