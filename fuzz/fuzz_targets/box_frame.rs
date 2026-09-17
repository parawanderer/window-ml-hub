//! Reading a box frame's tags never panics, and whenever the frame decodes, what the tags said matches what it says.
#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use wmlhub_box::schema::EventFrame;
use wmlhub_box::{Route, route};
use wmlhub_proto::prost::Message;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(structured) = bool::arbitrary(&mut u) else { return };
    let bytes = if structured {
        // a frame the box could have written: an arbitrary kind, with or without info
        let Ok(kind) = String::arbitrary(&mut u) else { return };
        let Ok(info) = bool::arbitrary(&mut u) else { return };
        let Ok(dropped) = u64::arbitrary(&mut u) else { return };
        EventFrame {
            v: Some(1),
            kind: Some(kind),
            dropped,
            info: info.then(wmlhub_box::schema::InfoResponse::default),
            ..Default::default()
        }
        .encode_to_vec()
    } else {
        u.take_rest().to_vec()
    };

    let (route, read) = route(&bytes);
    if let Ok(decoded) = EventFrame::decode(bytes.as_slice()) {
        assert_eq!(read.kind, decoded.kind.as_deref(), "kind read from tags differs from the decoded frame");
        assert_eq!(read.has_info, decoded.info.is_some(), "info presence differs from the decoded frame");
        assert!(read.readable, "a frame that decodes was not readable");
    }
    // whatever it is, it goes somewhere, and anything unreadable goes to the lossless channel
    if !read.readable {
        assert_eq!(route, Route::Edge);
    }
});
