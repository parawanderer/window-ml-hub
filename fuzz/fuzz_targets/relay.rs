//! The relay model checker, driven by libFuzzer: any byte string is an operation sequence, and every invariant in
//! `wmlhub_relay::model` is checked after every operation.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(violation) = wmlhub_relay::model::Model::run_bytes(data) {
        panic!("{violation}");
    }
});
