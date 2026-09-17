//! Generates the wire types from `proto/`. Uses protox, a protobuf compiler written in Rust, so building needs no
//! `protoc` on the machine.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../proto");
    let files = ["wmlhub/v1/hub.proto", "wmlhub/v1/identity.proto"];
    for file in files {
        println!("cargo:rerun-if-changed={root}/{file}");
    }
    let descriptors = protox::compile(files, [root])?;
    prost_build::Config::new()
        // The two fields a relay moves without reading: shared by reference instead of copied, so a payload decoded
        // from a websocket message is a slice of that message (docs/perf/README.md, encode once).
        .bytes([".wmlhub.v1.Envelope.payload", ".wmlhub.v1.Envelope.coalesce"])
        .compile_fds(descriptors)?;
    Ok(())
}
