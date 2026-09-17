//! Generates the wire types from `proto/`. Uses protox, a protobuf compiler written in Rust, so building needs no
//! `protoc` on the machine.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../proto");
    let files = ["wmlhub/v1/hub.proto", "wmlhub/v1/identity.proto"];
    for file in files {
        println!("cargo:rerun-if-changed={root}/{file}");
    }
    let descriptors = protox::compile(files, [root])?;
    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
