//! Generates the box event types from the vendored `api/events.proto` FOR TESTS ONLY (`box_schema`). The connector
//! itself never decodes a frame: it reads two tags and relays the bytes (docs/design/box-connector.md). The generated
//! types are what the tests check that reading against.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../proto/vendor/ollama");
    let file = "api/events.proto";
    println!("cargo:rerun-if-changed={root}/{file}");
    let descriptors = protox::compile([file], [root])?;
    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
