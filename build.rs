///
/// Cargo build script to generate the protobuf stubs.
///
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/common.proto")?;
    tonic_build::compile_protos("proto/internal.proto")?;
    tonic_build::compile_protos("proto/vault.proto")?;
    Ok(())
}