///
/// Cargo build script to generate the protobuf stubs.
///
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/common.proto")?;
    tonic_build::compile_protos("proto/internal.proto")?;
    tonic_build::compile_protos("proto/vault.proto")?;

    // Uncomment this to generate the test client stubs - if desired.
    // tonic_build::configure()
    //     .build_server(false)
    //     .build_client(true)
    //     .out_dir("tests/common/stubs")  // you can change the generated code's location
    //     .compile(
    //         &["proto/vault.proto"],
    //         &["proto"], // specify the root location to search proto dependencies
    //     ).unwrap();

    Ok(())
}