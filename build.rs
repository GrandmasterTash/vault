use std::{env, path::PathBuf};

///
/// Cargo build script to generate the protobuf stubs.
///
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/common.proto")?;
    tonic_build::compile_protos("proto/internal.proto")?;
    // Generate a file descriptor for the reflection service.
    let descriptor_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("vault_descriptor.bin");
    tonic_build::configure()
        .file_descriptor_set_path(&descriptor_path)
        .format(true)
        .compile(&["proto/vault.proto"], &["proto/"])?;

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