
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // use std::env;
    // println!("*** {:?}", env::var("OUT_DIR").unwrap());

    tonic_build::compile_protos("proto/vault.proto")?;
    Ok(())
}