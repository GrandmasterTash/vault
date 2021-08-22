use vault::utils::errors::VaultError;

#[tokio::main]
async fn main() -> Result<(), VaultError> {
    vault::lib_main().await
}