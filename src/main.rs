use vault::utils::errors::VaultError;

fn main() -> Result<(), VaultError> {
    tokio::runtime::Builder::new_multi_thread()
        // Cap the number of blocking threads - in some heavy-load argon cases we can see
        // explosions of threads so constraining here prohibits too much resource use.
        .max_blocking_threads(num_cpus::get())
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            vault::lib_main().await
        })
}