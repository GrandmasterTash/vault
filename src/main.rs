use vault::utils::errors::VaultError;

// #[tokio::main]
// async fn main() -> Result<(), VaultError> {
//     vault::lib_main().await
// }

fn main() -> Result<(), VaultError> {
    tokio::runtime::Builder::new_multi_thread()
        // .worker_threads(100)
        .max_blocking_threads(num_cpus::get()) // Our blocking threads are heavily CPU bound so protect
        // .max_blocking_threads(80) // Our blocking threads are heavily CPU bound so protect
        // .on_thread_start(||
        //     tracing::info!("Started {:?}", std::thread::current()))
        // .on_thread_start(|| {
        //     tracing::info!("Started {:?}", std::thread::current());
        //     let id = format!("{:?}", std::thread::current().id());
        //     if id == "ThreadId(100)" {
        //         panic!("BOOM");
        //     }
        // })
        // .on_thread_stop( ||tracing::info!("Stopped {:?}", std::thread::current()))
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            vault::lib_main().await
        })
}