use lazy_static::lazy_static;
use tonic::transport::Channel;
use tokio_retry::{Retry, strategy::FixedInterval};
use std::{collections::HashMap, thread::JoinHandle};
use parking_lot::{Mutex, RawMutex, lock_api::MutexGuard};
use vault::grpc::{admin::admin_client::AdminClient, api::vault_client::VaultClient};

lazy_static! {
    // A mutex around the TestContext to ensure only one test can be using the service at a time.
    // This ensures tests do not corrupt the configuration, data or mocks used by any other test.
    static ref TEST_MUTEX: Mutex<TestContext> = {
        let ctx = TestContext::default();
        ctx.config.apply();
        Mutex::new(ctx)
    };

    // A async runtime needed to run the service being tested in. This ensures when a test terminates,
    // the service is still running and available for another test.
    static ref RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .enable_io()
        .build()
        .unwrap();
}

///
/// Test's should start by calling start_vault to obtain a lock on the TestContext.
///
/// This will give them a gRPC client to talk to a running Vault server.
///
pub struct TestContext {
    config: TestConfig,
    handle: Option<JoinHandle<()>>,
    client: Option<VaultClient<Channel>>,
    admin: Option<AdminClient<Channel>>,
}

impl TestContext {
    pub fn client(&mut self) -> &mut VaultClient<Channel> {
        self.client.as_mut().expect("Someone asked for a test client when there wasn't one")
    }

    pub fn admin(&mut self) -> &mut AdminClient<Channel> {
        self.admin.as_mut().expect("Someone asked for a test admin client when there wasn't one")
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            handle: None,
            client: None,
            admin: None,
            config: Default::default()
        }
    }
}

#[derive(PartialEq)]
pub struct TestConfig {
    map: HashMap<&'static str, &'static str>
}

impl Default for TestConfig {
    fn default() -> Self {
        let mut map = HashMap::new();
        map.insert("PORT", "50011");
        map.insert("KAFKA_SERVERS", "localhost:29092");
        map.insert("KAFKA_TIMEOUT", "5000");
        map.insert("DB_NAME", "Vault_Tests");
        map.insert("MONGO_CREDENTIALS", "");
        map.insert("MONGO_URI", "mongodb://admin:changeme@localhost:27017");
        map.insert("DISTRIBUTED_TRACING", "false");
        map.insert("JAEGER_ENDPOINT", "");

        Self {
            map
        }
    }
}

impl TestConfig {
    ///
    /// Apply the configuration vaules to the local environment variables.
    ///
    fn apply(&self) {
        for entry in &self.map {
            if *entry.1 == String::default() {
                std::env::remove_var(entry.0);
            } else {
                std::env::set_var(entry.0, entry.1);
            }
        }
    }

    fn get(&self, key: &str) -> &str {
        self.map.get(key).expect(&format!("No test config {}", key))
    }
}


///
/// Acquires a lock so only one test may run at a time and returns a TestContext.
///
/// Ensures the vault server is started with the specified configuration.
///
/// The returned TestContext contains a gRPC client that can be used by the test to talk to
/// the running server.
///
pub async fn start_vault(config: TestConfig) -> MutexGuard<'static, RawMutex, TestContext> {
    let mut lock = TEST_MUTEX.lock();

    // If the configuration has changed - apply the new configuration. This allows tests
    // to run against a server instance where they control the configuration.
    if lock.config != config {
        lock.config = config;
        lock.config.apply();

        // Terminate and destroy any running server.
        lock.handle.take();

        // Destroy any previous test client.
        lock.client.take();
    }

    // If the server is not running, start it.
    if lock.handle.is_none() {
        // Launch the application in a separate runtime instance. This ensures it will survive test thread
        // teardowns. Because each thread runs in it's own green thread with a runtime with no worker threads,
        // we need to ensure the launched server survives a tear-down.
        let handle = RT.handle();
        lock.handle = Some(std::thread::spawn(move || {
            let _ignore = handle.block_on(async {
                vault::lib_main().await
            });
        }));

    } else {
        // If the server was running, reset any fixed clock that a previous test may have applied.
        // lock.admin().reset_time(Request::new(common::Empty::default()))
        //     .await
        //     .unwrap();
    }

    // Connect a test client to the service - the closure is used in retry spawn below.
    let port = lock.config.get("PORT");
    let connect = move || {
        VaultClient::connect(format!("http://[::]:{}", port))
    };

    // Try to connect for up-to 1 minute.
    let client = Retry::spawn(FixedInterval::from_millis(100).take(600), connect)
        .await
        .expect("Unable to connect test client to server under test");

    // Need to establish an admin client too.
    let connect = move || {
        AdminClient::connect(format!("http://[::]:{}", port))
    };

    // Try to connect for up-to 1 minute.
    let admin_client = Retry::spawn(FixedInterval::from_millis(100).take(600), connect)
        .await
        .expect("Unable to connect admin test client to server under test");

    // Put the clients in the TestContext struct for the test to use.
    lock.client = Some(client);
    lock.admin = Some(admin_client);

    lock
}