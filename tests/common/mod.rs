use rdkafka::admin::{AdminClient as KafkaAdminClient, AdminOptions};
use lazy_static::lazy_static;
use rdkafka::{ClientConfig, client::DefaultClientContext};
use tonic::transport::Channel;
use tokio_retry::{Retry, strategy::FixedInterval};
use std::{collections::HashMap, thread::JoinHandle, time::Duration};
use parking_lot::{Mutex, RawMutex, lock_api::MutexGuard};
use vault::{grpc::{admin::admin_client::AdminClient, api::vault_client::VaultClient}, utils::kafka::consumer::CONSUMER_TOPICS};

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
/// A mutex guard around a TestContext.
///
/// When this guard is dropped the lock is released and other tests can use the server.
///
/// This context can be used to obtain a client and perform operations on the server being
/// tested.
///
type TestContextLock<'a> = MutexGuard<'a, RawMutex, TestContext>;


///
/// Test's should start by calling start_vault to obtain a lock on the TestContext.
///
/// This will give them a gRPC client to talk to a running Vault server.
///
pub struct TestContext {
    config: TestConfig,
    server_handle: Option<JoinHandle<()>>,
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
            server_handle: None,
            client: None,
            admin: None,
            config: Default::default()
        }
    }
}

#[derive(Clone, PartialEq)]
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
pub async fn start_vault(config: TestConfig) -> TestContextLock<'static> {
    let mut ctx = TEST_MUTEX.lock();

    // If the configuration has changed - apply the new configuration. This allows tests
    // to run against a server instance where they control the configuration.
    if ctx.config != config {
        ctx.config = config.clone();
        ctx.config.apply();

        // Terminate and destroy any running server.
        ctx.server_handle.take();

        // Destroy any previous test client.
        ctx.client.take();
        ctx.admin.take();
    }

    // If the server is not running, start it.
    if ctx.server_handle.is_none() {
        // Before we start a new running server. Delete any Kafka topics it consumes. This stops
        // uncommitted messages from previous test runs from being delivered to the server and
        // causing it to try to process messages for data that doesn't exist.
        let admin_client: KafkaAdminClient<DefaultClientContext> = ClientConfig::new()
                .set("bootstrap.servers", format!("{}", config.get("KAFKA_SERVERS")))
                .create()
                .expect("test admin client creation failed");
        let opts = AdminOptions::new().operation_timeout(Some(Duration::from_millis(5000)));
        admin_client.delete_topics(&CONSUMER_TOPICS, &opts).await.expect("Unable to delete topics");

        // TODO: Connect to the MongoDB and drop any existing database to ensure we start with
        // clean data.

        // Launch the application in a separate runtime instance. This ensures it will survive test thread
        // teardowns. Because each thread runs in it's own green thread with a runtime with no worker threads,
        // we need to ensure the launched server survives a tear-down.
        let handle = RT.handle();
        ctx.server_handle = Some(std::thread::spawn(move || {
            let _ignore = handle.block_on(async {
                vault::lib_main().await
            });
        }));

        // Connect a test client to the service - the closure is used in retry spawn below.
        // let port = ctx.config.get("PORT");
        // let connect = move || {
        //     VaultClient::connect(format!("http://[::]:{}", port))
        // };

        // // Try to connect for up-to 1 minute.
        // let client = Retry::spawn(FixedInterval::from_millis(100).take(600), connect)
        //     .await
        //     .expect("Unable to connect test client to server under test");

        // // Need to establish an admin client too.
        // let connect = move || {
        //     AdminClient::connect(format!("http://[::]:{}", port))
        // };

        // // Try to connect for up-to 1 minute.
        // let admin_client = Retry::spawn(FixedInterval::from_millis(100).take(600), connect)
        //     .await
        //     .expect("Unable to connect admin test client to server under test");

        // // Put the clients in the TestContext struct for the test to use.
        // ctx.client = Some(client);
        // ctx.admin = Some(admin_client);

    } else {
        // TODO: If the server was running, reset any fixed clock that a previous test may have applied.
        // lock.admin().reset_time(Request::new(common::Empty::default()))
        //     .await
        //     .unwrap();
    }

    // TODO: Refactor so client not created every test. Consider holding in the other runtime.

    // Connect a test client to the service - the closure is used in retry spawn below.
    let port = ctx.config.get("PORT");
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
    ctx.client = Some(client);
    ctx.admin = Some(admin_client);

    ctx
}


pub mod helper {
    use super::TestContextLock;
    use tokio_retry::{Retry, strategy::FixedInterval};
    use tonic::{Request, Status};
    use vault::grpc::{admin, api::{self, vault_client::VaultClient}, common};

    ///
    /// Parse a numeric error code out of the body of an error Status response.
    ///
    pub fn error_code(status: Status) -> u32 {
        let raw = String::from_utf8(status.details().to_vec()).expect("Could not get an error code from the details of the status/response");
        raw.parse::<u32>().expect("The error code could not be parsed to a number")
    }

    ///
    /// Test helper to set vault to use a fixed time whenever it calls .now().
    ///
    pub async fn set_time(new_time: &str, ctx: &mut TestContextLock<'_>) {
        ctx.admin().set_time(
            Request::new(
                admin::NewTime { new_time: new_time.to_string() } ))
                .await
                .unwrap();
    }

    ///
    /// Test helper to set vault to use the normal clock for .now().
    ///
    pub async fn _reset_time(ctx: &mut TestContextLock<'_>) {
        ctx.admin().reset_time(Request::new(common::Empty::default()))
            .await
            .unwrap();
    }

    ///
    /// Test helper to call the hash password API when the response is expected to be success.
    ///
    pub async fn hash_password_assert_ok(plain_text_password: &str, password_id: Option<&str>, ctx: &mut TestContextLock<'_>)
        -> api::HashResponse {

        ctx.client()
            .hash_password(Request::new(api::HashRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.map(|s|s.to_string()),
                password_type: None,
            }))
            .await
            .unwrap() // This is the effective assert.
            .into_inner()
    }

    ///
    /// Test helper to call the hash password API when the response is expected to be an error Status.
    ///
    pub async fn hash_password_assert_err(plain_text_password: &str, password_id: Option<&str>, ctx: &mut TestContextLock<'_>)
        -> Status {

        ctx.client().hash_password(Request::new(api::HashRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.map(|s|s.to_string()),
                password_type: None,
            }))
            .await
            .err()
            .unwrap() // This is the effective assert.
    }

    ///
    /// Test helper to call the validate password API when the response is expected to be success.
    ///
    pub async fn validate_password_assert_ok(plain_text_password: &str, password_id: &str, ctx: &mut TestContextLock<'_>)
        -> api::ValidateResponse {

        ctx.client()
            .validate_password(Request::new(api::ValidateRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.to_string(),
            }))
            .await
            .unwrap() // This is the effective assert.
            .into_inner()
    }

    ///
    /// Test helper to call the validate password API when the response is expected to be an error Status.
    ///
    pub async fn validate_password_assert_err(plain_text_password: &str, password_id: &str, ctx: &mut TestContextLock<'_>)
        -> Status {

        ctx.client().validate_password(Request::new(api::ValidateRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.to_string(),
            }))
            .await
            .err()
            .unwrap() // This is the effective assert.
    }


    ///
    /// Test helper to call the create policy API when the response is expected to be a success.
    ///
    pub async fn create_policy_assert_ok(policy: api::NewPolicy, password_type: &str, activate: bool, ctx: &mut TestContextLock<'_>)
        -> api::CreatePolicyResponse {

        let request = Request::new(api::CreatePolicyRequest{
            policy: Some(policy),
            activate,
            password_type: Some(password_type.to_string())
        });

        ctx.client().create_password_policy(request)
            .await
            .unwrap() // This is the effective assert.
            .into_inner()
    }


    ///
    /// Test helper to call the get active policy API when the response is expected to be a success.
    ///
    pub async fn _get_active_policy_assert_ok(ctx: &mut TestContextLock<'_>)
        -> api::GetActivePolicyResponse {

        let request = Request::new(api::GetActivePolicyRequest{
            password_type: None,
        });

        ctx.client().get_active_policy(request)
            .await
            .unwrap() // This is the effective assert.
            .into_inner()
    }


    ///
    /// Makes the specified policy active (asserts response ok) then waits for the
    /// service to update to that policy.
    ///
    pub async fn make_active_and_wait(policy_id: &str, ctx: &mut TestContextLock<'_>) {

        let request = Request::new(api::MakeActiveRequest{
            policy_id: policy_id.to_string(),
            password_type: None
        });

        ctx.client().make_active(request)
            .await
            .unwrap(); // This is the effective assert.

        wait_until_active(policy_id, ctx.client()).await;
    }


    ///
    /// Wait until the policy_id specified is the active policy (activating a policy has eventual
    /// consistency) and return the policy from the API call.
    ///
    pub async fn wait_until_active(policy_id: &str, client: &mut VaultClient<tonic::transport::Channel>)
        -> api::Policy {

        let action_client = client.clone();
        let action = move || {
            get_active_policy_assert_id(policy_id.to_string(), action_client.clone())
        };

        // Wait for up to 10 seconds for the active policy to be changed. Probing ever 100ms.
        Retry::spawn(FixedInterval::from_millis(100).take(100), action)
            .await
            .expect("The active policy was not updated in time, probably a Kafka-related issue")
    }


    async fn get_active_policy_assert_id(expected_id: String, mut client: VaultClient<tonic::transport::Channel>) 
        -> Result<api::Policy, ()> {

        let request = tonic::Request::new(vault::grpc::api::GetActivePolicyRequest{
            password_type: None,
        });

        let actual = client.get_active_policy(request)
            .await
            .unwrap() // This is the effective assert.
            .into_inner()
            .policy
            .unwrap();

        match expected_id == actual.policy_id {
            true  => Ok(actual),
            false => {
                // println!("Waiting till {} active, current active is {}...", expected_id, actual.policy_id);
                Err(())
            },
        }
    }
}