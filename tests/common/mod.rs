use lazy_static::lazy_static;
use tokio_retry::{Retry, strategy::FixedInterval};
use parking_lot::{Mutex, RawMutex, lock_api::MutexGuard};
use rdkafka::{ClientConfig, client::DefaultClientContext};
use rdkafka::admin::{AdminClient as KafkaAdminClient, AdminOptions};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Uri};
use std::{collections::HashMap, thread::JoinHandle, time::Duration};
use vault::{grpc::{internal::internal_client::InternalClient, api::vault_client::VaultClient}, utils::kafka::consumer::CONSUMER_TOPICS};

lazy_static! {
    // A mutex around the TestContext to ensure only one test can be using the service at a time.
    // This ensures tests do not corrupt the configuration, data or mocks used by any other test.
    static ref TEST_MUTEX: Mutex<TestContext> = {
        let ctx = TestContext::default();
        ctx.config.apply();
        Mutex::new(ctx)
    };

    // Genereate a unique DB name for each test run to avoid collisions.
    static ref DB_NAME: String = format!("Vault_Tests_{}", chrono::Utc::now().timestamp());

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
    internal: Option<InternalClient<Channel>>,
}

impl TestContext {
    pub fn client(&mut self) -> &mut VaultClient<Channel> {
        self.client.as_mut().expect("Someone asked for a test client when there wasn't one")
    }

    pub fn internal(&mut self) -> &mut InternalClient<Channel> {
        self.internal.as_mut().expect("Someone asked for a test internal client when there wasn't one")
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            server_handle: None,
            client: None,
            internal: None,
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
        map.insert("ADDRESS", "[::1]:50011");
        map.insert("KAFKA_SERVERS", "localhost:29092");
        map.insert("KAFKA_TIMEOUT", "5000");
        map.insert("DB_NAME", &DB_NAME);
        map.insert("MONGO_URI", "mongodb://admin:changeme@localhost:27017");//TODO: Probably not used, need template variant.
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
/// Acquires a lock so only one test may run at a time and returns a TestContext(Lock).
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
        ctx.internal.take();
    }

    // If the server is not running, start it.
    if ctx.server_handle.is_none() {
        // Before we start a new running server. Delete any Kafka topics it consumes. This stops
        // uncommitted messages from previous test runs from being delivered to the server and
        // causing it to try to process messages for data that doesn't exist.
        let internal_client: KafkaAdminClient<DefaultClientContext> = ClientConfig::new()
                .set("bootstrap.servers", format!("{}", config.get("KAFKA_SERVERS")))
                .create()
                .expect("test admin client creation failed");
        let opts = AdminOptions::new().operation_timeout(Some(Duration::from_millis(5000)));
        internal_client.delete_topics(&CONSUMER_TOPICS, &opts).await.expect("Unable to delete topics");

        // Launch the application in a separate runtime instance. This ensures it will survive test thread
        // teardowns. Because each thread runs in it's own green thread with a runtime with no worker threads,
        // we need to ensure the launched server survives a tear-down.
        let handle = RT.handle();
        ctx.server_handle = Some(std::thread::spawn(move || {
            let _ignore = handle.block_on(async {
                vault::lib_main().await
            });
        }));
    }

    // Connect a test client to the service - the closure is used in retry spawn below.
    let address = ctx.config.get("ADDRESS");
    let connect = move || {
        connect_channel(address)
    };

    // Try to connect for up-to 1 minute.
    // let client_channel = Retry::spawn(FixedInterval::from_millis(100).take(600), connect)
    let client_channel = Retry::spawn(FixedInterval::from_millis(100).take(60), connect)
        .await
        .expect("Unable to connect test client to server under test");

    // Need to establish an admin client too.
    let connect = move || {
        connect_channel(address)
    };

    // Try to connect for up-to 1 minute.
    // let internal_channel = Retry::spawn(FixedInterval::from_millis(100).take(600), connect)
    let internal_channel = Retry::spawn(FixedInterval::from_millis(100).take(60), connect)
        .await
        .expect("Unable to connect admin test client to server under test");

    // Put the clients in the TestContext struct for the test to use.
    ctx.client = Some(VaultClient::new(client_channel));
    ctx.internal = Some(InternalClient::new(internal_channel));

    ctx
}

async fn connect_channel(address: &str) -> Result<tonic::transport::Channel, tonic::transport::Error> {
    let pem = tokio::fs::read("certs/ca.pem").await.unwrap();
    let ca = Certificate::from_pem(pem);

    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .domain_name("example.com");

    let uri = format!("http://{}", address).parse::<Uri>().unwrap();

    Channel::builder(uri)
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
}


pub mod helper {
    use super::TestContextLock;
    use chrono::{DateTime, Utc};
    use tokio_retry::{Retry, strategy::FixedInterval};
    use tonic::{Request, Status};
    use vault::grpc::{internal, api::{self, vault_client::VaultClient}, common};

    ///
    /// Parse a numeric error code out of the body of an error Status response.
    ///
    pub fn error_code(status: &Status) -> u32 {
        let raw = String::from_utf8(status.details().to_vec()).expect("Could not get an error code from the details of the status/response");
        raw.parse::<u32>().expect("The error code could not be parsed to a number")
    }

    ///
    /// Test helper to set vault to use a fixed time whenever it calls .now().
    ///
    pub async fn set_time(new_time: &str, ctx: &mut TestContextLock<'_>) {
        ctx.internal().set_time(
            Request::new(
                internal::NewTime { new_time: new_time.to_string() } ))
                .await
                .unwrap();
    }

    ///
    /// Test helper to set vault to use the normal clock for .now().
    ///
    pub async fn _reset_time(ctx: &mut TestContextLock<'_>) {
        ctx.internal().reset_time(Request::new(common::Empty::default()))
            .await
            .unwrap();
    }

    ///
    /// Test helper to call the hash password API when the response is expected to be success.
    ///
    pub async fn hash_password_assert_ok(plain_text_password: &str, password_id: Option<&str>, password_type: Option<&str>, ctx: &mut TestContextLock<'_>)
        -> api::HashResponse {

        ctx.client()
            .hash_password(Request::new(api::HashRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.map(|s|s.to_string()),
                password_type: password_type.map(|s|s.to_string()),
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
        -> bool {

        ctx.client()
            .validate_password(Request::new(api::ValidateRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.to_string(),
            }))
            .await
            .unwrap() // This is the effective assert.
            .into_inner();

        true
    }

    ///
    /// Test helper to call the validate password API when the response is expected to be an error Status.
    ///
    pub async fn validate_password_assert_err(plain_text_password: &str, password_id: &str, ctx: &mut TestContextLock<'_>)
        -> Status {

        ctx.client().validate_password(api::ValidateRequest {
                plain_text_password: plain_text_password.to_string(),
                password_id: password_id.to_string(),
            })
            .await
            .err()
            .unwrap() // This is the effective assert.
    }


    ///
    /// Test helper to call the create policy API when the response is expected to be a success.
    ///
    pub async fn create_policy_assert_ok(policy: api::NewPolicy, password_type: &str, activate: bool, ctx: &mut TestContextLock<'_>)
        -> api::CreatePolicyResponse {

        let request = api::CreatePolicyRequest{
            policy: Some(policy),
            activate,
            password_type: Some(password_type.to_string())
        };

        ctx.client().create_password_policy(request)
            .await
            .unwrap() // This is the effective assert.
            .into_inner()
    }

    ///
    /// Test helper to call the create policy API when the response is expected to be an invalid policy.
    ///
    pub async fn create_policy_assert_invalid(policy: api::NewPolicy, ctx: &mut TestContextLock<'_>, expected_msg: &str) {

        let request = api::CreatePolicyRequest{
            policy: Some(policy),
            activate: false,
            password_type: None
        };

        let status = ctx.client().create_password_policy(request)
            .await
            .err()
            .expect(expected_msg);

        assert_eq!(status.message(), expected_msg);
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(error_code(&status), 1003 /* InvalidPolicy */);
    }

        ///
    /// Test helper to call the create policy API when the response is expected to be an error code of some sort.
    ///
    pub async fn create_policy_assert_err(policy: api::NewPolicy, ctx: &mut TestContextLock<'_>, expected_msg: &str, expected_code: u32) {

        let request = api::CreatePolicyRequest{
            policy: Some(policy),
            activate: false,
            password_type: None
        };

        let status = ctx.client().create_password_policy(request)
            .await
            .err()
            .expect(expected_msg);

        assert_eq!(status.message(), expected_msg);
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(error_code(&status), expected_code);
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

        wait_until_active(policy_id, "DEFAULT", ctx.client()).await;
    }


    ///
    /// Wait until the policy_id specified is the active policy (activating a policy has eventual
    /// consistency) and return the policy from the API call.
    ///
    pub async fn wait_until_active(policy_id: &str, password_type: &str, client: &mut VaultClient<tonic::transport::Channel>)
        -> api::Policy {

        let action_client = client.clone();
        let action = move || {
            get_active_policy_for_wait(Some(password_type.to_string()), policy_id.to_string(), action_client.clone())
        };

        // Wait for up to 10 seconds for the active policy to be changed. Probing ever 100ms.
        Retry::spawn(FixedInterval::from_millis(100).take(100), action)
            .await
            .expect("The active policy was not updated in time, probably a Kafka-related issue")
    }

    ///
    /// Check if the active policy for the password_type matches the expected policy_id.
    /// This version won't panic and is intended to be used by the wait_until...
    ///
    async fn get_active_policy_for_wait(password_type: Option<String>, expected_id: String, mut client: VaultClient<tonic::transport::Channel>) 
        -> Result<api::Policy, String> {

        let request = tonic::Request::new(api::GetActivePolicyRequest{ password_type });

        match client.get_active_policy(request).await {
            Ok(response) => {
                match response.into_inner().policy {
                    Some(policy) => {
                        match expected_id == policy.policy_id {
                            true  => Ok(policy),
                            false => Err(format!("Expected policy_id {} but was {}", expected_id, policy.policy_id)),
                        }
                    },
                    None => Err(String::from("No policy returned")),
                }
            },
            Err(err) => Err(format!("{}", err)),
        }
    }

    ///
    /// Helper so tests can create and use a password policy that's not the default (although similar).
    ///
    pub fn sensible_policy() -> api::NewPolicy {
        api::NewPolicy {
            max_history_length: 3,
            max_age_days: 30,
            min_length: 5,
            max_length: 32,
            max_character_repeat: 4,
            min_letters: 2,
            max_letters: 32,
            min_numbers: 2,
            max_numbers: 32,
            min_symbols: 1,
            max_symbols: 32,
            max_failures: 3,
            lockout_seconds: 100,
            mixed_case_required: true,
            reset_timeout_seconds: 30,
            prohibited_phrases: vec!("password".to_string()),
            algorithm: Some(api::new_policy::Algorithm::ArgonPolicy(sensible_argon())),
        }
    }

    ///
    /// Helper to return a valid argon algorithm definition.
    ///
    pub fn sensible_argon() -> api::ArgonPolicy {
        api::ArgonPolicy {
            parallelism: 1,
            tag_length: 16,
            memory_size_kb: 8,
            iterations: 1,
            version: 19,
            hash_type: 2,
        }
    }

    ///
    /// Helper to return a valid bcrypt algorithm definition.
    ///
    pub fn sensible_bcrypt() -> api::BCryptPolicy {
        api::BCryptPolicy {
            version: 3 /* 2B */,
            cost: 10,
        }
    }

    pub fn sensible_pbkdf2() -> api::Pbkdf2Policy {
        api::Pbkdf2Policy {
            cost: 100,
            output_len: 16,
        }
    }

    ///
    /// Helper so tests can create and use a password policy that's not the default (although similar).
    ///
    pub fn sensible_policy_with_argon(argon: api::ArgonPolicy) -> api::NewPolicy {
        api::NewPolicy {
            max_history_length: 3,
            max_age_days: 30,
            min_length: 5,
            max_length: 32,
            max_character_repeat: 4,
            min_letters: 2,
            max_letters: 32,
            min_numbers: 2,
            max_numbers: 32,
            min_symbols: 1,
            max_symbols: 32,
            max_failures: 3,
            lockout_seconds: 100,
            mixed_case_required: true,
            reset_timeout_seconds: 30,
            prohibited_phrases: vec!("password".to_string()),
            algorithm: Some(api::new_policy::Algorithm::ArgonPolicy(argon)),
        }
    }

    ///
    /// Helper so tests can create and use a password policy that's not the default (although similar).
    ///
    pub fn sensible_policy_with_bcrypt(bcrypt: api::BCryptPolicy) -> api::NewPolicy {
        api::NewPolicy {
            max_history_length: 3,
            max_age_days: 30,
            min_length: 5,
            max_length: 32,
            max_character_repeat: 4,
            min_letters: 2,
            max_letters: 32,
            min_numbers: 2,
            max_numbers: 32,
            min_symbols: 1,
            max_symbols: 32,
            max_failures: 3,
            lockout_seconds: 100,
            mixed_case_required: true,
            reset_timeout_seconds: 30,
            prohibited_phrases: vec!("password".to_string()),
            algorithm: Some(api::new_policy::Algorithm::BcryptPolicy(bcrypt)),
        }
    }

        ///
    /// Helper so tests can create and use a password policy that's not the default (although similar).
    ///
    pub fn sensible_policy_with_pbkdf2(pbkdf2: api::Pbkdf2Policy) -> api::NewPolicy {
        api::NewPolicy {
            max_history_length: 3,
            max_age_days: 30,
            min_length: 5,
            max_length: 32,
            max_character_repeat: 4,
            min_letters: 2,
            max_letters: 32,
            min_numbers: 2,
            max_numbers: 32,
            min_symbols: 1,
            max_symbols: 32,
            max_failures: 3,
            lockout_seconds: 100,
            mixed_case_required: true,
            reset_timeout_seconds: 30,
            prohibited_phrases: vec!("password".to_string()),
            algorithm: Some(api::new_policy::Algorithm::Pbkdf2Policy(pbkdf2)),
        }
    }

    ///
    /// Helper to extract the api::ArgonPolicy from an api::Policy.
    ///
    pub fn get_argon(policy: &api::Policy) -> Option<&api::ArgonPolicy> {
        match &policy.algorithm {
            Some(alg) => match alg {
                api::policy::Algorithm::ArgonPolicy(argon) => Some(&argon),
                api::policy::Algorithm::BcryptPolicy(_) => None,
                api::policy::Algorithm::Pbkdf2Policy(_) => None,
            },
            None => None,
        }
    }

    ///
    /// Convert a &str in this format yyyy-mm-ddThh:MM:ssZ to a millisecond precision
    /// epoch timestamp.
    ///
    pub fn utc_secs_as_epoch(utc: &str) -> u64 {
        utc.parse::<DateTime<Utc>>().unwrap().timestamp_millis() as u64
    }
}