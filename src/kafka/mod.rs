pub mod consumer;
pub mod producer;

use serde::Serialize;
use std::{sync::Arc, time::Duration};
use crate::utils::{config::Configuration, context::ServiceContext};
use rdkafka::{ClientConfig, admin::{AdminClient, AdminOptions, NewTopic, TopicReplication}, client::DefaultClientContext};

pub mod prelude {
    pub const TOPIC_FAILURE_EXCEEDED:         &str = "password.failure.exceeded";
    pub const TOPIC_POLICY_CREATED:           &str = "password.policy.created";
    pub const TOPIC_POLICY_ACTIVATED:         &str = "password.policy.activated";
    pub const TOPIC_PASSWORD_TYPE_DELETED:    &str = "password.type.deleted";
    pub const TOPIC_PASSWORD_HASHED:          &str = "password.hashed";
    pub const TOPIC_PASSWORD_VERIFIED:        &str = "password.verified";
    pub const TOPIC_PASSWORD_DELETED:         &str = "password.deleted";
    pub const TOPIC_PASSWORD_RESET_STARTED:   &str = "password.reset.started";
    pub const TOPIC_PASSWORD_RESET_COMPLETED: &str = "password.reset.completed";
    pub const TOPIC_VAULT_HEARTBEAT:          &str = "vault.heartbeat";
}

///
/// The service sends itself a heartbeat message - used to monitor the health of the
/// Kafka instance.
///
#[derive(Serialize)]
pub struct Heartbeat{}

///
/// Pre-create any topics we want to subscribe to - seems to be an issue in the driver and auto-create doesn't work.
///
pub async fn create_topics(config: &Configuration) {
    tracing::info!("Creating kafka topics {:?}", consumer::CONSUMER_TOPICS);

    let admin_client = create_admin_client(config);
    let opts = AdminOptions::new().operation_timeout(Some(Duration::from_millis(config.kafka_timeout as u64)));

    let topics = consumer::CONSUMER_TOPICS
        .iter()
        .map(|topic| NewTopic::new(topic, 1, TopicReplication::Fixed(1)))
        .collect::<Vec<NewTopic>>();

    admin_client.create_topics(&topics, &opts)
        .await
        .expect("Cant create topics");
}


fn create_admin_client(config: &Configuration) -> AdminClient<DefaultClientContext> {
    ClientConfig::new()
        .set("bootstrap.servers", format!("{}", config.kafka_servers))
        .create()
        .expect("admin client creation failed")
}

///
/// Connect a Kafka consumer and wait for it to be ready to receive messages.
///
pub async fn start_and_wait_for_consumer(ctx: Arc<ServiceContext>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);

    // Spawn a consumer to monitor the active policy changes from other instances.
    tokio::spawn(async move {
        consumer::init_consumer(ctx, tx).await
    });

    // Wait until the consumer has sent us a signal that it's ready.
    if let Err(_) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
        panic!("Timeout waiting for the kafka consumer to signal it was ready.");
    }
}