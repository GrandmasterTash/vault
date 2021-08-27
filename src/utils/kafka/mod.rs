pub mod consumer;
pub mod producer;

use std::time::Duration;
use super::config::Configuration;
use rdkafka::{ClientConfig, admin::{AdminClient, AdminOptions, NewTopic, TopicReplication}, client::DefaultClientContext};

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