use std::time::Duration;

use rdkafka::{ClientConfig, message::OwnedHeaders, producer::{FutureProducer, FutureRecord}};
use crate::{APP_NAME, utils::{config::Configuration, errors::VaultError}};

pub fn producer(config: &Configuration) -> FutureProducer {
    ClientConfig::new()
        .set("bootstrap.servers", config.clone().kafka_servers)
        .set("message.timeout.ms", format!("{}", config.kafka_timeout))
        .create()
        .expect("Producer creation error")
}

pub async fn send(producer: &FutureProducer, config: &Configuration, topic: &str, payload: &str, version: u8) -> Result<(), VaultError> {
    producer
        .send(
            FutureRecord::to(topic)
                .payload(payload)
                .key("EVENT_LOG") // Partition key - use for sequencing
                .headers(OwnedHeaders::new()
                    .add("version", &format!("{}", version))
                    .add("sender", APP_NAME)),
            Duration::from_millis(config.kafka_timeout as u64),
        )
        .await?;
    Ok(())
}