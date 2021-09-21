use std::time::Duration;
use crate::{APP_NAME, utils::{config::Configuration, errors::VaultError}};
use rdkafka::{ClientConfig, message::OwnedHeaders, producer::{FutureProducer, FutureRecord}};
use tracing::{Instrument, instrument};

pub fn producer(config: &Configuration) -> FutureProducer {
    ClientConfig::new()
        .set("bootstrap.servers", config.clone().kafka_servers)
        .set("message.timeout.ms", format!("{}", config.kafka_timeout))
        .create()
        .expect("Producer creation error")
}

#[instrument(name="kafka:send", skip(producer, config, payload, version))]
pub async fn send(producer: &FutureProducer, config: &Configuration, topic: &str, payload: &str, version: u8) -> Result<(), VaultError> {
    send_no_trace(producer, config, topic, payload, version).await
}

pub async fn send_no_trace(producer: &FutureProducer, config: &Configuration, topic: &str, payload: &str, version: u8) -> Result<(), VaultError> {
    producer
        .send(
            FutureRecord::to(topic)
                .payload(payload)
                .key("EVENT_LOG") // Partition key - use fixed value to ensure sequencing is in order.
                .headers(OwnedHeaders::new()
                    .add("version", &format!("{}", version))
                    .add("sender", APP_NAME)),
            Duration::from_millis(config.kafka_timeout as u64),
        )
        .instrument(tracing::debug_span!("wibble"))
        .await?;
    Ok(())
}