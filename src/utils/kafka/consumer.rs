use std::sync::Arc;

use crate::APP_NAME;
use serde_json::Value;
use mongodb::Database;
use parking_lot::RwLock;
use rdkafka::ClientConfig;
use rdkafka::message::Message;
use rdkafka::consumer::{CommitMode, Consumer};
use rdkafka::consumer::stream_consumer::StreamConsumer;
use crate::model::policy::PolicyDB;
use crate::utils::config::Configuration;
use crate::utils::mongo::generate_id;

/// All the topics this service needs to monitor.
pub const CONSUMER_TOPICS: [&str;1] = ["password.policy.activated"];

///
/// A spawned Kafka consumer loop to handle any messages on topics we're subscribed to.
///
pub async fn init_consumer(config: Configuration, db: Database, active_policy: Arc<RwLock<PolicyDB>>) {
    tracing::info!("Consumer starting");

    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", &format!("{}_{}", APP_NAME, generate_id()))
        .set("bootstrap.servers", format!("{}", config.kafka_servers))
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", format!("{}", config.kafka_timeout + 1000 /* Must be more than the publisher timeout aparently? */))
        .set("enable.auto.commit", "true")
        .set("allow.auto.create.topics", "true") // Note: This doesn't work. So we use an admin client to pre-create topics we want to consume.
        //.set("statistics.interval.ms", "30000")
        //.set("auto.offset.reset", "smallest")
        .create()
        .expect("Consumer creation failed");

    consumer
        // .subscribe(&["password.policy.activated"].to_vec())
        .subscribe(&CONSUMER_TOPICS)
        .expect("Can't subscribe to specified topics");

    loop {
        match consumer.recv().await {
            Err(e) => {
                tracing::warn!("Kafka error: {}", e);
            },
            Ok(m) => {
                let payload = match m.payload_view::<str>() {
                    None => "",
                    Some(Ok(s)) => s,
                    Some(Err(e)) => {
                        tracing::warn!("Error while deserializing message payload: {:?}", e);
                        ""
                    }
                };

                // tracing::info!("key: '{:?}', payload: '{}', topic: {}, partition: {}, offset: {}, timestamp: {:?}",
                //         m.key(), payload, m.topic(), m.partition(), m.offset(), m.timestamp());

                // if let Some(headers) = m.headers() {
                //     for i in 0..headers.count() {
                //         let header = headers.get(i).unwrap();
                //         tracing::info!("  Header {:#?}: {:?}", header.0, header.1);
                //     }
                // }

                consumer.commit_message(&m, CommitMode::Async).unwrap();

                if m.topic() == "password.policy.activated" {
                    // Could check version header to route to alternated handlers.
                    handle_policy_activated(m.topic(), payload, db.clone(), active_policy.clone()).await;
                }
            }
        };
    }
}

///
/// If a new password policy is activated (either by us or another instance of valut) then update
/// our 'global' active policy so API requests are checked against it.
///
async fn handle_policy_activated(topic: &str, payload: &str, db: Database, active_policy: Arc<RwLock<PolicyDB>>) {
    if let Some(policy_id) =  get_policy_id_from(topic, payload) {
        let policy = PolicyDB::load(&policy_id, db)
            .await
            .expect(&format!("failed to load policy {} from the db", policy_id));
        {
            let mut lock = active_policy.write();
            *lock = policy;
        }
        tracing::info!("Password policy {} activated", policy_id);
    }
}

///
/// Parse the message payload and get the active_policy_id field.
///
fn get_policy_id_from(topic: &str, payload: &str) -> Option<String> {
    match serde_json::from_str::<Value>(payload) {
        Ok(json) => {
            match json.get("active_policy_id") {
                Some(policy_id) => {
                    match policy_id.as_str() {
                        Some(policy_id) => return Some(policy_id.to_string()),
                        None => tracing::warn!("Message on topic {} had no valid active_policy_id {:?}", topic, policy_id),
                    }
                },
                None => tracing::warn!("Invalid message received on topic {} - no active_policy_id", topic),
            };
        },
        Err(err) => tracing::warn!("Failed to parse json payload '{}' from topic {}: {}", payload, topic, err),
    };

    None
}