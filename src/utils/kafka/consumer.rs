use std::sync::Arc;
use chrono::DateTime;
use chrono::Utc;
use parking_lot::Mutex;
use rdkafka::Offset;
use tokio::sync::mpsc;
use super::prelude::*;
use tracing::instrument;
use crate::{APP_NAME, db};
use lazy_static::lazy_static;
use crate::utils::generate_id;
use rdkafka::message::Headers;
use rdkafka::message::Message;
use crate::utils::context::ServiceContext;
use rdkafka::consumer::{CommitMode, Consumer};
use rdkafka::{ClientConfig, TopicPartitionList};
use rdkafka::consumer::stream_consumer::StreamConsumer;
use crate::model::events::{PasswordTypeDeleted, PolicyActivated};

/// All the topics this service needs to monitor.
pub const CONSUMER_TOPICS: [&str;3] = [
    TOPIC_POLICY_ACTIVATED,
    TOPIC_PASSWORD_TYPE_DELETED,
    TOPIC_VAULT_HEARTBEAT];

lazy_static! {
    pub static ref KAFKA_HEARTBEAT: Mutex<DateTime<Utc>> = Mutex::new(Utc::now());
}

///
/// A spawned Kafka consumer loop to handle any messages on topics we're subscribed to.
///
pub async fn init_consumer(ctx: Arc<ServiceContext>, tx: mpsc::Sender<bool>) {
    tracing::info!("Consumer starting...");

    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", &format!("{}_{}", APP_NAME, generate_id()))
        .set("bootstrap.servers", format!("{}", ctx.config().kafka_servers))
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", format!("{}", ctx.config().kafka_timeout + 1000 /* Must be more than the publisher timeout aparently? */))
        .set("auto.offset.reset", "latest")
        .create()
        .expect("Consumer creation failed");

    // Assigning the topics is quicker than subscribing.
    let partition = 0;
    let mut tpl = TopicPartitionList::new();

    for topic in CONSUMER_TOPICS {
        tpl.add_partition_offset(&topic, partition, Offset::End)
            .expect(&format!("Unable to assign offset for topic {}", topic));
    }

    consumer
        .assign(&tpl)
        .expect("Can't assign consumer topic partition offsets");

    tracing::info!("Consumer started");
    tracing::debug!("Kafka consumer notifying server it's ready to receive");
    let _ = tx.send(true).await; // Ignore any send failures - main start-up will timeout anyway.

    loop {
        match consumer.recv().await {
            Err(e) => {
                tracing::warn!("Kafka error: {}", e);
            },
            Ok(m) => {
                // Only read the payload if we're interested in that topic.
                if CONSUMER_TOPICS.contains(&m.topic()) {
                    let payload = match m.payload_view::<str>() {
                        None => "",
                        Some(Ok(s)) => s,
                        Some(Err(e)) => {
                            tracing::warn!("Error while deserializing message payload: {:?}", e);
                            ""
                        }
                    };

                    tracing::debug!("key: '{:?}', payload: '{}', topic: {}, partition: {}, offset: {}, timestamp: {:?}",
                            m.key(), payload, m.topic(), m.partition(), m.offset(), m.timestamp());

                    if let Some(headers) = m.headers() {
                        for i in 0..headers.count() {
                            let header = headers.get(i).unwrap();
                            tracing::debug!("  Header {:#?}: {:?}", header.0, header.1);
                        }
                    }

                    match m.topic() {
                        TOPIC_POLICY_ACTIVATED      => handle_policy_activated(payload, ctx.clone()).await,
                        TOPIC_PASSWORD_TYPE_DELETED => handle_password_type_deleted(payload, ctx.clone()).await,
                        TOPIC_VAULT_HEARTBEAT       => handle_heartbeat(ctx.clone()),
                        _ => {},
                    };
                }

                consumer.commit_message(&m, CommitMode::Async).unwrap();
            }
        };
    }
}

///
/// If a new password policy is activated (either by us or another instance of valut) then update
/// our 'global' active policy so API requests are checked against it.
///
#[instrument(skip(ctx))]
async fn handle_policy_activated(payload: &str, ctx: Arc<ServiceContext>) {

    match serde_json::from_str::<PolicyActivated>(payload) {
        Ok(payload) => {
            let policy = db::policy::load(&payload.policy_id, ctx.db())
                .await
                .expect(&format!("failed to load policy {} from the db", payload.policy_id));

            ctx.apply_policy(policy, &payload.password_type, payload.activated_on);

            tracing::info!("Password policy {} activated for password type {}", payload.policy_id, payload.password_type);
        },
        Err(err) => tracing::warn!("Unable to process message on topic: {}: {}: {}", TOPIC_POLICY_ACTIVATED, payload, err),
    };
}


///
/// Update the heartbeat timestamp.
///
fn handle_heartbeat(ctx: Arc<ServiceContext>) {
    let mut lock = KAFKA_HEARTBEAT.lock();
    *lock = ctx.now();
}


///
/// If a password type has been deleted from the system, remove any active policy in our cache for it.
///
#[instrument(skip(ctx))]
async fn handle_password_type_deleted(payload: &str, ctx: Arc<ServiceContext>) {

    match serde_json::from_str::<PasswordTypeDeleted>(payload) {
        Ok(event) => {
            if ctx.remove_policy_by_type(&event.password_type) {
                tracing::info!("Removed active policy for password type {}", &event.password_type);
            } else {
                tracing::warn!("No active policy in cache for removed password type {}", &event.password_type);
            }
        },
        Err(err) => tracing::warn!("Unable to process message on topic: {}: {}: {}", TOPIC_PASSWORD_TYPE_DELETED, payload, err),
    };
}
