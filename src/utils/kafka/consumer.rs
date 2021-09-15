use std::sync::Arc;
use chrono::DateTime;
use chrono::Utc;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use super::prelude::*;
use tracing::instrument;
use crate::{APP_NAME, db};
use lazy_static::lazy_static;
use crate::utils::generate_id;
use rdkafka::message::Headers;
use rdkafka::message::Message;
use rdkafka::error::KafkaResult;
use crate::utils::context::ServiceContext;
use crate::model::events::{PasswordTypeDeleted, PolicyActivated};
use rdkafka::consumer::stream_consumer::StreamConsumer;
use rdkafka::{ClientConfig, ClientContext, TopicPartitionList};
use rdkafka::consumer::{CommitMode, Consumer, ConsumerContext, Rebalance};

/// All the topics this service needs to monitor.
pub const CONSUMER_TOPICS: [&str;3] = [
    TOPIC_POLICY_ACTIVATED,
    TOPIC_PASSWORD_TYPE_DELETED,
    TOPIC_VAULT_HEARTBEAT];

lazy_static! {
    pub static ref KAFKA_HEARTBEAT: Mutex<DateTime<Utc>> = Mutex::new(Utc::now());
}

// Because our app produces and consumes to/from the same topic, we need a signal during start-up
// that suspends the server start-up, until the consumergroup has been balanced and we know that
// our consumer will receive new messages on that topic.
//
// Without this, our server can send messages which it needs to listen to (active policy eventual
// consistency for example), but it would never receive those messages (and we always want latest
// offset when connecting).
struct CustomContext {
    tx: mpsc::Sender<bool> // Used to signal the main start-up sequence that the consumer is ready.
}

impl ClientContext for CustomContext {}

impl ConsumerContext for CustomContext {
    fn pre_rebalance(&self, rebalance: &Rebalance) {
        tracing::debug!("Pre rebalance {:?}", rebalance);
    }

    fn post_rebalance(&self, rebalance: &Rebalance) {
        tracing::debug!("Post rebalance {:?}", rebalance);

        // Send a signal to the start-up loop we have been put into a consumer group.
        // If we didn't do this, the server could start producing events we would miss.
        let tx = self.tx.clone();
        let _ = tokio::spawn(async move {
            tracing::info!("Consumer started");
            tracing::debug!("Kafka consumer notifying server it's ready to receive");
            let _ = tx.send(true).await; // Ignore any send failures - main start-up will timeout anyway.
        });
    }

    fn commit_callback(&self, result: KafkaResult<()>, _offsets: &TopicPartitionList) {
        tracing::debug!("Committing offsets: {:?}", result);
    }
}

///
/// A spawned Kafka consumer loop to handle any messages on topics we're subscribed to.
///
pub async fn init_consumer(ctx: Arc<ServiceContext>, tx: mpsc::Sender<bool>) {
    tracing::info!("Consumer starting...");

    let consumer: StreamConsumer<CustomContext> = ClientConfig::new()
        .set("group.id", &format!("{}_{}", APP_NAME, generate_id()))
        .set("bootstrap.servers", format!("{}", ctx.config().kafka_servers))
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", format!("{}", ctx.config().kafka_timeout + 1000 /* Must be more than the publisher timeout aparently? */))
        // .set("allow.auto.create.topics", "true") // Note: This doesn't work. So we use an admin client to pre-create topics we want to consume.
        //.set("statistics.interval.ms", "30000")
        .set("auto.offset.reset", "latest")
        // .set("fetch.max.wait.ms", "500")
        // .set_log_level(rdkafka::config::RDKafkaLogLevel::Debug)
        .create_with_context(CustomContext{tx})
        .expect("Consumer creation failed");

        // TODO: EDIT: assigning partitions myself with Assign instead of Subscribe results in startup time of around 2sec instead

    consumer
        // .assign(assignment)
        .subscribe(&CONSUMER_TOPICS)
        .expect("Can't subscribe to specified topics");

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
