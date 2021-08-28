use std::sync::Arc;
use crate::{APP_NAME, db};
use crate::services::context::ServiceContext;
use rdkafka::error::KafkaResult;
use rdkafka::{ClientConfig, ClientContext, TopicPartitionList};
use rdkafka::message::Message;
use rdkafka::consumer::{CommitMode, Consumer, ConsumerContext, Rebalance};
use rdkafka::consumer::stream_consumer::StreamConsumer;
use tokio::sync::mpsc;
use tracing::instrument;
use crate::model::policy::PolicyActivated;
use crate::utils::mongo::generate_id;

/// All the topics this service needs to monitor.
pub const CONSUMER_TOPICS: [&str;1] = ["password.policy.activated"];

// Because our app produces and consumes to/from the same topic, we need a signal during start-up
// that stops the server starting, until the consumergroup has been balanced and we know that
// our consumer will receive new messages on that topic.
//
// Without this, our server can send messages which it needs to listen to (policy eventual
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
            tracing::debug!("Kafka consumer notifying server it's ready to receive");
            let _ = tx.send(true).await; // Ignore any send failures.
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
    tracing::info!("Consumer starting");

    let consumer: StreamConsumer<CustomContext> = ClientConfig::new()
        .set("group.id", &format!("{}_{}", APP_NAME, generate_id()))
        .set("bootstrap.servers", format!("{}", ctx.config().kafka_servers))
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", format!("{}", ctx.config().kafka_timeout + 1000 /* Must be more than the publisher timeout aparently? */))
        .set("allow.auto.create.topics", "true") // Note: This doesn't work. So we use an admin client to pre-create topics we want to consume.
        //.set("statistics.interval.ms", "30000")
        .set("auto.offset.reset", "latest")
        // .set_log_level(rdkafka::config::RDKafkaLogLevel::Debug)
        .create_with_context(CustomContext{tx})
        .expect("Consumer creation failed");

    consumer
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

                // TODO: Ensure v1 version
                if m.topic() == "password.policy.activated" {
                    // Could check version header to route to alternated handlers.
                    handle_policy_activated(m.topic(), payload, ctx.clone()).await;
                }
            }
        };
    }
}

///
/// If a new password policy is activated (either by us or another instance of valut) then update
/// our 'global' active policy so API requests are checked against it.
///
// async fn handle_policy_activated(topic: &str, payload: &str, db: Database, active_policy: Arc<RwLock<PolicyDB>>) {
#[instrument(skip(ctx))]
async fn handle_policy_activated(topic: &str, payload: &str, ctx: Arc<ServiceContext>) {

    match serde_json::from_str::<PolicyActivated>(payload) {
        Ok(payload) => {
            let policy = db::policy::load(&payload.policy_id, ctx.db())
                .await
                .expect(&format!("failed to load policy {} from the db", payload.policy_id));

            ctx.apply_policy(policy, payload.activated_on);

            tracing::info!("Password policy {} activated", payload.policy_id);
        },
        Err(err) => tracing::warn!("Unable to process message on topic: {}: {}: {}", topic, payload, err),
    };
}
