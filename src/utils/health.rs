use serde_json::json;
use parking_lot::Mutex;
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use super::context::ServiceContext;
use crate::{db::mongo, kafka::{self, prelude::*, Heartbeat}};
use std::{sync::Arc, thread::JoinHandle as StdJoinHandle, time::Duration};
use tonic_health::{server::HealthReporter, proto::health_server::{Health, HealthServer}};

const LIVELINESS: &str = "LIVELINESS";
const READINESS:  &str = "READINESS";

const PULSE: u64 = 4000;
const TIMEOUT: u64 = 6000;

lazy_static! {
    pub static ref MONGODB_HEARTBEAT: Mutex<DateTime<Utc>> = Mutex::new(Utc::now());

    // A stalled MongoDB will block the runtime, so spawn a new one to monitor the health.
    static ref RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .enable_io()
        .max_blocking_threads(2)
        .worker_threads(1)
        .thread_name("mongodb-health")
        .build()
        .unwrap();
}

///
/// Create a readiness monitor to response to readiness probes.
///
/// If downstream connection issues are detected it will return NOT_SERVING.
///
pub async fn start(ctx: Arc<ServiceContext>) -> (HealthReporter, HealthServer<impl Health>) {
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter.set_service_status(LIVELINESS, tonic_health::ServingStatus::Serving).await;
    health_reporter.set_service_status(READINESS, tonic_health::ServingStatus::Serving).await;

    tokio::spawn(monitor(ctx.clone(), health_reporter.clone()));
    tracing::info!("Health probe enabled for services {} and {}", LIVELINESS, READINESS);
    (health_reporter, health_service)
}

pub async fn shutdown(mut health_reporter: HealthReporter) {
    health_reporter.set_service_status(LIVELINESS, tonic_health::ServingStatus::NotServing).await;
    health_reporter.set_service_status(READINESS, tonic_health::ServingStatus::NotServing).await;
}

///
/// Monitor the Kafka and MongoDB services and flip our health if they become un-contactable.
///
async fn monitor(ctx: Arc<ServiceContext>, mut reporter: HealthReporter) {

    // Track individually - so even if one is down, if the other goes down, we'll log.
    let mut mongo = true;
    let mut kafka = true;

    let _kafka_handle = start_kafka_heartbeat(ctx.clone());
    let _mongo_handle = start_mongo_heartbeat(ctx.clone());

    loop {
        // We'll keep checking the heartbeat as each pulse ticks.
        tokio::time::sleep(Duration::from_millis(PULSE)).await;

        let new_kafka = kafka_healthy().await;
        let new_mongo = mongo_healthy().await;
        let health = new_kafka && new_mongo;

        if (new_kafka != kafka) || (new_mongo != mongo) {
            if health {
                tracing::info!("Service healthy (Kafka {}, MongoDB {})", new_kafka, new_mongo);
                reporter.set_service_status(READINESS, tonic_health::ServingStatus::Serving).await;

            } else {
                tracing::error!("Service NOT healthy (Kafka {}, MongoDB {})", new_kafka, new_mongo);
                reporter.set_service_status(READINESS, tonic_health::ServingStatus::NotServing).await;
            }
        }

        kafka = new_kafka;
        mongo = new_mongo;
    }
}

///
/// Compare the when the last heartbeat was received to the timeout configuration.
///
async fn kafka_healthy() -> bool {
    let duration: chrono::Duration = {
        let lock = kafka::consumer::KAFKA_HEARTBEAT.lock();
        let last_heartbeat: DateTime<Utc> = *lock;
        Utc::now() - last_heartbeat
    };

    // Kafka heartbeat to be delayed and make it appear down.
    let limit = TIMEOUT as i64;

    tracing::trace!("Kafka hearbeat age {} < timeout {}", duration.num_milliseconds(), limit);
    duration.num_milliseconds() < limit
}

///
/// Perform a MongoDB 'ping' to check the service status.
///
async fn mongo_healthy() -> bool {
    let duration: chrono::Duration = {
        let lock = MONGODB_HEARTBEAT.lock();
        let last_heartbeat: DateTime<Utc> = *lock;
        Utc::now() - last_heartbeat
    };

    let limit = TIMEOUT as i64;

    tracing::trace!("MongoDB hearbeat age {} < timeout {}", duration.num_milliseconds(), limit);
    duration.num_milliseconds() < limit
}

///
/// Because a stalled Kafka doesn't block a tokio thread, spawn a tokio thread to send
/// heartbeat messages - the kafka consumer will handle them and update the heartbeat.
///
fn start_kafka_heartbeat(ctx: Arc<ServiceContext>) -> tokio::task::JoinHandle<()> {

    tokio::spawn(async move {
        loop {
            tracing::trace!("Sending Kafka heartbeat");

            // Send a heartbeat log - the kafka consumer will update the heartbeat timestamp.
            if let Err(err) = ctx.send_no_trace(TOPIC_VAULT_HEARTBEAT, json!(Heartbeat{})).await {
                tracing::trace!("Unable to send Kafka heartbeat: {:?}", err);
            }

            tokio::time::sleep(Duration::from_millis(PULSE)).await;
        }
    })
}

///
/// Start a new OS thread with an async runtime - use this to monitor MongoDB. We need
/// the OS thread because a stalled Mongo will block the tokio threads, so this way
/// we can use the async runtime in isolation from the main app.
///
fn start_mongo_heartbeat(ctx: Arc<ServiceContext>) -> StdJoinHandle<()> {
    let handle = RT.handle();

    std::thread::spawn(move || {
        handle.block_on(async {
            loop {
                tracing::trace!("Pinging MongoDB");

                match mongo::ping(ctx.db()).await {
                    Ok(_doc) => {
                        let mut lock = MONGODB_HEARTBEAT.lock();
                        *lock = Utc::now();
                    },
                    Err(err)   => {
                        tracing::trace!("Mongo ping failed: {:?}", err);
                    },
                };

                tokio::time::sleep(Duration::from_millis(PULSE)).await;
            }
        })
    })
}