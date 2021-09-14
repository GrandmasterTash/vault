mod db;
mod model;
mod services;
pub mod utils;

use db::mongo;
use dotenv::dotenv;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Server;
use utils::health;
use utils::errors::VaultError;
use utils::context::ServiceContext;
use utils::config::{Configuration, self};
use grpc::api::vault_server::VaultServer;
use grpc::internal::internal_server::InternalServer;
use opentelemetry::{global, sdk::{propagation::TraceContextPropagator,trace,trace::Sampler}};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, Registry, util::SubscriberInitExt};

#[cfg(feature = "kafka")]
use utils::kafka;

///
/// These are the generated gRPC/protobuf modules which give us access to the message structures, services,
/// servers and clients to talk to our APIs. The services are implemented in services/mod.rs
///
pub mod grpc {
    pub mod common {
        tonic::include_proto!("grpc.common");
    }

    pub mod api {
        tonic::include_proto!("grpc.vault");
    }

    pub mod internal {
        tonic::include_proto!("grpc.internal");
    }
}

const APP_NAME: &str = "Vault";

///
/// Entry point to start the app.
///
pub async fn lib_main() -> Result<(), VaultError> {

    // Load any local dev settings as environment variables from a .env file.
    dotenv().ok();

    // Default log level to INFO if it's not specified.
    config::default_env("RUST_LOG", "INFO");

    // Load the service configuration into struct and initialise any lazy statics.
    let config = Configuration::from_env().expect("The service configuration is not correct");

    // Initialise open-telemetry distributed tracing.
    let tracing = init_tracing(&config);

    tracing::info!("{}\n{}", BANNER, config.fmt_console()?);

    // The port we'll serve on.
    // let addr = format!("0.0.0.0:{}", config.port).parse().unwrap();
    let addr = format!("[::1]:{}", config.port).parse().unwrap();

    // Create a MongoDB client and connect to it before proceeding.
    let db = mongo::get_mongo_db(APP_NAME, &config).await?;

    // Ensure the schema is in sync with the code.
    mongo::update_mongo(&db).await?;

    // Load the active policy from the DB.
    let active_policies = db::policy::load_active(&db).await?;

    // Create any consumer topics we need to listen to.
    #[cfg(feature = "kafka")]
    kafka::create_topics(&config).await;

    // The service context allows any gRPC service access to shared stuff (databases, notification producers, etc.).
    let ctx = Arc::new(ServiceContext::new(
        config.clone(),
        db.clone(),
        active_policies));

    #[cfg(feature = "kafka")]
    start_and_wait_for_consumer(ctx.clone()).await;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<VaultServer<Arc<ServiceContext>>>()
        .await;

    tokio::spawn(health::monitor(ctx.clone(), health_reporter.clone()));

    tracing::info!("Health probe enabled for service grpc.vault.Vault");
    tracing::info!("{} listening on {}", APP_NAME, addr);

    Server::builder()
        .add_service(VaultServer::new(ctx.clone()))
        .add_service(InternalServer::new(ctx.clone()))
        .add_service(health_service)
        .serve(addr)
        .await?;

    if tracing {
        opentelemetry::global::shutdown_tracer_provider(); // sending remaining spans
    }

    println!("Shutting down now sir");
    // TODO: Need Ctrl-C handling - https://docs.rs/tokio/1.10.1/tokio/signal/index.html

    Ok(())
}

///
/// Connect a Kafka consumer and wait for it to be ready to receive messages.
///
async fn start_and_wait_for_consumer(ctx: Arc<ServiceContext>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);

    // Spawn a consumer to monitor the active policy changes from other instances.
    tokio::spawn(async move {
        kafka::consumer::init_consumer(ctx, tx).await
    });

    // Wait until the consumer has sent us a signal that it's ready.
    if let Err(_) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
        panic!("Timeout waiting for the kafka consumer to signal it was ready.");
    }
}


///
/// Initialise tracing and plug-in the Jaeger feature if enabled.
///
fn init_tracing(config: &Configuration) -> bool {
    global::set_text_map_propagator(TraceContextPropagator::new());

    match config.distributed_tracing {
        true => { // Install the Jaeger pipeline.
            let tracer = opentelemetry_jaeger::new_pipeline()
                .with_service_name(APP_NAME)
                .with_trace_config(trace::config().with_sampler(Sampler::AlwaysOn))
                .with_agent_endpoint(config.jaeger_endpoint.clone().unwrap_or_default())
                .install_batch(opentelemetry::runtime::Tokio)
                .expect("Unable to build Jaeger pipeline");

            if let Err(err) = Registry::default()
                .with(tracing_subscriber::EnvFilter::from_default_env()) // Set the tracing level to match RUST_LOG env variable.
                .with(tracing_subscriber::fmt::layer().with_test_writer().with_ansi(true))
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init() {
                    tracing::info!("Tracing already initialised: {}", err.to_string()); // Allowed error here - tests call this fn repeatedly.
            }

            return true
        },
        false => {
            if let Err(err) = Registry::default()
                .with(tracing_subscriber::EnvFilter::from_default_env()) // Set the tracing level to match RUST_LOG env variable.
                .with(tracing_subscriber::fmt::layer().with_test_writer().with_ansi(true))
                .try_init() {
                    tracing::info!("Tracing already initialised: {}", err.to_string()); // Allowed error here - tests call this fn repeatedly.
            }

            return false
        }
    }
}

const BANNER: &str = r#"
____   ____            .__   __
\   \ /   /____   __ __|  |_/  |_
 \   Y   /\__  \ |  |  \  |\   __\
  \     /  / __ \|  |  /  |_|  |
   \___/  (____  /____/|____/__|
               \/
"#;