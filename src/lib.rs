pub mod utils;
mod model;
mod services;

use utils::errors::VaultError;
use utils::mongo;
use dotenv::dotenv;
use std::sync::Arc;
use parking_lot::RwLock;
use tonic::transport::Server;
use services::ServiceContext;
use crate::model::policy::PolicyDB;
use utils::config::{Configuration, self};
use grpc::password_service_server::PasswordServiceServer;
use opentelemetry::{global, sdk::{propagation::TraceContextPropagator,trace,trace::Sampler}};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, Registry, util::SubscriberInitExt};

#[cfg(feature = "kafka")]
use utils::kafka;

pub mod grpc {
    tonic::include_proto!("grpc");
}

const APP_NAME: &str = "Vault";

//#[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
pub async fn lib_main() -> Result<(), VaultError> {
    // TODO: Move all this into an init_everything.

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

    // Create any consumer topics we need to listen to.
    #[cfg(feature = "kafka")]
    kafka::create_topics(&config).await;

    // Load the active policy from the DB.
    let active_policy = Arc::new(RwLock::new(PolicyDB::load_active(db.clone()).await?));

    // The service context allows any gRPC service access to shared stuff (databases, notification producers, etc.).
    let service_context = ServiceContext::new(
        config.clone(),
        db.clone(),
        active_policy.clone());

    // Spawn a consumer to monitor the active policy changes from other instances.
    #[cfg(feature = "kafka")]
    tokio::spawn(async move {
        kafka::consumer::init_consumer(config.clone(), db.clone(), active_policy.clone()).await
    });

    tracing::info!("{} listening on {}", APP_NAME, addr);

    Server::builder()
        .add_service(PasswordServiceServer::new(service_context))
        .serve(addr)
        .await?;

    if tracing {
        opentelemetry::global::shutdown_tracer_provider(); // sending remaining spans
    }

    println!("Shutting down now sir");

    Ok(())
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