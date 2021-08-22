use std::fmt::Write;
use std::env::VarError;
use config::ConfigError;
use serde::{Deserialize, Serialize};

use super::errors::VaultError;

///
/// The service configuration - initialised at start-up.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Configuration {
    pub port: i32,                       // The port to run this service on.
    pub kafka_servers: String,           // The Kafka brokers.
    pub kafka_timeout: i32,              // The Kafka message timeout.
    pub db_name: String,                 // The MongoDB name to use.
    pub mongo_uri: String,               // The MongoDB connection URI. If a credentials file is used, $USERNAME, $PASSWORD should be used in the uri as placeholders.
    pub mongo_credentials: Option<String>, // The path to the credentials file for MongoDB - None means use URI as-is.
    pub jaeger_endpoint: Option<String>, // If jaeger tracing is enabled, this is the endpoint to send traces to.
    pub distributed_tracing: bool,       // Send traces to Jaeger.
}

impl Configuration {
    ///
    /// Load the service's configuration.
    ///
    pub fn from_env() -> Result<Configuration, ConfigError> {
        let mut cfg = config::Config::default();

        // Merge any environment variables with the same name as the struct fields.
        cfg.merge(config::Environment::new())?;

        // Set defaults for settings that were not specified.
        cfg.set_default("port", 50011)?;
        cfg.set_default("kafka_servers", "localhost:29092")?;
        cfg.set_default("kafka_timeout", 5000)?;
        cfg.set_default("db_name", "Vault")?;
        cfg.set_default("mongo_credentials", None::<String>)?;
        cfg.set_default("mongo_uri", "mongodb://admin:changeme@localhost:27017")?;
        cfg.set_default("distributed_tracing", false)?;
        cfg.set_default("jaeger_endpoint", None::<String>)?;

        let config: Configuration = cfg.try_into()?;

        if config.distributed_tracing && config.jaeger_endpoint.is_none() {
            panic!("Distributed tracing is enabled but no Jaeger endpoint is configured.");
        }

        Ok(config)
    }

    ///
    /// Pretty-print the config with ansi colours.
    ///
    pub fn fmt_console(&self) -> Result<String, VaultError> {
        // Serialise to JSON so we have fields to iterate.
        let values = serde_json::to_value(&self)?;

        // Turn into a hashmap.
        let values = values.as_object().expect("No config props");

        // Sort by keys.
        let mut sorted: Vec<_> = values.iter().collect();
        sorted.sort_by_key(|a| a.0);

        let mut output = String::new();
        for (k, v) in sorted {
            write!(&mut output, "{:>23}: {}\n", k, v).unwrap();
        }

        Ok(output)
    }
}

///
/// If the specified environment variable is set for this process, set it to the default value specified.
///
pub fn default_env(key: &str, value: &str) {
    if let Err(VarError::NotPresent) = std::env::var(key) {
        std::env::set_var(key, value);
    }
}