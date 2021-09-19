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
    pub address: String,                   // The address and port to host the server on.
    pub kafka_servers: String,             // The Kafka brokers.
    pub kafka_timeout: i32,                // The Kafka message timeout in ms.
    pub db_name: String,                   // The MongoDB name to use.
    pub mongo_uri: String,                 // The MongoDB connection URI. username and password must exist in secrets/mongodb_username and secrets/mongodb_password respectively.
    pub jaeger_endpoint: Option<String>,   // If this is the jaeger endpoint to send traces to.
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
        cfg.set_default("address", "0.0.0.0:50011")?;
        cfg.set_default("kafka_servers", "localhost:29092")?;
        cfg.set_default("kafka_timeout", 5000)?;
        cfg.set_default("db_name", "Vault")?;
        cfg.set_default("mongo_uri", "mongodb://$USERNAME:$PASSWORD@localhost:27017")?;
        cfg.set_default("jaeger_endpoint", None::<String>)?;

        let config: Configuration = cfg.try_into()?;

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
            writeln!(&mut output, "{:>23}: {}", k, v).unwrap();
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