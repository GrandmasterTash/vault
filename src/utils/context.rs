use mongodb::Database;
use serde_json::Value;
use parking_lot::{RwLock, lock_api::RwLockReadGuard};
use chrono::{DateTime, Utc};
use crate::{model::policy::{ActivePolicy, Policy}, utils::{config::Configuration, errors::VaultError, time_provider::TimeProvider}};

#[cfg(feature = "kafka")]
use rdkafka::producer::FutureProducer;


///
/// The context is available to all gRPC service endpoints and gives them access to the DB, Kafka, config, etc.
///
pub struct ServiceContext {
    db: Database,
    config: Configuration,
    active_policy: RwLock<ActivePolicy>,
    time_provider: RwLock<TimeProvider>,

    #[cfg(feature = "kafka")]
    producer: FutureProducer,
}

impl ServiceContext {
    pub fn new(config: Configuration, db: Database, active_policy: ActivePolicy) -> Self {
        ServiceContext {
            db,
            config: config.clone(),
            active_policy: RwLock::new(active_policy),
            time_provider: RwLock::new(TimeProvider::default()),

            #[cfg(feature = "kafka")]
            producer: crate::utils::kafka::producer::producer(&config),
        }
    }

    #[allow(unused_variables)]
    pub async fn send(&self, topic: &str, payload: Value, version: u8) -> Result<(), VaultError> {
        #[cfg(feature = "kafka")]
        crate::utils::kafka::producer::send(
            &self.producer,
            &self.config,
            topic,
            &payload.to_string(),
            version).await?;

        Ok(())
    }

    pub fn now(&self) -> DateTime<Utc> {
        self.time_provider.read().now()
    }

    ///
    /// Set or clear the fixed time - if the request is succsseful returns true.
    ///
    /// It's possible that lock poisoning means this cannot be completed.
    ///
    pub fn set_now(&self, now: Option<DateTime<Utc>>) {
        self.time_provider.write().fix(now);
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    ///
    /// Returns the active password policy with a read-lock guard.
    ///
    pub fn active_policy(&self) -> RwLockReadGuard<'_, parking_lot::RawRwLock, ActivePolicy> {
        self.active_policy.read()
    }

    ///
    /// Update the current, in-memory active password policy.
    ///
    pub fn apply_policy(&self, policy: Policy, activated_on: DateTime<Utc>) {
        let mut lock = self.active_policy.write();
        *lock = ActivePolicy { policy, activated_on };
    }

    pub fn config(&self) -> &Configuration {
        &self.config
    }

}