use mongodb::Database;
use serde_json::Value;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use parking_lot::{RwLock, lock_api::RwLockReadGuard};
use crate::{model::policy::{ActivePolicy, Policy}, utils::{config::Configuration, errors::{ErrorCode, VaultError}, time_provider::TimeProvider}};

#[cfg(feature = "kafka")]
use rdkafka::producer::FutureProducer;


type ActivePoliciesRwLock<'a> = RwLockReadGuard<'a, parking_lot::RawRwLock, HashMap<String, ActivePolicy>>;


///
/// The context is available to all gRPC service endpoints and gives them access to the DB, Kafka, config, etc.
///
pub struct ServiceContext {
    db: Database,
    config: Configuration,
    active_policies: RwLock<HashMap<String/* password_type */, ActivePolicy>>,
    time_provider: RwLock<TimeProvider>,

    #[cfg(feature = "kafka")]
    producer: FutureProducer,
}


impl ServiceContext {
    pub fn new(config: Configuration, db: Database, active_policies: HashMap<String, ActivePolicy>)
        -> Self {

        ServiceContext {
            db,
            config: config.clone(),
            active_policies: RwLock::new(active_policies),
            time_provider: RwLock::new(TimeProvider::default()),

            #[cfg(feature = "kafka")]
            producer: crate::utils::kafka::producer::producer(&config),
        }
    }

    ///
    /// Publish the JSON payload to the topic specified - if Kafka is configured.
    ///
    #[allow(unused_variables)]
    pub async fn send(&self, topic: &str, payload: Value) -> Result<(), VaultError> {
        #[cfg(feature = "kafka")]
        crate::utils::kafka::producer::send(
            &self.producer,
            &self.config,
            topic,
            &payload.to_string(),
            1).await?;

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

    ///
    /// Returns the active password policies with a read-lock guard.
    ///
    pub fn active_policies(&self) -> ActivePoliciesRwLock {
        self.active_policies.read()
    }

    ///
    /// If there is an active policy for the password type specified, return a CLONE of it -
    /// otherwise return an error.
    ///
    pub fn active_policy_for_type(&self, password_type: &str) -> Result<Policy, VaultError> {

        let lock = self.active_policies.read();
        match lock.get(password_type) {
            Some(active_policy) => Ok(active_policy.policy.clone()),
            None => Err(ErrorCode::ActivePolicyNotFound
                .with_msg(&format!("Unable to find an active policy for password type {}", password_type))),
        }
    }

    ///
    /// Update the current, in-memory active password policy.
    ///
    pub fn apply_policy(&self, policy: Policy, password_type: &str, activated_on: DateTime<Utc>) {
        let mut lock = self.active_policies.write();
        lock.insert(password_type.to_string(), ActivePolicy { policy, activated_on });
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn config(&self) -> &Configuration {
        &self.config
    }

}