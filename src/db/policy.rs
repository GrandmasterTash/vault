use mongodb::{Database, bson::doc};
use crate::model::config::{prelude::*, Config};
use crate::model::policy::{ActivePolicy, Policy};
use crate::utils::errors::{ErrorCode, VaultError};

// TODO: Instrument all db methods.

#[cfg(feature = "kafka")] // Note: This cfg is temp
pub async fn load(policy_id: &str, db: &Database) -> Result<Policy, VaultError> {

    let result = db
        .collection::<Policy>("Policies")
        .find_one(doc!{ "policy_id": policy_id }, None)
        .await?;

    match result {
        Some(policy) => Ok(policy),
        None => return Err(ErrorCode::PolicyNotFound.with_msg(&format!("The policy {} does not exist", policy_id))),
    }
}


///
/// Using the Config singleton document in the database, load and return the current active password policy.
///
pub async fn load_active(db: &Database) -> Result<ActivePolicy, VaultError> {
    tracing::info!("Loading current config...");

    let config = db.collection::<Config>("Config")
        .find_one(doc!{ "config_id": SINGLETON }, None)
        .await?
        .expect("Unable to load the configuration from the database");

    tracing::info!("Loading active policy...");

    let active_policy_id = &config.active_policy_id;
    let result = db.collection::<Policy>("Policies")
        .find_one(doc!{ "policy_id": active_policy_id }, None).await?;

    tracing::info!("Loaded active policy");

    match result {
        Some(policy) => Ok(ActivePolicy { policy, activated_on: config.activated_on.into() }),

        None => return Err(ErrorCode::ActivePolicyNotFound
            .with_msg(&format!("The configured active policy '{}' was not found", active_policy_id))),
    }
}