use std::collections::HashMap;

use bson::Document;
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use mongodb::{Database, bson::doc};
use crate::db::mongo;
use crate::model::config::{prelude::*, Config};
use crate::model::policy::{ActivePolicy, Policy};
use crate::utils::context::ServiceContext;
use crate::utils::errors::{ErrorCode, VaultError};

#[tracing::instrument(skip(db))]
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
#[tracing::instrument(skip(db))]
pub async fn load_active(db: &Database)
    -> Result<HashMap<String/* password_type */, ActivePolicy>, VaultError> {

    tracing::info!("Loading active policies...");

    // Load the configuration for all password_types.
    let mut cursor = db.collection::<Config>("Config")
        .find(doc!{/* all */}, None)
        .await?;

    // Construct a hashmap of password_type -> active policy
    let mut active_policies = HashMap::new();
    while let Some(config) = cursor.try_next().await? {
        tracing::info!("Password type {} using policy {}", config.password_type, config.active_policy_id);

        active_policies.insert(
            config.password_type,
            ActivePolicy {
                policy: load(&config.active_policy_id, db).await?,
                activated_on: config.activated_on.to_chrono(),
            });
    }

    if active_policies.len() == 0 {
        return Err(ErrorCode::ActivePolicyNotFound
            .with_msg(&format!("There were no configured active policies in the database")))
    }

    Ok(active_policies)
}

#[tracing::instrument(skip(ctx))]
pub async fn make_active_by_id(policy_id: &str, password_type: &str, ctx: &ServiceContext) -> Result<DateTime<Utc>, VaultError> {
    let now = ctx.now();
    let filter = doc! { "password_type": password_type };
    let update = doc!{
        "$set": {
            PASSWORD_TYPE: password_type,
            ACTIVE_POLICY_ID: policy_id,
            ACTIVATED_ON: bson::DateTime::from_chrono(now)
        }
    };

    ctx.db().collection::<Document>("Config")
        .update_one(filter, update, mongo::upsert())
        .await
        .map_err(|e| VaultError::from(e))?;

    Ok(now)
}

#[tracing::instrument(skip(db))]
pub async fn policy_exists(policy_id: &str, db: &Database) -> Result<bool, VaultError> {
    let filter = doc!{ "policy_id": policy_id };
    let count = db.collection::<Document>("Policies")
        .count_documents(filter, None)
        .await
        .map_err(|e| VaultError::from(e))?;
    Ok(count == 1)
}