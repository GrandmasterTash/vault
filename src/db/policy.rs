use std::collections::HashMap;

use bson::Document;
use futures::TryStreamExt;
use chrono::{DateTime, Utc};
use crate::model::config::Config;
use mongodb::{Database, bson::doc};
use crate::db::{prelude::*, mongo};
use crate::model::policy::{ActivePolicy, Policy};
use crate::utils::context::ServiceContext;
use crate::utils::errors::{ErrorCode, VaultError};

#[tracing::instrument(name="db:insert", skip(db))]
pub async fn insert(policy: Policy, db: &Database) -> Result<(), VaultError> {
    let result = db.collection::<Policy>(POLICIES).insert_one(policy, None)
        .await
        .map_err(VaultError::from)?;


    tracing::debug!("Insert policy with MongoDB object id {}", result.inserted_id);

    Ok(())
}


#[tracing::instrument(name="db:load", skip(db))]
pub async fn load(policy_id: &str, db: &Database) -> Result<Policy, VaultError> {

    let result = db
        .collection::<Policy>(POLICIES)
        .find_one(doc!{ POLICY_ID: policy_id }, None)
        .await?;

    match result {
        Some(policy) => Ok(policy),
        None => return Err(ErrorCode::PolicyNotFound.with_msg(&format!("The policy {} does not exist", policy_id))),
    }
}


#[tracing::instrument(name="db:load_all", skip(db))]
pub async fn load_all(db: &Database) -> Result<Vec<Policy>, VaultError> {

    let cursor = db
        .collection::<Policy>(POLICIES)
        .find(doc!{}, None)
        .await?;

    Ok(cursor
        .try_collect()
        .await
        .unwrap_or_else(|_| vec![]))
}


///
/// Using the Config singleton document in the database, load and return the current active password policy.
///
#[tracing::instrument(name="db:load_active", skip(db))]
pub async fn load_active(db: &Database)
    -> Result<HashMap<String/* password_type */, ActivePolicy>, VaultError> {

    tracing::info!("Loading active policies...");

    // Load the configuration for all password_types.
    let mut cursor = db.collection::<Config>(CONFIG)
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

    if active_policies.is_empty() {
        return Err(ErrorCode::ActivePolicyNotFound
            .with_msg("There were no configured active policies in the database"))
    }

    Ok(active_policies)
}

#[tracing::instrument(name="db:make_active_by_id", skip(ctx))]
pub async fn make_active_by_id(policy_id: &str, password_type: &str, ctx: &ServiceContext) -> Result<DateTime<Utc>, VaultError> {
    let now = ctx.now();
    let filter = doc! { PASSWORD_TYPE: password_type };
    let update = doc!{
        "$set": {
            PASSWORD_TYPE: password_type,
            ACTIVE_POLICY_ID: policy_id,
            ACTIVATED_ON: bson::DateTime::from_chrono(now)
        }
    };

    ctx.db().collection::<Document>(CONFIG)
        .update_one(filter, update, mongo::upsert())
        .await
        .map_err(VaultError::from)?;

    Ok(now)
}

#[tracing::instrument(name="db:policy_exists", skip(db))]
pub async fn policy_exists(policy_id: &str, db: &Database) -> Result<bool, VaultError> {
    let filter = doc!{ POLICY_ID: policy_id };
    let count = db.collection::<Document>(POLICIES)
        .count_documents(filter, None)
        .await
        .map_err(VaultError::from)?;
    Ok(count == 1)
}

#[tracing::instrument(name="db:delete_password_type", skip(db))]
pub async fn delete_password_type(password_type: &str, db: &Database) -> Result<bool, VaultError> {
    let filter = doc!{ PASSWORD_TYPE: password_type };
    let result = db.collection::<Document>(CONFIG)
        .delete_one(filter, None)
        .await
        .map_err(VaultError::from)?;
    Ok(result.deleted_count > 0)
}