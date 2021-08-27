use bson::{Document, doc};
use serde_json::json;
use tonic::{Request, Response, Status};
use crate::{grpc::{api, common}, model::{config::prelude::*, policy::PolicyActivated}, utils::{errors::VaultError, mongo}};
use super::ServiceContext;
use crate::utils::errors::ErrorCode;

const V1: u8 = 1;

pub async fn make_active(ctx: &ServiceContext, request: Request<api::MakeActiveRequest>)
    -> Result<Response<common::Empty>, Status> {

    let request = request.into_inner();

    // Validate the policy exists.
    let filter = doc!{ "policy_id": &request.policy_id };
    let count = ctx.db().collection::<Document>("Policies")
        .count_documents(filter, None)
        .await
        .map_err(|e| VaultError::from(e))?;

    if count == 0 {
        return Err(ErrorCode::PolicyNotFound.with_msg("The policy requested was not found"))?
    }

    // Make it the active policy.
    make_active_by_id(&request.policy_id, ctx).await?;

    Ok(Response::new(common::Empty::default()))
}


pub async fn make_active_by_id(policy_id: &str, ctx: &ServiceContext) -> Result<(), VaultError> {
    let now = ctx.now();
    let filter = doc! { CONFIG_ID: SINGLETON };

    let update = doc!{
        "$set": {
            ACTIVE_POLICY_ID: policy_id,
            ACTIVATED_ON: bson::DateTime::from_chrono(now)
        }
    };

    ctx.db().collection::<Document>("Config")
        .update_one(filter, update, mongo::upsert())
        .await
        .map_err(|e| VaultError::from(e))?;

    tracing::info!("Sending Kafka notification to password.policy.activated {}", policy_id);

    ctx.send("password.policy.activated",
        json!(PolicyActivated {
            policy_id: policy_id.to_string(),
            activated_on: now,
        }),
        V1).await?;

    Ok(())
}