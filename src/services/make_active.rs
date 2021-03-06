use serde_json::json;
use super::ServiceContext;
use tonic::{Request, Response, Status};
use crate::{utils::errors::ErrorCode, kafka::prelude::*};
use crate::{db, db::prelude::*, grpc::{api, common}, model::events::PolicyActivated, utils::errors::VaultError};

pub async fn make_active(ctx: &ServiceContext, request: Request<api::MakeActiveRequest>)
    -> Result<Response<common::Empty>, Status> {

    let request = request.into_inner();

    // Validate the policy exists.
    if !db::policy::policy_exists(&request.policy_id, ctx.db()).await? {
        return Err(ErrorCode::PolicyNotFound.with_msg("The policy requested was not found").into())
    }

    // Make it the active policy.
    make_active_by_id(
        &request.policy_id,
        request.password_type.as_deref().unwrap_or(DEFAULT),
        ctx).await?;

    Ok(Response::new(common::Empty::default()))
}


pub async fn make_active_by_id(policy_id: &str, password_type: &str, ctx: &ServiceContext) -> Result<(), VaultError> {
    let when = db::policy::make_active_by_id(policy_id, password_type, ctx).await?;

    tracing::info!("Sending Kafka notification to {} {}", TOPIC_POLICY_ACTIVATED, policy_id);

    ctx.send(TOPIC_POLICY_ACTIVATED,
        json!(PolicyActivated {
            policy_id: policy_id.to_string(),
            password_type: password_type.to_string(),
            activated_on: when,
        })).await?;

    Ok(())
}