use serde_json::json;
use super::ServiceContext;
use tonic::{Request, Response, Status};
use crate::{model::config::prelude::DEFAULT, utils::errors::ErrorCode};
use crate::{db, grpc::{api, common}, model::policy::PolicyActivated, utils::errors::VaultError};

const V1: u8 = 1;

pub async fn make_active(ctx: &ServiceContext, request: Request<api::MakeActiveRequest>)
    -> Result<Response<common::Empty>, Status> {

    let request = request.into_inner();

    // Validate the policy exists.
    if !db::policy::policy_exists(&request.policy_id, ctx.db()).await? {
        return Err(ErrorCode::PolicyNotFound.with_msg("The policy requested was not found"))?
    }

    // Make it the active policy.
    make_active_by_id(
        &request.policy_id,
        &request.password_type.as_deref().unwrap_or(DEFAULT),
        ctx).await?;

    Ok(Response::new(common::Empty::default()))
}


pub async fn make_active_by_id(policy_id: &str, password_type: &str, ctx: &ServiceContext) -> Result<(), VaultError> {
    let when = db::policy::make_active_by_id(policy_id, password_type, ctx).await?;

    tracing::info!("Sending Kafka notification to password.policy.activated {}", policy_id);

    ctx.send("password.policy.activated",
        json!(PolicyActivated {
            policy_id: policy_id.to_string(),
            password_type: password_type.to_string(),
            activated_on: when,
        }),
        V1).await?;

    Ok(())
}