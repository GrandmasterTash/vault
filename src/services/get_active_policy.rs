use super::ServiceContext;
use tonic::{Request, Response, Status};
use crate::{grpc::api, db::prelude::*, utils::errors::ErrorCode};


pub async fn get_active_policy(ctx: &ServiceContext, request: Request<api::GetActivePolicyRequest>)
    -> Result<Response<api::GetActivePolicyResponse>, Status> {

    let request = request.into_inner();
    let password_type = request.password_type.unwrap_or(DEFAULT.to_string());

    let lock = ctx.active_policies();
    let active_policy = lock.get(&password_type);

    match active_policy {
        Some(active_policy) => Ok(Response::new(api::GetActivePolicyResponse {
                policy: active_policy.policy.clone().into(),
                activated_on: active_policy.activated_on.timestamp_millis() as u64,
            })),

        None => Err(ErrorCode::ActivePolicyNotFound
            .with_msg(&format!("Unable to find an active policy for password type {}", password_type)))?
    }

}