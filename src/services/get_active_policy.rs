use tonic::{Request, Response, Status};
use crate::grpc::{api, common};
use super::ServiceContext;


pub async fn get_active_policy(ctx: &ServiceContext, _request: Request<common::Empty>)
    -> Result<Response<api::GetActivePolicyResponse>, Status> {

    let active_policy = ctx.active_policy();

    Ok(Response::new(api::GetActivePolicyResponse {
        policy: active_policy.policy.clone().into(),
        activated_on: active_policy.activated_on.timestamp_millis() as u64,
    }))
}