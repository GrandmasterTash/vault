use tonic::{Request, Response, Status};
use crate::{db, grpc::{api, common}, utils::context::ServiceContext};

///
/// Return all the polcies defined in the system.
///
/// There's no use-case where there should be many policies so they are all returned
/// as one-batch.
///
pub async fn get_policies(ctx: &ServiceContext, _request: Request<common::Empty>)
    -> Result<Response<api::GetPoliciesResponse>, Status> {

    let policies: Vec<api::Policy> = db::policy::load_all(ctx.db())
        .await?
        .iter()
        .map(|p| p.into())
        .collect();

    Ok(Response::new(api::GetPoliciesResponse { policies }))
}