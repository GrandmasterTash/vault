use crate::grpc::common;
use super::ServiceContext;
use tonic::{Request, Response, Status};

pub async fn reset_time(ctx: &ServiceContext, _request: Request<common::Empty>)
    -> Result<Response<common::Empty>, Status> {

    ctx.set_now(None);
    tracing::info!("TimeProvider no-longer fixed");
    Ok(Response::new(common::Empty::default()))
}