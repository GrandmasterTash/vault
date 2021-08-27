use super::ServiceContext;
use chrono::{DateTime, Utc};
use crate::grpc::{admin, common};
use tonic::{Request, Response, Status};


pub async fn set_time(ctx: &ServiceContext, request: Request<admin::NewTime>)
    -> Result<Response<common::Empty>, Status> {

    let request = request.into_inner();
    let parsed = match DateTime::parse_from_rfc3339(&request.new_time) {
        Ok(parsed) => parsed.with_timezone(&Utc),
        Err(err) => return Err(Status::invalid_argument(format!("Could not parse datetime: {}", err))),
    };

    ctx.set_now(Some(parsed));
    tracing::info!("TimeProvider fixed to {:?}", parsed);
    Ok(Response::new(common::Empty::default()))
}


pub async fn reset_time(ctx: &ServiceContext, _request: Request<common::Empty>)
    -> Result<Response<common::Empty>, Status> {

    ctx.set_now(None);
    tracing::info!("TimeProvider no-longer fixed");
    Ok(Response::new(common::Empty::default()))
}