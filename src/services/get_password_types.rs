use tonic::{Request, Response, Status};
use crate::{grpc::{api, common}, utils::context::ServiceContext};


pub async fn get_password_types(ctx: &ServiceContext, _request: Request<common::Empty>)
    -> Result<Response<api::GetPasswordTypesResponse>, Status> {

    let password_types = {
        let lock = ctx.active_policies();
        lock.keys().cloned().collect::<Vec<String>>()
    };

    Ok(Response::new(api::GetPasswordTypesResponse { password_types }))
}