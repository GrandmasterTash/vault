use serde_json::json;
use tonic::{Request, Response, Status};
use crate::{db::{self, prelude::*}, grpc::api, model::policy::PasswordTypeDeleted, utils::{context::ServiceContext, errors::ErrorCode, kafka::prelude::*}};


pub async fn delete_password_type(ctx: &ServiceContext, request: Request<api::DeletePasswordTypeRequest>)
    -> Result<Response<api::DeleteResponse>, Status> {

    let request = request.into_inner();

    if request.password_type == DEFAULT {
        return Err(Status::from(ErrorCode::CannotRemoveDefault.with_msg("You may not remove the DEFAULT password_type")))
    }

    // Delete the MongoDB config.
    if !db::policy::delete_password_type(&request.password_type, ctx.db()).await? {
        return Err(Status::from(ErrorCode::PasswordTypeNotFound.with_msg("No such password type exists")))
    };

    // Delete any passwords for the type.
    let result = db::password::delete_by_type(&request.password_type, ctx.db()).await?;

    // Emit a notification so other instances remove any active policy for the password type.
    ctx.send(TOPIC_PASSWORD_TYPE_DELETED, json!(PasswordTypeDeleted { password_type: request.password_type.clone() } )).await?;

    Ok(Response::new(api::DeleteResponse { deleted_count: result }))
}