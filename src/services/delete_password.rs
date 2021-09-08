use mongodb::Database;
use futures::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use crate::{db, grpc::api, grpc::api::delete_request::DeleteBy, utils::{context::ServiceContext, errors::{ErrorCode, VaultError}}};

type DeletePasswordsStream = ReceiverStream<Result<api::DeleteResponse, Status>>;


pub async fn delete_password(ctx: &ServiceContext, request: Request<api::DeleteRequest>)
    -> Result<Response<api::DeleteResponse>, Status> {

    let request = request.into_inner();

    let deleted_count = delete_internal(request, ctx.db().clone()).await?;

    Ok(Response::new(api::DeleteResponse { deleted_count }))
}


pub async fn delete_passwords(ctx: &ServiceContext, request: Request<Streaming<api::DeleteRequest>>)
    -> Result<Response<DeletePasswordsStream>, Status>  {

    let mut stream = request.into_inner();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let db = ctx.db().clone();

    // Spawn a new thread to read the input stream and write to the output stream.
    tokio::spawn(async move {
        while let Some(request) = stream.next().await {
            match request {
                Ok(request) => {
                    // TODO: Handle errors and log stuff. For example disconnecting remote caused a panic.
                    let deleted_count = delete_internal(request, db.clone()).await.unwrap_or(0);
                    tx.send(Ok(api::DeleteResponse { deleted_count })).await.unwrap()
                },
                Err(err) => tx.send(Ok(api::DeleteResponse { deleted_count: 0 })).await.unwrap(),
            }
        }
    });

    Ok(Response::new(ReceiverStream::new(rx)))
}


async fn delete_internal(request: api::DeleteRequest, db: Database) -> Result<u64, VaultError> {
    Ok(match request.delete_by {
        Some(delete_by) => match delete_by {
            DeleteBy::PasswordId(password_id)     => db::password::delete(&password_id, &db).await?,
            DeleteBy::PasswordType(password_type) => db::password::delete_by_type(&password_type, &db).await?,
        },
        None => return Err(ErrorCode::DeleteByNotSpecified
            .with_msg("The request must specify whether to delete by password_id or password_type")),
    })
}