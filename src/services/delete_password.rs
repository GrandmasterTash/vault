use std::sync::Arc;
use serde_json::json;
use futures::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use crate::{db, grpc::api, grpc::api::delete_request::DeleteBy, model::events::PasswordDeleted, utils::{context::ServiceContext, errors::{ErrorCode, VaultError}, kafka::prelude::TOPIC_PASSWORD_DELETED}};

type DeletePasswordsStream = ReceiverStream<Result<api::DeleteResponse, Status>>;


pub async fn delete_password(ctx: Arc<ServiceContext>, request: Request<api::DeleteRequest>)
    -> Result<Response<api::DeleteResponse>, Status> {

    let request = request.into_inner();
    let deleted_count = delete_internal(&request, ctx).await?;

    Ok(Response::new(api::DeleteResponse { deleted_count }))
}


pub async fn delete_passwords(ctx: Arc<ServiceContext>, request: Request<Streaming<api::DeleteRequest>>)
    -> Result<Response<DeletePasswordsStream>, Status>  {

    let mut stream = request.into_inner();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let ctx_clone = ctx.clone();

    // Spawn a new task to read the input stream and write to the output stream.
    tokio::spawn(async move {
        while let Some(request) = stream.next().await {
            match request {
                Ok(request) => {
                    let deleted_count = match delete_internal(&request, ctx_clone.clone()).await {
                        Ok(count) => count,
                        Err(err) => {
                            tracing::error!("Failed to delete a password {:?} : {:?}", request, err);
                            0
                        },
                    };

                    if let Err(err) = tx.send(Ok(api::DeleteResponse { deleted_count })).await {
                        tracing::error!("Unable to notify response stream about the delete: {:?}", err);
                    };
                },
                Err(err) => {
                    tracing::error!("Failed to read a delete request from the stream: {:?}", err);
                    break; // Pull the plug to avoid an infinite loop.
                },
            }
        }
    });

    Ok(Response::new(ReceiverStream::new(rx)))
}


async fn delete_internal(request: &api::DeleteRequest, ctx: Arc<ServiceContext>) -> Result<u64, VaultError> {

    let deleted_count = match &request.delete_by {
        Some(delete_by) => match delete_by {
            DeleteBy::PasswordId(password_id) => {
                let count = db::password::delete(&password_id, ctx.db()).await?;

                ctx.send(TOPIC_PASSWORD_DELETED, json!(PasswordDeleted {
                    password_id: Some(password_id.clone()),
                    password_type: None
                })).await?;

                count
            },

            DeleteBy::PasswordType(password_type) => {
                let count = db::password::delete_by_type(&password_type, ctx.db()).await?;

                ctx.send(TOPIC_PASSWORD_DELETED, json!(PasswordDeleted {
                    password_id: None,
                    password_type: Some(password_type.clone())
                })).await?;

                count
            },
        },

        None => return Err(ErrorCode::DeleteByNotSpecified
            .with_msg("The request must specify whether to delete by password_id or password_type")),
    };

    Ok(deleted_count)
}