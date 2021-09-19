use std::sync::Arc;
use futures::StreamExt;
use serde_json::json;
use tokio_stream::wrappers::ReceiverStream;
use api::import_password_request::Password;
use tonic::{Request, Response, Status, Streaming};
use crate::{db::{self, prelude::*}, grpc::api, model::{algorithm, events::PasswordHashed}, kafka::prelude::*, services::hash_password::hash_and_store_password, utils::{self, context::ServiceContext, errors::{ErrorCode, VaultError}}};

type ImportPasswordsStream = ReceiverStream<Result<api::ImportPasswordResponse, Status>>;

pub async fn import_passwords(ctx: Arc<ServiceContext>, request: Request<Streaming<api::ImportPasswordRequest>>)
    -> Result<Response<ImportPasswordsStream>, Status>  {

    let mut stream = request.into_inner();
    let (tx, rx) = tokio::sync::mpsc::channel(4);

    // Spawn a new thread to read the input stream and write to the output stream.
    tokio::spawn(async move {
        while let Some(request) = stream.next().await {
            match request {
                Ok(request) => {
                    match import_internal(&request, ctx.clone()).await {
                        Ok(password_id) => {
                            if let Err(err) = tx.send(Ok(good_import_response(&password_id))).await {
                                tracing::error!("Unable to notify response stream about the import of password_id {}: {:?}", password_id, err);
                            };
                        },
                        Err(import_err) => {
                            match tx.send(Ok(bad_import_response(&format!("{:?}", import_err)))).await {
                                Ok(_) => tracing::error!("Failed to import a password {:?} : {:?}", request, import_err),
                                Err(send_err) => tracing::error!("Unable to notify response stream about the failed import {:?}: {:?}", import_err, send_err),
                            };
                        },
                    };
                },
                Err(read_err) => {
                    tracing::error!("Error reading from import stream: {}", read_err);
                    break; // If the stream is corrupted - pull the plug to avoid any possible infinite loop.
                },
            }
        }
    });

    Ok(Response::new(ReceiverStream::new(rx)))
}


async fn import_internal(request: &api::ImportPasswordRequest, ctx: Arc<ServiceContext>)
    -> Result<String, VaultError> {

    match &request.password {
        Some(password) => {
            let password_type = request.password_type.as_deref().unwrap_or(DEFAULT);

            match password {
                Password::PlainTextPassword(plain_text_password) => {
                    Ok(hash_and_store_password(
                        &ctx,
                        &plain_text_password,
                        &password_type,
                        None)
                        .await?)
                },
                Password::PhcString(phc) => {
                    // Parse the phc into a supported algorthm.
                    if !algorithm::is_supported(phc) {
                        return Err(ErrorCode::InvalidPHCFormat.with_msg(&format!("PHC not valid: {}", phc)))
                    }

                    // Get the policy for this password type.
                    let policy = ctx.active_policy_for_type(password_type)?;
                    let password_id = utils::generate_id();

                    // Upsert the password into the database.
                    let _result = db::password::upsert(&ctx, &password_id, &password_type, phc, policy.max_history_length).await?;

                    ctx.send(TOPIC_PASSWORD_HASHED, json!(PasswordHashed { password_id: password_id.clone() })).await?;

                    Ok(password_id)
                },
            }
        },
        None => return Err(ErrorCode::PasswordNotSpecified
            .with_msg("The request must specify whether to import a plain text password or a phc")),
    }
}

fn good_import_response(password_id: &str) -> api::ImportPasswordResponse {
    api::ImportPasswordResponse {
        result: Some(api::import_password_response::Result::PasswordId(password_id.to_string()))
    }
}

fn bad_import_response(message: &str) -> api::ImportPasswordResponse {
    api::ImportPasswordResponse {
        result: Some(api::import_password_response::Result::ErrorMessage(message.to_string()))
    }
}