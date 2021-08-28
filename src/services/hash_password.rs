use super::ServiceContext;
use tonic::{Request, Response, Status};
use crate::{db, grpc::api, utils::{errors::VaultError, mongo}};

///
/// Validate the password against the current password policy.
///
/// If it's okay, update or create the password specified.
///
pub async fn hash_password(ctx: &ServiceContext, request: Request<api::HashRequest>)
    -> Result<Response<api::HashResponse>, Status> {

    let hash_request = request.into_inner();

    // Check password against current policy.
    validate_password(ctx, &hash_request)?;

    let password_id = match hash_request.password_id {
        Some(password_id) => password_id.clone(),
        None => mongo::generate_id(),
    };

    // Hash new password with a snapshot of the current policy. This is a highly CPU-bound activity so
    // perform it in the blocking thread pool not on the main event loop.
    let policy = { ctx.active_policy().policy.clone() };
    let plain_text_password = hash_request.plain_text_password.clone();
    let phc = tokio::task::spawn_blocking(move || { policy.hash_into_phc(&plain_text_password) })
        .await
        .map_err(|e| VaultError::from(e))?
        ?;

    let _result = db::password::upsert(&ctx, &password_id, &phc).await?;

    Ok(Response::new(api::HashResponse { password_id }))
}

///
/// Check the password doesn't violate the active policy.
///
fn validate_password(ctx: &ServiceContext, request: &api::HashRequest) -> Result<(), VaultError> {
    let active_policy = ctx.active_policy();
    active_policy.policy.validate_pattern(&request.plain_text_password)?;
    Ok(())
}