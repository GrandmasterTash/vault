use tonic::{Request, Response, Status};
use crate::{db, grpc::api, model::{config::prelude::DEFAULT, policy::Policy}, utils::{context::ServiceContext, errors::{ErrorCode, VaultError}}};

///
/// Validate the password against the current password policy.
///
/// If it's okay, update or create the password specified.
///
pub async fn hash_password(ctx: &ServiceContext, request: Request<api::HashRequest>)
    -> Result<Response<api::HashResponse>, Status> {

    let request = request.into_inner();
    let password_type = request.password_type.as_deref().unwrap_or(DEFAULT);

    // Check password against current policy.
    let policy = validate_password_get_policy(ctx, &request, &password_type)?;

    let password_id = match request.password_id {
        Some(password_id) => password_id.clone(),
        None => db::mongo::generate_id(),
    };

    // Hash new password with a snapshot of the current policy. This is a highly CPU-bound activity so
    // perform it in the blocking thread pool not on the main event loop.
    let plain_text_password = request.plain_text_password.clone();
    let phc = tokio::task::spawn_blocking(move || { policy.hash_into_phc(&plain_text_password) })
        .await
        .map_err(|e| VaultError::from(e))?
        ?;

    let _result = db::password::upsert(&ctx, &password_id, &password_type, &phc).await?;

    Ok(Response::new(api::HashResponse { password_id }))
}


///
/// Check the password doesn't violate the active policy.
///
/// If it's good, return the active policy to the caller.
///
fn validate_password_get_policy(ctx: &ServiceContext, request: &api::HashRequest, password_type: &str) -> Result<Policy, VaultError> {
    let lock = ctx.active_policies();
    let active_policy = lock.get(password_type);

    match active_policy {
        Some(active_policy) => {
            active_policy.policy.validate_pattern(&request.plain_text_password)?;
            Ok(active_policy.policy.clone())
        },

        None => Err(ErrorCode::ActivePolicyNotFound
            .with_msg(&format!("No active policy found for password type {}", password_type))),
    }
}