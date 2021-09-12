use tonic::{Request, Response, Status};
use crate::{db, db::prelude::*, grpc::api, model::policy::Policy, utils::{self, context::ServiceContext, errors::VaultError}};

///
/// Validate the password against the current password policy.
///
/// If it's okay, update or create the password specified.
///
pub async fn hash_password(ctx: &ServiceContext, request: Request<api::HashRequest>)
    -> Result<Response<api::HashResponse>, Status> {

    let request = request.into_inner();
    let password_type = request.password_type.as_deref().unwrap_or(DEFAULT);
    let password_id = hash_and_store_password(
        ctx,
        &request.plain_text_password,
        &password_type,
        request.password_id)
        .await?;

    Ok(Response::new(api::HashResponse { password_id }))
}

pub async fn hash_and_store_password(ctx: &ServiceContext, plain_text_password: &str, password_type: &str, password_id: Option<String>)
    -> Result<String, VaultError> {

    // Check password against current policy.
    let policy = validate_password_get_policy(ctx, plain_text_password, password_type).await?;

    let (password_id, password) = match &password_id {
        Some(password_id) => {
            (password_id.clone(), db::password::load_if_present(password_id, ctx.db()).await?)
        },
        None => (utils::generate_id(), None),
    };

    // TODO: Check the password_type on the request matches that on the password if present.

    // Hash new password with a snapshot of the current policy. This is a highly CPU-bound activity so
    // perform it in the blocking thread pool not on the main event loop.
    let plain_text_password = plain_text_password.to_string();
    let policy_for_hashing = policy.clone();
    let phc = tokio::task::spawn_blocking(move || {
            // If this is an existing password, to check it's not been used before we need to load
            // the existing details from the DB.
            if let Some(password) = password {
                policy_for_hashing.validate_history(&plain_text_password, &password)?;
            }
            policy_for_hashing.hash_into_phc(&plain_text_password)
        })
        .await
        .map_err(|e| VaultError::from(e))?
        ?;

    let _result = db::password::upsert(&ctx, &password_id, &password_type, &phc, policy.max_history_length).await?;

    Ok(password_id)
}


///
/// Check the password doesn't violate the active policy.
///
/// If it's good, return the active policy to the caller.
///
async fn validate_password_get_policy(ctx: &ServiceContext, plain_text_password: &str, password_type: &str)
    -> Result<Policy, VaultError> {

    let policy = ctx.active_policy_for_type(password_type)?;
    policy.validate_pattern(plain_text_password)?;
    Ok(policy)
}