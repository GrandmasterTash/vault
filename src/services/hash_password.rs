use serde_json::json;
use tonic::{Request, Response, Status};
use crate::{db, db::prelude::*, grpc::api, model::{events::PasswordHashed, policy::Policy}, kafka::prelude::*, utils::{self, context::ServiceContext, errors::{ErrorCode, VaultError}}};
use lazy_static::lazy_static;

lazy_static! {
    // Limit the number of CPU-bound tasks.
    // TODO: If this fixes the perf issue - suggest the task spawning is done at a lower level and controlled there.
    static ref SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::new(num_cpus::get());
}

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
        password_type,
        request.password_id)
        .await?;

    Ok(Response::new(api::HashResponse { password_id }))
}


pub async fn hash_and_store_password(ctx: &ServiceContext, plain_text_password: &str, password_type: &str, password_id: Option<String>)
    -> Result<String, VaultError> {

    // Check password against current policy.
    let policy = validate_password_get_policy(ctx, plain_text_password, password_type).await?;

    // Get the supplied or generated password_id, and if it exists in the DB, the password record.
    let (password_id, password) = match &password_id {
        Some(password_id) => {
            let password = db::password::load_if_present(password_id, ctx.db()).await?;

            // Check the password_type on the request matches that on the password record.
            if let Some(password) = &password {
                if password.password_type != password_type {
                    return Err(ErrorCode::PasswordTypesDontMatch
                        .with_msg(&format!("The password_type on the request {} didn't match the stored type for password_id {}", password_type, password_id)))
                }
            }

            (password_id.clone(), password)
        },
        None => (utils::generate_id(), None),
    };

    // Hash new password with a snapshot of the current policy. This is a highly CPU-bound activity so
    // perform it in the blocking thread pool not on the main event loop.
    let plain_text_password = plain_text_password.to_string();
    let policy_for_hashing = policy.clone();

    // Limit how many requests can do this.
    let a_permit = SEMAPHORE.acquire().await.unwrap();
    let phc = tokio::task::spawn_blocking(move || {
            // If this is an existing password, to check it's not been used before we need to load
            // the existing details from the DB.
            if let Some(password) = password {
                policy_for_hashing.validate_history(&plain_text_password, &password)?;
            }
            policy_for_hashing.hash_into_phc(&plain_text_password)
        })
        .await
        .map_err(VaultError::from)?
        ?;

    let _result = db::password::upsert(ctx, &password_id, password_type, &phc, policy.max_history_length).await?;

    ctx.send(TOPIC_PASSWORD_HASHED, json!(PasswordHashed { password_id: password_id.clone() })).await?;

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