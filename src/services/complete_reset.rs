use serde_json::json;
use chrono::{DateTime, Duration, Utc};
use tonic::{Request, Response, Status};
use crate::{db, grpc::{api, common}, kafka::prelude::*, model::{events::PasswordResetCompleted, password::Password, policy::Policy}, utils::{context::ServiceContext, errors::{ErrorCode, VaultError}}};


pub async fn complete_reset_password(ctx: &ServiceContext, request: Request<api::CompleteResetRequest>)
    -> Result<Response<common::Empty>, Status> {

    let request = request.into_inner();

    // Get the password from the DB.
    let password = db::password::load(&request.password_id, ctx.db()).await?;

    // Is the reset code and time on the password?
    validate_password(&password)?;

    // Get the active policy for the password.
    let policy = ctx.active_policy_for_type(&password.password_type)?;

    // Check the new password against the policy.
    policy.validate_pattern(&request.plain_text_password)?;

    // Has the reset code expired? If so reject and clear it from the password.
    if reset_expired(ctx, &password, &policy) {
        return Err(Status::from(ErrorCode::ResetWindowExpired
            .with_msg("The period to reset the password has expired, you must initiate the process again")))
    }

    // Hash the new password in a blocking thread.
    let plain_text_password = request.plain_text_password.clone();
    let policy_for_hashing = policy.clone();
    let password_hashing = password.clone();
    let phc = tokio::task::spawn_blocking(move || {
            // Check this password against the password-history to prohibit reusing old passwords.
            policy_for_hashing.validate_history(&plain_text_password, &password_hashing)?;

            policy_for_hashing.hash_into_phc(&plain_text_password)
        })
        .await
        .map_err(VaultError::from)?
        ?;

    // Update the password in the database.
    let _result = db::password::upsert(ctx, &password.password_id, &password.password_type, &phc, policy.max_history_length).await?;

    ctx.send(TOPIC_PASSWORD_RESET_COMPLETED,
        json!(PasswordResetCompleted{ password_id: password.password_id.clone() })).await?;

    Ok(Response::new(common::Empty{}))
}


fn validate_password(password: &Password) -> Result<(), VaultError> {

    if password.reset_code.is_none() {
        return Err(ErrorCode::NoResetCode
            .with_msg(&format!("Unable to complete password reset, password {} has no reset code", password.password_id)))
    }

    if password.reset_started_at.is_none() {
        return Err(ErrorCode::NoResetTimestamp
            .with_msg(&format!("Unable to complete password reset, password {} has no reset timestamp", password.password_id)))
    }

    Ok(())
}


fn reset_expired(ctx: &ServiceContext, password: &Password, policy: &Policy) -> bool {

    // How long since the reset code was issued?
    let reset_started_at: DateTime<Utc> = password.reset_started_at.expect("reset started at was missing on the password").into();
    let duration: Duration = ctx.now() - reset_started_at;

    // Get the lock-out period from the active policy.
    duration.num_seconds() > policy.reset_timeout_seconds as i64
}