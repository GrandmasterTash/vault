use serde_json::json;
use super::ServiceContext;
use chrono::{DateTime, Duration, Utc};
use tonic::{Request, Response, Status};
use crate::{db, grpc::api, model::{algorithm, config::prelude::DEFAULT, password::Password, policy::Policy}, utils::errors::{ErrorCode, VaultError}};

pub async fn validate_password(ctx: &ServiceContext, request: Request<api::ValidateRequest>)
    -> Result<Response<api::ValidateResponse>, Status> {

    // Get the domain-level gRPC request struct.
    let request = request.into_inner();

    // Load the password from MongoDB.
    let password = db::password::load(&request.password_id, ctx.db()).await?;

    // Get a snapshot of the policy as we'll need it potentially over the course of some io and
    // we don't want to hold a read lock for too long.
    let policy = {
        let password_type = password.password_type.as_deref().unwrap_or(DEFAULT);
        let lock = ctx.active_policies();
        // TODO: Consider putting this into a method on context that result<Policy, VaultError>....
        match lock.get(password_type) {
            Some(active_policy) => active_policy.policy.clone(),
            None => return Err(Status::from(ErrorCode::ActivePolicyNotFound
                .with_msg(&format!("No active policy found for password type {}", password_type)))),
        }
    };

    // // If we've failed too many times recently, reject the request.
    if locked_out(ctx, &password, &policy) {
        return Err(Status::from(ErrorCode::TooManyFailedAttempts
            .with_msg("The request has failed too many times, please wait and try again")))
    }

    // Validate the password matches the hashed password from the db. This is a highlly CPU-bound activity and
    // should be performed on the blocking worker thread pool.
    // let valid = algorithm::validate(&request.plain_text_password, &password.phc).await?;
    let phc = password.phc.clone();
    let plain_text_password = request.plain_text_password.clone();
    let valid = tokio::task::spawn_blocking(move || { algorithm::validate(&plain_text_password, &phc) })
        .await
        .map_err(|e| VaultError::from(e))?
        ?;

    // If the password is not valid, bump the failure count in the db.
    if !valid {
        db::password::increase_failure_count(ctx, &password).await?;

        // Are we over the failure limit? Raise a notification.
        if password.failure_count.unwrap_or(0) > policy.max_failures {
            tracing::warn!("Password id {} has exceeded the failure threshold", request.password_id);

            ctx.send(
                "password.failure.exceeded",
                json!({ "password_id": request.password_id.clone() }),
                1).await?;
        }

        return Err(Status::from(ErrorCode::PasswordNotMatch.with_msg("The passwords did not match")))
    }

    // Has the password expired? If so, indicate in the response it must be changed.
    let must_change = expired(ctx, &password, &policy); // TODO: This should return a failure but with this body?

    // Clear any failure details on the password and stamp the last successful use.
    db::password::clear_failure_details(ctx, &password).await?;
    Ok(Response::new(api::ValidateResponse { must_change }))

}

///
/// If a previous validate attempt has failed more than the active policy allows,
/// return true if it was within the lockout period on the policy.
///
/// i.e. after x failures, prohibit any more attempts for y seconds.
///
/// Whenever a successful validate attempt is performed, the last_failure and
/// failure_counts are reset.
///
fn locked_out(ctx: &ServiceContext, password: &Password, policy: &Policy) -> bool {

    // Has the password failed a previous attempt?
    if let Some(first_failure) = password.first_failure {
        if password.failure_count.unwrap_or(0) > policy.max_failures {
            // How long since our last failed attempt.
            let first_failure: DateTime<Utc> = first_failure.into();
            let duration: Duration = ctx.now() - first_failure;

            // Get the lock-out period from the active policy.
            return duration.num_seconds() < policy.lockout_seconds as i64
        }
    }

    false
}

///
/// If the password hasn't been changed within the rotation period, indicate to the caller it now
/// needs to be rotated.
///
fn expired(ctx: &ServiceContext, password: &Password, policy: &Policy) -> bool {
    let changed_on: DateTime<Utc> = password.changed_on.into();
    let duration: Duration = ctx.now() - changed_on;
    duration.num_days() > policy.max_age_days as i64
}