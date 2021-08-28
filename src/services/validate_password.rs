use serde_json::json;
use bson::{Document, doc};
use super::ServiceContext;
use chrono::{DateTime, Duration, Utc};
use tonic::{Request, Response, Status};
use crate::{grpc::api, model::{algorthm, password::PasswordDB, policy::PolicyDB}, utils::errors::{ErrorCode, VaultError}};

pub async fn validate_password(ctx: &ServiceContext, request: Request<api::ValidateRequest>)
    -> Result<Response<api::ValidateResponse>, Status> {

    // Get the domain-level gRPC request struct.
    let request = request.into_inner();

    // Load the password from MongoDB.
    let password = load_password(&request.password_id, &ctx).await?;

    // Get a snapshot of the policy as we'll need it potentially over the course of some io and
    // we don't want to hold a read lock for too long.
    let policy = ctx.active_policy().policy.clone();

    // // If we've failed too many times recently, reject the request.
    if locked_out(ctx, &password, &policy) {
        return Err(Status::from(ErrorCode::TooManyFailedAttempts
            .with_msg("The request has failed too many times, please wait and try again")))
    }

    // Validate the password matches the hashed password from the db. This is a highlly CPU-bound activity and
    // should be performed on the blocking worker thread pool.
    // let valid = algorthm::validate(&request.plain_text_password, &password.phc).await?;
    let phc = password.phc.clone();
    let plain_text_password = request.plain_text_password.clone();
    let valid = tokio::task::spawn_blocking(move || { algorthm::validate(&plain_text_password, &phc) })
        .await
        .map_err(|e| VaultError::from(e))?
        ?;

    // If the password is not valid, bump the failure count in the db.
    if !valid {
        increase_failure_count(ctx, &password).await?;

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
    clear_failure_details(ctx, &password).await?;
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
fn locked_out(ctx: &ServiceContext, password: &PasswordDB, policy: &PolicyDB) -> bool {

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
fn expired(ctx: &ServiceContext, password: &PasswordDB, policy: &PolicyDB) -> bool {
    let changed_on: DateTime<Utc> = password.changed_on.into();
    let duration: Duration = ctx.now() - changed_on;
    duration.num_days() > policy.max_age_days as i64
}


///
/// Load the requested password from the database.
///
async fn load_password(password_id: &str, ctx: &ServiceContext) -> Result<PasswordDB, VaultError> {

    let filter = doc!{ "password_id": password_id };

    match ctx.db().collection::<PasswordDB>("Passwords").find_one(filter, None)
        .await
        .map_err(|e| VaultError::from(e))? {

        Some(password) => Ok(password),
        None => Err(ErrorCode::PasswordNotFound.with_msg("The password requested does not exist").into())
    }
}


///
/// Bump the failure count and, if not set yet, timestamp the failure date.
///
async fn increase_failure_count(ctx: &ServiceContext, password: &PasswordDB) -> Result<(), VaultError> {

    let filter = doc!{ "password_id": &password.password_id };

    // Update the failure count and potentially the first_failure timestamp.
    let update = match password.first_failure {
        Some(_) => doc!("$inc": { "failure_count": 1 }),
        None => doc!{
            "$inc": { "failure_count": 1 },
            "$set": { "first_failure": bson::DateTime::from_chrono(ctx.now()) }
        },
    };

    ctx.db().collection::<Document>("Passwords").update_one(filter, update, None)
        .await
        .map_err(|e| VaultError::from(e))?;

    Ok(())
}

///
/// Clear any failure details and timestamp a successful validate operation.
///
async fn clear_failure_details(ctx: &ServiceContext, password: &PasswordDB) -> Result<(), VaultError> {

    let filter = doc!{ "password_id": &password.password_id };

    // Update the failure count and potentially the first_failure timestamp.
    let update = doc!{
            "$unset": { "failure_count": "", "first_failure": "" },
            "$set": { "last_success": bson::DateTime::from_chrono(ctx.now()) }
    };

    ctx.db().collection::<Document>("Passwords").update_one(filter, update, None)
        .await
        .map_err(|e| VaultError::from(e))?;

    Ok(())
}