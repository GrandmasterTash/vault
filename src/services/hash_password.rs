use super::ServiceContext;
use bson::{Document, doc};
use chrono::Utc;
use tonic::{Request, Response, Status};
use crate::{utils::{errors::VaultError, mongo}, grpc::{HashRequest, HashResponse}};

///
/// Validate the password against the current password policy.
///
/// If it's okay, update or create the password specified.
///
pub async fn hash_password(ctx: &ServiceContext, request: Request<HashRequest>)
    -> Result<Response<HashResponse>, Status> {

    let hash_request = request.into_inner();

    // Check password against current policy.
    validate_password(ctx, &hash_request)?;

    let password_id = match hash_request.password_id {
        Some(password_id) => password_id.clone(),
        None => mongo::generate_id(),
    };

    // Hash new password with a snapshot of the current policy. This is a highly CPU-bound activity so
    // perform it in the blocking thread pool not on the main event loop.
    let policy = { ctx.active_policy.read().clone() };
    let plain_text_password = hash_request.plain_text_password.clone();
    // let phc = policy.hash_into_phc(&hash_request.plain_text_password)?;
    let phc = tokio::task::spawn_blocking(move || { policy.hash_into_phc(&plain_text_password) })
        .await
        .map_err(|e| VaultError::from(e))?
        ?;


    // Store in db.
    let filter = doc! {
        "password_id": &password_id,
    };

    let update = doc!{
        "$set": {
            "password_id": &password_id,
            "phc": phc,
            "changed_on": bson::DateTime::from_chrono(Utc::now()),  // TODO: Use a timeprovider.
        }
    };

    ctx.db.collection::<Document>("Passwords").update_one(filter, update, mongo::upsert())
        .await
        .map_err(|e| VaultError::from(e))?;

    Ok(Response::new(HashResponse { password_id }))
}

///
/// Check the password doesn't violate the active policy.
///
fn validate_password(ctx: &ServiceContext, request: &HashRequest) -> Result<(), VaultError> {
    let policy = ctx.active_policy.read();
    policy.validate_pattern(&request.plain_text_password)?;
    Ok(())
}