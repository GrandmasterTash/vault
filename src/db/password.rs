use mongodb::Database;
use bson::{Document, doc};
use crate::{db::mongo, model::password::Password, utils::context::ServiceContext, utils::errors::{ErrorCode, VaultError}};


///
/// Load the requested password from the database.
///
#[tracing::instrument(skip(db))]
pub async fn load(password_id: &str, db: &Database) -> Result<Password, VaultError> {

    let filter = doc!{ "password_id": password_id };

    match db.collection::<Password>("Passwords").find_one(filter, None)
        .await
        .map_err(|e| VaultError::from(e))? {

        Some(password) => Ok(password),
        None => Err(ErrorCode::PasswordNotFound.with_msg("The password requested does not exist").into())
    }
}


///
/// Create or update the password specified.
///
#[tracing::instrument(skip(ctx, phc))]
pub async fn upsert(ctx: &ServiceContext, password_id: &str, password_type: &str, phc: &str) -> Result<(), VaultError> {
    let filter = doc! {
        "password_id": password_id,
    };

    let update = doc!{
        "$set": {
            "password_id": password_id,
            "password_type": password_type,
            "phc": phc,
            "changed_on": bson::DateTime::from_chrono(ctx.now()),
        }
    };

    ctx.db().collection::<Document>("Passwords").update_one(filter, update, mongo::upsert())
        .await
        .map_err(|e| VaultError::from(e))?;

    Ok(())
}

///
/// Bump the failure count and, if not set yet, timestamp the failure date.
///
#[tracing::instrument(skip(ctx, password), fields(password_id=?password.password_id))]
pub async fn increase_failure_count(ctx: &ServiceContext, password: &Password) -> Result<(), VaultError> {

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
#[tracing::instrument(skip(ctx, password), fields(password_id=?password.password_id))]
pub async fn clear_failure_details(ctx: &ServiceContext, password: &Password) -> Result<(), VaultError> {

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