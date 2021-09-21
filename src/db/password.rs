use mongodb::Database;
use bson::{Document, doc};
use crate::{db::{prelude::*, mongo}, model::password::Password, utils::context::ServiceContext, utils::errors::{ErrorCode, VaultError}};


///
/// Load the requested password from the database.
///
#[tracing::instrument(name="db:load", skip(db))]
pub async fn load(password_id: &str, db: &Database) -> Result<Password, VaultError> {

    let filter = doc!{ PASSWORD_ID: password_id };

    match db.collection::<Password>(PASSWORDS).find_one(filter, None)
        .await
        .map_err(VaultError::from)? {

        Some(password) => Ok(password),
        None => Err(ErrorCode::PasswordNotFound.with_msg("The password requested does not exist"))
    }
}


///
/// Load the requested password from the database - if it exists.
///
#[tracing::instrument(name="db:load_if_present", skip(db))]
pub async fn load_if_present(password_id: &str, db: &Database) -> Result<Option<Password>, VaultError> {

    let filter = doc!{ PASSWORD_ID: password_id };

    db.collection::<Password>(PASSWORDS).find_one(filter, None)
        .await
        .map_err(VaultError::from)
}


///
/// Create or update the password specified.
///
#[tracing::instrument(name="db:upsert", skip(ctx, phc))]
pub async fn upsert(ctx: &ServiceContext, password_id: &str, password_type: &str, phc: &str, max_history: u32)
    -> Result<(), VaultError> {

    let filter = doc! {
        PASSWORD_ID: password_id,
    };

    // Note: The $push below appends the password to the end of history, but only keeps the last x 
    // phcs in the history array.
    let update = doc!{
        "$unset": {
            FAILURE_COUNT: "",
            FIRST_FAILURE: "" ,
            RESET_CODE: "",
            RESET_STARTED_AT: ""
        },
        "$set": {
            PASSWORD_ID: password_id,
            PASSWORD_TYPE: password_type,
            PHC: phc,
            CHANGED_ON: bson::DateTime::from_chrono(ctx.now()),
        },
        "$push": {
            HISTORY: {
                "$each": [ phc ],
                "$slice": -(max_history as i32)
            }
        }
    };

    ctx.db().collection::<Document>(PASSWORDS).update_one(filter, update, mongo::upsert())
        .await
        .map_err(VaultError::from)?;

    Ok(())
}


#[tracing::instrument(name="db:delete", skip(db))]
pub async fn delete(password_id: &str, db: &Database) -> Result<u64, VaultError> {

    let filter = doc! {
        PASSWORD_ID: password_id,
    };

    let result = db.collection::<Document>(PASSWORDS).delete_one(filter, None)
        .await
        .map_err(VaultError::from)?;

    Ok(result.deleted_count)
}


#[tracing::instrument(name="db:delete_by_type", skip(db))]
pub async fn delete_by_type(password_type: &str, db: &Database) -> Result<u64, VaultError> {

    let filter = doc! {
        PASSWORD_TYPE: password_type,
    };

    let result = db.collection::<Document>(PASSWORDS).delete_many(filter, None)
        .await
        .map_err(VaultError::from)?;

    Ok(result.deleted_count)
}


#[tracing::instrument(name="db:store_reset_code", skip(reset_code, ctx))]
pub async fn store_reset_code(password_id: &str, reset_code: &str, ctx: &ServiceContext)
    -> Result<(), VaultError> {

    let filter = doc! {
        PASSWORD_ID: password_id,
    };

    let update = doc!{
        "$set": {
            RESET_CODE: reset_code,
            RESET_STARTED_AT: bson::DateTime::from_chrono(ctx.now()),
        }
    };

    ctx.db().collection::<Document>(PASSWORDS).update_one(filter, update, None)
        .await
        .map_err(VaultError::from)?;

    Ok(())
}

///
/// Bump the failure count and, if not set yet, timestamp the failure date.
///
#[tracing::instrument(name="db:increase_failure_count", skip(ctx, password), fields(password_id=?password.password_id))]
pub async fn increase_failure_count(ctx: &ServiceContext, password: &Password)
    -> Result<(), VaultError> {

    let filter = doc!{ PASSWORD_ID: &password.password_id };

    // Update the failure count and potentially the first_failure timestamp.
    let update = match password.first_failure {
        Some(_) => doc!("$inc": { FAILURE_COUNT: 1 }),
        None => doc!{
            "$inc": { FAILURE_COUNT: 1 },
            "$set": { FIRST_FAILURE: bson::DateTime::from_chrono(ctx.now()) }
        },
    };

    ctx.db().collection::<Document>(PASSWORDS).update_one(filter, update, None)
        .await
        .map_err(VaultError::from)?;

    Ok(())
}

///
/// Clear any failure details and timestamp a successful validate operation.
///
#[tracing::instrument(name="db:record_success", skip(ctx, password), fields(password_id=?password.password_id))]
pub async fn record_success(ctx: &ServiceContext, password: &Password) -> Result<(), VaultError> {

    let filter = doc!{ PASSWORD_ID: &password.password_id };

    // Update the failure count and potentially the first_failure timestamp.
    let update = doc!{
            "$unset": {
                FAILURE_COUNT: "",
                FIRST_FAILURE: "" ,
                RESET_CODE: "",
                RESET_STARTED_AT: ""
            },
            "$set": {
                LAST_SUCCESS: bson::DateTime::from_chrono(ctx.now())
            }
    };

    ctx.db().collection::<Document>(PASSWORDS).update_one(filter, update, None)
        .await
        .map_err(VaultError::from)?;

    Ok(())
}