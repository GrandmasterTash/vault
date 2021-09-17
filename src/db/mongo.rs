use std::fs;
use tracing::info;
use crate::db::prelude::*;
use mongodb::error::ErrorKind;
use crate::model::config::Config;
use crate::model::policy::Policy;
use crate::utils::errors::ErrorCode;
use crate::utils::errors::VaultError;
use crate::utils::config::Configuration;
use mongodb::{Client, Database, bson::{Document, doc}, options::{ClientOptions, UpdateOptions}};

///
/// Run any schema-like updates against MongoDB that haven't been run yet.
///
pub async fn update_mongo(db: &Database) -> Result<(), VaultError> {
    create_init_indexes(db).await?;
    create_default_policy(db).await?;
    create_default_config(db).await?;
    Ok(())
}

async fn create_init_indexes(db: &Database) -> Result<(), VaultError> {
    // Note: the current driver doesn't yet support creating indexes on collections, so the dbcommand must be used instead.
    // https://docs.mongodb.com/manual/reference/command/createIndexes/#createindexes

    db.run_command(doc! { "createIndexes": "Passwords", "indexes": [
        { "key": { PASSWORD_ID: 1 }, "name": "idx_password_id", "unique": true },
        { "key": { PASSWORD_TYPE: 1 }, "name": "idx_password_type", "unique": false }] }, None).await?;
    db.run_command(doc! { "createIndexes": POLICIES, "indexes": [{ "key": { POLICY_ID: 1 }, "name": "idx_policy_id", "unique": true }] }, None).await?;
    db.run_command(doc! { "createIndexes": CONFIG,   "indexes": [{ "key": { PASSWORD_TYPE: 1 }, "name": "idx_password_type", "unique": true }] }, None).await?;

    Ok(())
}

///
/// Create a policy with an id of DEFAULT.
///
async fn create_default_policy(db: &Database) -> Result<(), VaultError> {
    let result = db.collection::<Policy>("Policies")
        .insert_one(Policy::default(), None).await;

    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            match is_duplicate_err(&err) {
                true  => Ok(()),
                false => Err(VaultError::from(err)),
            }
        },
    }
}

///
/// Indicates if the MongoDB error is from a duplicate key violation.
///
pub fn is_duplicate_err(err: &mongodb::error::Error) -> bool {
    let ec = err.clone();
    match *ec.kind {
        ErrorKind::Write(sub_err) => match sub_err {
            mongodb::error::WriteFailure::WriteError(we) => {
                if we.code == 11000 /* Duplicate insert */ {
                    return true
                }

                false
            },
            _ => false,
        },
        _ => return false
    }
}

///
/// Create the default config document IF IT DOESN'T EXIST.
///
async fn create_default_config(db: &Database) -> Result<(), VaultError> {
    let _ignored = db.collection::<Config>("Config")
        .insert_one(Config::default(), None).await;
    Ok(())
}


pub async fn get_mongo_db(app_name: &str, config: &Configuration) -> Result<Database, VaultError> {

    // Read username and password from a secrets file.
    let username = fs::read_to_string("secrets/mongodb_username")
        .map_err(|err| ErrorCode::UnableToReadCredentials
            .with_msg(&format!("Unable to read credentials from secrets/mongodb_username: {}", err)))?;

    let password = fs::read_to_string("secrets/mongodb_password")
        .map_err(|err| ErrorCode::UnableToReadCredentials
            .with_msg(&format!("Unable to read credentials from secrets/mongodb_password: {}", err)))?;

    let uri = config.mongo_uri.replace("$USERNAME", &username).replace("$PASSWORD", &password);

    // Parse the uri now.
    let mut client_options = ClientOptions::parse(&uri).await?;

    // Manually set an option.
    client_options.app_name = Some(app_name.to_string());

    // Get a handle to the deployment.
    let client = Client::with_options(client_options)?;

    info!("Connecting to MongoDB...");

    let db = client.database(&config.db_name);
    ping(&db).await?;

    info!("Connected to MongoDB");
    Ok(db)
}


pub async fn ping(db: &Database) -> Result<Document, VaultError> {
    Ok(db.run_command(doc! { "ping": 1 }, None).await?)
}


pub fn upsert() -> UpdateOptions {
    UpdateOptions::builder().upsert(true).build()
}