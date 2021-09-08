use std::fs;
use uuid::Uuid;
use serde::Serialize;
use tracing::{debug, info};
use mongodb::error::ErrorKind;
use crate::model::config::Config;
use crate::model::policy::Policy;
use crate::utils::errors::ErrorCode;
use crate::utils::errors::VaultError;
use crate::utils::config::Configuration;
use mongodb::{Client, Database, bson::{self, Document, doc}, options::{ClientOptions, UpdateOptions}};

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
        { "key": { "password_id": 1 }, "name": "idx_password_id", "unique": true },
        { "key": { "password_type": 1 }, "name": "idx_password_type", "unique": false }] }, None).await?;
    db.run_command(doc! { "createIndexes": "Policies", "indexes": [{ "key": { "policy_id": 1 }, "name": "idx_policy_id", "unique": true }] }, None).await?;
    db.run_command(doc! { "createIndexes": "Config",   "indexes": [{ "key": { "password_type": 1 }, "name": "idx_password_type", "unique": true }] }, None).await?;

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

    let uri = match &config.mongo_credentials {
        Some(filename) => {
            debug!("Loading MongoDB credentials from secrets file {}", filename);

            // Read username and password from a secrets file.
            let credentials = fs::read_to_string(filename)
                .map_err(|err| VaultError::new(ErrorCode::UnableToReadCredentials, &format!("Unable to read credentials from {}: {}", filename, err)))?;
            let mut credentials = credentials.lines();
            let uri = config.mongo_uri.replace("$USERNAME", credentials.next().unwrap_or_default());
            uri.replace("$PASSWORD", credentials.next().unwrap_or_default())
        },
        None => config.mongo_uri.clone(),
    };

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

// TODO: Move to a utils module
pub fn generate_id() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

pub trait Persistable<T: Serialize> {
    ///
    /// Convert into a MongoDB BSON document.
    ///
    fn to_doc(&self) -> Result<Document, VaultError>;
}

impl<T: Serialize> Persistable<T> for T {
    fn to_doc(&self) -> Result<Document, VaultError> {
        let bson = bson::to_bson(self)
            .map_err(|err| VaultError::new(ErrorCode::InvalidBSON, &format!("Failed to serialise BSON: {}", err)))?;

        match bson.as_document() {
            Some(doc) => Ok(doc.to_owned()),
            None => Err(VaultError::new(ErrorCode::InvalidBSON, &format!("Result is empty Document")))
        }
    }
}


pub fn upsert() -> UpdateOptions {
    UpdateOptions::builder().upsert(true).build()
}