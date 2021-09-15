use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

///
/// A notification sent between instances of Vault to signify the active policy has changed.
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyActivated {
    pub policy_id: String,
    pub password_type: String,
    pub activated_on: DateTime<Utc>,
}

///
/// A notification sent between instances of Vault when a password type is removed.
///
/// This is a deletion of the configuration for that type (active policy) and any
/// associated passwords using that type.
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordTypeDeleted {
    pub password_type: String
}

///
/// A notification indicating a specific password has been deleted or all passwords
/// with a given type have been deleted (latter is not the same as the PasswordTypeDeleted
/// notification which also includes the config for the type).
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordDeleted {
    pub password_id: Option<String>,
    pub password_type: Option<String>
}

///
/// A notification sent when a new or existing password has been hashed.
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordHashed {
    pub password_id: String
}

///
/// A notification sent when a password has successfully been verified.
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordVerified {
    pub password_id: String
}

///
/// A notification sent when a password has failed to be verified x times, where
/// x is the policies maximum attempts.
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordAttemptsExceeded {
    pub password_id: String
}

///
/// A notification sent when phase 1/2 of the reset process is completed.
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordResetStarted {
    pub password_id: String
}

///
/// A notification sent when phase 2/2 of the reset process is completed.
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordResetCompleted {
    pub password_id: String
}