use chrono::Utc;
use serde::{Deserialize, Serialize};
use self::prelude::*;

// This ensures only one persisted document exists.
pub mod prelude {
    // TODO: move default to model.mod
    pub const DEFAULT:   &str = "DEFAULT";

    // TODO: Move these to db.mod
    pub const PASSWORD_TYPE:    &str = "password_type";
    pub const ACTIVATED_ON:     &str = "activated_on";
    pub const ACTIVE_POLICY_ID: &str = "active_policy_id";
}

///
/// Represent the persisted configuration in MongoDB - not to be confused with
/// The service's config populated from the environment variables at start-up.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    // config_id: String,            // Always 'SINGLETON' TODO: Until we have password groups/types.
    pub password_type: String, // Unique identifier.
    pub active_policy_id: String,
    pub activated_on: bson::DateTime
}


impl Default for Config {
    fn default() -> Self {
        Self {
            password_type: DEFAULT.to_string(),
            active_policy_id: DEFAULT.to_string(),
            activated_on: Utc::now().into()
        }
    }
}