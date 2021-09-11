use chrono::Utc;
use crate::db::prelude::*;
use serde::{Deserialize, Serialize};


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