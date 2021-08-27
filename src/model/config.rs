use chrono::Utc;
use serde::{Deserialize, Serialize};
use self::prelude::*;

// This ensures only one persisted document exists.
pub mod prelude {
    pub const SINGLETON: &str = "SINGLETON";   // TODO: Drop this when pwd-groups are added? Have a config per group.
    pub const DEFAULT:   &str = "DEFAULT";

    pub const CONFIG_ID:        &str = "config_id";
    pub const ACTIVATED_ON:     &str = "activated_on";
    pub const ACTIVE_POLICY_ID: &str = "active_policy_id";
}

///
/// Represent the persisted configuration in MongoDB - not to be confused with
/// The service's config populated from the environment variables at start-up.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    config_id: String,            // Always 'SINGLETON' TODO: Until we have password groups/types.
    pub active_policy_id: String,
    pub activated_on: bson::DateTime
}


impl Default for Config {
    fn default() -> Self {
        Self {
            config_id: SINGLETON.to_string(),
            active_policy_id: DEFAULT.to_string(),
            activated_on: Utc::now().into()
        }
    }
}