use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasswordDB {
    pub password_id: String,
    pub phc: String,
    pub changed_on: bson::DateTime,
    pub last_success: Option<bson::DateTime>,
    pub first_failure: Option<bson::DateTime>,
    pub failure_count: Option<u32>,
    pub reset_code: Option<String>,
    pub reset_started_at: Option<bson::DateTime>,
    pub history: Option<Vec<String>>,
}