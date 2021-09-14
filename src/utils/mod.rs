use uuid::Uuid;

pub mod config;
pub mod context;
pub mod errors;
pub mod health;
pub mod kafka;
pub mod time_provider;


pub fn generate_id() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}