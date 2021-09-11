use uuid::Uuid;

pub mod config;
pub mod context;
pub mod errors;
pub mod time_provider;

#[cfg(feature = "kafka")]
pub mod kafka;


pub fn generate_id() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}