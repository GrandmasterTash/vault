use std::collections::HashMap;
use bson::Document;
use chrono::Utc;
use crate::grpc::api;
use serde::{Deserialize, Serialize};
use mongodb::{Database, bson::doc};
use crate::utils::errors::ErrorCode;
use super::algorthm::{Algorthm, ArgonPolicyDB, BcryptPolicyDB, PBKDF2PolicyDB};
use crate::utils::errors::VaultError;

// Rename the grpc structs to end in API.
// Rename the DB structs to drop the DB bit.

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyDB {
    pub policy_id: String,
    pub created_on: bson::DateTime,
    pub max_history_length: u32,
    pub max_age_days: u32,
    pub min_length: u32,
    pub max_length: u32,
    pub max_character_repeat: u32,
    pub min_letters: u32,
    pub max_letters: u32,
    pub min_numbers: u32,
    pub max_numbers: u32,
    pub min_symbols: u32,
    pub max_symbols: u32,
    pub max_failures: u32,
    pub lockout_seconds: u32,
    pub reset_timeout_seconds: u32,
    pub mixed_case_required: bool,
    pub algorthm_type: Algorthm,
    pub argon_policy: Option<ArgonPolicyDB>,
    pub bcrypt_policy: Option<BcryptPolicyDB>,
    pub pbkdf2_policy: Option<PBKDF2PolicyDB>,
    pub prohibited_phrases: Vec<String>,
}

impl Default for PolicyDB {
    fn default() -> Self {
        PolicyDB {
            policy_id: String::from("DEFAULT"),
            created_on: bson::DateTime::from_chrono(Utc::now()), // TODO: singleton TimeProvider.
            max_history_length: 5,
            max_age_days: 30,
            min_length: 8,
            max_length: 128,
            max_character_repeat: 2,
            min_letters: 1,
            max_letters: 128,
            min_numbers: 1,
            max_numbers: 128,
            min_symbols: 1,
            max_symbols: 128,
            max_failures: 3,
            lockout_seconds: 60,
            reset_timeout_seconds: 5 * 60,
            mixed_case_required: true,
            algorthm_type: Algorthm::Argon,
            argon_policy: Some(ArgonPolicyDB::default()),
            bcrypt_policy: None,
            pbkdf2_policy: None,
            prohibited_phrases: vec!(
                "password".to_string(),
                "qwerty".to_string()),
        }
    }
}

impl PolicyDB {
    // TODO: Move these load methods out of here - to where they are called from.
    #[cfg(feature = "kafka")]
    pub async fn load(policy_id: &str, db: Database) -> Result<Self, VaultError> {
        match db.collection::<PolicyDB>("Policies").find_one(doc!{ "policy_id": policy_id }, None).await? {
            Some(policy) => Ok(policy),
            None => return Err(ErrorCode::PolicyNotFound.with_msg(&format!("The policy {} does not exist", policy_id))),
        }
    }

    ///
    /// Using the Config singleton document in the database, load and return the current active password policy.
    ///
    pub async fn load_active(db: Database) -> Result<Self, VaultError> {
        let config = db.collection::<Document>("Config").find_one(doc!{ "config_id": "SINGLETON" }, None).await?;
        let active_policy_id = match &config {
            Some(config) => config.get_str("active_policy_id")?,
            None => return Err(ErrorCode::ConfigDocumentNotFound.with_msg("The config document was not found")),
        };

        match db.collection::<PolicyDB>("Policies").find_one(doc!{ "policy_id": active_policy_id }, None).await? {
            Some(policy) => Ok(policy),
            None => return Err(ErrorCode::ActivePolicyNotFound.with_msg(&format!("The configured active policy '{}' was not found", active_policy_id))),
        }
    }

    ///
    /// Check the plain text password doesn't violate this policies format.
    ///
    /// The history of the password is not validated. This must be done seperately.
    ///
    pub fn validate_pattern(&self, plain_text_password: &str) -> Result<(), VaultError> {

        for phrase in &self.prohibited_phrases {
            if plain_text_password.contains(phrase.as_str()) {
                return Err(ErrorCode::PasswordContainsBannedPhrase
                    .with_msg(&format!("the phrase '{}' is not allowed", phrase)))
            }
        }

        if plain_text_password.len() < self.min_length as usize {
            return Err(ErrorCode::PasswordTooShort
                .with_msg(&format!("passwords must be at least {} characters", self.min_length)
            ))
        }

        if plain_text_password.len() > self.max_length as usize {
            return Err(ErrorCode::PasswordTooLong
                .with_msg(&format!("passwords may not be more than {} characters", self.max_length)
            ))
        }

        let character_counts: HashMap<char, u32> = plain_text_password
            .chars()
            .fold(HashMap::new(), |mut map, c| {
                *map.entry(c).or_insert(0) += 1;
                map
            });

        if let Some(entry) = character_counts
            .iter()
            .find(|(_k,&v)|v > self.max_character_repeat) {
            return Err(ErrorCode::CharacterRepeatedTooManyTimes
                .with_msg(&format!("'{}' was repeated too many times ({} is the maximum)", entry.0, self.max_character_repeat)
            ))
        }

        let letters = plain_text_password
            .chars()
            .filter(|c| c.is_alphabetic())
            .count();

        if letters < self.min_letters as usize {
            return Err(ErrorCode::NotEnoughLetters.
                with_msg(&format!("a password must contain at least {} letters", self.min_letters)))
        }

        if letters > self.max_letters as usize {
            return Err(ErrorCode::TooManyLetters
                .with_msg(&format!("a password must not contain more than {} letters", self.max_letters)))
        }

        let numbers = plain_text_password
            .chars()
            .filter(|c| c.is_numeric())
            .count();

        if numbers < self.min_numbers as usize {
            return Err(ErrorCode::NotEnoughNumbers
                .with_msg(&format!("a password must contain at least {} numbers", self.min_numbers)))
        }

        if numbers > self.max_numbers as usize {
            return Err(ErrorCode::TooManyNumbers
                .with_msg(&format!("a password must not contain more than {} numbers", self.max_numbers)))
        }

        let symbols = plain_text_password
            .chars()
            .filter(|c| !c.is_alphanumeric())
            .count();

        if symbols < self.min_symbols as usize {
            return Err(ErrorCode::NotEnoughSymbols
                .with_msg(&format!("a password must contain at least {} symbols", self.min_symbols)))
        }

        if symbols > self.max_symbols as usize {
            return Err(ErrorCode::TooManySymbols
                .with_msg(&format!("a password must not contain more than {} symbols", self.max_symbols)))
        }

        if self.mixed_case_required {
            if !plain_text_password.chars().any(|c| c.is_lowercase())
                || !plain_text_password.chars().any(|c| c.is_uppercase()) {

                return Err(ErrorCode::NotMixedCase
                    .with_msg("a password must contain a mixture of upper and lower case"))
            }
        }

        Ok(())
    }

    fn argon_policy(&self) -> &ArgonPolicyDB {
        self.argon_policy.as_ref().unwrap()
    }

    // fn bcrypt_policy(&self) -> &BcryptPolicyDB {
    //     self.bcrypt_policy.as_ref().unwrap()
    // }

    // fn pbkdf2_policy(&self) -> &PBKDF2PolicyDB {
    //     self.pbkdf2_policy.as_ref().unwrap()
    // }

    ///
    /// Use the hashing algorthm to hash the password and build a PHC string.
    ///
    /// ref: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    ///
    pub fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError> {
        match self.algorthm_type {
            Algorthm::Argon  => self.argon_policy().hash_into_phc(plain_text_password),
            Algorthm::BCrypt => todo!(),
            Algorthm::PBKDF2 => todo!(),
        }
    }
}

// TODO: impl From<grpc::Policy> for PolicyDB

impl From<api::Policy> for bson::Document {
    fn from(policy: api::Policy) -> Self {
        let mut doc = doc!{
            "max_history_length": policy.max_history_length,
            "max_age_days": policy.max_age_days,
            "min_length": policy.min_length,
            "max_length": policy.max_length,
            "max_character_repeat": policy.max_character_repeat,
            "min_letters": policy.min_letters,
            "max_letters": policy.max_letters,
            "min_numbers": policy.min_numbers,
            "max_numbers": policy.max_numbers,
            "min_symbols": policy.min_symbols,
            "max_symbols": policy.max_symbols,
            "mixed_case_required": policy.mixed_case_required,
            "max_failures": policy.max_failures,
            "lockout_seconds": policy.lockout_seconds,
            "reset_timeout_seconds": policy.reset_timeout_seconds,
            "prohibited_phrases": policy.prohibited_phrases,
        };

        if let Some(algorthm) = policy.algorthm {
            match &algorthm {
                api::policy::Algorthm::ArgonPolicy(algorthm)  => {
                    doc.insert("algorthm_type", Algorthm::Argon.to_string());
                    doc.insert("argon_policy",
                        doc!{
                            "parallelism": algorthm.parallelism,
                            "tag_length": algorthm.tag_length,
                            "memory_size_kb": algorthm.memory_size_kb,
                            "iterations": algorthm.iterations,
                            "version": algorthm.version,
                            "hash_type": algorthm.hash_type
                        });
                },
                api::policy::Algorthm::BcyrptPolicy(algorthm) => {
                    doc.insert("algorthm_type", Algorthm::BCrypt.to_string());
                    doc.insert("bcrypt_policy",
                        doc!{
                            "version": algorthm.version.clone(),
                            "cost": algorthm.cost
                        });
                },
                api::policy::Algorthm::Pbkfd2Policy(algorthm) => {
                    doc.insert("algorthm_type", Algorthm::PBKDF2.to_string());
                    doc.insert("pbkfd2_policy",
                        doc!{
                            "cost": algorthm.cost
                        });
                }
            }
        }

        doc
    }
}