use chrono::Utc;
use chrono::DateTime;
use crate::grpc::api;
use std::collections::HashMap;
use crate::model::config::Config;
use mongodb::{Database, bson::doc};
use super::algorthm::ArgonHashType;
use serde::{Deserialize, Serialize};
use crate::model::config::prelude::*;
use crate::utils::errors::{ErrorCode, VaultError};
use crate::services::context::{ActivePolicy, ServiceContext};
use super::algorthm::{Algorthm, ArgonPolicyDB, BcryptPolicyDB, PBKDF2PolicyDB};

///
/// A notification sent between instances of Vault to signify the active policy has changed.
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyActivated {
    pub policy_id: String,
    pub activated_on: DateTime<Utc>,
}

// TODO: Rename the DB structs to drop the DB bit.

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
    pub argon_policy:  Option<ArgonPolicyDB>,
    pub bcrypt_policy: Option<BcryptPolicyDB>,
    pub pbkdf2_policy: Option<PBKDF2PolicyDB>,
    pub prohibited_phrases: Vec<String>,
}

impl Default for PolicyDB {
    fn default() -> Self {
        PolicyDB {
            policy_id: DEFAULT.to_string(),
            created_on: bson::DateTime::from_chrono(Utc::now()),
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

impl From<PolicyDB> for api::Policy {
    fn from(policy: PolicyDB) -> Self {
        api::Policy {
            policy_id:             policy.policy_id.clone(),
            created_on:            policy.created_on.timestamp_millis() as u64,
            max_history_length:    policy.max_history_length,
            max_age_days:          policy.max_age_days,
            min_length:            policy.min_length,
            max_length:            policy.max_length,
            max_character_repeat:  policy.max_character_repeat,
            min_letters:           policy.min_letters,
            max_letters:           policy.max_letters,
            min_numbers:           policy.min_numbers,
            max_numbers:           policy.max_numbers,
            min_symbols:           policy.min_symbols,
            max_symbols:           policy.max_symbols,
            max_failures:          policy.max_failures,
            lockout_seconds:       policy.lockout_seconds,
            mixed_case_required:   policy.mixed_case_required,
            reset_timeout_seconds: policy.reset_timeout_seconds,
            prohibited_phrases:    policy.prohibited_phrases.iter().cloned().collect(),
            algorthm:              match policy.algorthm_type {
                Algorthm::Argon => Some(api::policy::Algorthm::ArgonPolicy(api::ArgonPolicy {
                    parallelism:    policy.argon_policy().parallelism,
                    tag_length:     policy.argon_policy().tag_length,
                    memory_size_kb: policy.argon_policy().memory_size_kb,
                    iterations:     policy.argon_policy().iterations,
                    version:        policy.argon_policy().version,
                    hash_type:      match policy.argon_policy().hash_type {
                        ArgonHashType::ARGON2D  => 0,
                        ArgonHashType::ARGON2I  => 1,
                        ArgonHashType::ARGON2ID => 2,
                    },
                })),
                Algorthm::BCrypt => todo!(),
                Algorthm::PBKDF2 => todo!(),
            }
        }
    }
}

impl From<PolicyDB> for Option<api::Policy> {
    fn from(policy: PolicyDB) -> Self {
        Some(policy.into())
    }
}

impl From<api::Policy> for PolicyDB {
    fn from(policy: api::Policy) -> Self {
        PolicyDB {
            policy_id:             policy.policy_id,
            created_on:            bson::DateTime::from_millis(policy.created_on as i64),
            max_history_length:    policy.max_history_length,
            max_age_days:          policy.max_age_days,
            min_length:            policy.min_length,
            max_length:            policy.max_length,
            max_character_repeat:  policy.max_character_repeat,
            min_letters:           policy.min_letters,
            max_letters:           policy.max_letters,
            min_numbers:           policy.min_numbers,
            max_numbers:           policy.max_numbers,
            min_symbols:           policy.min_symbols,
            max_symbols:           policy.max_symbols,
            max_failures:          policy.max_failures,
            lockout_seconds:       policy.lockout_seconds,
            reset_timeout_seconds: policy.reset_timeout_seconds,
            mixed_case_required:   policy.mixed_case_required,
            algorthm_type:         policy.algorthm.as_ref().into(),
            argon_policy:          match &policy.algorthm {
                                       Some(argon) => argon.into(),
                                       None        => None,
                                   },
            bcrypt_policy:         match &policy.algorthm {
                                       Some(bcrypt) => bcrypt.into(),
                                       None         => None,
                                   },
            pbkdf2_policy:         match &policy.algorthm {
                                       Some(pbkdf2) => pbkdf2.into(),
                                       None         => None,
                                   },
            prohibited_phrases:    policy.prohibited_phrases,
        }
    }
}

impl From<Option<&api::policy::Algorthm>> for Algorthm {
    fn from(alogrithm: Option<&api::policy::Algorthm>) -> Self {
        match alogrithm.expect("No algorithm on the policy") { // Validated against in create_policy
            api::policy::Algorthm::ArgonPolicy(_)  => Algorthm::Argon,
            api::policy::Algorthm::BcyrptPolicy(_) => Algorthm::BCrypt,
            api::policy::Algorthm::Pbkfd2Policy(_) => Algorthm::PBKDF2,
        }
    }
}

impl From<&api::policy::Algorthm> for Option<ArgonPolicyDB> {
    fn from(alogrithm: &api::policy::Algorthm) -> Self {
        match alogrithm {
            api::policy::Algorthm::ArgonPolicy(argon) => {
                Some(ArgonPolicyDB{
                    parallelism:    argon.parallelism,
                    tag_length:     argon.tag_length,
                    memory_size_kb: argon.memory_size_kb,
                    iterations:     argon.iterations,
                    version:        argon.version,
                    hash_type:      match argon.hash_type {
                        0 => ArgonHashType::ARGON2D,
                        1 => ArgonHashType::ARGON2I,
                        2 => ArgonHashType::ARGON2ID,
                        unknown @ _ => panic!("Unhandled protobuf argon hash_type {}", unknown)
                    },
                })
            },
            api::policy::Algorthm::BcyrptPolicy(_) => None,
            api::policy::Algorthm::Pbkfd2Policy(_) => None,
        }
    }
}

impl From<&api::policy::Algorthm> for Option<BcryptPolicyDB> {
    fn from(alogrithm: &api::policy::Algorthm) -> Self {
        match alogrithm {
            api::policy::Algorthm::ArgonPolicy(_)  => None,
            api::policy::Algorthm::BcyrptPolicy(bcrypt) => {
                Some(BcryptPolicyDB {
                    version: bcrypt.version.clone(),
                    cost:    bcrypt.cost,
                })
            },
            api::policy::Algorthm::Pbkfd2Policy(_) => None,
        }
    }
}

impl From<&api::policy::Algorthm> for Option<PBKDF2PolicyDB> {
    fn from(alogrithm: &api::policy::Algorthm) -> Self {
        match alogrithm {
            api::policy::Algorthm::ArgonPolicy(_)  => None,
            api::policy::Algorthm::BcyrptPolicy(_) => None,
            api::policy::Algorthm::Pbkfd2Policy(pbkfd2) => Some(PBKDF2PolicyDB { cost: pbkfd2.cost }),
        }
    }
}


#[cfg(feature = "kafka")] // TODO: This cfg is temp
pub async fn load(policy_id: &str, ctx: &ServiceContext) -> Result<PolicyDB, VaultError> {
    let result = ctx.db()
        .collection::<PolicyDB>("Policies")
        .find_one(doc!{ "policy_id": policy_id }, None)
        .await?;

    match result {
        Some(policy) => Ok(policy),
        None => return Err(ErrorCode::PolicyNotFound.with_msg(&format!("The policy {} does not exist", policy_id))),
    }
}


///
/// Using the Config singleton document in the database, load and return the current active password policy.
///
pub async fn load_active(db: &Database) -> Result<ActivePolicy, VaultError> {
    tracing::info!("Loading current config...");

    let config = db.collection::<Config>("Config")
        .find_one(doc!{ "config_id": SINGLETON }, None)
        .await?
        .expect("Unable to load the configuration from the database");

    tracing::info!("Loading active policy...");

    let active_policy_id = &config.active_policy_id;
    let result = db.collection::<PolicyDB>("Policies")
        .find_one(doc!{ "policy_id": active_policy_id }, None).await?;

    tracing::info!("Loaded active policy");

    match result {
        Some(policy) => Ok(ActivePolicy { policy, activated_on: config.activated_on.into() }),

        None => return Err(ErrorCode::ActivePolicyNotFound
            .with_msg(&format!("The configured active policy '{}' was not found", active_policy_id))),
    }
}