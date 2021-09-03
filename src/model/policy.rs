use chrono::Utc;
use chrono::DateTime;
use crate::grpc::api;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::utils::errors::{ErrorCode, VaultError};
use crate::model::{config::prelude::*, algorithm::{Algorithm, pbkdf2::PBKDF2Policy, argon::ArgonPolicy, bcrypt::BCryptPolicy }};

///
/// In-memory cache of the active policy - held in a map where password_type is the key.
///
pub struct ActivePolicy {
    pub policy: Policy,
    pub activated_on: DateTime<Utc>,
}

///
/// A notification sent between instances of Vault to signify the active policy has changed.
///
#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyActivated {
    pub policy_id: String,
    pub password_type: String,
    pub activated_on: DateTime<Utc>,
}


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Policy {
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
    pub algorithm_type: Algorithm,
    pub argon_policy:  Option<ArgonPolicy>,
    pub bcrypt_policy: Option<BCryptPolicy>,
    pub pbkdf2_policy: Option<PBKDF2Policy>,
    pub prohibited_phrases: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
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
            algorithm_type: Algorithm::PBKDF2,
            // argon_policy: Some(ArgonPolicy::default()),
            argon_policy: None,
            bcrypt_policy: None,
            pbkdf2_policy: Some(PBKDF2Policy::default()),
            prohibited_phrases: vec!(
                "password".to_string(),
                "qwerty".to_string()),
        }
    }
}

impl Policy {
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

    fn argon_policy(&self) -> &ArgonPolicy {
        self.argon_policy.as_ref().unwrap()
    }

    fn bcrypt_policy(&self) -> &BCryptPolicy {
        self.bcrypt_policy.as_ref().unwrap()
    }

    fn pbkdf2_policy(&self) -> &PBKDF2Policy {
        self.pbkdf2_policy.as_ref().unwrap()
    }

    ///
    /// Use the hashing algorithm to hash the password and build a PHC string.
    ///
    /// ref: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    ///
    pub fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError> {
        match self.algorithm_type {
            Algorithm::Argon  => self.argon_policy().hash_into_phc(plain_text_password),
            Algorithm::BCrypt => self.bcrypt_policy().hash_into_phc(plain_text_password),
            Algorithm::PBKDF2 => self.pbkdf2_policy().hash_into_phc(plain_text_password),
        }
    }
}

impl From<Policy> for api::Policy {
    fn from(policy: Policy) -> Self {
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
            algorithm:              match policy.algorithm_type {
                Algorithm::Argon  => Some(api::policy::Algorithm::ArgonPolicy(policy.argon_policy().into())),
                Algorithm::BCrypt => Some(api::policy::Algorithm::BcryptPolicy(policy.bcrypt_policy().into())),
                Algorithm::PBKDF2 => Some(api::policy::Algorithm::Pbkdf2Policy(policy.pbkdf2_policy().into())),
            }
        }
    }
}

impl From<Policy> for Option<api::Policy> {
    fn from(policy: Policy) -> Self {
        Some(policy.into())
    }
}

impl From<api::NewPolicy> for Policy {
    fn from(policy: api::NewPolicy) -> Self {
        Policy {
            policy_id:             String::default(),
            // created_on:            bson::DateTime::from_millis(policy.created_on as i64),
            created_on:            bson::DateTime::now(),
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
            algorithm_type:        policy.algorithm.as_ref().into(),
            argon_policy:          match &policy.algorithm {
                                       Some(argon) => argon.into(),
                                       None        => None,
                                   },
            bcrypt_policy:         match &policy.algorithm {
                                       Some(bcrypt) => bcrypt.into(),
                                       None         => None,
                                   },
            pbkdf2_policy:         match &policy.algorithm {
                                       Some(pbkdf2) => pbkdf2.into(),
                                       None         => None,
                                   },
            prohibited_phrases:    policy.prohibited_phrases,
        }
    }
}

impl From<Option<&api::new_policy::Algorithm>> for Algorithm {
    fn from(alogrithm: Option<&api::new_policy::Algorithm>) -> Self {
        match alogrithm.expect("No algorithm on the policy") { // Validated against in create_policy
            api::new_policy::Algorithm::ArgonPolicy(_)  => Algorithm::Argon,
            api::new_policy::Algorithm::BcryptPolicy(_) => Algorithm::BCrypt,
            api::new_policy::Algorithm::Pbkdf2Policy(_) => Algorithm::PBKDF2,
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pattern_prohibited_phrases() -> Result<(), VaultError> {
        let policy = Policy::default();
        let result = policy.validate_pattern("password123");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::PasswordContainsBannedPhrase,
            "the phrase 'password' is not allowed"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_min_length() -> Result<(), VaultError> {
        let policy = Policy::default();
        let result = policy.validate_pattern("A!1");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::PasswordTooShort,
            "passwords must be at least 8 characters"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_max_length() -> Result<(), VaultError> {
        let policy = Policy::default();
        let result = policy.validate_pattern("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz!£$%^&*()_+-='@;:#~[{]},<.>/?`¬01234567890abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz!£$%^&*()_+-='@;:#~[{]},<.>/?`¬01234567890");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::PasswordTooLong,
            "passwords may not be more than 128 characters"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_repeated() -> Result<(), VaultError> {
        let policy = Policy::default();
        let result = policy.validate_pattern("A!heelllo");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::CharacterRepeatedTooManyTimes,
            "'l' was repeated too many times (2 is the maximum)"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_min_letters() -> Result<(), VaultError> {
        let policy = Policy::default();
        let result = policy.validate_pattern("!123456789");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::NotEnoughLetters,
            "a password must contain at least 1 letters"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_max_letters() -> Result<(), VaultError> {
        let mut policy = Policy::default();
        policy.max_letters = 4;
        let result = policy.validate_pattern("!1abcdefg");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::TooManyLetters,
            "a password must not contain more than 4 letters"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_min_numbers() -> Result<(), VaultError> {
        let policy = Policy::default();
        let result = policy.validate_pattern("!abcdefg");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::NotEnoughNumbers,
            "a password must contain at least 1 numbers"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_max_numbers() -> Result<(), VaultError> {
        let mut policy = Policy::default();
        policy.max_numbers = 5;
        let result = policy.validate_pattern("!a123456789");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::TooManyNumbers,
            "a password must not contain more than 5 numbers"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_min_symbols() -> Result<(), VaultError> {
        let policy = Policy::default();
        let result = policy.validate_pattern("1abcdefg");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::NotEnoughSymbols,
            "a password must contain at least 1 symbols"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_max_symbols() -> Result<(), VaultError> {
        let mut policy = Policy::default();
        policy.max_symbols = 6;
        let result = policy.validate_pattern("!a1!\"£$%^&*()");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::TooManySymbols,
            "a password must not contain more than 6 symbols"));

        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_validate_pattern_mixed_case() -> Result<(), VaultError> {
        let policy = Policy::default();
        let result = policy.validate_pattern("1!abcdefg");
        let expected: Result<(), VaultError> = Err(VaultError::new(
            ErrorCode::NotMixedCase,
            "a password must contain a mixture of upper and lower case"));

        assert_eq!(result, expected);
        Ok(())
    }
}