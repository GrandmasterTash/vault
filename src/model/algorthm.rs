use serde::{Deserialize, Serialize};
use derive_more::{Display};
use std::{str::FromStr};
use rand_core::OsRng;
use std::convert::TryFrom;
use crate::utils::errors::{ErrorCode, VaultError};
use argon2::{Argon2, Version, password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}};

#[derive(Clone, Copy, Debug, Deserialize, Display, Serialize, PartialEq)]
pub enum Algorthm {
    Argon,
    BCrypt,
    PBKDF2,
}

#[derive(Clone, Copy, Debug, Deserialize, Display, Serialize, PartialEq)]
pub enum ArgonHashType {
    ARGON2D,
    ARGON2I,
    ARGON2ID
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArgonPolicyDB {
    pub parallelism: u32,
    pub tag_length: u32,
    pub memory_size_kb: u32,
    pub iterations: u32,
    pub version: u32,
    pub hash_type: ArgonHashType
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BcryptPolicyDB {
    pub version: String,
    pub cost: u32
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PBKDF2PolicyDB {
    pub cost: u32
}

///
/// Validate if the plain_text_password matches the hashed password provided.
///
/// The algorithm is constructed and used from the PHC string provided.
///
pub fn validate(plain_text_password: &str, phc: &str) -> Result<bool, VaultError> {
    match select(phc)? {
        Algorthm::Argon  => validate_argon(phc, plain_text_password),
        Algorthm::BCrypt => todo!(),
        Algorthm::PBKDF2 => todo!(),
    }
}

///
/// Parse the first part of the phc string and return the algorthm.
///
fn select(phc: &str) -> Result<Algorthm, VaultError> {
    let mut split = phc.split("$");
    split.next(); /* Skip first it's blank */

    match split.next() {
        Some(algorthm) => Algorthm::from_str(algorthm),
        None => return Err(ErrorCode::InvalidPHCFormat.with_msg("The PHC is invalid, there's no algorthm")),
    }
}

impl FromStr for Algorthm {
    type Err = VaultError;

    fn from_str(input: &str) -> Result<Algorthm, Self::Err> {
        match input {
            "argon2i" |
            "argon2d" |
            "argon2id" => Ok(Algorthm::Argon),
            _          => Err(ErrorCode::InvalidPHCFormat.with_msg(&format!("algorithm {} is un-handled", input))),
        }
    }
}

pub fn validate_argon(phc: &str, plain_text_password: &str) -> Result<bool, VaultError> {
    let parsed_hash = PasswordHash::new(&phc).unwrap();
    match Argon2::default().verify_password(plain_text_password.as_bytes(), &parsed_hash) {
        Ok(_)  => Ok(true),
        Err(_) => Ok(false),
    }
}

impl Default for ArgonPolicyDB {
    fn default() -> Self {
        ArgonPolicyDB {
            parallelism: 1,
            tag_length: 128,
            memory_size_kb: 1024 * 16,
            iterations: 1,
            version: 19,
            hash_type: ArgonHashType::ARGON2ID
        }
    }
}

impl ArgonPolicyDB {
    pub fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError> {
        let password = plain_text_password.as_bytes();
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::new(
            None /* TODO: pepper */,
            self.iterations,
            self.memory_size_kb,
            self.parallelism,
            Version::try_from(self.version)?)?;

        // Hash password to PHC string ($argon2id$v=19$...)
        Ok(argon2.hash_password_simple(password, salt.as_ref())?.to_string())
    }
}

impl FromStr for ArgonHashType {
    type Err = VaultError;

    fn from_str(input: &str) -> Result<ArgonHashType, Self::Err> {
        match input {
            "argon2i"  => Ok(ArgonHashType::ARGON2I),
            "argon2d"  => Ok(ArgonHashType::ARGON2D),
            "argon2id" => Ok(ArgonHashType::ARGON2ID),
            _          => Err(ErrorCode::UnknownAlgorithmVariant.with_msg(&format!("Unknown argon variant {}", input))),
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_select_argon2id() -> Result<(), VaultError> {
        let phc = "$argon2id$v=19$m=16384,t=20,p=1$77QFGJMDLMwvR7+lYvuNtw$82Byd2enomP62Z01Wcb1g5+KApYhQygW6BEYCXnZj5A";
        assert_eq!(select(phc)?, Algorthm::Argon);
        Ok(())
    }
}