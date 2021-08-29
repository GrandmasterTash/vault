pub mod argon;
pub mod bcrypt;
pub mod pbkdf2;

use std::str::FromStr;
use derive_more::Display;
use serde::{Deserialize, Serialize};
use crate::utils::errors::{ErrorCode, VaultError};

#[derive(Clone, Copy, Debug, Deserialize, Display, Serialize, PartialEq)]
pub enum Algorithm {
    Argon,
    BCrypt,
    PBKDF2,
}


///
/// Validate if the plain_text_password matches the hashed password provided.
///
/// The algorithm is constructed and used from the PHC string provided.
///
pub fn validate(plain_text_password: &str, phc: &str) -> Result<bool, VaultError> {
    match select(phc)? {
        Algorithm::Argon  => argon::validate(phc, plain_text_password),
        Algorithm::BCrypt => bcrypt::validate(phc, plain_text_password),
        Algorithm::PBKDF2 => pbkdf2::validate(phc, plain_text_password),
    }
}

///
/// Parse the first part of the phc string and return the algorithm.
///
fn select(phc: &str) -> Result<Algorithm, VaultError> {
    let mut split = phc.split("$");
    split.next(); /* Skip first it's blank */

    match split.next() {
        Some(algorithm) => Algorithm::from_str(algorithm),
        None => return Err(ErrorCode::InvalidPHCFormat.with_msg("The PHC is invalid, there's no algorithm")),
    }
}

impl FromStr for Algorithm {
    type Err = VaultError;

    fn from_str(input: &str) -> Result<Algorithm, Self::Err> {
        match input {
            "argon2i"  |
            "argon2d"  |
            "argon2id" => Ok(Algorithm::Argon),

            "2a" |
            "2b" |
            "2x" |
            "2y" => Ok(Algorithm::BCrypt),

            "pbkdf2-sha256" => Ok(Algorithm::PBKDF2),

            _ => Err(ErrorCode::InvalidPHCFormat.with_msg(&format!("algorithm {} is un-handled", input))),
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
        assert_eq!(select(phc)?, Algorithm::Argon);
        Ok(())
    }

    // TODO: Lots more unit tests please!
}