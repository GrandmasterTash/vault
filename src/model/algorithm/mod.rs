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
/// Use the phc values from an old password to hash the new password into a new phc.
///
pub fn rehash(plain_text_password: &str, phc: &str) -> Result<String, VaultError> {
    match select(phc)? {
        Algorithm::Argon  => argon::rehash_using_phc(phc, plain_text_password),
        Algorithm::BCrypt => bcrypt::rehash_using_phc(phc, plain_text_password),
        Algorithm::PBKDF2 => pbkdf2::rehash_using_phc(phc, plain_text_password),
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

            "pbkdf2-sha256" |
            "pbkdf2-sha512" => Ok(Algorithm::PBKDF2),

            _ => Err(ErrorCode::InvalidPHCFormat.with_msg(&format!("algorithm {} is un-handled", input))),
        }
    }
}


#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_select_returns_argon_from_phc() -> Result<(), VaultError> {
        let phc = "$argon2i$v=19$m=16384,t=20,p=1$77QFGJMDLMwvR7+lYvuNtw$82Byd2enomP62Z01Wcb1g5+KApYhQygW6BEYCXnZj5A";
        assert_eq!(select(phc)?, Algorithm::Argon);

        let phc = "$argon2d$v=19$m=16384,t=20,p=1$77QFGJMDLMwvR7+lYvuNtw$82Byd2enomP62Z01Wcb1g5+KApYhQygW6BEYCXnZj5A";
        assert_eq!(select(phc)?, Algorithm::Argon);

        let phc = "$argon2id$v=19$m=16384,t=20,p=1$77QFGJMDLMwvR7+lYvuNtw$82Byd2enomP62Z01Wcb1g5+KApYhQygW6BEYCXnZj5A";
        assert_eq!(select(phc)?, Algorithm::Argon);
        Ok(())
    }

    #[test]
    fn test_select_returns_bcrypt_from_phc() -> Result<(), VaultError> {
        let phc = "$2a$04$W0DIaTXVQSS2XED2bjStKO7AazXOlO.eC6/q.3VDhs0n5.xIOlSCS";
        assert_eq!(select(phc)?, Algorithm::BCrypt);

        let phc = "$2b$04$W0DIaTXVQSS2XED2bjStKO7AazXOlO.eC6/q.3VDhs0n5.xIOlSCS";
        assert_eq!(select(phc)?, Algorithm::BCrypt);

        let phc = "$2x$04$W0DIaTXVQSS2XED2bjStKO7AazXOlO.eC6/q.3VDhs0n5.xIOlSCS";
        assert_eq!(select(phc)?, Algorithm::BCrypt);

        let phc = "$2y$04$W0DIaTXVQSS2XED2bjStKO7AazXOlO.eC6/q.3VDhs0n5.xIOlSCS";
        assert_eq!(select(phc)?, Algorithm::BCrypt);
        Ok(())
    }

    #[test]
    fn test_select_returns_pbkdf2_from_phc() -> Result<(), VaultError> {
        let phc = "$pbkdf2-sha256$i=4,l=16$FE+25Z4NMtEnKEOnNSHZEw$jrsU6A1tBrv09TwFoVNJEg";
        assert_eq!(select(phc)?, Algorithm::PBKDF2);
        Ok(())
    }

    #[test]
    fn test_select_returns_error_from_invalid_phc() -> Result<(), VaultError> {
        let phc = "$wobble$i=4,l=16$FE+25Z4NMtEnKEOnNSHZEw$jrsU6A1tBrv09TwFoVNJEg";
        let result = select(phc);
        let error = result.err().unwrap();
        assert_eq!(error.error_code(), ErrorCode::InvalidPHCFormat);
        Ok(())
    }
}