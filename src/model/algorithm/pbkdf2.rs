use pbkdf2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, Salt};
use pbkdf2::{Pbkdf2, password_hash::SaltString};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use crate::{grpc::api, utils::errors::VaultError};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PBKDF2Policy {
    pub cost: u32,

    // TODO: We can also use sha256 or sha512 variants.
    pub output_len: u32, // Hash output length in bytes
}

impl Default for PBKDF2Policy {
    fn default() -> Self {
        Self {
            cost: 1, // Do not use this in production unless you want to be brute forced.,
            output_len: 32,
        }
    }
}


pub fn validate(phc: &str, plain_text_password: &str) -> Result<bool, VaultError> {
    let parsed_hash = PasswordHash::new(&phc)?;
    Ok(Pbkdf2.verify_password(plain_text_password.as_bytes(), &parsed_hash).is_ok())
}


pub fn hash_into_phc(pbkdf2: &PBKDF2Policy, plain_text_password: &str) -> Result<String, VaultError> {
    // TODO: A pepper.
    let salt = SaltString::generate(&mut OsRng);
    let salt = Salt::new(salt.as_str()).unwrap();
    let params = pbkdf2::Params {
        rounds: pbkdf2.cost,
        output_length: pbkdf2.output_len as usize,
    };

    // Hash password to PHC string ($pbkdf2-sha256$...)
    Ok(Pbkdf2.hash_password_customized(
        plain_text_password.as_bytes(),
        None,
        None,
        params,
        salt)?.to_string())
}


///
/// Take a pre-existing phc string, and use all the values to hash a different plain-text password
/// to produce a new phc. Typically this can be used to compare new passwords against old password
/// history to detect duplicates.
///
pub fn rehash_using_phc(phc: &str, plain_text_password: &str) -> Result<String, VaultError> {
    let parsed_hash = PasswordHash::new(&phc)?;

    let params = pbkdf2::Params {
        rounds: parsed_hash.params.get("i").expect("No rounds in phc").decimal().expect("rounds in phc was not numeric"),
        output_length: parsed_hash.params.get("l").expect("No output length in phc").decimal().expect("output length in phc was not numeric") as usize,
    };

    Ok(Pbkdf2.hash_password_customized(
        plain_text_password.as_bytes(),
        None,
        parsed_hash.version,
        params,
        parsed_hash.salt.unwrap())?
        .to_string())
}


impl From<&PBKDF2Policy> for api::Pbkdf2Policy {
    fn from(pbkdf2: &PBKDF2Policy) -> Self {
        api::Pbkdf2Policy {
            cost: pbkdf2.cost,
            output_len: pbkdf2.output_len,
        }
    }
}

impl From<&api::new_policy::Algorithm> for Option<PBKDF2Policy> {
    fn from(alogrithm: &api::new_policy::Algorithm) -> Self {
        match alogrithm {
            api::new_policy::Algorithm::ArgonPolicy(_)  => None,
            api::new_policy::Algorithm::BcryptPolicy(_) => None,
            api::new_policy::Algorithm::Pbkdf2Policy(pbkdf2) => Some(PBKDF2Policy {
                cost: pbkdf2.cost,
                output_len: pbkdf2.output_len,
            }),
        }
    }
}


#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_basic_hash_and_verify() -> Result<(), VaultError> {
        let pbkdf2 = PBKDF2Policy::default();
        let phc = hash_into_phc(&pbkdf2, "wibble")?;

        assert_eq!(validate(&phc, "wibble")?, true);
        assert_eq!(validate(&phc, "wobble")?, false);
        Ok(())
    }

    #[test]
    fn test_use_existing_phc_details_to_rehash() -> Result<(), VaultError> {
        let pbkdf2 = PBKDF2Policy::default();
        let phc1 = hash_into_phc(&pbkdf2, "wibble")?;
        let phc2 = rehash_using_phc(&phc1, "wibble")?;

        assert_eq!(phc1, phc2);
        Ok(())
    }

}