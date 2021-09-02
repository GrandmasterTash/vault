use pbkdf2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, Salt};
use pbkdf2::{Pbkdf2, password_hash::SaltString};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use crate::{grpc::api, utils::errors::VaultError};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PBKDF2Policy {
    pub cost: u32,
    pub dk_len: u32, // Derived key length in bytes (password length)
}

impl Default for PBKDF2Policy {
    fn default() -> Self {
        Self {
            cost: 1, // Do not use this in production unless you want to be brute forced.,
            dk_len: 32,
        }
    }
}

impl PBKDF2Policy {
    pub fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError> {
        // TODO: A pepper.
        let salt = SaltString::generate(&mut OsRng);
        let salt = Salt::new(salt.as_str()).unwrap();
        let params = pbkdf2::Params {
            rounds: self.cost,
            output_length: self.dk_len as usize,
        };

        // Hash password to PHC string ($pbkdf2-sha256$...)
        Ok(Pbkdf2.hash_password_customized(
            plain_text_password.as_bytes(),
            None,
            None,
            params,
            salt)?.to_string())
        // Ok(Pbkdf2.hash_password(plain_text_password.as_bytes(), &salt)?.to_string())
    }
}


pub fn validate(phc: &str, plain_text_password: &str) -> Result<bool, VaultError> {
    let parsed_hash = PasswordHash::new(&phc)?;
    Ok(Pbkdf2.verify_password(plain_text_password.as_bytes(), &parsed_hash).is_ok())
}


impl From<&PBKDF2Policy> for api::Pbkdf2Policy {
    fn from(pbkdf2: &PBKDF2Policy) -> Self {
        api::Pbkdf2Policy {
            cost: pbkdf2.cost,
            dk_len: pbkdf2.dk_len,
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
                dk_len: pbkdf2.dk_len,
            }),
        }
    }
}