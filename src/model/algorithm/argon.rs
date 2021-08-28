use rand_core::OsRng;
use std::str::FromStr;
use derive_more::Display;
use std::convert::TryFrom;
use serde::{Deserialize, Serialize};
use crate::{grpc::api, utils::errors::{ErrorCode, VaultError}};

#[derive(Clone, Copy, Debug, Deserialize, Display, Serialize, PartialEq)]
pub enum ArgonHashType {
    ARGON2D,
    ARGON2I,
    ARGON2ID
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArgonPolicy {
    pub parallelism: u32,
    pub tag_length: u32,
    pub memory_size_kb: u32,
    pub iterations: u32,
    pub version: u32,
    pub hash_type: ArgonHashType
}


pub fn validate(phc: &str, plain_text_password: &str) -> Result<bool, VaultError> {
    let parsed_hash = argon2::PasswordHash::new(&phc).unwrap();
    match argon2::PasswordVerifier::verify_password(&argon2::Argon2::default(), plain_text_password.as_bytes(), &parsed_hash) {
        Ok(_)  => Ok(true),
        Err(_) => Ok(false),
    }
}


impl Default for ArgonPolicy {
    fn default() -> Self {
        ArgonPolicy {
            parallelism: 1,
            tag_length: 128,
            memory_size_kb: 1024 * 16,
            iterations: 1,
            version: 19,
            hash_type: ArgonHashType::ARGON2ID
        }
    }
}

// make module fn like validate.
impl ArgonPolicy {
    pub fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError> {
        let password = plain_text_password.as_bytes();
        let salt = argon2::password_hash::SaltString::generate(&mut OsRng);

        let argon2 = argon2::Argon2::new(
            None /* TODO: pepper */,
            self.iterations,
            self.memory_size_kb,
            self.parallelism,
            argon2::Version::try_from(self.version)?)?;

        // Hash password to PHC string ($argon2id$v=19$...)
        Ok(argon2::PasswordHasher::hash_password_simple(&argon2, password, salt.as_ref())?.to_string())
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

impl From<&ArgonPolicy> for api::ArgonPolicy {
    fn from(argon: &ArgonPolicy) -> Self {
        api::ArgonPolicy {
            parallelism:    argon.parallelism,
            tag_length:     argon.tag_length,
            memory_size_kb: argon.memory_size_kb,
            iterations:     argon.iterations,
            version:        argon.version,
            hash_type:      match argon.hash_type {
                ArgonHashType::ARGON2D  => api::argon_policy::HashType::Argon2d.into(),
                ArgonHashType::ARGON2I  => api::argon_policy::HashType::Argon2i.into(),
                ArgonHashType::ARGON2ID => api::argon_policy::HashType::Argon2id.into(),
            },
        }
    }
}

impl From<&api::policy::Algorithm> for Option<ArgonPolicy> {
    fn from(alogrithm: &api::policy::Algorithm) -> Self {
        match alogrithm {
            api::policy::Algorithm::ArgonPolicy(argon) => {
                Some(ArgonPolicy{
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
            api::policy::Algorithm::BcryptPolicy(_) => None,
            api::policy::Algorithm::Pbkfd2Policy(_) => None,
        }
    }
}