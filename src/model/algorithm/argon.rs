use rand_core::OsRng;
use std::{fs, str::FromStr};
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
    let pepper = pepper()?;
    let algorithm = argon2::Argon2::new(
        Some(pepper.as_bytes()),
        12, // Ignored - phc values are used.
        12, // Ignored - phc values are used.
        1,  // Ignored - phc values are used.
        argon2::Version::V0x13)?;

    let parsed_hash = argon2::PasswordHash::new(&phc).unwrap();
    match argon2::PasswordVerifier::verify_password(&algorithm, plain_text_password.as_bytes(), &parsed_hash) {
        Ok(_)  => Ok(true),
        Err(_) => Ok(false),
    }
}


pub fn hash_into_phc(argon: &ArgonPolicy, plain_text_password: &str) -> Result<String, VaultError> {
    let password = plain_text_password.as_bytes();
    let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
    let pepper = pepper()?;

    let algorithm = argon2::Argon2::new(
        Some(pepper.as_bytes()),
        argon.iterations,
        argon.memory_size_kb,
        argon.parallelism,
        argon2::Version::try_from(argon.version)?)?;

    // Hash password to PHC string ($argon2id$v=19$...)
    Ok(argon2::PasswordHasher::hash_password_simple(&algorithm, password, salt.as_ref())?.to_string())
}


///
/// Read the secret pepper from a file - this is a blocking operation.
///
fn pepper() -> Result<String, VaultError> {
    fs::read_to_string("secrets/pepper")
        .map_err(|err| VaultError::new(ErrorCode::SecretFileMissing, &format!("Unable to read secret: {}", err)))
}


///
/// Take a pre-existing phc string, and use all the values to hash a different plain-text password
/// to produce a new phc. Typically this can be used to compare new passwords against old password
/// history to detect duplicates.
///
pub fn rehash_using_phc(phc: &str, plain_text_password: &str) -> Result<String, VaultError> {

    // Extract the details from the phc to apply the same hashing computation to a new plain text password.
    let parsed_hash = argon2::PasswordHash::new(&phc).unwrap();
    let salt = parsed_hash.salt.expect("Could not parse salt from phc");
    let iterations = parsed_hash.params.get("t").expect("No iterations in phc").decimal().expect("Iterations in phc not numeric");
    let memory_size_kb = parsed_hash.params.get("m").expect("No memory size in phc").decimal().expect("Memory size in phc not numeric");
    let parallelism = parsed_hash.params.get("p").expect("No parallelism in phc").decimal().expect("Parallelism in phc no numeric");
    let version = parsed_hash.version.expect("No version in phc");
    let pepper = pepper()?;

    let alogrithm = argon2::Argon2::new(
        Some(pepper.as_bytes()),
        iterations,
        memory_size_kb,
        parallelism,
        argon2::Version::try_from(version)?)?;

    // Hash password to PHC string ($argon2id$v=19$...)
    Ok(argon2::PasswordHasher::hash_password_simple(&alogrithm, plain_text_password.as_bytes(), salt.as_ref())?.to_string())
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


// impl FromStr for ArgonHashType {
//     type Err = VaultError;

//     fn from_str(input: &str) -> Result<ArgonHashType, Self::Err> {
//         match input {
//             "argon2i"  => Ok(ArgonHashType::ARGON2I),
//             "argon2d"  => Ok(ArgonHashType::ARGON2D),
//             "argon2id" => Ok(ArgonHashType::ARGON2ID),
//             _          => Err(ErrorCode::UnknownAlgorithmVariant.with_msg(&format!("Unknown argon variant {}", input))),
//         }
//     }
// }

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

impl From<&api::new_policy::Algorithm> for Option<ArgonPolicy> {
    fn from(alogrithm: &api::new_policy::Algorithm) -> Self {
        match alogrithm {
            api::new_policy::Algorithm::ArgonPolicy(argon) => {
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
            api::new_policy::Algorithm::BcryptPolicy(_) => None,
            api::new_policy::Algorithm::Pbkdf2Policy(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_basic_hash_and_verify() -> Result<(), VaultError> {
        let argon = ArgonPolicy::default();
        let phc = hash_into_phc(&argon, "wibble")?;

        assert_eq!(validate(&phc, "wibble")?, true);
        assert_eq!(validate(&phc, "wobble")?, false);
        Ok(())
    }

    #[test]
    fn test_use_existing_phc_details_to_rehash() -> Result<(), VaultError> {
        let argon = ArgonPolicy::default();
        let phc1 = hash_into_phc(&argon, "wibble")?;
        let phc2 = rehash_using_phc(&phc1, "wibble")?;

        assert_eq!(phc1, phc2);
        Ok(())
    }
}