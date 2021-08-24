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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ArgonHashType {
    ARGON2D,
    ARGON2I,
    ARGON2ID
}

// TODO: This is not a policy it is also a general algorthm
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

// pub trait Hasher {
//     async fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError>;
// }

// // TODO: Move each alg into sub-module.
// impl Hasher for ArgonPolicyDB {
//     fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError> {
//         let password = plain_text_password.as_bytes();
//         let salt = SaltString::generate(&mut OsRng);

//         let argon2 = Argon2::new(
//             None /* TODO: pepper */,
//             self.iterations,
//             self.memory_size_kb,
//             self.parallelism,
//             Version::try_from(self.version)?)?;
//             // .expect("Unable to create argon2 hasher");

//         // Hash password to PHC string ($argon2id$v=19$...)
//         Ok(argon2.hash_password_simple(password, salt.as_ref())?.to_string())
//     }
// }

// impl Hasher for BcryptPolicyDB {
//     fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError> {
//         Ok(format!("wibble$bcrypt${}", plain_text_password)) // TODO: Brcypt
//     }
// }

// impl Hasher for PBKDF2PolicyDB {
//     fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError> {
//         Ok(format!("wibble$pbkdf2${}", plain_text_password)) // TODO: pdbkdf2
//     }
// }
// pub trait Validator {
//     fn validate(&self, plain_text_password: &str) -> Result<bool, InternalError>;
// }

// impl Validator for ArgonPolicyDB {
//     fn validate(&self, plain_text_password: &str) -> Result<bool, InternalError> {
//         todo!()
//     }
// }

// impl Validator for BcryptPolicyDB {
//     fn validate(&self, plain_text_password: &str) -> Result<bool, InternalError> {
//         todo!()
//     }
// }

// impl Validator for PBKDF2PolicyDB {
//     fn validate(&self, plain_text_password: &str) -> Result<bool, InternalError> {
//         todo!()
//     }
// }

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
        // None => return Err(VaultError::new(ErrorCode::InvalidPHCFormat, &format!("The PHC is invalid, there's no algorthm"))),
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
            // .expect("Unable to create argon2 hasher");

        // Hash password to PHC string ($argon2id$v=19$...)
        Ok(argon2.hash_password_simple(password, salt.as_ref())?.to_string())
    }


    // ///
    // /// Inflate an argon algorthm from a string in the form: -
    // ///
    // ///   $argon2id$v=19$m=16384,t=20,p=1$77QFGJMDLMwvR7+lYvuNtw$82Byd2enomP62Z01Wcb1g5+KApYhQygW6BEYCXnZj5A
    // ///
    // /// Such that the return value is an Argon algorthm and the encapsulated salt (base64 encoded) and
    // /// hashed password (base64 encoded).
    // ///
    // pub fn from_phc(phc: &str) -> Result<(Self, /* salt */&str, /* password */&str), InternalError> {
    //     // TODO: Nom the string into a DB struct.

    //     let mut split = phc.split("$");

    //     let hash_type = match split.next() {
    //         Some(algorthm) => ArgonHashType::from_str(algorthm)?,
    //         None => return Err(InternalError::InvalidPHCFormat{ algorthm: "Argon".to_string(), cause: "no algorthm".to_string() }),
    //     };

    //     let version = match split.next() {
    //         Some(version) => {
    //             // TODO: Split by = should v=<blah>.

    //             version.parse::<u32>()
    //                 .map_err(|e| InternalError::InvalidPHCFormat{ algorthm: "Argon".to_string(), cause: format!("invalid version: {}", e) })?
    //         },
    //         None => return Err(InternalError::InvalidPHCFormat{ algorthm: "Argon".to_string(), cause: "no version".to_string() }),
    //     };

    //     // TODO: Make above a fn and re-use....
    //     let memory_size_kb = match split.next() {
    //         Some(memory_size_kb) => memory_size_kb.parse::<u32>().map_err(|e| InternalError::InvalidPHCFormat{ algorthm: "Argon".to_string(), cause: format!("invalid memory size: {}", e) })?,
    //         None => return Err(InternalError::InvalidPHCFormat{ algorthm: "Argon".to_string(), cause: "no memory size".to_string() }),
    //     };

    //     let tag_length = match split.next() {
    //         Some(tag_length) => tag_length.parse::<u32>().map_err(|e| InternalError::InvalidPHCFormat{ algorthm: "Argon".to_string(), cause: format!("invalid tag length: {}", e) })?,
    //         None => return Err(InternalError::InvalidPHCFormat{ algorthm: "Argon".to_string(), cause: "no tag length".to_string() }),
    //     };

    //     let iterations = match split.next() {
    //         Some(iterations) => iterations.parse::<u32>().map_err(|e| InternalError::InvalidPHCFormat{ algorthm: "Argon".to_string(), cause: format!("invalid iterations: {}", e) })?,
    //         None => return Err(InternalError::InvalidPHCFormat{ algorthm: "Argon".to_string(), cause: "no iterations".to_string() }),
    //     };

    //     // TODO: Salt, then hash.

    //     // Ok(ArgonPolicyDB {
    //     //     parallelism: 1,
    //     //     tag_length: 128,
    //     //     memory_size_kb: 1024 * 16,
    //     //     iterations: 20,
    //     //     version: 19,
    //     //     hash_type: ArgonHashType::ARGON2ID
    //     // })
    //     todo!()
    // }
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