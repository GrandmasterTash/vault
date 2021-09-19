use rand_core::OsRng;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::{grpc::api, utils::errors::{ErrorCode, VaultError}};

#[allow(clippy::enum_variant_names)] // Stop clippy complaining they all start with same name.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum BCryptVersion {
    TwoA,
    TwoB,
    TwoX,
    TwoY
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BCryptPolicy {
    pub version: BCryptVersion,
    pub cost: u32
}


pub fn validate(phc: &str, plain_text_password: &str) -> Result<bool, VaultError> {
    bcrypt::verify(plain_text_password, phc).map_err(VaultError::from)
}


pub fn hash_into_phc(bcrypt: &BCryptPolicy, plain_text_password: &str) -> Result<String, VaultError> {
    // Use argon to generate a salt.
    let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
    let salt: String = salt.as_str().chars().take(16).collect();
    let hashed = bcrypt::hash_with_salt(plain_text_password, bcrypt.cost, salt.as_bytes())?;

    Ok(hashed.format_for_version(bcrypt.version.into()))
}


///
/// Take a pre-existing phc string, and use all the values to hash a different plain-text password
/// to produce a new phc. Typically this can be used to compare new passwords against old password
/// history to detect duplicates.
///
pub fn rehash_using_phc(phc: &str, plain_text_password: &str) -> Result<String, VaultError> {

    let version = get_internal_version(phc)?;
    let hashed = bcrypt::HashParts::from_str(phc)?;
    let salt = base64::decode_config(hashed.get_salt(), base64::BCRYPT).unwrap();

    Ok(bcrypt::hash_with_salt(plain_text_password, hashed.get_cost(), &salt)?.format_for_version(version))
}

///
/// Return the 3rd party bcrypt version enum from the phc string.
///
/// Needed because their implementation of HashParts doesn't expose it :(
///
fn get_internal_version(phc: &str) -> Result<bcrypt::Version, VaultError> {
    let mut split = phc.split('$');
    split.next(); /* Skip first it's blank */

    match split.next() {
        Some(algorithm) => {
            match algorithm {
                "2a" => Ok(bcrypt::Version::TwoA),
                "2b" => Ok(bcrypt::Version::TwoB),
                "2x" => Ok(bcrypt::Version::TwoX),
                "2y" => Ok(bcrypt::Version::TwoY),
                _    => Err(ErrorCode::InvalidPHCFormat.with_msg(&format!("algorithm {} is un-handled", algorithm))),
            }
        },
        None => Err(ErrorCode::InvalidPHCFormat.with_msg("The PHC is invalid, there's no algorithm")),
    }
}


impl Default for BCryptPolicy {
    fn default() -> Self {
        Self {
            version: BCryptVersion::TwoB,
            cost: bcrypt::DEFAULT_COST
        }
    }
}

impl From<BCryptVersion> for bcrypt::Version {
    fn from(version: BCryptVersion) -> Self {
        match version {
            BCryptVersion::TwoA => bcrypt::Version::TwoA,
            BCryptVersion::TwoB => bcrypt::Version::TwoB,
            BCryptVersion::TwoX => bcrypt::Version::TwoX,
            BCryptVersion::TwoY => bcrypt::Version::TwoY,
        }
    }
}

impl From<&BCryptPolicy> for api::BCryptPolicy {
    fn from(bcrypt: &BCryptPolicy) -> Self {
        api::BCryptPolicy {
            version: match bcrypt.version {
                BCryptVersion::TwoA => api::b_crypt_policy::BCryptVersion::Twoa.into(),
                BCryptVersion::TwoX => api::b_crypt_policy::BCryptVersion::Twox.into(),
                BCryptVersion::TwoY => api::b_crypt_policy::BCryptVersion::Twoy.into(),
                BCryptVersion::TwoB => api::b_crypt_policy::BCryptVersion::Twob.into(),
            },
            cost: bcrypt.cost,
        }
    }
}

impl From<&api::new_policy::Algorithm> for Option<BCryptPolicy> {
    fn from(alogrithm: &api::new_policy::Algorithm) -> Self {
        match alogrithm {
            api::new_policy::Algorithm::BcryptPolicy(bcrypt) => {
                Some(BCryptPolicy {
                    version: match bcrypt.version {
                        0 => BCryptVersion::TwoA,
                        1 => BCryptVersion::TwoX,
                        2 => BCryptVersion::TwoY,
                        3 => BCryptVersion::TwoB,
                        unknown => panic!("Unhandled protobuf bcrypt version {}", unknown)
                    },
                    cost: bcrypt.cost,
                })
            },
            api::new_policy::Algorithm::ArgonPolicy(_)  => None,
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
        let bcrypt = BCryptPolicy::default();
        let phc = hash_into_phc(&bcrypt, "wibble")?;

        assert_eq!(validate(&phc, "wibble")?, true);
        assert_eq!(validate(&phc, "wobble")?, false);
        Ok(())
    }

    #[test]
    fn test_use_existing_phc_details_to_rehash() -> Result<(), VaultError> {
        let bcrypt = BCryptPolicy::default();
        let phc1 = hash_into_phc(&bcrypt, "wibble")?;
        let phc2 = rehash_using_phc(&phc1, "wibble")?;

        assert_eq!(phc1, phc2);
        Ok(())
    }

}