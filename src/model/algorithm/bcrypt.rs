use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use crate::{grpc::api, utils::errors::VaultError};

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
    bcrypt::verify(plain_text_password, phc).map_err(|e| VaultError::from(e))
}

impl Default for BCryptPolicy {
    fn default() -> Self {
        Self {
            version: BCryptVersion::TwoB,
            cost: 4 // Performance for tests - always chose stronger in prod.
        }
    }
}

impl BCryptPolicy {
    pub fn hash_into_phc(&self, plain_text_password: &str) -> Result<String, VaultError> {
        // Use argon to generate a salt.
        let salt = argon2::password_hash::SaltString::generate(&mut OsRng); // TODO: include a pepper.
        let salt: String = salt.as_str().chars().take(16).collect();
        let hashed = bcrypt::hash_with_salt(plain_text_password, self.cost, salt.as_bytes())?;

        Ok(hashed.format_for_version(self.version.into()))
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

impl From<&api::policy::Algorithm> for Option<BCryptPolicy> {
    fn from(alogrithm: &api::policy::Algorithm) -> Self {
        match alogrithm {
            api::policy::Algorithm::BcryptPolicy(bcrypt) => {
                Some(BCryptPolicy {
                    version: match bcrypt.version {
                        0 => BCryptVersion::TwoA,
                        1 => BCryptVersion::TwoX,
                        2 => BCryptVersion::TwoY,
                        3 => BCryptVersion::TwoB,
                        unknown @ _ => panic!("Unhandled protobuf bcrypt version {}", unknown)
                    },
                    cost: bcrypt.cost,
                })
            },
            api::policy::Algorithm::ArgonPolicy(_)  => None,
            api::policy::Algorithm::Pbkfd2Policy(_) => None,
        }
    }
}